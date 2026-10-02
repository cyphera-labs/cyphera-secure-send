//! Login, callback, logout, and the session view. Anonymous mode answers the
//! session view with "not authenticated" and has no login to offer.

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect, Response};
use axum_extra::extract::cookie::CookieJar;
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

use super::SharedState;
use crate::audit::{AuditEvent, AuditEventType, ClientContext, Reason};
use crate::auth::RequestPrincipal;
use crate::auth::oidc::{OidcError, safe_next};

/// The principal for this request: the session named by the cookie, if any
/// and if valid. Anonymous mode never has one.
pub async fn principal(state: &SharedState, headers: &HeaderMap) -> RequestPrincipal {
    let Some(oidc) = &state.oidc else {
        return RequestPrincipal::anonymous();
    };
    let jar = CookieJar::from_headers(headers);
    let Some(cookie) = jar.get(oidc.cookies.session_name()) else {
        return RequestPrincipal::anonymous();
    };
    match oidc.sessions.get(cookie.value()).await {
        Ok(Some(session)) => RequestPrincipal {
            subject: Some(session.subject),
            email: Some(session.email),
            issuer: Some(session.issuer),
        },
        Ok(None) => RequestPrincipal::anonymous(),
        // Fail closed: a session that cannot be confirmed is no session.
        Err(e) => {
            tracing::warn!(error = %e, "the session store cannot be reached");
            RequestPrincipal::anonymous()
        }
    }
}

#[derive(Serialize)]
pub struct SessionView {
    pub authenticated: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
}

pub async fn session(State(state): State<SharedState>, headers: HeaderMap) -> Json<SessionView> {
    let p = principal(&state, &headers).await;
    Json(SessionView {
        authenticated: p.is_authenticated(),
        email: p.email.as_ref().map(|e| e.to_string()),
        subject: p.subject,
    })
}

#[derive(Deserialize)]
pub struct LoginQuery {
    pub next: Option<String>,
}

pub async fn login(
    State(state): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<LoginQuery>,
) -> Response {
    let Some(oidc) = &state.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(refused) = at_the_door(&state, peer, &headers).await {
        return refused.into_response();
    }
    let next = safe_next(q.next.as_deref());
    match oidc.begin_login(next).await {
        Ok((url, login_state)) => {
            let jar = CookieJar::new().add(oidc.cookies.login(login_state, oidc.login_ttl()));
            (jar, Redirect::to(url.as_str())).into_response()
        }
        Err(_) => (StatusCode::SERVICE_UNAVAILABLE, "login is unavailable").into_response(),
    }
}

#[derive(Deserialize)]
pub struct CallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
    pub error_description: Option<String>,
}

pub async fn callback(
    State(state): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Query(q): Query<CallbackQuery>,
) -> Response {
    let Some(oidc) = &state.oidc else {
        return StatusCode::NOT_FOUND.into_response();
    };
    if let Err(refused) = at_the_door(&state, peer, &headers).await {
        return refused.into_response();
    }
    let ctx = client_context(&state, peer, &headers);
    let jar = CookieJar::from_headers(&headers);
    let remove_login = jar
        .clone()
        .remove(oidc.cookies.removal(oidc.cookies.login_name()));

    if let Some(err) = q.error {
        tracing::warn!(
            error = %sanitize(&err),
            description = %sanitize(q.error_description.as_deref().unwrap_or_default()),
            "provider reported a sign-in error"
        );
        state.audit.emit(
            AuditEvent::failure(AuditEventType::AuthLoginFailed, Reason::ProviderError)
                .with_client(&ctx),
        );
        return (
            StatusCode::BAD_REQUEST,
            remove_login,
            "sign-in was not completed",
        )
            .into_response();
    }

    let (Some(code), Some(returned_state)) = (q.code, q.state) else {
        state.audit.emit(
            AuditEvent::failure(AuditEventType::AuthLoginFailed, Reason::IncompleteResponse)
                .with_client(&ctx),
        );
        return (
            StatusCode::BAD_REQUEST,
            remove_login,
            "sign-in response is incomplete",
        )
            .into_response();
    };
    let bound = jar
        .get(oidc.cookies.login_name())
        .map(|c| c.value().to_owned());
    if bound.as_deref() != Some(returned_state.as_str()) {
        state.audit.emit(
            AuditEvent::failure(AuditEventType::AuthLoginFailed, Reason::StateMismatch)
                .with_client(&ctx),
        );
        return (
            StatusCode::BAD_REQUEST,
            remove_login,
            "sign-in response does not match this browser",
        )
            .into_response();
    }

    match oidc.complete_login(&returned_state, &code).await {
        Ok((session_id, session, next)) => {
            metrics::counter!("securesend_auth_logins_total").increment(1);
            let mut event = AuditEvent::success(AuditEventType::AuthLogin).with_client(&ctx);
            event.subject = Some(session.subject.clone());
            event.issuer = Some(session.issuer.clone());
            event.sender = Some(session.email.to_string());
            state.audit.emit(event);
            let jar = remove_login.add(
                oidc.cookies
                    .session(session_id, oidc.sessions.session_ttl()),
            );
            (jar, Redirect::to(&next)).into_response()
        }
        // Not a failure of the sign-in: the store behind it cannot be reached.
        // The browser is told to try again rather than that it was refused.
        Err(OidcError::Store(e)) => {
            tracing::warn!(error = %sanitize(&e), "the session store cannot be reached");
            (
                StatusCode::SERVICE_UNAVAILABLE,
                remove_login,
                "sign-in is unavailable right now; try again",
            )
                .into_response()
        }
        Err(e) => {
            metrics::counter!("securesend_auth_failures_total").increment(1);
            tracing::warn!(error = %sanitize(&e.to_string()), "sign-in could not be completed");
            state.audit.emit(
                AuditEvent::failure(AuditEventType::AuthLoginFailed, Reason::TokenRejected)
                    .with_client(&ctx),
            );
            (
                StatusCode::UNAUTHORIZED,
                remove_login,
                "sign-in could not be verified",
            )
                .into_response()
        }
    }
}

pub async fn logout(
    State(state): State<SharedState>,
    axum::extract::ConnectInfo(peer): axum::extract::ConnectInfo<SocketAddr>,
    headers: HeaderMap,
) -> Response {
    let Some(oidc) = &state.oidc else {
        return StatusCode::NO_CONTENT.into_response();
    };
    let ctx = client_context(&state, peer, &headers);
    let jar = CookieJar::from_headers(&headers);
    if let Some(cookie) = jar.get(oidc.cookies.session_name()) {
        if let Ok(Some(session)) = oidc.sessions.get(cookie.value()).await {
            let mut event = AuditEvent::success(AuditEventType::AuthLogout).with_client(&ctx);
            event.subject = Some(session.subject);
            event.issuer = Some(session.issuer);
            state.audit.emit(event);
        }
        if let Err(e) = oidc.sessions.revoke(cookie.value()).await {
            // The cookie is removed regardless; the session then expires on
            // its own. Worth knowing, not worth failing the sign-out for.
            tracing::warn!(error = %e, "could not end the session in the store");
        }
    }
    let jar = jar.remove(oidc.cookies.removal(oidc.cookies.session_name()));
    (StatusCode::NO_CONTENT, jar).into_response()
}

/// Provider-supplied text goes to the application log only, bounded and
/// stripped of control characters.
fn sanitize(s: &str) -> String {
    s.chars().filter(|c| !c.is_control()).take(200).collect()
}

/// The sign-in door has a per-address limit like the others. It is the one
/// anonymous door whose every accepted knock costs a request to the identity
/// provider under this deployment's credentials.
async fn at_the_door(
    state: &SharedState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> Result<(), super::error::ApiError> {
    let (ip, ctx, _) = super::messages::context(state, peer, headers).await;
    super::messages::rate_limited(state, super::ratelimit::Endpoint::Auth, ip, &ctx)
}

fn client_context(state: &SharedState, peer: SocketAddr, headers: &HeaderMap) -> ClientContext {
    let ip = super::client_ip::resolve(
        peer,
        headers,
        &state.settings.server.trusted_proxies,
        state.settings.server.trusted_hops,
    );
    let audit = &state.settings.audit;
    ClientContext {
        ip: audit.include_client_ip.then(|| ip.to_string()),
        user_agent: if audit.include_user_agent {
            headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.chars().take(256).collect())
        } else {
            None
        },
        subject: None,
        issuer: None,
    }
}
