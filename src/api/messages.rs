//! The three message endpoints.

use axum::Json;
use axum::extract::{ConnectInfo, FromRequestParts, Path, State};
use axum::http::request::Parts;
use axum::http::{HeaderMap, StatusCode};
use axum::response::IntoResponse;
use serde::{Deserialize, Serialize};
use std::marker::PhantomData;
use std::net::SocketAddr;
use time::format_description::well_known::Rfc3339;

use super::error::{ApiError, ApiJson};
use super::ratelimit::Endpoint;
use super::{SharedState, client_ip};
use crate::application::{CreateError, CreateRequest};
use crate::audit::{AuditEvent, AuditEventType, ClientContext, Reason};
use crate::auth::RequestPrincipal;
use crate::domain::envelope::EnvelopeWire;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CreateBody {
    pub sender: String,
    pub recipient: String,
    pub ttl_seconds: u64,
    pub verifier: String,
    pub envelope: EnvelopeWire,
}

#[derive(Serialize)]
pub struct CreateResponse {
    pub id: String,
    pub revoke_token: String,
    pub expires_at: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConsumeBody {
    pub proof: String,
}

#[derive(Serialize)]
pub struct ConsumeResponse {
    pub sender: String,
    /// True when the identity provider vouched for the sender's address;
    /// false when the sender typed it. The interface says which.
    pub sender_authenticated: bool,
    pub recipient: String,
    pub created_at: String,
    pub envelope: EnvelopeWire,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeBody {
    pub revoke_token: String,
}

pub(super) async fn context(
    state: &SharedState,
    peer: SocketAddr,
    headers: &HeaderMap,
) -> (std::net::IpAddr, ClientContext, RequestPrincipal) {
    let ip = client_ip::resolve(
        peer,
        headers,
        &state.settings.server.trusted_proxies,
        state.settings.server.trusted_hops,
    );
    let principal = super::auth::principal(state, headers).await;
    let audit = &state.settings.audit;
    let ctx = ClientContext {
        ip: audit.include_client_ip.then(|| ip.to_string()),
        user_agent: if audit.include_user_agent {
            headers
                .get("user-agent")
                .and_then(|v| v.to_str().ok())
                .map(|s| s.chars().take(256).collect())
        } else {
            None
        },
        subject: principal.subject.clone(),
        issuer: principal.issuer.clone(),
    };
    (ip, ctx, principal)
}

pub(super) fn rate_limited(
    state: &SharedState,
    endpoint: Endpoint,
    ip: std::net::IpAddr,
    ctx: &ClientContext,
) -> Result<(), ApiError> {
    let within_identity = match &ctx.subject {
        Some(subject) => state.limiters.check_identity(endpoint, subject),
        None => true,
    };
    if within_identity && state.limiters.check(endpoint, ip) {
        return Ok(());
    }
    metrics::counter!("securesend_rate_limited_total", "endpoint" => endpoint.as_str())
        .increment(1);
    let reason = match endpoint {
        Endpoint::Create => Reason::Create,
        Endpoint::Consume => Reason::Consume,
        Endpoint::Revoke => Reason::Revoke,
        Endpoint::Auth => Reason::Login,
    };
    state
        .audit
        .emit(AuditEvent::failure(AuditEventType::RateLimited, reason).with_client(ctx));
    Err(ApiError::RateLimited)
}

/// Which door a request is at. Each is a marker for the gate below.
pub struct Create;
pub struct Consume;
pub struct Revoke;

pub trait Door: Send + Sync + 'static {
    const ENDPOINT: Endpoint;
}
impl Door for Create {
    const ENDPOINT: Endpoint = Endpoint::Create;
}
impl Door for Consume {
    const ENDPOINT: Endpoint = Endpoint::Consume;
}
impl Door for Revoke {
    const ENDPOINT: Endpoint = Endpoint::Revoke;
}

/// Who is calling and whether they may, decided from the request head
/// alone. Being an extractor of the head rather than a call inside the
/// handler is what puts it before the body: a caller who is over their limit
/// is refused before the service reads, buffers or parses anything they
/// sent, so the limit bounds their cost as well as their count.
pub struct Gate<D: Door> {
    pub ctx: ClientContext,
    pub principal: RequestPrincipal,
    _door: PhantomData<D>,
}

impl<D: Door> FromRequestParts<SharedState> for Gate<D> {
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, state: &SharedState) -> Result<Self, ApiError> {
        let ConnectInfo(peer) = ConnectInfo::<SocketAddr>::from_request_parts(parts, state)
            .await
            .map_err(|_| ApiError::Internal)?;
        let (ip, ctx, principal) = context(state, peer, &parts.headers).await;
        rate_limited(state, D::ENDPOINT, ip, &ctx)?;
        Ok(Self {
            ctx,
            principal,
            _door: PhantomData,
        })
    }
}

pub async fn create(
    State(state): State<SharedState>,
    Gate { ctx, principal, .. }: Gate<Create>,
    ApiJson(body): ApiJson<CreateBody>,
) -> Result<impl IntoResponse, ApiError> {
    let request = CreateRequest {
        sender: body.sender,
        recipient: body.recipient,
        ttl_seconds: body.ttl_seconds,
        verifier: body.verifier,
        envelope: body.envelope,
    };
    let created = state
        .service
        .create(request, &principal, &ctx)
        .await
        .map_err(|e| match e {
            CreateError::Denied => ApiError::Forbidden,
            CreateError::Full => ApiError::Capacity,
            CreateError::Internal => ApiError::Internal,
            CreateError::Envelope(crate::domain::EnvelopeError::TooLarge) => ApiError::TooLarge,
            other => ApiError::BadRequest(other.to_string()),
        })?;

    Ok((
        StatusCode::CREATED,
        Json(CreateResponse {
            id: created.id.to_string(),
            revoke_token: created.revoke_token.to_base64url(),
            expires_at: created.expires_at.format(&Rfc3339).unwrap_or_default(),
        }),
    ))
}

pub async fn consume(
    State(state): State<SharedState>,
    Gate { ctx, principal, .. }: Gate<Consume>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<ConsumeBody>,
) -> Result<impl IntoResponse, ApiError> {
    let consumed = state
        .service
        .consume(&id, &body.proof, &principal, &ctx)
        .await
        .ok_or(ApiError::Unavailable)?;

    Ok(Json(ConsumeResponse {
        sender: consumed.sender.to_string(),
        sender_authenticated: consumed.sender_authenticated,
        recipient: consumed.recipient.to_string(),
        created_at: consumed.created_at.format(&Rfc3339).unwrap_or_default(),
        envelope: consumed.envelope.to_wire(),
    }))
}

pub async fn revoke(
    State(state): State<SharedState>,
    Gate { ctx, .. }: Gate<Revoke>,
    Path(id): Path<String>,
    ApiJson(body): ApiJson<RevokeBody>,
) -> Result<impl IntoResponse, ApiError> {
    state.service.revoke(&id, &body.revoke_token, &ctx).await;
    Ok(StatusCode::NO_CONTENT)
}
