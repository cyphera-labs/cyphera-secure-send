//! HTTP surface. Public listener: the interface, the message API, branding.
//! Management listener: liveness, readiness, metrics.

pub mod auth;
pub mod branding;
pub mod client_ip;
pub mod error;
pub mod headers;
pub mod management;
pub mod messages;
pub mod ratelimit;
pub mod static_files;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::http::StatusCode;
use axum::routing::{get, post};
use std::sync::Arc;
use std::time::Duration;
use tower_http::timeout::TimeoutLayer;

use crate::application::MessageService;
use crate::audit::AuditSink;
use crate::auth::oidc::OidcProvider;
use crate::config::Settings;

pub struct AppState {
    pub settings: Settings,
    pub service: MessageService,
    pub audit: Arc<dyn AuditSink>,
    pub limiters: ratelimit::Limiters,
    pub branding: branding::BrandingAssets,
    /// Present in OIDC mode only.
    pub oidc: Option<Arc<OidcProvider>>,
}

pub type SharedState = Arc<AppState>;

pub fn public_router(state: SharedState) -> Router {
    let body_limit = state.service.limits().envelope.max_request_body_bytes();
    let hsts = state.settings.server.hsts;
    let request_timeout = Duration::from_secs(state.settings.server.request_timeout_seconds);

    let api = Router::new()
        .route("/v1/messages", post(messages::create))
        .route("/v1/messages/{id}/consume", post(messages::consume))
        .route("/v1/messages/{id}/revoke", post(messages::revoke))
        .route("/v1/ui-config", get(branding::ui_config))
        .route("/v1/session", get(auth::session))
        .route("/v1/health", get(management::health))
        .layer(DefaultBodyLimit::max(body_limit))
        // A body that trickles in, or stops, is dropped rather than held.
        .layer(TimeoutLayer::with_status_code(
            StatusCode::REQUEST_TIMEOUT,
            request_timeout,
        ));

    Router::new()
        .merge(api)
        .route("/auth/login", get(auth::login))
        .route("/auth/callback", get(auth::callback))
        .route("/auth/logout", post(auth::logout))
        .route("/brand/logo", get(branding::logo))
        .route("/brand/favicon", get(branding::favicon))
        .merge(static_files::router())
        .fallback(static_files::not_found)
        .layer(axum::middleware::from_fn(move |req, next| {
            headers::apply(req, next, hsts)
        }))
        .with_state(state)
}
