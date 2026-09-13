//! HTTP surface. Public listener: the interface, the message API, branding.
//! Management listener: liveness, readiness, metrics.

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
use axum::routing::{get, post};
use std::sync::Arc;

use crate::application::MessageService;
use crate::audit::AuditSink;
use crate::config::Settings;

pub struct AppState {
    pub settings: Settings,
    pub service: MessageService,
    pub audit: Arc<dyn AuditSink>,
    pub limiters: ratelimit::Limiters,
    pub branding: branding::BrandingAssets,
}

pub type SharedState = Arc<AppState>;

pub fn public_router(state: SharedState) -> Router {
    let body_limit = state.service.limits().envelope.max_request_body_bytes();
    let hsts = state.settings.server.hsts;

    let api = Router::new()
        .route("/v1/messages", post(messages::create))
        .route("/v1/messages/{id}/consume", post(messages::consume))
        .route("/v1/messages/{id}/revoke", post(messages::revoke))
        .route("/v1/ui-config", get(branding::ui_config))
        .route("/v1/health", get(management::health))
        .layer(DefaultBodyLimit::max(body_limit));

    Router::new()
        .merge(api)
        .route("/brand/logo", get(branding::logo))
        .route("/brand/favicon", get(branding::favicon))
        .merge(static_files::router())
        .fallback(static_files::not_found)
        .layer(axum::middleware::from_fn(move |req, next| {
            headers::apply(req, next, hsts)
        }))
        .with_state(state)
}
