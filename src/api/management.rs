//! Health, readiness, stats, and metrics. Served on the management listener;
//! only the minimal health probe is also on the public listener, because the
//! detailed views reveal how much traffic the service carries.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Deserialize;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::SharedState;
use crate::application::CounterSnapshot;
use crate::audit::{AuditEvent, AuditEventType};
use crate::auth::session::AccountRef;
use crate::domain::Email;
use crate::storage::StoreError;

#[derive(Serialize)]
pub struct Health {
    status: &'static str,
}

/// The public probe. Says nothing beyond "the process answers".
pub async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

pub struct ManagementState {
    pub app: SharedState,
    pub ready: Arc<AtomicBool>,
    pub prometheus: PrometheusHandle,
    pub started: Instant,
    pub started_at: OffsetDateTime,
}

impl ManagementState {
    pub fn new(app: SharedState, ready: Arc<AtomicBool>, prometheus: PrometheusHandle) -> Self {
        Self {
            app,
            ready,
            prometheus,
            started: Instant::now(),
            started_at: OffsetDateTime::now_utc(),
        }
    }
}

#[derive(Serialize)]
pub struct DetailedHealth {
    pub status: &'static str,
    pub ready: bool,
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub started_at: String,
    pub storage: StorageHealth,
}

#[derive(Serialize)]
pub struct StorageHealth {
    pub backend: &'static str,
    pub active_messages: u64,
    pub used_bytes: u64,
    pub budget_bytes: u64,
    pub used_percent: f64,
}

#[derive(Serialize)]
pub struct Stats {
    pub version: &'static str,
    pub uptime_seconds: u64,
    pub started_at: String,
    pub storage: StorageHealth,
    pub totals: Totals,
    pub limits: Limits,
}

#[derive(Serialize)]
pub struct Totals {
    #[serde(flatten)]
    pub lifecycle: CounterSnapshot,
    pub expired: u64,
    pub evicted: u64,
}

#[derive(Serialize)]
pub struct Limits {
    pub max_plaintext_bytes: usize,
    pub min_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub default_ttl_seconds: u64,
    pub ttl_options_seconds: Vec<u64>,
    pub max_failed_proofs: u32,
    pub create_per_minute: u32,
    pub consume_per_minute: u32,
}

async fn storage_health(state: &ManagementState) -> Result<StorageHealth, StoreError> {
    let store = state.app.service.store();
    let s = store.stats().await?;
    let used_percent = if s.budget_bytes == 0 {
        0.0
    } else {
        (s.weighted_bytes as f64 / s.budget_bytes as f64) * 100.0
    };
    Ok(StorageHealth {
        backend: store.backend_name(),
        active_messages: s.active_messages,
        used_bytes: s.weighted_bytes,
        budget_bytes: s.budget_bytes,
        used_percent: (used_percent * 10.0).round() / 10.0,
    })
}

/// What the management listener says when the store cannot be reached: the
/// process is alive, which is what liveness asks, but it is not serving.
fn store_unreachable(e: &StoreError) -> Response {
    tracing::warn!(error = %e, "the message store cannot be reached");
    (
        StatusCode::SERVICE_UNAVAILABLE,
        Json(serde_json::json!({"status": "store unavailable"})),
    )
        .into_response()
}

fn started_at(state: &ManagementState) -> String {
    state.started_at.format(&Rfc3339).unwrap_or_default()
}

async fn livez() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn readyz(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    if state.ready.load(Ordering::SeqCst) {
        (StatusCode::OK, "ready")
    } else {
        (StatusCode::SERVICE_UNAVAILABLE, "not ready")
    }
}

async fn detailed_health(State(state): State<Arc<ManagementState>>) -> Response {
    let ready = state.ready.load(Ordering::SeqCst);
    let storage = match storage_health(&state).await {
        Ok(storage) => storage,
        Err(e) => return store_unreachable(&e),
    };
    let body = DetailedHealth {
        status: if ready { "ok" } else { "stopping" },
        ready,
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started.elapsed().as_secs(),
        started_at: started_at(&state),
        storage,
    };
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body)).into_response()
}

async fn stats(State(state): State<Arc<ManagementState>>) -> Response {
    let (store, storage) = match (
        state.app.service.store().stats().await,
        storage_health(&state).await,
    ) {
        (Ok(store), Ok(storage)) => (store, storage),
        (Err(e), _) | (_, Err(e)) => return store_unreachable(&e),
    };
    let settings = &state.app.settings;
    Json(Stats {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started.elapsed().as_secs(),
        started_at: started_at(&state),
        storage,
        totals: Totals {
            lifecycle: state.app.service.counters().snapshot(),
            expired: store.expired_total,
            evicted: store.evicted_total,
        },
        limits: Limits {
            max_plaintext_bytes: settings.messages.max_plaintext_bytes,
            min_ttl_seconds: settings.messages.min_ttl_seconds,
            max_ttl_seconds: settings.messages.max_ttl_seconds,
            default_ttl_seconds: settings.messages.default_ttl_seconds,
            ttl_options_seconds: settings.messages.ttl_options_seconds.clone(),
            max_failed_proofs: settings.messages.max_failed_proofs,
            create_per_minute: settings.rate_limits.create_per_minute,
            consume_per_minute: settings.rate_limits.consume_per_minute,
        },
    })
    .into_response()
}

async fn metrics(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    // The gauges describe the store; when it cannot be reached they keep
    // their last values and the counters below still tell the story.
    if let Ok(stats) = state.app.service.store().stats().await {
        metrics::gauge!("securesend_messages_active").set(stats.active_messages as f64);
        metrics::gauge!("securesend_store_bytes").set(stats.weighted_bytes as f64);
        metrics::gauge!("securesend_store_budget_bytes").set(stats.budget_bytes as f64);
    }
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.prometheus.render(),
    )
}

/// One account to sign out everywhere, named the way an operator knows it.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RevokeSessionsBody {
    /// The stable identifier the provider issued, as audit events carry it.
    pub subject: Option<String>,
    /// The address, for when the subject is not to hand.
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct RevokeSessionsResponse {
    pub sessions_ended: u64,
}

/// Ends every session one account holds, now. Disabling the account at the
/// provider stops its next sign-in; this stops the ones it already has, so
/// the two together make revocation immediate. It lives on the management
/// listener because that listener is the operator's, and reachable only
/// where the deployment lets operators reach it.
async fn revoke_sessions(
    State(state): State<Arc<ManagementState>>,
    Json(body): Json<RevokeSessionsBody>,
) -> impl IntoResponse {
    let Some(oidc) = &state.app.oidc else {
        return (
            StatusCode::NOT_FOUND,
            Json(
                serde_json::json!({"error": "no sessions: the service is not in enterprise mode"}),
            ),
        )
            .into_response();
    };
    let email = match body.email.as_deref().map(Email::parse) {
        None => None,
        Some(Ok(email)) => Some(email),
        Some(Err(_)) => {
            return (
                StatusCode::BAD_REQUEST,
                Json(serde_json::json!({"error": "email is not a valid address"})),
            )
                .into_response();
        }
    };
    let subject = body.subject.filter(|s| !s.trim().is_empty());
    if subject.is_none() && email.is_none() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "name the account by subject or by email"})),
        )
            .into_response();
    }
    let account = AccountRef { subject, email };
    let ended = match oidc.sessions.revoke_account(&account).await {
        Ok(ended) => ended,
        Err(e) => return store_unreachable(&e),
    };

    metrics::counter!("securesend_sessions_revoked_total").increment(ended);
    let mut event = AuditEvent::success(AuditEventType::AuthSessionsRevoked);
    event.subject = account.subject.clone();
    event.issuer = Some(oidc.issuer().to_owned());
    event.sender = account.email.as_ref().map(ToString::to_string);
    event.active_messages = None;
    state.app.audit.emit(event);
    tracing::info!(
        sessions_ended = ended,
        "an operator ended an account's sessions"
    );

    (
        StatusCode::OK,
        Json(RevokeSessionsResponse {
            sessions_ended: ended,
        }),
    )
        .into_response()
}

pub fn router(state: Arc<ManagementState>) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/v1/health", get(detailed_health))
        .route("/v1/stats", get(stats))
        .route("/v1/sessions/revoke", post(revoke_sessions))
        .route("/metrics", get(metrics))
        .with_state(state)
}
