//! Health, readiness, stats, and metrics. Served on the management listener;
//! only the minimal health probe is also on the public listener, because the
//! detailed views reveal how much traffic the service carries.

use axum::Json;
use axum::Router;
use axum::extract::State;
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::get;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::Serialize;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Instant;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::SharedState;
use crate::application::CounterSnapshot;

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

async fn storage_health(state: &ManagementState) -> StorageHealth {
    let s = state.app.service.store().stats().await;
    let used_percent = if s.budget_bytes == 0 {
        0.0
    } else {
        (s.weighted_bytes as f64 / s.budget_bytes as f64) * 100.0
    };
    StorageHealth {
        backend: "memory",
        active_messages: s.active_messages,
        used_bytes: s.weighted_bytes,
        budget_bytes: s.budget_bytes,
        used_percent: (used_percent * 10.0).round() / 10.0,
    }
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

async fn detailed_health(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    let ready = state.ready.load(Ordering::SeqCst);
    let body = DetailedHealth {
        status: if ready { "ok" } else { "stopping" },
        ready,
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started.elapsed().as_secs(),
        started_at: started_at(&state),
        storage: storage_health(&state).await,
    };
    let code = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };
    (code, Json(body))
}

async fn stats(State(state): State<Arc<ManagementState>>) -> Json<Stats> {
    let store = state.app.service.store().stats().await;
    let settings = &state.app.settings;
    Json(Stats {
        version: env!("CARGO_PKG_VERSION"),
        uptime_seconds: state.started.elapsed().as_secs(),
        started_at: started_at(&state),
        storage: storage_health(&state).await,
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
}

async fn metrics(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    let stats = state.app.service.store().stats().await;
    metrics::gauge!("securesend_messages_active").set(stats.active_messages as f64);
    metrics::gauge!("securesend_store_bytes").set(stats.weighted_bytes as f64);
    metrics::gauge!("securesend_store_budget_bytes").set(stats.budget_bytes as f64);
    (
        StatusCode::OK,
        [("content-type", "text/plain; version=0.0.4; charset=utf-8")],
        state.prometheus.render(),
    )
}

pub fn router(state: Arc<ManagementState>) -> Router {
    Router::new()
        .route("/livez", get(livez))
        .route("/readyz", get(readyz))
        .route("/v1/health", get(detailed_health))
        .route("/v1/stats", get(stats))
        .route("/metrics", get(metrics))
        .with_state(state)
}
