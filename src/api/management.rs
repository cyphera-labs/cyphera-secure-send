//! Health, readiness, and metrics. Served on the management listener; only
//! the minimal health probe is also on the public listener.

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

use super::SharedState;

#[derive(Serialize)]
pub struct Health {
    status: &'static str,
}

pub async fn health() -> Json<Health> {
    Json(Health { status: "ok" })
}

pub struct ManagementState {
    pub app: SharedState,
    pub ready: Arc<AtomicBool>,
    pub prometheus: PrometheusHandle,
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

async fn metrics(State(state): State<Arc<ManagementState>>) -> impl IntoResponse {
    let stats = state.app.service.store().stats();
    metrics::gauge!("securesend_messages_active").set(stats.active_messages as f64);
    metrics::gauge!("securesend_store_bytes").set(stats.weighted_bytes as f64);
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
        .route("/metrics", get(metrics))
        .with_state(state)
}
