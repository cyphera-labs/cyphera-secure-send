//! The management listener: stats, detailed health, readiness, metrics.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
use http_body_util::BodyExt;
use metrics_exporter_prometheus::PrometheusBuilder;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, OnceLock};
use tower::ServiceExt;

use cyphera_secure_send::api::management::{self, ManagementState};
use cyphera_secure_send::api::public_router;
use cyphera_secure_send::audit::MemorySink;
use cyphera_secure_send::config::Settings;

struct Harness {
    public: Router,
    mgmt: Router,
    ready: Arc<AtomicBool>,
}

async fn harness() -> Harness {
    let mut settings = Settings::default();
    settings.messages.kdf.min_iterations = 1000;
    settings.messages.max_failed_proofs = 2;
    settings.validate().unwrap();
    let state = cyphera_secure_send::build_state(settings, Some(Arc::new(MemorySink::default())))
        .await
        .unwrap();
    let ready = Arc::new(AtomicBool::new(true));
    static RECORDER: OnceLock<metrics_exporter_prometheus::PrometheusHandle> = OnceLock::new();
    let prometheus = RECORDER
        .get_or_init(|| {
            PrometheusBuilder::new()
                .install_recorder()
                .expect("one recorder per process")
        })
        .clone();
    let mgmt_state = Arc::new(ManagementState::new(
        state.clone(),
        ready.clone(),
        prometheus,
    ));
    Harness {
        public: public_router(state),
        mgmt: management::router(mgmt_state),
        ready,
    }
}

async fn get(app: &Router, path: &str) -> (StatusCode, Value) {
    let res = app
        .clone()
        .oneshot(Request::get(path).body(Body::empty()).unwrap())
        .await
        .unwrap();
    let status = res.status();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = serde_json::from_slice(&bytes)
        .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()));
    (status, value)
}

async fn post(app: &Router, path: &str, body: Value) -> StatusCode {
    let mut req = Request::post(path)
        .header(header::CONTENT_TYPE, "application/json")
        .body(Body::from(serde_json::to_vec(&body).unwrap()))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(
        "192.0.2.50:4000".parse::<SocketAddr>().unwrap(),
    ));
    app.clone().oneshot(req).await.unwrap().status()
}

fn create_body(verifier: &str) -> Value {
    json!({
        "sender": "alice@example.com",
        "recipient": "bob@example.com",
        "ttl_seconds": 3600,
        "verifier": verifier,
        "envelope": {
            "version": 1,
            "kdf": {"name": "PBKDF2-SHA256", "iterations": 1000, "salt": BASE64_NOPAD.encode(&[1u8; 16])},
            "cipher": {"name": "AES-256-GCM", "iv": BASE64_NOPAD.encode(&[2u8; 12])},
            "ciphertext": BASE64_NOPAD.encode(&[3u8; 48]),
        }
    })
}

#[tokio::test]
async fn stats_reflect_the_lifecycle() {
    let h = harness().await;
    let (status, stats) = get(&h.mgmt, "/v1/stats").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(stats["storage"]["active_messages"], 0);
    assert_eq!(stats["totals"]["created"], 0);
    assert_eq!(stats["limits"]["max_failed_proofs"], 2);
    assert_eq!(stats["version"], env!("CARGO_PKG_VERSION"));
    assert!(stats["storage"]["budget_bytes"].as_u64().unwrap() > 0);

    let proof = [7u8; 32];
    let verifier = BASE64URL_NOPAD.encode(&Sha256::digest(proof));
    assert_eq!(
        post(&h.public, "/v1/messages", create_body(&verifier)).await,
        StatusCode::CREATED
    );
    assert_eq!(
        post(&h.public, "/v1/messages", create_body(&verifier)).await,
        StatusCode::CREATED
    );

    let (_, stats) = get(&h.mgmt, "/v1/stats").await;
    assert_eq!(stats["storage"]["active_messages"], 2);
    assert!(stats["storage"]["used_bytes"].as_u64().unwrap() > 0);
    assert_eq!(stats["totals"]["created"], 2);

    let (_, health) = get(&h.mgmt, "/v1/health").await;
    assert_eq!(health["status"], "ok");
    assert_eq!(health["ready"], true);
    assert_eq!(health["storage"]["active_messages"], 2);

    let (st, _) = get(&h.mgmt, "/readyz").await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn stats_count_burns_consumes_and_rate_limits() {
    let h = harness().await;
    let proof = [7u8; 32];
    let verifier = BASE64URL_NOPAD.encode(&Sha256::digest(proof));
    let proof_b64 = BASE64URL_NOPAD.encode(&proof);
    let wrong = BASE64URL_NOPAD.encode(&[9u8; 32]);

    let mut ids = Vec::new();
    for _ in 0..2 {
        let mut req = Request::post("/v1/messages")
            .header(header::CONTENT_TYPE, "application/json")
            .body(Body::from(
                serde_json::to_vec(&create_body(&verifier)).unwrap(),
            ))
            .unwrap();
        req.extensions_mut().insert(ConnectInfo(
            "192.0.2.51:4000".parse::<SocketAddr>().unwrap(),
        ));
        let res = h.public.clone().oneshot(req).await.unwrap();
        let bytes = res.into_body().collect().await.unwrap().to_bytes();
        let v: Value = serde_json::from_slice(&bytes).unwrap();
        ids.push(v["id"].as_str().unwrap().to_owned());
    }

    assert_eq!(
        post(
            &h.public,
            &format!("/v1/messages/{}/consume", ids[0]),
            json!({"proof": wrong})
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(
            &h.public,
            &format!("/v1/messages/{}/consume", ids[0]),
            json!({"proof": wrong})
        )
        .await,
        StatusCode::NOT_FOUND
    );
    assert_eq!(
        post(
            &h.public,
            &format!("/v1/messages/{}/consume", ids[1]),
            json!({"proof": proof_b64})
        )
        .await,
        StatusCode::OK
    );

    let (_, stats) = get(&h.mgmt, "/v1/stats").await;
    assert_eq!(stats["storage"]["active_messages"], 0);
    assert_eq!(stats["totals"]["created"], 2);
    assert_eq!(stats["totals"]["consumed"], 1);
    assert_eq!(stats["totals"]["consume_failed"], 1);
    assert_eq!(stats["totals"]["burned"], 1);
    assert_eq!(stats["totals"]["expired"], 0);
    assert_eq!(stats["totals"]["rate_limited"], 0);
}

#[tokio::test]
async fn readiness_and_detailed_health_track_shutdown() {
    let h = harness().await;
    let (st, _) = get(&h.mgmt, "/readyz").await;
    assert_eq!(st, StatusCode::OK);
    let (st, _) = get(&h.mgmt, "/livez").await;
    assert_eq!(st, StatusCode::OK);
    h.ready.store(false, Ordering::SeqCst);
    let (st, _) = get(&h.mgmt, "/readyz").await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    let (st, health) = get(&h.mgmt, "/v1/health").await;
    assert_eq!(st, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(health["status"], "stopping");
    let (st, _) = get(&h.mgmt, "/livez").await;
    assert_eq!(st, StatusCode::OK);
}

#[tokio::test]
async fn metrics_render_in_prometheus_format() {
    let h = harness().await;
    let (st, body) = get(&h.mgmt, "/metrics").await;
    assert_eq!(st, StatusCode::OK);
    let text = body.as_str().unwrap();
    assert!(text.contains("securesend_messages_active"));
    assert!(text.contains("securesend_store_budget_bytes"));
}

#[tokio::test]
async fn public_health_stays_minimal() {
    let h = harness().await;
    let (st, body) = get(&h.public, "/v1/health").await;
    assert_eq!(st, StatusCode::OK);
    assert_eq!(body, json!({"status": "ok"}));
    let (st, _) = get(&h.public, "/v1/stats").await;
    assert_eq!(st, StatusCode::NOT_FOUND);
}
