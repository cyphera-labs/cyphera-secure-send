//! HTTP-level behavior: uniform failure responses, headers on every route,
//! size and rate limits, and the create/consume/revoke lifecycle.

use axum::Router;
use axum::body::Body;
use axum::extract::ConnectInfo;
use axum::http::{Request, StatusCode, header};
use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
use http_body_util::BodyExt;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::net::SocketAddr;
use std::sync::Arc;
use tower::ServiceExt;

use cyphera_secure_send::api::public_router;
use cyphera_secure_send::audit::MemorySink;
use cyphera_secure_send::config::Settings;

struct Harness {
    app: Router,
    audit: Arc<MemorySink>,
}

fn harness(tweak: impl FnOnce(&mut Settings)) -> Harness {
    let mut settings = Settings::default();
    settings.messages.kdf.min_iterations = 1;
    settings.audit.include_client_ip = true;
    tweak(&mut settings);
    settings.validate().unwrap();
    let audit = Arc::new(MemorySink::default());
    let state = cyphera_secure_send::build_state(settings, Some(audit.clone())).unwrap();
    Harness {
        app: public_router(state),
        audit,
    }
}

fn peer(ip: &str) -> SocketAddr {
    format!("{ip}:40000").parse().unwrap()
}

async fn send(
    app: &Router,
    method: &str,
    path: &str,
    body: Option<Value>,
    ip: &str,
) -> (StatusCode, axum::http::HeaderMap, Value) {
    let mut builder = Request::builder().method(method).uri(path);
    if body.is_some() {
        builder = builder.header(header::CONTENT_TYPE, "application/json");
    }
    let mut req = builder
        .body(match body {
            Some(v) => Body::from(serde_json::to_vec(&v).unwrap()),
            None => Body::empty(),
        })
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(peer(ip)));
    let res = app.clone().oneshot(req).await.unwrap();
    let status = res.status();
    let headers = res.headers().clone();
    let bytes = res.into_body().collect().await.unwrap().to_bytes();
    let value = if bytes.is_empty() {
        Value::Null
    } else {
        serde_json::from_slice(&bytes)
            .unwrap_or(Value::String(String::from_utf8_lossy(&bytes).into()))
    };
    (status, headers, value)
}

fn proof_and_verifier() -> (String, String) {
    let proof = [7u8; 32];
    let verifier = Sha256::digest(proof);
    (
        BASE64URL_NOPAD.encode(&proof),
        BASE64URL_NOPAD.encode(&verifier),
    )
}

fn create_body(verifier: &str, ciphertext_len: usize) -> Value {
    json!({
        "sender": "alice@example.com",
        "recipient": "bob@example.com",
        "ttl_seconds": 3600,
        "verifier": verifier,
        "envelope": {
            "version": 1,
            "kdf": {"name": "PBKDF2-SHA256", "iterations": 1000, "salt": BASE64_NOPAD.encode(&[1u8; 16])},
            "cipher": {"name": "AES-256-GCM", "iv": BASE64_NOPAD.encode(&[2u8; 12])},
            "ciphertext": BASE64_NOPAD.encode(&vec![3u8; ciphertext_len]),
        }
    })
}

async fn create(app: &Router, verifier: &str) -> (String, String) {
    let (status, _, body) = send(
        app,
        "POST",
        "/v1/messages",
        Some(create_body(verifier, 48)),
        "192.0.2.10",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    (
        body["id"].as_str().unwrap().to_owned(),
        body["revoke_token"].as_str().unwrap().to_owned(),
    )
}

#[tokio::test]
async fn lifecycle_create_consume_once() {
    let h = harness(|_| {});
    let (proof, verifier) = proof_and_verifier();
    let (id, _) = create(&h.app, &verifier).await;
    assert_eq!(id.len(), 26);

    let (status, _, body) = send(
        &h.app,
        "POST",
        &format!("/v1/messages/{id}/consume"),
        Some(json!({"proof": proof})),
        "192.0.2.20",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["sender"], "alice@example.com");
    assert_eq!(body["envelope"]["cipher"]["name"], "AES-256-GCM");

    let (status, _, body) = send(
        &h.app,
        "POST",
        &format!("/v1/messages/{id}/consume"),
        Some(json!({"proof": proof})),
        "192.0.2.20",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert_eq!(body, json!({"error": "unavailable"}));

    let types: Vec<&str> = h.audit.events().iter().map(|e| e.event_type).collect();
    assert!(types.contains(&"message.created"));
    assert!(types.contains(&"message.consumed"));
    assert!(types.contains(&"message.consume_failed"));
}

#[tokio::test]
async fn every_consume_failure_is_identical() {
    let h = harness(|s| s.messages.max_failed_proofs = 2);
    let (proof, verifier) = proof_and_verifier();
    let (id, _) = create(&h.app, &verifier).await;
    let wrong = BASE64URL_NOPAD.encode(&[9u8; 32]);
    let unknown_id = "abcdefghijklmnopqrstuvwxyz";

    let mut responses = Vec::new();
    responses.push(
        send(
            &h.app,
            "POST",
            &format!("/v1/messages/{unknown_id}/consume"),
            Some(json!({"proof": proof})),
            "192.0.2.1",
        )
        .await,
    );
    responses.push(
        send(
            &h.app,
            "POST",
            "/v1/messages/not-a-valid-id/consume",
            Some(json!({"proof": proof})),
            "192.0.2.1",
        )
        .await,
    );
    responses.push(
        send(
            &h.app,
            "POST",
            &format!("/v1/messages/{id}/consume"),
            Some(json!({"proof": wrong})),
            "192.0.2.1",
        )
        .await,
    );
    responses.push(
        send(
            &h.app,
            "POST",
            &format!("/v1/messages/{id}/consume"),
            Some(json!({"proof": wrong})),
            "192.0.2.1",
        )
        .await,
    );
    responses.push(
        send(
            &h.app,
            "POST",
            &format!("/v1/messages/{id}/consume"),
            Some(json!({"proof": proof})),
            "192.0.2.1",
        )
        .await,
    );

    let (id2, revoke2) = create(&h.app, &verifier).await;
    let (st, _, _) = send(
        &h.app,
        "POST",
        &format!("/v1/messages/{id2}/revoke"),
        Some(json!({"revoke_token": revoke2})),
        "192.0.2.1",
    )
    .await;
    assert_eq!(st, StatusCode::NO_CONTENT);
    responses.push(
        send(
            &h.app,
            "POST",
            &format!("/v1/messages/{id2}/consume"),
            Some(json!({"proof": proof})),
            "192.0.2.1",
        )
        .await,
    );

    for (status, headers, body) in &responses {
        assert_eq!(*status, StatusCode::NOT_FOUND);
        assert_eq!(*body, json!({"error": "unavailable"}));
        assert_eq!(
            headers.get(header::CONTENT_TYPE).unwrap(),
            "application/json"
        );
    }
    let lengths: Vec<_> = responses
        .iter()
        .map(|(_, h, _)| h.get(header::CONTENT_LENGTH).cloned())
        .collect();
    assert!(lengths.windows(2).all(|w| w[0] == w[1]));

    let burned = h
        .audit
        .events()
        .iter()
        .filter(|e| e.event_type == "message.burned")
        .count();
    assert_eq!(burned, 1);
}

#[tokio::test]
async fn revoke_always_returns_no_content() {
    let h = harness(|_| {});
    let (_, verifier) = proof_and_verifier();
    let (id, revoke) = create(&h.app, &verifier).await;
    let wrong = BASE64URL_NOPAD.encode(&[1u8; 32]);
    for (path, token) in [
        (format!("/v1/messages/{id}/revoke"), wrong.clone()),
        (
            "/v1/messages/abcdefghijklmnopqrstuvwxyz/revoke".to_owned(),
            revoke.clone(),
        ),
        ("/v1/messages/bad/revoke".to_owned(), revoke.clone()),
        (format!("/v1/messages/{id}/revoke"), revoke.clone()),
        (format!("/v1/messages/{id}/revoke"), revoke.clone()),
    ] {
        let (status, _, body) = send(
            &h.app,
            "POST",
            &path,
            Some(json!({"revoke_token": token})),
            "192.0.2.3",
        )
        .await;
        assert_eq!(status, StatusCode::NO_CONTENT);
        assert_eq!(body, Value::Null);
    }
    let revoked = h
        .audit
        .events()
        .iter()
        .filter(|e| {
            e.event_type == "message.revoked"
                && e.outcome == cyphera_secure_send::audit::Outcome::Success
        })
        .count();
    assert_eq!(revoked, 1);
}

#[tokio::test]
async fn security_headers_on_every_route() {
    let h = harness(|s| s.server.hsts = true);
    for (method, path, body) in [
        ("GET", "/", None),
        ("GET", "/m/abcdefghijklmnopqrstuvwxyz", None),
        ("GET", "/v1/ui-config", None),
        ("GET", "/v1/health", None),
        ("GET", "/does-not-exist", None),
        ("GET", "/brand/logo", None),
        (
            "POST",
            "/v1/messages/abcdefghijklmnopqrstuvwxyz/consume",
            Some(json!({"proof": "x"})),
        ),
    ] {
        let (_, headers, _) = send(&h.app, method, path, body, "192.0.2.4").await;
        assert_eq!(
            headers.get(header::CACHE_CONTROL).unwrap(),
            "no-store",
            "{path}"
        );
        assert_eq!(
            headers.get(header::REFERRER_POLICY).unwrap(),
            "no-referrer",
            "{path}"
        );
        assert_eq!(
            headers.get(header::X_CONTENT_TYPE_OPTIONS).unwrap(),
            "nosniff",
            "{path}"
        );
        let csp = headers
            .get(header::CONTENT_SECURITY_POLICY)
            .unwrap()
            .to_str()
            .unwrap();
        assert!(csp.contains("default-src 'none'"), "{path}");
        assert!(!csp.contains("unsafe"), "{path}");
        assert!(
            headers.get(header::STRICT_TRANSPORT_SECURITY).is_some(),
            "{path}"
        );
        assert_eq!(
            headers.get("cross-origin-resource-policy").unwrap(),
            "same-origin"
        );
    }
}

#[tokio::test]
async fn create_validates_and_reports_request_problems_only() {
    let h = harness(|_| {});
    let (_, verifier) = proof_and_verifier();

    let mut b = create_body(&verifier, 48);
    b["sender"] = json!("not-an-email");
    let (status, _, body) = send(&h.app, "POST", "/v1/messages", Some(b), "192.0.2.5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert!(body["error"].as_str().unwrap().starts_with("sender"));

    let mut b = create_body(&verifier, 48);
    b["ttl_seconds"] = json!(999_999);
    let (status, _, _) = send(&h.app, "POST", "/v1/messages", Some(b), "192.0.2.5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut b = create_body(&verifier, 48);
    b["verifier"] = json!("nope");
    let (status, _, _) = send(&h.app, "POST", "/v1/messages", Some(b), "192.0.2.5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut b = create_body(&verifier, 48);
    b["envelope"]["kdf"]["name"] = json!("scrypt");
    let (status, _, _) = send(&h.app, "POST", "/v1/messages", Some(b), "192.0.2.5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);

    let mut b = create_body(&verifier, 48);
    b["extra"] = json!(1);
    let (status, _, body) = send(&h.app, "POST", "/v1/messages", Some(b), "192.0.2.5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
    assert_eq!(body, json!({"error": "malformed request"}));

    let mut b = create_body(&verifier, 48);
    b["envelope"]["plaintext"] = json!("leak");
    let (status, _, _) = send(&h.app, "POST", "/v1/messages", Some(b), "192.0.2.5").await;
    assert_eq!(status, StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn oversized_bodies_are_refused_before_parsing() {
    let h = harness(|s| s.messages.max_plaintext_bytes = 1024);
    let (_, verifier) = proof_and_verifier();
    let (status, _, _) = send(
        &h.app,
        "POST",
        "/v1/messages",
        Some(create_body(&verifier, 1040)),
        "192.0.2.6",
    )
    .await;
    assert_eq!(status, StatusCode::CREATED);
    let (status, _, _) = send(
        &h.app,
        "POST",
        "/v1/messages",
        Some(create_body(&verifier, 1041)),
        "192.0.2.6",
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
    let (status, _, _) = send(
        &h.app,
        "POST",
        "/v1/messages",
        Some(create_body(&verifier, 20_000)),
        "192.0.2.6",
    )
    .await;
    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE);
}

#[tokio::test]
async fn wrong_content_type_is_rejected() {
    let h = harness(|_| {});
    let mut req = Request::builder()
        .method("POST")
        .uri("/v1/messages/abcdefghijklmnopqrstuvwxyz/consume")
        .header(header::CONTENT_TYPE, "text/plain")
        .body(Body::from(r#"{"proof":"x"}"#))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(peer("192.0.2.7")));
    let res = h.app.clone().oneshot(req).await.unwrap();
    assert_eq!(res.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn rate_limits_are_per_client_and_audited() {
    let h = harness(|s| s.rate_limits.consume_per_minute = 3);
    let (proof, _) = proof_and_verifier();
    let path = "/v1/messages/abcdefghijklmnopqrstuvwxyz/consume";
    for _ in 0..3 {
        let (status, _, _) = send(
            &h.app,
            "POST",
            path,
            Some(json!({"proof": proof})),
            "192.0.2.8",
        )
        .await;
        assert_eq!(status, StatusCode::NOT_FOUND);
    }
    let (status, _, body) = send(
        &h.app,
        "POST",
        path,
        Some(json!({"proof": proof})),
        "192.0.2.8",
    )
    .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(body, json!({"error": "rate limited"}));
    let (status, _, _) = send(
        &h.app,
        "POST",
        path,
        Some(json!({"proof": proof})),
        "192.0.2.9",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
    assert!(
        h.audit
            .events()
            .iter()
            .any(|e| e.event_type == "rate_limited" && e.client_ip.as_deref() == Some("192.0.2.8"))
    );
}

#[tokio::test]
async fn trusted_proxy_header_is_honored_only_from_trusted_peers() {
    let h = harness(|s| {
        s.server.trusted_proxies = vec!["10.0.0.0/8".parse().unwrap()];
        s.rate_limits.consume_per_minute = 1;
    });
    let path = "/v1/messages/abcdefghijklmnopqrstuvwxyz/consume";
    let mut req = Request::builder()
        .method("POST")
        .uri(path)
        .header(header::CONTENT_TYPE, "application/json")
        .header("x-forwarded-for", "198.51.100.77")
        .body(Body::from(r#"{"proof":"x"}"#))
        .unwrap();
    req.extensions_mut().insert(ConnectInfo(peer("10.1.2.3")));
    let _ = h.app.clone().oneshot(req).await.unwrap();
    assert!(
        h.audit
            .events()
            .iter()
            .any(|e| e.client_ip.as_deref() == Some("198.51.100.77"))
    );
}

#[tokio::test]
async fn audit_stream_never_carries_secrets() {
    let h = harness(|s| {
        s.messages.max_failed_proofs = 1;
        s.audit.include_user_agent = true;
    });
    let (proof, verifier) = proof_and_verifier();
    let (id, revoke) = create(&h.app, &verifier).await;
    let wrong = BASE64URL_NOPAD.encode(&[9u8; 32]);
    let _ = send(
        &h.app,
        "POST",
        &format!("/v1/messages/{id}/consume"),
        Some(json!({"proof": wrong})),
        "192.0.2.11",
    )
    .await;
    let (id2, _) = create(&h.app, &verifier).await;
    let _ = send(
        &h.app,
        "POST",
        &format!("/v1/messages/{id2}/consume"),
        Some(json!({"proof": proof})),
        "192.0.2.11",
    )
    .await;
    let (id3, revoke3) = create(&h.app, &verifier).await;
    let _ = send(
        &h.app,
        "POST",
        &format!("/v1/messages/{id3}/revoke"),
        Some(json!({"revoke_token": revoke3})),
        "192.0.2.11",
    )
    .await;

    let ciphertext = BASE64_NOPAD.encode(&[3u8; 48]);
    let all = serde_json::to_string(&h.audit.events()).unwrap();
    for secret in [
        proof.as_str(),
        verifier.as_str(),
        wrong.as_str(),
        revoke.as_str(),
        revoke3.as_str(),
        ciphertext.as_str(),
        "/m/",
        "#",
    ] {
        assert!(!all.contains(secret), "audit stream contains {secret}");
    }
    assert!(all.contains(&id) && all.contains("alice@example.com"));
}

#[tokio::test]
async fn ui_config_exposes_only_non_secret_settings() {
    let h = harness(|s| s.branding.company_name = "Acme".into());
    let (status, _, body) = send(&h.app, "GET", "/v1/ui-config", None, "192.0.2.12").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["company_name"], "Acme");
    assert_eq!(body["ttl_options_seconds"][0], 300);
    assert!(body.get("bind").is_none());
    assert!(body.get("tls").is_none());
}

#[tokio::test]
async fn shell_is_served_for_page_routes_and_assets_are_reachable() {
    let h = harness(|_| {});
    for path in [
        "/",
        "/m/abcdefghijklmnopqrstuvwxyz",
        "/r/abcdefghijklmnopqrstuvwxyz",
    ] {
        let (status, headers, body) = send(&h.app, "GET", path, None, "192.0.2.13").await;
        assert_eq!(status, StatusCode::OK, "{path}");
        assert!(
            headers
                .get(header::CONTENT_TYPE)
                .unwrap()
                .to_str()
                .unwrap()
                .starts_with("text/html")
        );
        assert!(body.as_str().unwrap().contains("<!doctype html>"));
    }
    let (status, _, _) = send(&h.app, "GET", "/assets/../Cargo.toml", None, "192.0.2.13").await;
    assert_ne!(status, StatusCode::OK);
}
