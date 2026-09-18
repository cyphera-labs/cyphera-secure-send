//! The OIDC mode end to end against an in-process OpenID provider that signs
//! real RS256 ID tokens and enforces PKCE, so the relying party's discovery,
//! code exchange, token verification, session, and the closed-mode rules are
//! all exercised over real HTTP.

use axum::extract::{Form, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Redirect};
use axum::routing::{get, post};
use axum::{Json, Router};
use data_encoding::{BASE64_NOPAD, BASE64URL_NOPAD};
use jsonwebtoken::{Algorithm, EncodingKey, Header};
use rsa::pkcs8::EncodePrivateKey;
use rsa::traits::PublicKeyParts;
use rsa::{RsaPrivateKey, rand_core::OsRng};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex};

use cyphera_secure_send::api::public_router;
use cyphera_secure_send::audit::{MemorySink, Reason};
use cyphera_secure_send::config::{EmailClaim, Mode, Settings, UnverifiedEmail};
use cyphera_secure_send::domain::MessageId;

// ------------------------------------------------------------ fake provider

struct Idp {
    issuer: String,
    client_id: String,
    client_secret: String,
    signing_key: EncodingKey,
    jwk_n: String,
    jwk_e: String,
    /// The user the next login will produce.
    next_email: Mutex<String>,
    /// What the next token says about that address: Some(true), Some(false),
    /// or None for a token that omits the claim entirely.
    next_email_verified: Mutex<Option<bool>>,
    /// code -> (nonce, code_challenge)
    codes: Mutex<HashMap<String, (String, String)>>,
    token_calls: Mutex<u32>,
}

#[derive(Deserialize)]
struct AuthorizeQuery {
    response_type: String,
    client_id: String,
    redirect_uri: String,
    state: String,
    nonce: String,
    code_challenge: String,
    code_challenge_method: String,
    scope: String,
}

#[derive(Deserialize)]
struct TokenForm {
    grant_type: String,
    code: String,
    redirect_uri: Option<String>,
    code_verifier: String,
    client_id: Option<String>,
    client_secret: Option<String>,
}

async fn discovery(State(idp): State<Arc<Idp>>) -> Json<Value> {
    Json(json!({
        "issuer": idp.issuer,
        "authorization_endpoint": format!("{}/authorize", idp.issuer),
        "token_endpoint": format!("{}/token", idp.issuer),
        "jwks_uri": format!("{}/jwks", idp.issuer),
        "response_types_supported": ["code"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["RS256"],
        "scopes_supported": ["openid", "profile", "email"],
        "token_endpoint_auth_methods_supported": ["client_secret_basic", "client_secret_post"],
        "code_challenge_methods_supported": ["S256"],
        "claims_supported": ["sub", "email", "preferred_username"],
    }))
}

async fn jwks(State(idp): State<Arc<Idp>>) -> Json<Value> {
    Json(
        json!({"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": "test-1", "n": idp.jwk_n, "e": idp.jwk_e}]}),
    )
}

async fn authorize(
    State(idp): State<Arc<Idp>>,
    Query(q): Query<AuthorizeQuery>,
) -> impl IntoResponse {
    assert_eq!(q.response_type, "code");
    assert_eq!(q.client_id, idp.client_id);
    assert_eq!(q.code_challenge_method, "S256");
    assert!(q.scope.split(' ').any(|s| s == "openid"));
    assert!(q.scope.split(' ').any(|s| s == "email"));
    let code = BASE64URL_NOPAD.encode(&Sha256::digest(format!("{}{}", q.state, q.nonce)));
    idp.codes
        .lock()
        .unwrap()
        .insert(code.clone(), (q.nonce, q.code_challenge));
    Redirect::to(&format!(
        "{}?code={}&state={}",
        q.redirect_uri, code, q.state
    ))
}

async fn token(
    State(idp): State<Arc<Idp>>,
    headers: HeaderMap,
    Form(f): Form<TokenForm>,
) -> impl IntoResponse {
    *idp.token_calls.lock().unwrap() += 1;
    assert_eq!(f.grant_type, "authorization_code");
    // Client authentication: basic or post.
    let authed = match headers.get("authorization").and_then(|v| v.to_str().ok()) {
        Some(h) if h.starts_with("Basic ") => {
            let decoded = data_encoding::BASE64.decode(&h.as_bytes()[6..]).unwrap();
            let s = String::from_utf8(decoded).unwrap();
            s == format!("{}:{}", idp.client_id, idp.client_secret)
        }
        _ => {
            f.client_id.as_deref() == Some(&idp.client_id)
                && f.client_secret.as_deref() == Some(&idp.client_secret)
        }
    };
    if !authed {
        return (
            StatusCode::UNAUTHORIZED,
            Json(json!({"error": "invalid_client"})),
        )
            .into_response();
    }
    let Some((nonce, challenge)) = idp.codes.lock().unwrap().remove(&f.code) else {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant"})),
        )
            .into_response();
    };
    let expected = BASE64URL_NOPAD.encode(&Sha256::digest(f.code_verifier.as_bytes()));
    if expected != challenge {
        return (
            StatusCode::BAD_REQUEST,
            Json(json!({"error": "invalid_grant", "error_description": "pkce"})),
        )
            .into_response();
    }
    let _ = f.redirect_uri;
    let now = time::OffsetDateTime::now_utc().unix_timestamp();
    let email = idp.next_email.lock().unwrap().clone();
    let verified = *idp.next_email_verified.lock().unwrap();
    let mut claims = json!({
        "iss": idp.issuer,
        "sub": format!("sub-{}", email),
        "aud": idp.client_id,
        "exp": now + 300,
        "iat": now,
        "nonce": nonce,
        "email": email,
        "preferred_username": email,
    });
    match verified {
        Some(v) => claims["email_verified"] = json!(v),
        None => {
            claims.as_object_mut().unwrap().remove("email_verified");
        }
    }
    let mut header = Header::new(Algorithm::RS256);
    header.kid = Some("test-1".into());
    let id_token = jsonwebtoken::encode(&header, &claims, &idp.signing_key).unwrap();
    Json(json!({"access_token": "at-1", "token_type": "Bearer", "expires_in": 300, "id_token": id_token})).into_response()
}

async fn start_idp() -> Arc<Idp> {
    let key = RsaPrivateKey::new(&mut OsRng, 2048).unwrap();
    let pem = key.to_pkcs8_pem(rsa::pkcs8::LineEnding::LF).unwrap();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let idp = Arc::new(Idp {
        issuer: format!("http://{addr}"),
        client_id: "securesend".into(),
        client_secret: "x".repeat(24),
        signing_key: EncodingKey::from_rsa_pem(pem.as_bytes()).unwrap(),
        jwk_n: BASE64URL_NOPAD.encode(&key.n().to_bytes_be()),
        jwk_e: BASE64URL_NOPAD.encode(&key.e().to_bytes_be()),
        next_email: Mutex::new("bob@acme.com".into()),
        next_email_verified: Mutex::new(Some(true)),
        codes: Mutex::new(HashMap::new()),
        token_calls: Mutex::new(0),
    });
    let app = Router::new()
        .route("/.well-known/openid-configuration", get(discovery))
        .route("/jwks", get(jwks))
        .route("/authorize", get(authorize))
        .route("/token", post(token))
        .with_state(idp.clone());
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    idp
}

// ------------------------------------------------------------ app under test

struct App {
    base: String,
    audit: Arc<MemorySink>,
}

async fn start_app(idp: &Idp, tweak: impl FnOnce(&mut Settings)) -> App {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let base = format!("http://{addr}");
    let mut settings = Settings::default();
    settings.server.public_base_url = Some(base.clone());
    settings.mode = Mode::Enterprise;
    settings.enterprise.oidc.issuer = idp.issuer.clone();
    settings.enterprise.oidc.client_id = idp.client_id.clone();
    settings.enterprise.oidc.client_secret = Some(idp.client_secret.clone());
    settings.enterprise.creation.allowed_domains = vec!["acme.com".into()];
    settings.messages.kdf.min_iterations = 1;
    settings.rate_limits.consume_per_minute = 200;
    settings.rate_limits.create_per_minute = 200;
    tweak(&mut settings);
    settings.validate().unwrap();
    let audit = Arc::new(MemorySink::default());
    let state = cyphera_secure_send::build_state(settings, Some(audit.clone()))
        .await
        .unwrap();
    let router = public_router(state).into_make_service_with_connect_info::<SocketAddr>();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    App { base, audit }
}

fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .cookie_store(true)
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .unwrap()
}

/// Walks the browser through login: app → provider → app callback. Returns
/// the final redirect target.
async fn sign_in(app: &App, idp: &Idp, c: &reqwest::Client, email: &str, next: &str) -> String {
    *idp.next_email.lock().unwrap() = email.to_owned();
    *idp.next_email_verified.lock().unwrap() = Some(true);
    let r = c
        .get(format!("{}/auth/login?next={}", app.base, next))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let to_idp = r.headers()["location"].to_str().unwrap().to_owned();
    assert!(to_idp.starts_with(&idp.issuer), "{to_idp}");
    assert!(to_idp.contains("code_challenge="));
    assert!(to_idp.contains("nonce="));
    assert!(to_idp.contains("state="));
    let r = c.get(&to_idp).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    let back = r.headers()["location"].to_str().unwrap().to_owned();
    assert!(back.starts_with(&format!("{}/auth/callback?", app.base)));
    let r = c.get(&back).send().await.unwrap();
    assert_eq!(
        r.status(),
        StatusCode::SEE_OTHER,
        "{}",
        r.text().await.unwrap()
    );
    r.headers()["location"].to_str().unwrap().to_owned()
}

fn proof_and_verifier(seed: u8) -> (String, String) {
    let proof = [seed; 32];
    (
        BASE64URL_NOPAD.encode(&proof),
        BASE64URL_NOPAD.encode(&Sha256::digest(proof)),
    )
}

fn create_body(sender: &str, recipient: &str, verifier: &str) -> Value {
    json!({
        "sender": sender,
        "recipient": recipient,
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
async fn login_establishes_a_session_bound_to_the_browser() {
    let idp = start_idp().await;
    let app = start_app(&idp, |_| {}).await;
    let c = client();

    let r = c
        .get(format!("{}/v1/session", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(
        r.json::<Value>().await.unwrap(),
        json!({"authenticated": false})
    );

    // A real message identifier: the callback only returns the browser to a
    // page this service actually serves.
    let target = MessageId::generate().unwrap().to_string();
    let landed = sign_in(&app, &idp, &c, "bob@acme.com", &format!("/m/{target}")).await;
    assert_eq!(landed, format!("/m/{target}"));

    let v: Value = c
        .get(format!("{}/v1/session", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["authenticated"], true);
    assert_eq!(v["email"], "bob@acme.com");
    assert_eq!(v["subject"], "sub-bob@acme.com");
    assert_eq!(*idp.token_calls.lock().unwrap(), 1);

    let events = app.audit.events();
    let login = events
        .iter()
        .find(|e| e.event_type == "auth.login")
        .expect("login audited");
    assert_eq!(login.subject.as_deref(), Some("sub-bob@acme.com"));
    assert_eq!(login.issuer.as_deref(), Some(idp.issuer.as_str()));

    let r = c
        .post(format!("{}/auth/logout", app.base))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NO_CONTENT);
    let v: Value = c
        .get(format!("{}/v1/session", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["authenticated"], false);
    assert!(
        app.audit
            .events()
            .iter()
            .any(|e| e.event_type == "auth.logout")
    );
}

#[tokio::test]
async fn callback_without_the_login_cookie_is_refused() {
    let idp = start_idp().await;
    let app = start_app(&idp, |_| {}).await;
    let c = client();
    let r = c
        .get(format!("{}/auth/login?next=/", app.base))
        .send()
        .await
        .unwrap();
    let to_idp = r.headers()["location"].to_str().unwrap().to_owned();
    let r = c.get(&to_idp).send().await.unwrap();
    let back = r.headers()["location"].to_str().unwrap().to_owned();

    // A different browser (no login cookie) presenting the same callback URL.
    let other = client();
    let r = other.get(&back).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
    assert!(
        app.audit
            .events()
            .iter()
            .any(|e| e.event_type == "auth.login_failed")
    );
    let v: Value = other
        .get(format!("{}/v1/session", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["authenticated"], false);

    // The foreign attempt did not consume the login, so the legitimate browser
    // still completes it; after that the state is spent and a replay fails.
    let r = c.get(&back).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);
    // The login cookie was cleared on success, so a replay fails the
    // browser-binding check before it could reach the spent state.
    let r = c.get(&back).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::BAD_REQUEST);
}

#[tokio::test]
async fn open_redirects_are_not_followed() {
    let idp = start_idp().await;
    let app = start_app(&idp, |_| {}).await;
    let c = client();
    let landed = sign_in(&app, &idp, &c, "bob@acme.com", "https://evil.example/phish").await;
    assert_eq!(landed, "/");
}

#[tokio::test]
async fn closed_mode_requires_a_session_and_binds_sender_and_recipient() {
    let idp = start_idp().await;
    let app = start_app(&idp, |_| {}).await;
    let (proof, verifier) = proof_and_verifier(7);

    // Anonymous create is refused.
    let anon = client();
    let r = anon
        .post(format!("{}/v1/messages", app.base))
        .json(&create_body("alice@acme.com", "bob@acme.com", &verifier))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Alice signs in and creates; the typed sender is ignored in favor of her identity.
    let alice = client();
    sign_in(&app, &idp, &alice, "alice@acme.com", "/").await;
    let r = alice
        .post(format!("{}/v1/messages", app.base))
        .json(&create_body("mallory@acme.com", "bob@acme.com", &verifier))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = r.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();
    let created = app
        .audit
        .events()
        .into_iter()
        .find(|e| e.event_type == "message.created")
        .unwrap();
    assert_eq!(created.sender.as_deref(), Some("alice@acme.com"));
    assert_eq!(created.subject.as_deref(), Some("sub-alice@acme.com"));

    // A recipient outside the allowed domains is refused.
    let r = alice
        .post(format!("{}/v1/messages", app.base))
        .json(&create_body("alice@acme.com", "bob@other.com", &verifier))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Anonymous consume gets the generic answer and burns nothing.
    let r = anon
        .post(format!("{}/v1/messages/{id}/consume", app.base))
        .json(&json!({"proof": proof}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        r.json::<Value>().await.unwrap(),
        json!({"error": "unavailable"})
    );

    // Carol, signed in but not the recipient, gets the same generic answer, and the message survives.
    let carol = client();
    sign_in(&app, &idp, &carol, "carol@acme.com", "/").await;
    let r = carol
        .post(format!("{}/v1/messages/{id}/consume", app.base))
        .json(&json!({"proof": proof}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    assert_eq!(
        r.json::<Value>().await.unwrap(),
        json!({"error": "unavailable"})
    );
    let denied = app
        .audit
        .events()
        .into_iter()
        .filter(|e| e.event_type == "message.access_denied" && e.reason == Some(Reason::Consume))
        .count();
    assert_eq!(denied, 2, "anonymous and carol");

    // Bob, the named recipient, reads it exactly once.
    let bob = client();
    sign_in(&app, &idp, &bob, "bob@acme.com", &format!("/m/{id}")).await;
    let r = bob
        .post(format!("{}/v1/messages/{id}/consume", app.base))
        .json(&json!({"proof": proof}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    let body: Value = r.json().await.unwrap();
    assert_eq!(body["sender"], "alice@acme.com");
    assert_eq!(body["recipient"], "bob@acme.com");
    let r = bob
        .post(format!("{}/v1/messages/{id}/consume", app.base))
        .json(&json!({"proof": proof}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);
    let consumed = app
        .audit
        .events()
        .into_iter()
        .find(|e| e.event_type == "message.consumed")
        .unwrap();
    assert_eq!(consumed.subject.as_deref(), Some("sub-bob@acme.com"));
}

#[tokio::test]
async fn a_user_outside_the_allowed_domains_cannot_create() {
    let idp = start_idp().await;
    let app = start_app(&idp, |_| {}).await;
    let (_, verifier) = proof_and_verifier(9);
    let eve = client();
    sign_in(&app, &idp, &eve, "eve@other.com", "/").await;
    let r = eve
        .post(format!("{}/v1/messages", app.base))
        .json(&create_body("eve@other.com", "bob@acme.com", &verifier))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);
}

/// The MSP and helpdesk shape: only authenticated staff may create, and the
/// customer, who has no account here, reads with the link and the password.
#[tokio::test]
async fn an_authenticated_employee_can_hand_a_secret_to_an_outside_customer() {
    let idp = start_idp().await;
    let app = start_app(&idp, |s| {
        s.enterprise.recipient.require_oidc = false;
        s.enterprise.recipient.require_identity_match = false;
        s.enterprise.recipient.external_recipients = true;
    })
    .await;
    let (proof, verifier) = proof_and_verifier(11);

    // A stranger still cannot create one.
    let anon = client();
    let r = anon
        .post(format!("{}/v1/messages", app.base))
        .json(&create_body(
            "nobody@other.com",
            "cust@other.com",
            &verifier,
        ))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::FORBIDDEN);

    // Alice signs in and addresses a customer outside the directory.
    let alice = client();
    sign_in(&app, &idp, &alice, "alice@acme.com", "/").await;
    let r = alice
        .post(format!("{}/v1/messages", app.base))
        .json(&create_body("alice@acme.com", "cust@other.com", &verifier))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::CREATED);
    let id = r.json::<Value>().await.unwrap()["id"]
        .as_str()
        .unwrap()
        .to_owned();

    // The customer reads it once, without an account.
    let r = anon
        .post(format!("{}/v1/messages/{id}/consume", app.base))
        .json(&json!({"proof": proof}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::OK);
    assert_eq!(
        r.json::<Value>().await.unwrap()["recipient"],
        "cust@other.com"
    );

    // And only once.
    let r = anon
        .post(format!("{}/v1/messages/{id}/consume", app.base))
        .json(&json!({"proof": proof}))
        .send()
        .await
        .unwrap();
    assert_eq!(r.status(), StatusCode::NOT_FOUND);

    // The sender is still the verified identity, and the event says so.
    let created = app
        .audit
        .events()
        .into_iter()
        .find(|e| e.event_type == "message.created")
        .unwrap();
    assert_eq!(created.sender.as_deref(), Some("alice@acme.com"));
    assert_eq!(created.subject.as_deref(), Some("sub-alice@acme.com"));
}

/// Signing in proves control of an account. It does not prove control of
/// every address attached to that account, and authorization rests on the
/// address, so a token that says the address is unverified must not produce
/// a session.
#[tokio::test]
async fn an_address_the_provider_has_not_verified_cannot_sign_in() {
    let idp = start_idp().await;
    let app = start_app(&idp, |_| {}).await;

    for claim in [Some(false), None] {
        let c = client();
        *idp.next_email.lock().unwrap() = "forged@acme.com".to_owned();
        *idp.next_email_verified.lock().unwrap() = claim;
        let r = c
            .get(format!("{}/auth/login?next=/", app.base))
            .send()
            .await
            .unwrap();
        let to_idp = r.headers()["location"].to_str().unwrap().to_owned();
        let r = c.get(&to_idp).send().await.unwrap();
        let back = r.headers()["location"].to_str().unwrap().to_owned();
        let r = c.get(&back).send().await.unwrap();
        assert_eq!(r.status(), StatusCode::UNAUTHORIZED, "claim {claim:?}");

        let v: Value = c
            .get(format!("{}/v1/session", app.base))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        assert_eq!(v["authenticated"], false, "claim {claim:?}");
    }
    assert!(
        app.audit
            .events()
            .iter()
            .any(|e| e.event_type == "auth.login_failed")
    );
}

/// A directory that is authoritative for its addresses but does not send the
/// verification claim is a real and common shape. It works only when the
/// operator says so.
#[tokio::test]
async fn a_deployment_can_accept_an_unverified_address_deliberately() {
    let idp = start_idp().await;
    let app = start_app(&idp, |s| {
        s.enterprise.oidc.unverified_email = UnverifiedEmail::Accept;
    })
    .await;
    let c = client();
    *idp.next_email.lock().unwrap() = "alice@acme.com".to_owned();
    *idp.next_email_verified.lock().unwrap() = None;
    let r = c
        .get(format!("{}/auth/login?next=/", app.base))
        .send()
        .await
        .unwrap();
    let to_idp = r.headers()["location"].to_str().unwrap().to_owned();
    let r = c.get(&to_idp).send().await.unwrap();
    let back = r.headers()["location"].to_str().unwrap().to_owned();
    let r = c.get(&back).send().await.unwrap();
    assert_eq!(r.status(), StatusCode::SEE_OTHER);

    // Even then, a claim that explicitly says unverified is still refused.
    let c2 = client();
    *idp.next_email_verified.lock().unwrap() = Some(false);
    let r = c2
        .get(format!("{}/auth/login?next=/", app.base))
        .send()
        .await
        .unwrap();
    let to_idp = r.headers()["location"].to_str().unwrap().to_owned();
    let r = c2.get(&to_idp).send().await.unwrap();
    let back = r.headers()["location"].to_str().unwrap().to_owned();
    assert_eq!(
        c2.get(&back).send().await.unwrap().status(),
        StatusCode::UNAUTHORIZED
    );
}

/// The configured claim is the only one consulted; a provider that omits it
/// cannot have another claim quietly substituted.
#[tokio::test]
async fn the_configured_claim_is_not_silently_swapped_for_another() {
    let idp = start_idp().await;
    let app = start_app(&idp, |s| {
        s.enterprise.oidc.email_claim = EmailClaim::PreferredUsername;
    })
    .await;
    let c = client();
    sign_in(&app, &idp, &c, "alice@acme.com", "/").await;
    let v: Value = c
        .get(format!("{}/v1/session", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["email"], "alice@acme.com");
}

#[tokio::test]
async fn ui_config_reports_the_mode_and_cookies_are_http_only_lax() {
    let idp = start_idp().await;
    let app = start_app(&idp, |_| {}).await;
    let c = client();
    let v: Value = c
        .get(format!("{}/v1/ui-config", app.base))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(v["mode"], "enterprise");

    let r = c
        .get(format!("{}/auth/login?next=/", app.base))
        .send()
        .await
        .unwrap();
    let set_cookie = r
        .headers()
        .get("set-cookie")
        .unwrap()
        .to_str()
        .unwrap()
        .to_owned();
    assert!(set_cookie.starts_with("securesend_login="), "{set_cookie}");
    assert!(set_cookie.contains("HttpOnly"));
    assert!(set_cookie.contains("SameSite=Lax"));
    assert!(set_cookie.contains("Path=/"));
    assert!(
        !set_cookie.contains("Secure"),
        "plain http base URL must not set Secure"
    );
}
