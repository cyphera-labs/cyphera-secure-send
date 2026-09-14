//! Audit events: lifecycle metadata only. By construction an event cannot
//! carry plaintext, a password, a key, a proof, a verifier, a link secret, a
//! revoke token, or a usable URL; none of those types appear in `AuditEvent`.

use serde::Serialize;
use std::io::Write;
use std::sync::Mutex;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::domain::MessageId;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditEventType {
    MessageCreated,
    MessageConsumed,
    MessageConsumeFailed,
    MessageBurned,
    MessageRevoked,
    MessageExpired,
    MessageEvicted,
    MessageAccessDenied,
    RateLimited,
    AuthLogin,
    AuthLoginFailed,
    AuthLogout,
    ServerStarted,
    ServerStopping,
}

impl AuditEventType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::MessageCreated => "message.created",
            Self::MessageConsumed => "message.consumed",
            Self::MessageConsumeFailed => "message.consume_failed",
            Self::MessageBurned => "message.burned",
            Self::MessageRevoked => "message.revoked",
            Self::MessageExpired => "message.expired",
            Self::MessageEvicted => "message.evicted",
            Self::MessageAccessDenied => "message.access_denied",
            Self::RateLimited => "rate_limited",
            Self::AuthLogin => "auth.login",
            Self::AuthLoginFailed => "auth.login_failed",
            Self::AuthLogout => "auth.logout",
            Self::ServerStarted => "server.started",
            Self::ServerStopping => "server.stopping",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Outcome {
    Success,
    Failure,
}

/// Why something failed. Written to the audit stream, never to the client.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    NotFound,
    WrongProof,
    WrongRevokeToken,
    Burned,
    Unauthorized,
    Create,
    Consume,
    Revoke,
    ProviderError,
    StateMismatch,
    TokenRejected,
}

#[derive(Clone, Debug, Serialize)]
pub struct AuditEvent {
    pub event_id: String,
    #[serde(rename = "type")]
    pub event_type: &'static str,
    pub time: String,
    pub outcome: Outcome,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<Reason>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ttl_seconds: Option<i64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expires_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failed_proofs: Option<u32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client_ip: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user_agent: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subject: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub issuer: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_messages: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

impl AuditEvent {
    pub fn new(event_type: AuditEventType, outcome: Outcome) -> Self {
        Self {
            event_id: random_event_id(),
            event_type: event_type.as_str(),
            time: OffsetDateTime::now_utc()
                .format(&Rfc3339)
                .unwrap_or_default(),
            outcome,
            reason: None,
            message_id: None,
            sender: None,
            recipient: None,
            ttl_seconds: None,
            expires_at: None,
            failed_proofs: None,
            client_ip: None,
            user_agent: None,
            subject: None,
            issuer: None,
            active_messages: None,
            detail: None,
        }
    }

    pub fn success(event_type: AuditEventType) -> Self {
        Self::new(event_type, Outcome::Success)
    }

    pub fn failure(event_type: AuditEventType, reason: Reason) -> Self {
        let mut e = Self::new(event_type, Outcome::Failure);
        e.reason = Some(reason);
        e
    }

    pub fn with_message(mut self, id: &MessageId) -> Self {
        self.message_id = Some(id.to_string());
        self
    }

    pub fn with_client(mut self, client: &ClientContext) -> Self {
        self.client_ip = client.ip.clone();
        self.user_agent = client.user_agent.clone();
        self.subject = client.subject.clone();
        self.issuer = client.issuer.clone();
        self
    }
}

/// What the request layer knows about the caller, already filtered by the
/// audit settings (fields the operator did not opt into are `None`).
#[derive(Clone, Debug, Default)]
pub struct ClientContext {
    pub ip: Option<String>,
    pub user_agent: Option<String>,
    pub subject: Option<String>,
    pub issuer: Option<String>,
}

fn random_event_id() -> String {
    let mut buf = [0u8; 16];
    if getrandom::fill(&mut buf).is_err() {
        return "00000000000000000000000000".to_owned();
    }
    data_encoding::BASE32_NOPAD
        .encode(&buf)
        .to_ascii_lowercase()
}

pub trait AuditSink: Send + Sync {
    fn emit(&self, event: AuditEvent);
}

/// One JSON object per line on standard output.
pub struct StdoutJsonSink {
    out: Mutex<std::io::Stdout>,
}

impl StdoutJsonSink {
    pub fn new() -> Self {
        Self {
            out: Mutex::new(std::io::stdout()),
        }
    }
}

impl Default for StdoutJsonSink {
    fn default() -> Self {
        Self::new()
    }
}

impl AuditSink for StdoutJsonSink {
    fn emit(&self, event: AuditEvent) {
        let Ok(line) = serde_json::to_string(&event) else {
            return;
        };
        let mut out = match self.out.lock() {
            Ok(guard) => guard,
            Err(poisoned) => poisoned.into_inner(),
        };
        let _ = writeln!(out, "{line}");
        let _ = out.flush();
    }
}

pub struct DiscardSink;

impl AuditSink for DiscardSink {
    fn emit(&self, _event: AuditEvent) {}
}

/// Collects events in memory. For tests.
#[derive(Default)]
pub struct MemorySink {
    events: Mutex<Vec<AuditEvent>>,
}

impl MemorySink {
    pub fn events(&self) -> Vec<AuditEvent> {
        self.events.lock().map(|e| e.clone()).unwrap_or_default()
    }
}

impl AuditSink for MemorySink {
    fn emit(&self, event: AuditEvent) {
        if let Ok(mut events) = self.events.lock() {
            events.push(event);
        }
    }
}
