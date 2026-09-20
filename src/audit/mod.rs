//! Audit events: lifecycle metadata only. By construction an event cannot
//! carry plaintext, a password, a key, a proof, a verifier, a link secret, a
//! revoke token, a usable URL, or any free text: every field is a typed
//! identifier, an address, a timestamp, a count, or an enumerated code.
//! Diagnostics belong in the application log, not here.

use serde::Serialize;
use std::io::Write;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::mpsc::SyncSender;
use std::time::Duration;
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
    IncompleteResponse,
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
    /// Whether the address in `sender` was established by the identity
    /// provider, as opposed to typed by whoever created the message. The
    /// recipient address is always typed by the sender, so it carries no
    /// such claim.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sender_authenticated: Option<bool>,
    /// On a retrieval: whether the reader was signed in.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reader_authenticated: Option<bool>,
    /// On a retrieval: whether the service required the reader to be the
    /// address the message names.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recipient_binding_enforced: Option<bool>,
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
            sender_authenticated: None,
            reader_authenticated: None,
            recipient_binding_enforced: None,
            ttl_seconds: None,
            expires_at: None,
            failed_proofs: None,
            client_ip: None,
            user_agent: None,
            subject: None,
            issuer: None,
            active_messages: None,
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

    /// Records that the sender address came from the identity provider
    /// rather than from a form field.
    pub fn with_sender_authenticated(mut self, authenticated: bool) -> Self {
        self.sender_authenticated = Some(authenticated);
        self
    }

    /// Records what the reader actually proved: whether they were signed in,
    /// and whether the service required them to be the named recipient.
    pub fn with_reader(mut self, authenticated: bool, binding_enforced: bool) -> Self {
        self.reader_authenticated = Some(authenticated);
        self.recipient_binding_enforced = Some(binding_enforced);
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

    /// Waits, up to the given time, for everything emitted so far to reach
    /// its destination. Called once at shutdown so the final events land.
    fn flush(&self, _wait: Duration) {}
}

/// One JSON object per line on standard output, written by its own thread.
///
/// A request must never wait on the log. Standard output is a pipe to
/// whatever collects it, and a collector that stalls would otherwise stall
/// every handler behind one lock, then the liveness probe, then the whole
/// process, and a restart discards every pending message. So handlers hand
/// the line to a bounded queue and carry on; the writer thread does the
/// blocking work. When the queue is full the line is dropped and counted,
/// which is the honest outcome: a log that cannot keep up loses records, and
/// the count says how many.
pub struct StdoutJsonSink {
    queue: SyncSender<Item>,
    dropped: AtomicU64,
}

enum Item {
    Line(String),
    /// Answered once everything queued before it has been written.
    Flush(SyncSender<()>),
}

/// How many lines may wait for the writer before new ones are dropped.
const AUDIT_QUEUE_LINES: usize = 8192;

impl StdoutJsonSink {
    pub fn new() -> Self {
        Self::with_writer(std::io::stdout())
    }

    /// The same sink over any destination. Exists so a test can stall the
    /// destination and prove callers are not stalled with it.
    pub fn with_writer(out: impl Write + Send + 'static) -> Self {
        let (queue, inbox) = std::sync::mpsc::sync_channel::<Item>(AUDIT_QUEUE_LINES);
        std::thread::Builder::new()
            .name("audit-writer".to_owned())
            .spawn(move || {
                let mut out = out;
                for item in inbox {
                    match item {
                        Item::Line(line) => {
                            let _ = writeln!(out, "{line}");
                        }
                        Item::Flush(ack) => {
                            let _ = out.flush();
                            let _ = ack.send(());
                        }
                    }
                }
                let _ = out.flush();
            })
            .expect("spawn the audit writer thread");
        Self {
            queue,
            dropped: AtomicU64::new(0),
        }
    }

    /// Lines dropped because the queue was full.
    pub fn dropped(&self) -> u64 {
        self.dropped.load(Ordering::Relaxed)
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
        if self.queue.try_send(Item::Line(line)).is_err() {
            let dropped = self.dropped.fetch_add(1, Ordering::Relaxed) + 1;
            metrics::counter!("securesend_audit_dropped_total").increment(1);
            // Loud once, then at widening intervals, so a stalled collector
            // does not also flood the application log.
            if dropped.is_power_of_two() {
                tracing::warn!(
                    dropped,
                    "audit output cannot keep up; records are being dropped"
                );
            }
        }
    }

    fn flush(&self, wait: Duration) {
        let (ack, done) = std::sync::mpsc::sync_channel(1);
        if self.queue.send(Item::Flush(ack)).is_ok() {
            let _ = done.recv_timeout(wait);
        }
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A destination that blocks until released, standing in for a log
    /// collector that has stopped reading.
    struct Stalled(std::sync::Arc<(Mutex<bool>, std::sync::Condvar)>);

    impl Write for Stalled {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            let (open, released) = &*self.0;
            let mut open = open.lock().unwrap();
            while !*open {
                open = released.wait(open).unwrap();
            }
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    /// The property the design rests on: a request never waits on the log.
    #[test]
    fn a_stalled_destination_does_not_stall_callers() {
        let gate = std::sync::Arc::new((Mutex::new(false), std::sync::Condvar::new()));
        let sink = StdoutJsonSink::with_writer(Stalled(gate.clone()));

        let started = std::time::Instant::now();
        for _ in 0..(AUDIT_QUEUE_LINES + 500) {
            sink.emit(AuditEvent::success(AuditEventType::ServerStarted));
        }
        // Well past the queue's depth, and still no caller has waited.
        assert!(started.elapsed() < Duration::from_secs(2));
        assert!(
            sink.dropped() >= 400,
            "overflow must be counted, got {}",
            sink.dropped()
        );

        // Release the destination and the queued lines drain.
        *gate.0.lock().unwrap() = true;
        gate.1.notify_all();
        sink.flush(Duration::from_secs(5));
    }
}
