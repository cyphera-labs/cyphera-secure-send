//! The message lifecycle: create, consume, revoke. This is the only place that
//! touches the store, the authorizer, and the audit sink together.

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::audit::{AuditEvent, AuditEventType, AuditSink, ClientContext, Reason};
use crate::auth::{ConsumeAuthorizer, Decision, RequestPrincipal};
use crate::domain::email::EmailError;
use crate::domain::envelope::EnvelopeWire;
use crate::domain::ids::IdError;
use crate::domain::{
    Email, Envelope, EnvelopeError, EnvelopeLimits, MessageId, Proof, RevokeToken, StoredMessage,
    Verifier,
};
use crate::storage::{MessageStore, RevokeOutcome, StoreError, TakeOutcome};

#[derive(Clone, Copy, Debug)]
pub struct MessageLimits {
    pub min_ttl_seconds: u64,
    pub max_ttl_seconds: u64,
    pub envelope: EnvelopeLimits,
}

/// A create request after transport decoding, before validation.
#[derive(Debug)]
pub struct CreateRequest {
    pub sender: String,
    pub recipient: String,
    pub ttl_seconds: u64,
    pub verifier: String,
    pub envelope: EnvelopeWire,
}

/// Validation failures. These are safe to show: they describe the request,
/// not any stored message.
#[derive(Debug, thiserror::Error)]
pub enum CreateError {
    #[error("sender: {0}")]
    Sender(EmailError),
    #[error("recipient: {0}")]
    Recipient(EmailError),
    #[error("ttl_seconds must be between {min} and {max}")]
    Ttl { min: u64, max: u64 },
    #[error("verifier must be 32 bytes, base64url")]
    Verifier,
    #[error("envelope: {0}")]
    Envelope(#[from] EnvelopeError),
    #[error("not permitted")]
    Denied,
    #[error("service is at capacity")]
    Full,
    #[error("internal error")]
    Internal,
}

#[derive(Debug)]
pub struct Created {
    pub id: MessageId,
    pub revoke_token: RevokeToken,
    pub expires_at: OffsetDateTime,
}

/// The consumed message, handed to exactly one caller.
#[derive(Debug)]
pub struct Consumed {
    pub sender: Email,
    /// Whether the sender's address came from the identity provider rather
    /// than from the sender. The reader is shown the difference.
    pub sender_authenticated: bool,
    pub recipient: Email,
    pub created_at: OffsetDateTime,
    pub envelope: Envelope,
}

/// Lifecycle totals since the process started. Mirrors the Prometheus
/// counters in a form a JSON endpoint can hand back.
#[derive(Debug, Default)]
pub struct Counters {
    pub created: AtomicU64,
    pub consumed: AtomicU64,
    pub consume_failed: AtomicU64,
    pub burned: AtomicU64,
    pub revoked: AtomicU64,
    pub access_denied: AtomicU64,
    pub rate_limited: AtomicU64,
}

#[derive(Clone, Copy, Debug, Default, serde::Serialize)]
pub struct CounterSnapshot {
    pub created: u64,
    pub consumed: u64,
    pub consume_failed: u64,
    pub burned: u64,
    pub revoked: u64,
    pub access_denied: u64,
    pub rate_limited: u64,
}

impl Counters {
    pub fn snapshot(&self) -> CounterSnapshot {
        CounterSnapshot {
            created: self.created.load(Ordering::Relaxed),
            consumed: self.consumed.load(Ordering::Relaxed),
            consume_failed: self.consume_failed.load(Ordering::Relaxed),
            burned: self.burned.load(Ordering::Relaxed),
            revoked: self.revoked.load(Ordering::Relaxed),
            access_denied: self.access_denied.load(Ordering::Relaxed),
            rate_limited: self.rate_limited.load(Ordering::Relaxed),
        }
    }
}

fn bump(counter: &AtomicU64) {
    counter.fetch_add(1, Ordering::Relaxed);
}

pub struct MessageService {
    store: Arc<dyn MessageStore>,
    authorizer: Arc<dyn ConsumeAuthorizer>,
    audit: Arc<dyn AuditSink>,
    limits: MessageLimits,
    counters: Counters,
}

impl MessageService {
    pub fn new(
        store: Arc<dyn MessageStore>,
        authorizer: Arc<dyn ConsumeAuthorizer>,
        audit: Arc<dyn AuditSink>,
        limits: MessageLimits,
    ) -> Self {
        Self {
            store,
            authorizer,
            audit,
            limits,
            counters: Counters::default(),
        }
    }

    pub fn limits(&self) -> &MessageLimits {
        &self.limits
    }

    pub fn counters(&self) -> &Counters {
        &self.counters
    }

    pub fn store(&self) -> &Arc<dyn MessageStore> {
        &self.store
    }

    pub async fn create(
        &self,
        request: CreateRequest,
        principal: &RequestPrincipal,
        client: &ClientContext,
    ) -> Result<Created, CreateError> {
        let sender = match &principal.email {
            Some(me) => me.clone(),
            None => Email::parse(&request.sender).map_err(CreateError::Sender)?,
        };
        let recipient = Email::parse(&request.recipient).map_err(CreateError::Recipient)?;
        let (min, max) = (self.limits.min_ttl_seconds, self.limits.max_ttl_seconds);
        if request.ttl_seconds < min || request.ttl_seconds > max {
            return Err(CreateError::Ttl { min, max });
        }
        let verifier =
            Verifier::from_base64url(&request.verifier).map_err(|_| CreateError::Verifier)?;
        let envelope = Envelope::validate(&request.envelope, &self.limits.envelope)?;

        if self
            .authorizer
            .authorize_create(principal, &sender, &recipient)
            == Decision::Deny
        {
            let mut event =
                AuditEvent::failure(AuditEventType::MessageAccessDenied, Reason::Create)
                    .with_client(client);
            event.sender = Some(sender.to_string());
            event.recipient = Some(recipient.to_string());
            self.audit.emit(event);
            bump(&self.counters.access_denied);
            return Err(CreateError::Denied);
        }

        let id = MessageId::generate().map_err(|_| CreateError::Internal)?;
        let revoke_token = RevokeToken::generate().map_err(|_| CreateError::Internal)?;
        let created_at = OffsetDateTime::now_utc();
        let expires_at = created_at + time::Duration::seconds(request.ttl_seconds as i64);

        let stored = StoredMessage {
            id: id.clone(),
            sender: sender.clone(),
            sender_authenticated: principal.is_authenticated(),
            recipient: recipient.clone(),
            envelope,
            verifier,
            revoke_token_hash: revoke_token.hash(),
            created_at,
            expires_at,
            failed_proofs: 0,
        };

        match self.store.put(stored).await {
            Ok(()) => {}
            Err(StoreError::Full) => return Err(CreateError::Full),
            Err(StoreError::Unavailable(_)) => return Err(CreateError::Internal),
        }

        metrics::counter!("securesend_messages_created_total").increment(1);
        bump(&self.counters.created);
        let mut event = AuditEvent::success(AuditEventType::MessageCreated)
            .with_message(&id)
            .with_client(client)
            .with_sender_authenticated(principal.is_authenticated());
        event.sender = Some(sender.to_string());
        event.recipient = Some(recipient.to_string());
        event.ttl_seconds = Some(request.ttl_seconds as i64);
        event.expires_at = expires_at.format(&Rfc3339).ok();
        self.audit.emit(event);

        Ok(Created {
            id,
            revoke_token,
            expires_at,
        })
    }

    /// Returns `None` for every failure. The audit stream records why.
    pub async fn consume(
        &self,
        id: &str,
        proof: &str,
        principal: &RequestPrincipal,
        client: &ClientContext,
    ) -> Option<Consumed> {
        let Ok(id) = MessageId::parse(id) else {
            self.consume_failed(None, Reason::NotFound, None, client);
            return None;
        };
        let Ok(proof) = Proof::from_base64url(proof) else {
            self.consume_failed(Some(&id), Reason::WrongProof, None, client);
            return None;
        };

        let policy = self.authorizer.consume_policy(principal);
        let binding_enforced = policy.expected_recipient.is_some();
        match self.store.take(&id, &proof, &policy).await {
            TakeOutcome::Taken(message) => {
                let message = *message;
                metrics::counter!("securesend_messages_consumed_total").increment(1);
                bump(&self.counters.consumed);
                let mut event = AuditEvent::success(AuditEventType::MessageConsumed)
                    .with_message(&id)
                    .with_client(client)
                    .with_sender_authenticated(message.sender_authenticated)
                    .with_reader(principal.is_authenticated(), binding_enforced);
                event.sender = Some(message.sender.to_string());
                event.recipient = Some(message.recipient.to_string());
                event.ttl_seconds = Some(message.ttl_seconds());
                self.audit.emit(event);
                Some(Consumed {
                    sender: message.sender,
                    sender_authenticated: message.sender_authenticated,
                    recipient: message.recipient,
                    created_at: message.created_at,
                    envelope: message.envelope,
                })
            }
            TakeOutcome::Denied { recipient } => {
                metrics::counter!("securesend_messages_access_denied_total").increment(1);
                bump(&self.counters.access_denied);
                let mut event =
                    AuditEvent::failure(AuditEventType::MessageAccessDenied, Reason::Consume)
                        .with_message(&id)
                        .with_client(client);
                event.recipient = Some(recipient.to_string());
                self.audit.emit(event);
                None
            }
            TakeOutcome::Missing => {
                self.consume_failed(Some(&id), Reason::NotFound, None, client);
                None
            }
            TakeOutcome::WrongProof { failed_proofs } => {
                self.consume_failed(Some(&id), Reason::WrongProof, Some(failed_proofs), client);
                None
            }
            TakeOutcome::Burned { failed_proofs } => {
                metrics::counter!("securesend_messages_burned_total").increment(1);
                bump(&self.counters.burned);
                let mut event = AuditEvent::failure(AuditEventType::MessageBurned, Reason::Burned)
                    .with_message(&id)
                    .with_client(client);
                event.failed_proofs = Some(failed_proofs);
                self.audit.emit(event);
                None
            }
        }
    }

    fn consume_failed(
        &self,
        id: Option<&MessageId>,
        reason: Reason,
        failed_proofs: Option<u32>,
        client: &ClientContext,
    ) {
        metrics::counter!("securesend_messages_consume_failed_total").increment(1);
        bump(&self.counters.consume_failed);
        let mut event =
            AuditEvent::failure(AuditEventType::MessageConsumeFailed, reason).with_client(client);
        if let Some(id) = id {
            event = event.with_message(id);
        }
        event.failed_proofs = failed_proofs;
        self.audit.emit(event);
    }

    /// Always succeeds from the caller's point of view.
    pub async fn revoke(&self, id: &str, revoke_token: &str, client: &ClientContext) {
        let Ok(id) = MessageId::parse(id) else {
            self.audit.emit(
                AuditEvent::failure(AuditEventType::MessageRevoked, Reason::NotFound)
                    .with_client(client),
            );
            return;
        };
        let Ok(token) = RevokeToken::from_base64url(revoke_token) else {
            self.audit.emit(
                AuditEvent::failure(AuditEventType::MessageRevoked, Reason::WrongRevokeToken)
                    .with_message(&id)
                    .with_client(client),
            );
            return;
        };
        let event = match self.store.revoke(&id, &token).await {
            RevokeOutcome::Revoked => {
                metrics::counter!("securesend_messages_revoked_total").increment(1);
                bump(&self.counters.revoked);
                AuditEvent::success(AuditEventType::MessageRevoked)
            }
            RevokeOutcome::Missing => {
                AuditEvent::failure(AuditEventType::MessageRevoked, Reason::NotFound)
            }
            RevokeOutcome::WrongToken => {
                AuditEvent::failure(AuditEventType::MessageRevoked, Reason::WrongRevokeToken)
            }
        };
        self.audit.emit(event.with_message(&id).with_client(client));
    }
}

impl From<IdError> for CreateError {
    fn from(_: IdError) -> Self {
        CreateError::Internal
    }
}
