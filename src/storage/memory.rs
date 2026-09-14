//! In-memory store on a bounded, per-entry-expiring cache. Messages live only
//! as long as the process; a restart clears everything, by design.

use async_trait::async_trait;
use moka::Expiry;
use moka::future::Cache;
use moka::notification::RemovalCause;
use moka::ops::compute::{CompResult, Op};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};
use time::OffsetDateTime;

use super::{MessageStore, RevokeOutcome, StoreError, StoreStats, TakeOutcome, TakePolicy};
use crate::audit::{AuditEvent, AuditEventType, AuditSink};
use crate::domain::{MessageId, Proof, RevokeToken, StoredMessage, Verifier};

pub struct MemoryStore {
    cache: Cache<MessageId, StoredMessage>,
    max_failed_proofs: u32,
    budget_bytes: u64,
    expired: Arc<AtomicU64>,
    evicted: Arc<AtomicU64>,
}

struct ExpireAtField;

impl Expiry<MessageId, StoredMessage> for ExpireAtField {
    fn expire_after_create(
        &self,
        _: &MessageId,
        value: &StoredMessage,
        _: Instant,
    ) -> Option<Duration> {
        Some(remaining(value))
    }

    fn expire_after_update(
        &self,
        _: &MessageId,
        value: &StoredMessage,
        _: Instant,
        _: Option<Duration>,
    ) -> Option<Duration> {
        Some(remaining(value))
    }
}

fn remaining(value: &StoredMessage) -> Duration {
    let left = value.expires_at - OffsetDateTime::now_utc();
    if left.is_positive() {
        Duration::from_nanos(left.whole_nanoseconds().clamp(1, i64::MAX as i128) as u64)
    } else {
        Duration::from_nanos(1)
    }
}

impl MemoryStore {
    pub fn new(
        memory_budget_bytes: u64,
        max_failed_proofs: u32,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        let expired = Arc::new(AtomicU64::new(0));
        let evicted = Arc::new(AtomicU64::new(0));
        let (expired_l, evicted_l) = (expired.clone(), evicted.clone());
        let listener = move |_key: Arc<MessageId>, value: StoredMessage, cause: RemovalCause| {
            let event_type = match cause {
                RemovalCause::Expired => AuditEventType::MessageExpired,
                RemovalCause::Size => AuditEventType::MessageEvicted,
                RemovalCause::Explicit | RemovalCause::Replaced => return,
            };
            match event_type {
                AuditEventType::MessageExpired => {
                    expired_l.fetch_add(1, Ordering::Relaxed);
                    metrics::counter!("securesend_messages_expired_total").increment(1)
                }
                _ => {
                    evicted_l.fetch_add(1, Ordering::Relaxed);
                    metrics::counter!("securesend_messages_evicted_total").increment(1)
                }
            }
            let mut event = AuditEvent::success(event_type).with_message(&value.id);
            event.sender = Some(value.sender.to_string());
            event.recipient = Some(value.recipient.to_string());
            audit.emit(event);
        };

        let cache = Cache::builder()
            .max_capacity(memory_budget_bytes)
            .weigher(|_k: &MessageId, v: &StoredMessage| v.weight())
            .expire_after(ExpireAtField)
            .eviction_listener(listener)
            .build();

        Self {
            cache,
            max_failed_proofs,
            budget_bytes: memory_budget_bytes,
            expired,
            evicted,
        }
    }

    /// Drives expiry and eviction housekeeping to completion. Used by tests
    /// and by the periodic maintenance task.
    pub async fn run_pending_tasks(&self) {
        self.cache.run_pending_tasks().await;
    }
}

#[async_trait]
impl MessageStore for MemoryStore {
    async fn put(&self, message: StoredMessage) -> Result<(), StoreError> {
        if u64::from(message.weight()) > self.cache.policy().max_capacity().unwrap_or(u64::MAX) {
            return Err(StoreError::Full);
        }
        self.cache.insert(message.id.clone(), message).await;
        Ok(())
    }

    async fn take(&self, id: &MessageId, proof: &Proof, policy: &TakePolicy) -> TakeOutcome {
        let max = self.max_failed_proofs;
        let proof = proof.clone();
        let policy = policy.clone();
        let result = self
            .cache
            .entry(id.clone())
            .and_compute_with(|entry| {
                let proof = proof.clone();
                let policy = policy.clone();
                async move {
                    match entry {
                        None => Op::Nop,
                        Some(e) => {
                            let current = e.into_value();
                            if !policy.permits(&current.recipient) {
                                return Op::Nop;
                            }
                            let matched = current.verifier.matches(&proof);
                            if matched || current.failed_proofs + 1 >= max {
                                Op::Remove
                            } else {
                                Op::Put(StoredMessage {
                                    failed_proofs: current.failed_proofs + 1,
                                    ..current
                                })
                            }
                        }
                    }
                }
            })
            .await;

        match result {
            CompResult::StillNone(_) => {
                Verifier::dummy().matches(&proof);
                TakeOutcome::Missing
            }
            CompResult::Removed(entry) => {
                let message = entry.into_value();
                if message.verifier.matches(&proof) {
                    TakeOutcome::Taken(Box::new(message))
                } else {
                    TakeOutcome::Burned {
                        failed_proofs: message.failed_proofs + 1,
                    }
                }
            }
            CompResult::ReplacedWith(entry) => TakeOutcome::WrongProof {
                failed_proofs: entry.into_value().failed_proofs,
            },
            CompResult::Unchanged(entry) => TakeOutcome::Denied {
                recipient: entry.into_value().recipient,
            },
            CompResult::Inserted(_) => TakeOutcome::Missing,
        }
    }

    async fn revoke(&self, id: &MessageId, token: &RevokeToken) -> RevokeOutcome {
        let token = token.clone();
        let result = self
            .cache
            .entry(id.clone())
            .and_compute_with(|entry| {
                let token = token.clone();
                async move {
                    match entry {
                        None => Op::Nop,
                        Some(e) => {
                            if e.value().revoke_token_hash.matches(&token) {
                                Op::Remove
                            } else {
                                Op::Nop
                            }
                        }
                    }
                }
            })
            .await;
        match result {
            CompResult::Removed(_) => RevokeOutcome::Revoked,
            CompResult::StillNone(_) => {
                Verifier::dummy().matches(&token);
                RevokeOutcome::Missing
            }
            CompResult::Unchanged(_) => RevokeOutcome::WrongToken,
            CompResult::Inserted(_) | CompResult::ReplacedWith(_) => RevokeOutcome::Missing,
        }
    }

    async fn stats(&self) -> StoreStats {
        self.cache.run_pending_tasks().await;
        StoreStats {
            active_messages: self.cache.entry_count(),
            weighted_bytes: self.cache.weighted_size(),
            budget_bytes: self.budget_bytes,
            expired_total: self.expired.load(Ordering::Relaxed),
            evicted_total: self.evicted.load(Ordering::Relaxed),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::MemorySink;
    use crate::domain::ids::Secret;
    use crate::domain::{Email, Envelope};
    use std::sync::atomic::{AtomicUsize, Ordering};
    use tokio::sync::Barrier;

    fn message(ttl_secs: i64) -> (StoredMessage, Secret, Secret) {
        let proof = Secret::generate().unwrap();
        let revoke = Secret::generate().unwrap();
        let now = OffsetDateTime::now_utc();
        let m = StoredMessage {
            id: MessageId::generate().unwrap(),
            sender: Email::parse("a@example.com").unwrap(),
            recipient: Email::parse("b@example.com").unwrap(),
            envelope: Envelope {
                iterations: 100_000,
                salt: vec![1; 16],
                iv: vec![2; 12],
                ciphertext: vec![3; 48],
            },
            verifier: proof.hash(),
            revoke_token_hash: revoke.hash(),
            created_at: now,
            expires_at: now + time::Duration::seconds(ttl_secs),
            failed_proofs: 0,
        };
        (m, proof, revoke)
    }

    fn store(sink: Arc<MemorySink>) -> MemoryStore {
        MemoryStore::new(10 * 1024 * 1024, 3, sink)
    }

    #[tokio::test]
    async fn take_returns_the_message_exactly_once() {
        let s = store(Arc::new(MemorySink::default()));
        let (m, proof, _) = message(60);
        let id = m.id.clone();
        s.put(m).await.unwrap();
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await,
            TakeOutcome::Taken(_)
        ));
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await,
            TakeOutcome::Missing
        ));
    }

    #[tokio::test]
    async fn concurrent_correct_proofs_yield_one_winner() {
        let s = Arc::new(store(Arc::new(MemorySink::default())));
        let (m, proof, _) = message(60);
        let id = m.id.clone();
        s.put(m).await.unwrap();

        let n = 64;
        let barrier = Arc::new(Barrier::new(n));
        let wins = Arc::new(AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..n {
            let (s, id, proof, barrier, wins) = (
                s.clone(),
                id.clone(),
                proof.clone(),
                barrier.clone(),
                wins.clone(),
            );
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                if let TakeOutcome::Taken(_) = s.take(&id, &proof, &TakePolicy::allow_any()).await {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(wins.load(Ordering::SeqCst), 1);
        assert_eq!(s.stats().await.active_messages, 0);
    }

    #[tokio::test]
    async fn wrong_proofs_count_up_then_burn() {
        let sink = Arc::new(MemorySink::default());
        let s = store(sink.clone());
        let (m, proof, _) = message(60);
        let id = m.id.clone();
        s.put(m).await.unwrap();
        let wrong = Secret::generate().unwrap();
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await,
            TakeOutcome::WrongProof { failed_proofs: 1 }
        ));
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await,
            TakeOutcome::WrongProof { failed_proofs: 2 }
        ));
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await,
            TakeOutcome::Burned { failed_proofs: 3 }
        ));
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await,
            TakeOutcome::Missing
        ));
    }

    #[tokio::test]
    async fn wrong_proof_keeps_the_original_expiry() {
        let s = store(Arc::new(MemorySink::default()));
        let (m, _, _) = message(1);
        let id = m.id.clone();
        s.put(m).await.unwrap();
        let wrong = Secret::generate().unwrap();
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await,
            TakeOutcome::WrongProof { .. }
        ));
        tokio::time::sleep(Duration::from_millis(1300)).await;
        s.run_pending_tasks().await;
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await,
            TakeOutcome::Missing
        ));
    }

    #[tokio::test]
    async fn expiry_removes_and_audits() {
        let sink = Arc::new(MemorySink::default());
        let s = store(sink.clone());
        let (m, proof, _) = message(1);
        let id = m.id.clone();
        s.put(m).await.unwrap();
        tokio::time::sleep(Duration::from_millis(1300)).await;
        s.run_pending_tasks().await;
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await,
            TakeOutcome::Missing
        ));
        let events = sink.events();
        assert!(
            events.iter().any(|e| e.event_type == "message.expired"
                && e.message_id.as_deref() == Some(id.as_str()))
        );
    }

    #[tokio::test]
    async fn a_refusing_policy_leaves_the_message_untouched() {
        let s = store(Arc::new(MemorySink::default()));
        let (m, proof, _) = message(60);
        let id = m.id.clone();
        s.put(m).await.unwrap();
        match s.take(&id, &proof, &TakePolicy::deny_all()).await {
            TakeOutcome::Denied { recipient } => assert_eq!(recipient.as_str(), "b@example.com"),
            other => panic!("expected Denied, got {other:?}"),
        }
        let wrong = Secret::generate().unwrap();
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::deny_all()).await,
            TakeOutcome::Denied { .. }
        ));
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await,
            TakeOutcome::Taken(_)
        ));
    }

    #[tokio::test]
    async fn revoke_requires_the_token() {
        let s = store(Arc::new(MemorySink::default()));
        let (m, proof, revoke) = message(60);
        let id = m.id.clone();
        s.put(m).await.unwrap();
        let wrong = Secret::generate().unwrap();
        assert_eq!(s.revoke(&id, &wrong).await, RevokeOutcome::WrongToken);
        assert_eq!(s.revoke(&id, &revoke).await, RevokeOutcome::Revoked);
        assert_eq!(s.revoke(&id, &revoke).await, RevokeOutcome::Missing);
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await,
            TakeOutcome::Missing
        ));
    }

    #[tokio::test]
    async fn over_budget_messages_are_refused_and_pressure_evicts() {
        let sink = Arc::new(MemorySink::default());
        let s = MemoryStore::new(2000, 3, sink.clone());
        let (m, _, _) = message(60);
        let mut huge = m.clone();
        huge.envelope.ciphertext = vec![0; 4000];
        assert!(matches!(s.put(huge).await, Err(StoreError::Full)));
        for _ in 0..10 {
            let (m, _, _) = message(60);
            s.put(m).await.unwrap();
        }
        s.run_pending_tasks().await;
        assert!(s.stats().await.weighted_bytes <= 2000);
        assert!(
            sink.events()
                .iter()
                .any(|e| e.event_type == "message.evicted")
        );
    }
}
