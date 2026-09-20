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
    /// Serialises admission. The cache decides whether a new entry fits only
    /// while it settles its pending work, so two creates racing past the
    /// same free-space check could both be told yes and one be dropped.
    admission: tokio::sync::Mutex<()>,
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
            admission: tokio::sync::Mutex::new(()),
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
    /// Stores a message, or says it cannot. The cache never evicts an
    /// accepted message to make room for a new one: a sender who was told
    /// "delivered" must be able to rely on it, and a sender who cannot be
    /// accommodated must be told so rather than handed a link to nothing.
    async fn put(&self, message: StoredMessage) -> Result<(), StoreError> {
        let weight = u64::from(message.weight());
        let _admitting = self.admission.lock().await;

        // Settle expiries first so freed room counts, then ask whether this
        // one fits in what is left.
        self.cache.run_pending_tasks().await;
        if self.cache.weighted_size().saturating_add(weight) > self.budget_bytes {
            return Err(StoreError::Full);
        }

        let id = message.id.clone();
        self.cache.insert(id.clone(), message).await;
        // Apply the insert now, so the next caller's check sees it, and so
        // the cache's own admission decision is final before we answer.
        self.cache.run_pending_tasks().await;
        if self.cache.contains_key(&id) {
            Ok(())
        } else {
            Err(StoreError::Full)
        }
    }

    async fn take(
        &self,
        id: &MessageId,
        proof: &Proof,
        policy: &TakePolicy,
    ) -> Result<TakeOutcome, StoreError> {
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

        Ok(match result {
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
            CompResult::Unchanged(entry) => {
                // Denied inside the closure before any comparison, so pay for
                // one here: a probe must cost the same whether the message
                // exists or not.
                Verifier::dummy().matches(&proof);
                TakeOutcome::Denied {
                    recipient: entry.into_value().recipient,
                }
            }
            CompResult::Inserted(_) => TakeOutcome::Missing,
        })
    }

    async fn revoke(
        &self,
        id: &MessageId,
        token: &RevokeToken,
    ) -> Result<RevokeOutcome, StoreError> {
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
        Ok(match result {
            CompResult::Removed(_) => RevokeOutcome::Revoked,
            CompResult::StillNone(_) => {
                Verifier::dummy().matches(&token);
                RevokeOutcome::Missing
            }
            CompResult::Unchanged(_) => RevokeOutcome::WrongToken,
            CompResult::Inserted(_) | CompResult::ReplacedWith(_) => RevokeOutcome::Missing,
        })
    }

    async fn stats(&self) -> Result<StoreStats, StoreError> {
        self.cache.run_pending_tasks().await;
        Ok(StoreStats {
            active_messages: self.cache.entry_count(),
            weighted_bytes: self.cache.weighted_size(),
            budget_bytes: self.budget_bytes,
            expired_total: self.expired.load(Ordering::Relaxed),
            evicted_total: self.evicted.load(Ordering::Relaxed),
        })
    }

    fn backend_name(&self) -> &'static str {
        "memory"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::audit::MemorySink;
    use crate::domain::envelope::{Cipher, Kdf};
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
            sender_authenticated: false,
            recipient: Email::parse("b@example.com").unwrap(),
            envelope: Envelope {
                version: 1,
                kdf: Kdf::Pbkdf2Sha256 {
                    iterations: 100_000,
                    salt: vec![1; 16],
                },
                cipher: Cipher::Aes256Gcm { iv: vec![2; 12] },
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

    /// The failure that matters most: a store at its budget must refuse,
    /// never acknowledge a message it then quietly drops.
    #[tokio::test]
    async fn a_full_store_refuses_rather_than_dropping_what_it_acknowledged() {
        let sink = Arc::new(MemorySink::default());
        let (sample, _, _) = message(3600);
        // Room for a handful, then no more.
        let store = MemoryStore::new(u64::from(sample.weight()) * 5, 3, sink);

        let mut accepted = Vec::new();
        let mut refused = 0;
        for _ in 0..40 {
            let (m, proof, _) = message(3600);
            match store.put(m.clone()).await {
                Ok(()) => accepted.push((m.id, proof)),
                Err(StoreError::Full) => refused += 1,
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        assert!(refused > 0, "the budget should have been reached");
        assert!(!accepted.is_empty());

        // Every acknowledgement was honest.
        for (id, proof) in accepted {
            let outcome = store
                .take(&id, &proof, &TakePolicy::allow_any())
                .await
                .unwrap();
            assert!(
                matches!(outcome, TakeOutcome::Taken(_)),
                "an acknowledged message must be retrievable"
            );
        }
        // And nothing was evicted to make that so.
        assert_eq!(store.stats().await.unwrap().evicted_total, 0);
    }

    /// Room freed by expiry is room the next sender may use. The cache keeps
    /// its own clock, so this waits for a real second rather than a paused one.
    #[tokio::test]
    async fn expiry_frees_room_for_the_next_message() {
        let sink = Arc::new(MemorySink::default());
        let (sample, _, _) = message(3600);
        let store = MemoryStore::new(u64::from(sample.weight()) * 2, 3, sink);

        let (short, _, _) = message(1);
        store.put(short).await.unwrap();
        let (a, _, _) = message(3600);
        store.put(a).await.unwrap();
        let (b, _, _) = message(3600);
        assert!(matches!(store.put(b.clone()).await, Err(StoreError::Full)));

        tokio::time::sleep(Duration::from_millis(1100)).await;
        store.put(b).await.unwrap();
    }

    #[tokio::test]
    async fn take_returns_the_message_exactly_once() {
        let s = store(Arc::new(MemorySink::default()));
        let (m, proof, _) = message(60);
        let id = m.id.clone();
        s.put(m).await.unwrap();
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await.unwrap(),
            TakeOutcome::Taken(_)
        ));
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await.unwrap(),
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
                if let TakeOutcome::Taken(_) =
                    s.take(&id, &proof, &TakePolicy::allow_any()).await.unwrap()
                {
                    wins.fetch_add(1, Ordering::SeqCst);
                }
            }));
        }
        for h in handles {
            h.await.unwrap();
        }
        assert_eq!(wins.load(Ordering::SeqCst), 1);
        assert_eq!(s.stats().await.unwrap().active_messages, 0);
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
            s.take(&id, &wrong, &TakePolicy::allow_any()).await.unwrap(),
            TakeOutcome::WrongProof { failed_proofs: 1 }
        ));
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await.unwrap(),
            TakeOutcome::WrongProof { failed_proofs: 2 }
        ));
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await.unwrap(),
            TakeOutcome::Burned { failed_proofs: 3 }
        ));
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await.unwrap(),
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
            s.take(&id, &wrong, &TakePolicy::allow_any()).await.unwrap(),
            TakeOutcome::WrongProof { .. }
        ));
        tokio::time::sleep(Duration::from_millis(1300)).await;
        s.run_pending_tasks().await;
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::allow_any()).await.unwrap(),
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
            s.take(&id, &proof, &TakePolicy::allow_any()).await.unwrap(),
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
        match s.take(&id, &proof, &TakePolicy::deny_all()).await.unwrap() {
            TakeOutcome::Denied { recipient } => assert_eq!(recipient.as_str(), "b@example.com"),
            other => panic!("expected Denied, got {other:?}"),
        }
        let wrong = Secret::generate().unwrap();
        assert!(matches!(
            s.take(&id, &wrong, &TakePolicy::deny_all()).await.unwrap(),
            TakeOutcome::Denied { .. }
        ));
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await.unwrap(),
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
        assert_eq!(
            s.revoke(&id, &wrong).await.unwrap(),
            RevokeOutcome::WrongToken
        );
        assert_eq!(
            s.revoke(&id, &revoke).await.unwrap(),
            RevokeOutcome::Revoked
        );
        assert_eq!(
            s.revoke(&id, &revoke).await.unwrap(),
            RevokeOutcome::Missing
        );
        assert!(matches!(
            s.take(&id, &proof, &TakePolicy::allow_any()).await.unwrap(),
            TakeOutcome::Missing
        ));
    }

    #[tokio::test]
    async fn over_budget_messages_are_refused_and_pressure_never_evicts() {
        let sink = Arc::new(MemorySink::default());
        let s = MemoryStore::new(4000, 3, sink.clone());
        let (m, _, _) = message(60);
        let mut huge = m.clone();
        huge.envelope.ciphertext = vec![0; 8000];
        assert!(matches!(s.put(huge).await, Err(StoreError::Full)));

        let mut accepted = 0;
        for _ in 0..10 {
            let (m, _, _) = message(60);
            match s.put(m).await {
                Ok(()) => accepted += 1,
                Err(StoreError::Full) => {}
                Err(other) => panic!("unexpected {other:?}"),
            }
        }
        assert!(accepted > 0 && accepted < 10);
        let stats = s.stats().await.unwrap();
        assert!(stats.weighted_bytes <= 4000);
        assert_eq!(stats.active_messages, accepted);
        // Pressure is answered at the door, never by discarding what was accepted.
        assert_eq!(stats.evicted_total, 0);
        assert!(
            !sink
                .events()
                .iter()
                .any(|e| e.event_type == "message.evicted")
        );
    }
}
