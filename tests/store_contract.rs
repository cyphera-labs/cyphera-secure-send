//! The store contract, run against every backend. What the memory store
//! promises, the shared store must promise identically: one take, counted
//! failures, a burn at the limit, a policy honoured before the proof, a
//! revoke that needs the token, a budget enforced at the door, expiry that
//! frees room, and one winner under a race.
//!
//! The memory backend always runs. The Redis backend runs when
//! `SECURESEND_TEST_REDIS_URL` names a server, with a fresh key prefix per
//! test so runs do not see each other.

use std::sync::Arc;
use std::time::Duration;
use time::OffsetDateTime;
use tokio::sync::Barrier;

use cyphera_secure_send::audit::MemorySink;
use cyphera_secure_send::auth::session::{AccountRef, PendingLogin, SessionStore};
use cyphera_secure_send::domain::envelope::{Cipher, Kdf};
use cyphera_secure_send::domain::ids::Secret;
use cyphera_secure_send::domain::{Email, Envelope, MessageId, StoredMessage};
use cyphera_secure_send::storage::memory::MemoryStore;
use cyphera_secure_send::storage::redis::{RedisConnection, RedisSessionStore, RedisStore};
use cyphera_secure_send::storage::{
    MessageStore, RevokeOutcome, StoreError, TakeOutcome, TakePolicy,
};

const MAX_FAILED: u32 = 3;

struct Backend {
    name: &'static str,
    messages: Arc<dyn MessageStore>,
    sessions: Arc<dyn SessionStore>,
    audit: Arc<MemorySink>,
}

fn message(ttl_secs: i64, ciphertext_len: usize) -> (StoredMessage, Secret, Secret) {
    let proof = Secret::generate().unwrap();
    let revoke = Secret::generate().unwrap();
    let now = OffsetDateTime::now_utc();
    let m = StoredMessage {
        id: MessageId::generate().unwrap(),
        sender: Email::parse("a@example.com").unwrap(),
        sender_authenticated: false,
        recipient: Email::parse("bob@example.com").unwrap(),
        envelope: Envelope {
            version: 1,
            kdf: Kdf::Pbkdf2Sha256 {
                iterations: 100_000,
                salt: vec![1; 16],
            },
            cipher: Cipher::Aes256Gcm { iv: vec![2; 12] },
            ciphertext: vec![3; ciphertext_len],
        },
        verifier: proof.hash(),
        revoke_token_hash: revoke.hash(),
        created_at: now,
        expires_at: now + time::Duration::seconds(ttl_secs),
        failed_proofs: 0,
    };
    (m, proof, revoke)
}

/// Every backend available here, each with the given budget.
async fn backends(budget: u64) -> Vec<Backend> {
    let mut out = Vec::new();
    let audit = Arc::new(MemorySink::default());
    out.push(Backend {
        name: "memory",
        messages: Arc::new(MemoryStore::new(budget, MAX_FAILED, audit.clone())),
        sessions: Arc::new(cyphera_secure_send::auth::session::MemorySessionStore::new(
            Duration::from_secs(60),
            Duration::from_secs(60),
        )),
        audit,
    });
    if let Ok(url) = std::env::var("SECURESEND_TEST_REDIS_URL") {
        let prefix = format!("t{}", &Secret::generate().unwrap().to_base64url()[..8]);
        let conn = RedisConnection::connect(&url, &prefix, Duration::from_secs(5))
            .await
            .expect("the test redis answers");
        let audit = Arc::new(MemorySink::default());
        out.push(Backend {
            name: "redis",
            messages: Arc::new(RedisStore::new(
                conn.clone(),
                budget,
                MAX_FAILED,
                audit.clone(),
            )),
            sessions: Arc::new(RedisSessionStore::new(
                conn,
                Duration::from_secs(60),
                Duration::from_secs(60),
            )),
            audit,
        });
    } else {
        eprintln!("SECURESEND_TEST_REDIS_URL is not set; the contract runs against memory only");
    }
    out
}

#[tokio::test]
async fn a_message_is_taken_once_with_the_right_proof() {
    for b in backends(10 << 20).await {
        let (m, proof, _) = message(60, 48);
        let id = m.id.clone();
        b.messages.put(m).await.unwrap();

        let first = b
            .messages
            .take(&id, &proof, &TakePolicy::allow_any())
            .await
            .unwrap();
        let TakeOutcome::Taken(taken) = first else {
            panic!("{}: first take should succeed, got {first:?}", b.name)
        };
        assert_eq!(taken.id.as_str(), id.as_str(), "{}", b.name);
        assert_eq!(taken.envelope.ciphertext, vec![3; 48], "{}", b.name);

        let again = b
            .messages
            .take(&id, &proof, &TakePolicy::allow_any())
            .await
            .unwrap();
        assert!(
            matches!(again, TakeOutcome::Missing),
            "{}: {again:?}",
            b.name
        );
        assert_eq!(
            b.messages.stats().await.unwrap().active_messages,
            0,
            "{}",
            b.name
        );
    }
}

#[tokio::test]
async fn wrong_proofs_are_counted_and_the_limit_burns_the_message() {
    for b in backends(10 << 20).await {
        let (m, proof, _) = message(60, 48);
        let id = m.id.clone();
        b.messages.put(m).await.unwrap();
        let wrong = Secret::generate().unwrap();

        for expected in 1..MAX_FAILED {
            let outcome = b
                .messages
                .take(&id, &wrong, &TakePolicy::allow_any())
                .await
                .unwrap();
            assert!(
                matches!(outcome, TakeOutcome::WrongProof { failed_proofs } if failed_proofs == expected),
                "{}: attempt {expected} gave {outcome:?}",
                b.name
            );
        }
        let last = b
            .messages
            .take(&id, &wrong, &TakePolicy::allow_any())
            .await
            .unwrap();
        assert!(
            matches!(last, TakeOutcome::Burned { failed_proofs } if failed_proofs == MAX_FAILED),
            "{}: {last:?}",
            b.name
        );
        // Burned means gone, even for the right proof.
        let after = b
            .messages
            .take(&id, &proof, &TakePolicy::allow_any())
            .await
            .unwrap();
        assert!(matches!(after, TakeOutcome::Missing), "{}", b.name);
    }
}

#[tokio::test]
async fn a_denied_caller_neither_burns_nor_learns() {
    for b in backends(10 << 20).await {
        let (m, proof, _) = message(60, 48);
        let id = m.id.clone();
        b.messages.put(m).await.unwrap();
        let wrong = Secret::generate().unwrap();

        // Denied outright, and denied as the wrong recipient: many wrong
        // proofs, none counted.
        let stranger = TakePolicy::only(Email::parse("carol@example.com").unwrap());
        for policy in [TakePolicy::deny_all(), stranger] {
            for _ in 0..(MAX_FAILED * 2) {
                let outcome = b.messages.take(&id, &wrong, &policy).await.unwrap();
                assert!(
                    matches!(outcome, TakeOutcome::Denied { ref recipient } if recipient.as_str() == "bob@example.com"),
                    "{}: {outcome:?}",
                    b.name
                );
            }
        }
        // The recipient, case-insensitively, still reads it once.
        let bob = TakePolicy::only(Email::parse("Bob@Example.com").unwrap());
        let outcome = b.messages.take(&id, &proof, &bob).await.unwrap();
        assert!(
            matches!(outcome, TakeOutcome::Taken(_)),
            "{}: {outcome:?}",
            b.name
        );
    }
}

#[tokio::test]
async fn revoking_needs_the_token() {
    for b in backends(10 << 20).await {
        let (m, proof, revoke) = message(60, 48);
        let id = m.id.clone();
        b.messages.put(m).await.unwrap();

        let wrong = Secret::generate().unwrap();
        assert_eq!(
            b.messages.revoke(&id, &wrong).await.unwrap(),
            RevokeOutcome::WrongToken,
            "{}",
            b.name
        );
        assert_eq!(
            b.messages.revoke(&id, &revoke).await.unwrap(),
            RevokeOutcome::Revoked,
            "{}",
            b.name
        );
        assert_eq!(
            b.messages.revoke(&id, &revoke).await.unwrap(),
            RevokeOutcome::Missing,
            "{}",
            b.name
        );
        let after = b
            .messages
            .take(&id, &proof, &TakePolicy::allow_any())
            .await
            .unwrap();
        assert!(matches!(after, TakeOutcome::Missing), "{}", b.name);
    }
}

#[tokio::test]
async fn a_full_store_refuses_and_everything_acknowledged_is_readable() {
    let (sample, _, _) = message(60, 4096);
    let budget = u64::from(sample.weight()) * 5;
    for b in backends(budget).await {
        let mut accepted = Vec::new();
        let mut refused = 0;
        for _ in 0..40 {
            let (m, proof, _) = message(60, 4096);
            match b.messages.put(m.clone()).await {
                Ok(()) => accepted.push((m.id, proof)),
                Err(StoreError::Full) => refused += 1,
                Err(e) => panic!("{}: {e}", b.name),
            }
        }
        assert!(refused > 0 && !accepted.is_empty(), "{}", b.name);
        let stats = b.messages.stats().await.unwrap();
        assert_eq!(stats.active_messages, accepted.len() as u64, "{}", b.name);
        assert!(stats.weighted_bytes <= budget, "{}", b.name);
        assert_eq!(stats.evicted_total, 0, "{}", b.name);
        for (id, proof) in accepted {
            let outcome = b
                .messages
                .take(&id, &proof, &TakePolicy::allow_any())
                .await
                .unwrap();
            assert!(
                matches!(outcome, TakeOutcome::Taken(_)),
                "{}: an acknowledged message must be readable",
                b.name
            );
        }
        assert_eq!(
            b.messages.stats().await.unwrap().weighted_bytes,
            0,
            "{}: the counter settles back to zero",
            b.name
        );
    }
}

#[tokio::test]
async fn expiry_frees_room_and_is_audited() {
    let (sample, _, _) = message(60, 48);
    let budget = u64::from(sample.weight()) * 2;
    for b in backends(budget).await {
        let (short, _, _) = message(1, 48);
        let short_id = short.id.clone();
        b.messages.put(short).await.unwrap();
        let (a, _, _) = message(60, 48);
        b.messages.put(a).await.unwrap();
        let (c, _, _) = message(60, 48);
        assert!(
            matches!(b.messages.put(c.clone()).await, Err(StoreError::Full)),
            "{}",
            b.name
        );

        tokio::time::sleep(Duration::from_millis(1200)).await;
        // Housekeeping settles the expiry; then there is room again.
        let stats = b.messages.stats().await.unwrap();
        assert_eq!(stats.active_messages, 1, "{}", b.name);
        assert_eq!(stats.expired_total, 1, "{}", b.name);
        b.messages.put(c).await.unwrap();
        assert!(
            b.audit
                .events()
                .iter()
                .any(|e| e.event_type == "message.expired"
                    && e.message_id.as_deref() == Some(short_id.as_str())),
            "{}: expiry is audited",
            b.name
        );
    }
}

#[tokio::test]
async fn many_racing_takers_produce_exactly_one_winner() {
    for b in backends(10 << 20).await {
        let (m, proof, _) = message(60, 48);
        let id = m.id.clone();
        b.messages.put(m).await.unwrap();

        let racers = 40;
        let barrier = Arc::new(Barrier::new(racers));
        let mut handles = Vec::new();
        for _ in 0..racers {
            let (store, barrier, id, proof) = (
                b.messages.clone(),
                barrier.clone(),
                id.clone(),
                proof.clone(),
            );
            handles.push(tokio::spawn(async move {
                barrier.wait().await;
                matches!(
                    store
                        .take(&id, &proof, &TakePolicy::allow_any())
                        .await
                        .unwrap(),
                    TakeOutcome::Taken(_)
                )
            }));
        }
        let mut winners = 0;
        for h in handles {
            if h.await.unwrap() {
                winners += 1;
            }
        }
        assert_eq!(winners, 1, "{}", b.name);
    }
}

#[tokio::test]
async fn sessions_round_trip_logins_are_single_use_and_accounts_can_be_ended() {
    for b in backends(10 << 20).await {
        b.sessions
            .start_login(
                "st".into(),
                PendingLogin {
                    pkce_verifier: "v".into(),
                    nonce: "n".into(),
                    next: "/".into(),
                },
            )
            .await
            .unwrap();
        let first = b.sessions.take_login("st").await.unwrap();
        assert_eq!(first.map(|p| p.nonce), Some("n".to_owned()), "{}", b.name);
        assert!(
            b.sessions.take_login("st").await.unwrap().is_none(),
            "{}: a state works once",
            b.name
        );

        let alice = Email::parse("alice@example.com").unwrap();
        let (a1, s) = b
            .sessions
            .create("alice-sub".into(), alice.clone(), "iss".into())
            .await
            .unwrap();
        let (a2, _) = b
            .sessions
            .create("alice-sub".into(), alice.clone(), "iss".into())
            .await
            .unwrap();
        let (b1, _) = b
            .sessions
            .create(
                "bob-sub".into(),
                Email::parse("bob@example.com").unwrap(),
                "iss".into(),
            )
            .await
            .unwrap();
        assert_eq!(
            b.sessions.get(&a1).await.unwrap().unwrap().email.as_str(),
            s.email.as_str(),
            "{}",
            b.name
        );

        b.sessions.revoke(&a2).await.unwrap();
        assert!(b.sessions.get(&a2).await.unwrap().is_none(), "{}", b.name);

        let ended = b
            .sessions
            .revoke_account(&AccountRef {
                subject: None,
                email: Some(Email::parse("ALICE@example.com").unwrap()),
            })
            .await
            .unwrap();
        assert_eq!(
            ended, 1,
            "{}: one of Alice's sessions was still live",
            b.name
        );
        assert!(b.sessions.get(&a1).await.unwrap().is_none(), "{}", b.name);
        assert!(
            b.sessions.get(&b1).await.unwrap().is_some(),
            "{}: Bob is untouched",
            b.name
        );
        assert_eq!(
            b.sessions
                .revoke_account(&AccountRef {
                    subject: Some("alice-sub".into()),
                    email: None
                })
                .await
                .unwrap(),
            0,
            "{}",
            b.name
        );
    }
}
