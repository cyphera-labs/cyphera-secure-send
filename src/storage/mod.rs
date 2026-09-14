//! The message store. `take` is the only read, and it verifies and removes in
//! one atomic step. There is no `get`, no `exists`, and no separate `delete`.

pub mod memory;

use async_trait::async_trait;

use crate::domain::{MessageId, Proof, RevokeToken, StoredMessage};

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("message store is full")]
    Full,
    #[error("message store unavailable: {0}")]
    Unavailable(String),
}

/// What the caller is allowed to take, decided from the caller alone before
/// the store is touched, and evaluated inside the atomic step before the
/// proof so a denied caller neither burns nor learns. Plain data on purpose:
/// a distributed store has to carry it into its own atomic operation.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TakePolicy {
    /// The caller may not take anything.
    pub deny: bool,
    /// The message's recipient must equal this address (case-insensitive).
    pub expected_recipient: Option<crate::domain::Email>,
}

impl TakePolicy {
    pub fn allow_any() -> Self {
        Self {
            deny: false,
            expected_recipient: None,
        }
    }

    pub fn deny_all() -> Self {
        Self {
            deny: true,
            expected_recipient: None,
        }
    }

    pub fn only(recipient: crate::domain::Email) -> Self {
        Self {
            deny: false,
            expected_recipient: Some(recipient),
        }
    }

    pub fn permits(&self, recipient: &crate::domain::Email) -> bool {
        if self.deny {
            return false;
        }
        match &self.expected_recipient {
            None => true,
            Some(expected) => expected.as_str().eq_ignore_ascii_case(recipient.as_str()),
        }
    }
}

/// Result of an atomic take. Only `Taken` carries the message; every other
/// variant is reported to the client identically.
#[derive(Debug)]
pub enum TakeOutcome {
    /// Proof matched; the message was removed and is returned exactly once.
    Taken(Box<StoredMessage>),
    /// The guard refused the caller; the message is untouched.
    Denied { recipient: crate::domain::Email },
    /// No message under that id (never existed, expired, consumed, revoked,
    /// evicted, or burned earlier).
    Missing,
    /// Proof did not match; the failure counter was advanced.
    WrongProof { failed_proofs: u32 },
    /// Proof did not match and the counter reached its limit; the message was
    /// destroyed.
    Burned { failed_proofs: u32 },
}

#[derive(Debug, PartialEq, Eq)]
pub enum RevokeOutcome {
    Revoked,
    Missing,
    WrongToken,
}

#[derive(Clone, Copy, Debug, Default)]
pub struct StoreStats {
    pub active_messages: u64,
    pub weighted_bytes: u64,
    pub budget_bytes: u64,
    pub expired_total: u64,
    pub evicted_total: u64,
}

#[async_trait]
pub trait MessageStore: Send + Sync {
    async fn put(&self, message: StoredMessage) -> Result<(), StoreError>;
    async fn take(&self, id: &MessageId, proof: &Proof, policy: &TakePolicy) -> TakeOutcome;
    async fn revoke(&self, id: &MessageId, token: &RevokeToken) -> RevokeOutcome;
    /// Exact figures; implementations settle pending housekeeping first.
    async fn stats(&self) -> StoreStats;
}
