//! Core types. Everything here is plain data with strict constructors; no I/O.

pub mod email;
pub mod envelope;
pub mod ids;

pub use email::Email;
pub use envelope::{Envelope, EnvelopeError, EnvelopeLimits};
pub use ids::{MessageId, Proof, RevokeToken, Verifier};

use time::OffsetDateTime;

/// A message as the server holds it: ciphertext plus the metadata needed to
/// hand it over exactly once. There is no plaintext, password, or key anywhere
/// in this struct, and the retrieval secret and revoke token exist only as
/// hashes.
#[derive(Clone, Debug)]
pub struct StoredMessage {
    pub id: MessageId,
    pub sender: Email,
    /// Whether `sender` was established by the identity provider at creation
    /// time. Carried so a retrieval event can state the sender's provenance
    /// without the reader's own session being mistaken for it.
    pub sender_authenticated: bool,
    pub recipient: Email,
    pub envelope: Envelope,
    pub verifier: Verifier,
    pub revoke_token_hash: Verifier,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub failed_proofs: u32,
}

impl StoredMessage {
    /// Approximate resident size, used as the cache weight. The constant
    /// covers the fixed fields, the allocations' headers, and the cache's
    /// own bookkeeping per entry, measured at roughly three times the
    /// payload for a small message; under-counting it lets the store exceed
    /// the container's memory before its own budget.
    pub fn weight(&self) -> u32 {
        let bytes = self.envelope.resident_bytes()
            + self.sender.as_str().len()
            + self.recipient.as_str().len()
            + 1024;
        u32::try_from(bytes).unwrap_or(u32::MAX)
    }

    pub fn ttl_seconds(&self) -> i64 {
        (self.expires_at - self.created_at).whole_seconds()
    }
}
