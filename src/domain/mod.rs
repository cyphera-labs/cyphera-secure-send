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
    pub recipient: Email,
    pub envelope: Envelope,
    pub verifier: Verifier,
    pub revoke_token_hash: Verifier,
    pub created_at: OffsetDateTime,
    pub expires_at: OffsetDateTime,
    pub failed_proofs: u32,
}

impl StoredMessage {
    /// Approximate resident size, used as the cache weight.
    pub fn weight(&self) -> u32 {
        let bytes = self.envelope.ciphertext.len()
            + self.envelope.salt.len()
            + self.envelope.iv.len()
            + self.sender.as_str().len()
            + self.recipient.as_str().len()
            + 256;
        u32::try_from(bytes).unwrap_or(u32::MAX)
    }

    pub fn ttl_seconds(&self) -> i64 {
        (self.expires_at - self.created_at).whole_seconds()
    }
}
