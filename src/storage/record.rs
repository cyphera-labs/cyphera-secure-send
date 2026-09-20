//! The message as a backend outside this process holds it: every field in a
//! form that survives serialisation and comes back as the same message. The
//! domain types stay free of wire concerns; this is the one place they are
//! spelled out.

use data_encoding::BASE64URL_NOPAD;
use serde::{Deserialize, Serialize};
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use crate::domain::envelope::{Envelope, EnvelopeLimits, EnvelopeWire};
use crate::domain::{Email, MessageId, StoredMessage, Verifier};

#[derive(Debug, thiserror::Error)]
#[error("stored record is not a message: {0}")]
pub struct RecordError(String);

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MessageRecord {
    pub id: String,
    pub sender: String,
    pub sender_authenticated: bool,
    pub recipient: String,
    pub envelope: EnvelopeWire,
    pub verifier: String,
    pub revoke_token_hash: String,
    pub created_at: String,
    pub expires_at: String,
    pub failed_proofs: u32,
}

impl MessageRecord {
    pub fn from_message(m: &StoredMessage) -> Self {
        Self {
            id: m.id.to_string(),
            sender: m.sender.to_string(),
            sender_authenticated: m.sender_authenticated,
            recipient: m.recipient.to_string(),
            envelope: m.envelope.to_wire(),
            verifier: m.verifier.to_base64url(),
            revoke_token_hash: m.revoke_token_hash.to_base64url(),
            created_at: m.created_at.format(&Rfc3339).unwrap_or_default(),
            expires_at: m.expires_at.format(&Rfc3339).unwrap_or_default(),
            failed_proofs: m.failed_proofs,
        }
    }

    /// Back to a message. The envelope is re-validated against generous
    /// bounds rather than the deployment's current ones: a message stored
    /// under yesterday's limits must still open today.
    pub fn into_message(self) -> Result<StoredMessage, RecordError> {
        let lenient = EnvelopeLimits {
            max_plaintext_bytes: 16 * 1024 * 1024,
            kdf: crate::domain::envelope::KdfAlgorithm::Pbkdf2Sha256,
            min_iterations: 1,
            max_iterations: u32::MAX,
        };
        let bad = |what: &str| RecordError(what.to_owned());
        Ok(StoredMessage {
            id: MessageId::parse(&self.id).map_err(|_| bad("id"))?,
            sender: Email::parse(&self.sender).map_err(|_| bad("sender"))?,
            sender_authenticated: self.sender_authenticated,
            recipient: Email::parse(&self.recipient).map_err(|_| bad("recipient"))?,
            envelope: Envelope::validate(&self.envelope, &lenient).map_err(|_| bad("envelope"))?,
            verifier: Verifier::from_base64url(&self.verifier).map_err(|_| bad("verifier"))?,
            revoke_token_hash: Verifier::from_base64url(&self.revoke_token_hash)
                .map_err(|_| bad("revoke token"))?,
            created_at: OffsetDateTime::parse(&self.created_at, &Rfc3339)
                .map_err(|_| bad("created_at"))?,
            expires_at: OffsetDateTime::parse(&self.expires_at, &Rfc3339)
                .map_err(|_| bad("expires_at"))?,
            failed_proofs: self.failed_proofs,
        })
    }

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).unwrap_or_default()
    }

    pub fn from_json(s: &str) -> Result<Self, RecordError> {
        serde_json::from_str(s).map_err(|e| RecordError(e.to_string()))
    }
}

/// The verifier's stored spelling, for backends that hold text.
impl Verifier {
    pub fn to_base64url(&self) -> String {
        BASE64URL_NOPAD.encode(self.as_bytes())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain::envelope::{Cipher, Kdf};
    use crate::domain::ids::Secret;

    #[test]
    fn a_message_survives_the_round_trip_exactly() {
        let proof = Secret::generate().unwrap();
        let revoke = Secret::generate().unwrap();
        let now = OffsetDateTime::now_utc().replace_nanosecond(0).unwrap();
        let m = StoredMessage {
            id: MessageId::generate().unwrap(),
            sender: Email::parse("a@example.com").unwrap(),
            sender_authenticated: true,
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
            expires_at: now + time::Duration::seconds(60),
            failed_proofs: 2,
        };
        let json = MessageRecord::from_message(&m).to_json();
        let back = MessageRecord::from_json(&json)
            .unwrap()
            .into_message()
            .unwrap();
        assert_eq!(back.id.as_str(), m.id.as_str());
        assert_eq!(back.sender.as_str(), "a@example.com");
        assert!(back.sender_authenticated);
        assert_eq!(back.envelope.ciphertext, m.envelope.ciphertext);
        assert_eq!(back.envelope.kdf, m.envelope.kdf);
        assert!(back.verifier.matches(&proof));
        assert!(back.revoke_token_hash.matches(&revoke));
        assert_eq!(back.created_at, now);
        assert_eq!(back.failed_proofs, 2);
        assert!(!json.contains("plaintext"));
    }
}
