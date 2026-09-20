//! Identifiers and secrets.
//!
//! * `MessageId` is public: it appears in the URL path and in audit events.
//! * The link secret never reaches the server at all (it lives in the URL
//!   fragment and feeds the browser-side key derivation).
//! * `Proof` is what the browser derives from password + link secret and sends
//!   at consume time. The server stores only `Verifier = SHA-256(proof)`.
//! * `RevokeToken` is returned to the sender once; the server stores its hash.

use data_encoding::{BASE32_NOPAD, BASE64URL_NOPAD};
use sha2::{Digest, Sha256};
use std::fmt;
use subtle::ConstantTimeEq;

const ID_BYTES: usize = 16;
const ID_CHARS: usize = 26;
const SECRET_BYTES: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum IdError {
    #[error("invalid identifier")]
    InvalidId,
    #[error("invalid secret encoding")]
    InvalidSecret,
    #[error("system randomness unavailable")]
    Randomness,
}

fn random_bytes<const N: usize>() -> Result<[u8; N], IdError> {
    let mut buf = [0u8; N];
    getrandom::fill(&mut buf).map_err(|_| IdError::Randomness)?;
    Ok(buf)
}

/// 128-bit random identifier, lowercase base32, 26 characters. Not secret.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct MessageId(String);

impl MessageId {
    pub fn generate() -> Result<Self, IdError> {
        let bytes: [u8; ID_BYTES] = random_bytes()?;
        Ok(Self(BASE32_NOPAD.encode(&bytes).to_ascii_lowercase()))
    }

    /// Parses an identifier from untrusted input. Shape only; existence is
    /// never implied by success here.
    pub fn parse(s: &str) -> Result<Self, IdError> {
        if s.len() != ID_CHARS {
            return Err(IdError::InvalidId);
        }
        if !s
            .bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit())
        {
            return Err(IdError::InvalidId);
        }
        BASE32_NOPAD
            .decode(s.to_ascii_uppercase().as_bytes())
            .map_err(|_| IdError::InvalidId)?;
        Ok(Self(s.to_owned()))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl fmt::Display for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for MessageId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MessageId({})", self.0)
    }
}

/// A 32-byte secret supplied by a client. Never logged, never displayed.
#[derive(Clone)]
pub struct Secret([u8; SECRET_BYTES]);

impl Secret {
    pub fn generate() -> Result<Self, IdError> {
        Ok(Self(random_bytes()?))
    }

    pub fn from_base64url(s: &str) -> Result<Self, IdError> {
        let decoded = BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| IdError::InvalidSecret)?;
        let bytes: [u8; SECRET_BYTES] = decoded.try_into().map_err(|_| IdError::InvalidSecret)?;
        Ok(Self(bytes))
    }

    pub fn to_base64url(&self) -> String {
        BASE64URL_NOPAD.encode(&self.0)
    }

    pub fn hash(&self) -> Verifier {
        Verifier(Sha256::digest(self.0).into())
    }
}

impl fmt::Debug for Secret {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Secret(..)")
    }
}

/// The value the browser sends to prove it holds both the password and the
/// link secret.
pub type Proof = Secret;

/// The token that lets the sender revoke before retrieval.
pub type RevokeToken = Secret;

/// SHA-256 of a `Secret`. Safe to keep in memory: it cannot be inverted and
/// it is not accepted by any endpoint.
#[derive(Clone)]
pub struct Verifier([u8; 32]);

impl Verifier {
    pub fn from_base64url(s: &str) -> Result<Self, IdError> {
        let decoded = BASE64URL_NOPAD
            .decode(s.as_bytes())
            .map_err(|_| IdError::InvalidSecret)?;
        let bytes: [u8; 32] = decoded.try_into().map_err(|_| IdError::InvalidSecret)?;
        Ok(Self(bytes))
    }

    /// Constant-time comparison against the hash of a presented secret.
    pub(crate) fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    pub fn matches(&self, presented: &Secret) -> bool {
        let candidate = presented.hash();
        self.0.ct_eq(&candidate.0).into()
    }

    /// A fixed verifier used to keep the failure path's timing identical when
    /// there is no stored message to compare against.
    pub fn dummy() -> Self {
        Self([0x5a; 32])
    }
}

impl fmt::Debug for Verifier {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("Verifier(..)")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_round_trips_and_rejects_bad_shapes() {
        let id = MessageId::generate().unwrap();
        assert_eq!(id.as_str().len(), 26);
        assert_eq!(MessageId::parse(id.as_str()).unwrap(), id);
        assert!(MessageId::parse("").is_err());
        assert!(MessageId::parse(&id.as_str().to_ascii_uppercase()).is_err());
        assert!(MessageId::parse("abcdefghijklmnopqrstuvwxy!").is_err());
        assert!(MessageId::parse("8888888888888888888888888z").is_err());
    }

    #[test]
    fn secret_round_trips_and_verifier_matches() {
        let s = Secret::generate().unwrap();
        let encoded = s.to_base64url();
        assert_eq!(encoded.len(), 43);
        let back = Secret::from_base64url(&encoded).unwrap();
        assert!(s.hash().matches(&back));
        let other = Secret::generate().unwrap();
        assert!(!s.hash().matches(&other));
        assert!(Secret::from_base64url("short").is_err());
        assert!(Secret::from_base64url(&format!("{encoded}=")).is_err());
    }

    #[test]
    fn verifier_parses_from_base64url() {
        let s = Secret::generate().unwrap();
        let v = Verifier::from_base64url(&BASE64URL_NOPAD.encode(&s.hash().0)).unwrap();
        assert!(v.matches(&s));
    }
}
