//! The versioned encryption envelope produced by the browser. The server
//! validates its shape strictly and stores it opaquely; it never decrypts.
//!
//! Every algorithm is a variant, and every version is a match arm. Adding a
//! key derivation means a new `Kdf` variant with its own parameter rules and
//! a new arm in `validate`; nothing else changes, and the old one keeps
//! being accepted for as long as links carrying it may still be opened.

use data_encoding::BASE64_NOPAD;
use serde::{Deserialize, Serialize};

/// The envelope format version the interface produces today.
pub const VERSION: u32 = 1;
const SALT_BYTES: usize = 16;
const IV_BYTES: usize = 12;
const GCM_TAG_BYTES: usize = 16;

/// A password-stretching algorithm the service knows how to describe and
/// bound. The browser does the work; the server checks the parameters are
/// within what it will store and what the interface will derive.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum KdfAlgorithm {
    Pbkdf2Sha256,
}

impl KdfAlgorithm {
    /// The name on the wire, which is also what the interface advertises.
    pub fn wire_name(self) -> &'static str {
        match self {
            KdfAlgorithm::Pbkdf2Sha256 => "PBKDF2-SHA256",
        }
    }

    fn from_wire_name(name: &str) -> Option<Self> {
        match name {
            "PBKDF2-SHA256" => Some(KdfAlgorithm::Pbkdf2Sha256),
            _ => None,
        }
    }
}

/// The key derivation an envelope was made with, parameters included.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Kdf {
    Pbkdf2Sha256 { iterations: u32, salt: Vec<u8> },
}

impl Kdf {
    pub fn algorithm(&self) -> KdfAlgorithm {
        match self {
            Kdf::Pbkdf2Sha256 { .. } => KdfAlgorithm::Pbkdf2Sha256,
        }
    }

    /// The work factor, in the algorithm's own unit.
    pub fn work_factor(&self) -> u32 {
        match self {
            Kdf::Pbkdf2Sha256 { iterations, .. } => *iterations,
        }
    }

    pub fn salt(&self) -> &[u8] {
        match self {
            Kdf::Pbkdf2Sha256 { salt, .. } => salt,
        }
    }
}

/// The cipher an envelope was sealed with.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Cipher {
    Aes256Gcm { iv: Vec<u8> },
}

impl Cipher {
    pub fn wire_name(&self) -> &'static str {
        match self {
            Cipher::Aes256Gcm { .. } => "AES-256-GCM",
        }
    }

    pub fn iv(&self) -> &[u8] {
        match self {
            Cipher::Aes256Gcm { iv } => iv,
        }
    }
}

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EnvelopeError {
    #[error("unsupported envelope version")]
    Version,
    #[error("unsupported key derivation")]
    Kdf,
    #[error("key derivation iterations out of range")]
    Iterations,
    #[error("unsupported cipher")]
    Cipher,
    #[error("malformed salt")]
    Salt,
    #[error("malformed iv")]
    Iv,
    #[error("malformed ciphertext")]
    Ciphertext,
    #[error("ciphertext too large")]
    TooLarge,
}

#[derive(Clone, Copy, Debug)]
pub struct EnvelopeLimits {
    pub max_plaintext_bytes: usize,
    /// The one algorithm the interface produces, and the bounds on its
    /// work factor. A second algorithm gets its own bounds beside these.
    pub kdf: KdfAlgorithm,
    pub min_iterations: u32,
    pub max_iterations: u32,
}

impl EnvelopeLimits {
    /// The largest ciphertext a conforming client can produce for the
    /// configured plaintext limit.
    pub fn max_ciphertext_bytes(&self) -> usize {
        self.max_plaintext_bytes + GCM_TAG_BYTES
    }

    /// The largest request body that can carry such an envelope, with room
    /// for base64 expansion, the JSON framing, and the other fields.
    pub fn max_request_body_bytes(&self) -> usize {
        self.max_ciphertext_bytes().div_ceil(3) * 4 + 4096
    }
}

/// Wire form, exactly as the browser sends it and as it is returned.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvelopeWire {
    pub version: u32,
    pub kdf: KdfWire,
    pub cipher: CipherWire,
    pub ciphertext: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct KdfWire {
    pub name: String,
    pub iterations: u32,
    pub salt: String,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CipherWire {
    pub name: String,
    pub iv: String,
}

/// Validated form. Constructing one proves the shape is acceptable.
#[derive(Clone, Debug)]
pub struct Envelope {
    pub version: u32,
    pub kdf: Kdf,
    pub cipher: Cipher,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn validate(wire: &EnvelopeWire, limits: &EnvelopeLimits) -> Result<Self, EnvelopeError> {
        // One arm per format version this service still accepts. A version
        // stays here until no link carrying it can still be alive.
        match wire.version {
            1 => Self::validate_v1(wire, limits),
            _ => Err(EnvelopeError::Version),
        }
    }

    fn validate_v1(wire: &EnvelopeWire, limits: &EnvelopeLimits) -> Result<Self, EnvelopeError> {
        let kdf = Self::validate_kdf(&wire.kdf, limits)?;
        let cipher = Self::validate_cipher(&wire.cipher)?;
        if wire.ciphertext.len() > limits.max_ciphertext_bytes().div_ceil(3) * 4 {
            return Err(EnvelopeError::TooLarge);
        }
        let ciphertext = decode(&wire.ciphertext).ok_or(EnvelopeError::Ciphertext)?;
        if ciphertext.len() < GCM_TAG_BYTES {
            return Err(EnvelopeError::Ciphertext);
        }
        if ciphertext.len() > limits.max_ciphertext_bytes() {
            return Err(EnvelopeError::TooLarge);
        }
        Ok(Self {
            version: 1,
            kdf,
            cipher,
            ciphertext,
        })
    }

    /// Each algorithm checks its own parameters against its own bounds.
    fn validate_kdf(wire: &KdfWire, limits: &EnvelopeLimits) -> Result<Kdf, EnvelopeError> {
        let algorithm = KdfAlgorithm::from_wire_name(&wire.name).ok_or(EnvelopeError::Kdf)?;
        if algorithm != limits.kdf {
            return Err(EnvelopeError::Kdf);
        }
        match algorithm {
            KdfAlgorithm::Pbkdf2Sha256 => {
                if wire.iterations < limits.min_iterations
                    || wire.iterations > limits.max_iterations
                {
                    return Err(EnvelopeError::Iterations);
                }
                let salt = decode(&wire.salt).ok_or(EnvelopeError::Salt)?;
                if salt.len() != SALT_BYTES {
                    return Err(EnvelopeError::Salt);
                }
                Ok(Kdf::Pbkdf2Sha256 {
                    iterations: wire.iterations,
                    salt,
                })
            }
        }
    }

    fn validate_cipher(wire: &CipherWire) -> Result<Cipher, EnvelopeError> {
        match wire.name.as_str() {
            "AES-256-GCM" => {
                let iv = decode(&wire.iv).ok_or(EnvelopeError::Iv)?;
                if iv.len() != IV_BYTES {
                    return Err(EnvelopeError::Iv);
                }
                Ok(Cipher::Aes256Gcm { iv })
            }
            _ => Err(EnvelopeError::Cipher),
        }
    }

    pub fn to_wire(&self) -> EnvelopeWire {
        EnvelopeWire {
            version: self.version,
            kdf: KdfWire {
                name: self.kdf.algorithm().wire_name().to_owned(),
                iterations: self.kdf.work_factor(),
                salt: BASE64_NOPAD.encode(self.kdf.salt()),
            },
            cipher: CipherWire {
                name: self.cipher.wire_name().to_owned(),
                iv: BASE64_NOPAD.encode(self.cipher.iv()),
            },
            ciphertext: BASE64_NOPAD.encode(&self.ciphertext),
        }
    }

    /// Bytes held for this envelope's variable parts.
    pub fn resident_bytes(&self) -> usize {
        self.ciphertext.len() + self.kdf.salt().len() + self.cipher.iv().len()
    }
}

fn decode(s: &str) -> Option<Vec<u8>> {
    let trimmed = s.trim_end_matches('=');
    BASE64_NOPAD.decode(trimmed.as_bytes()).ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn limits() -> EnvelopeLimits {
        EnvelopeLimits {
            max_plaintext_bytes: 64,
            kdf: KdfAlgorithm::Pbkdf2Sha256,
            min_iterations: 1000,
            max_iterations: 10_000,
        }
    }

    fn good() -> EnvelopeWire {
        EnvelopeWire {
            version: 1,
            kdf: KdfWire {
                name: "PBKDF2-SHA256".into(),
                iterations: 5000,
                salt: BASE64_NOPAD.encode(&[1u8; 16]),
            },
            cipher: CipherWire {
                name: "AES-256-GCM".into(),
                iv: BASE64_NOPAD.encode(&[2u8; 12]),
            },
            ciphertext: BASE64_NOPAD.encode(&[3u8; 40]),
        }
    }

    #[test]
    fn accepts_a_conforming_envelope_and_round_trips() {
        let env = Envelope::validate(&good(), &limits()).unwrap();
        assert_eq!(env.ciphertext.len(), 40);
        let wire = env.to_wire();
        assert_eq!(wire.ciphertext, good().ciphertext);
        assert_eq!(wire.kdf.salt, good().kdf.salt);
    }

    #[test]
    fn accepts_padded_base64_too() {
        let mut w = good();
        w.ciphertext.push('=');
        assert!(Envelope::validate(&w, &limits()).is_ok());
    }

    #[test]
    fn rejects_each_deviation() {
        let l = limits();
        let mut w = good();
        w.version = 2;
        assert_eq!(
            Envelope::validate(&w, &l).unwrap_err(),
            EnvelopeError::Version
        );
        let mut w = good();
        w.kdf.name = "scrypt".into();
        assert_eq!(Envelope::validate(&w, &l).unwrap_err(), EnvelopeError::Kdf);
        let mut w = good();
        w.kdf.iterations = 10;
        assert_eq!(
            Envelope::validate(&w, &l).unwrap_err(),
            EnvelopeError::Iterations
        );
        let mut w = good();
        w.kdf.iterations = 1_000_000;
        assert_eq!(
            Envelope::validate(&w, &l).unwrap_err(),
            EnvelopeError::Iterations
        );
        let mut w = good();
        w.cipher.name = "AES-128-GCM".into();
        assert_eq!(
            Envelope::validate(&w, &l).unwrap_err(),
            EnvelopeError::Cipher
        );
        let mut w = good();
        w.kdf.salt = BASE64_NOPAD.encode(&[0u8; 8]);
        assert_eq!(Envelope::validate(&w, &l).unwrap_err(), EnvelopeError::Salt);
        let mut w = good();
        w.cipher.iv = "!!!".into();
        assert_eq!(Envelope::validate(&w, &l).unwrap_err(), EnvelopeError::Iv);
        let mut w = good();
        w.ciphertext = BASE64_NOPAD.encode(&[0u8; 4]);
        assert_eq!(
            Envelope::validate(&w, &l).unwrap_err(),
            EnvelopeError::Ciphertext
        );
        let mut w = good();
        w.ciphertext = BASE64_NOPAD.encode(&[0u8; 81]);
        assert_eq!(
            Envelope::validate(&w, &l).unwrap_err(),
            EnvelopeError::TooLarge
        );
    }

    #[test]
    fn body_limit_covers_the_largest_envelope() {
        let l = EnvelopeLimits {
            max_plaintext_bytes: 65536,
            kdf: KdfAlgorithm::Pbkdf2Sha256,
            min_iterations: 1,
            max_iterations: 1,
        };
        let biggest = BASE64_NOPAD.encode(&vec![0u8; l.max_ciphertext_bytes()]);
        assert!(biggest.len() + 4096 <= l.max_request_body_bytes());
    }
}
