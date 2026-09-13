//! The versioned encryption envelope produced by the browser. The server
//! validates its shape strictly and stores it opaquely; it never decrypts.

use data_encoding::BASE64_NOPAD;
use serde::{Deserialize, Serialize};

pub const VERSION: u32 = 1;
pub const KDF_NAME: &str = "PBKDF2-SHA256";
pub const CIPHER_NAME: &str = "AES-256-GCM";
const SALT_BYTES: usize = 16;
const IV_BYTES: usize = 12;
const GCM_TAG_BYTES: usize = 16;

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
    pub iterations: u32,
    pub salt: Vec<u8>,
    pub iv: Vec<u8>,
    pub ciphertext: Vec<u8>,
}

impl Envelope {
    pub fn validate(wire: &EnvelopeWire, limits: &EnvelopeLimits) -> Result<Self, EnvelopeError> {
        if wire.version != VERSION {
            return Err(EnvelopeError::Version);
        }
        if wire.kdf.name != KDF_NAME {
            return Err(EnvelopeError::Kdf);
        }
        if wire.kdf.iterations < limits.min_iterations
            || wire.kdf.iterations > limits.max_iterations
        {
            return Err(EnvelopeError::Iterations);
        }
        if wire.cipher.name != CIPHER_NAME {
            return Err(EnvelopeError::Cipher);
        }
        let salt = decode(&wire.kdf.salt).ok_or(EnvelopeError::Salt)?;
        if salt.len() != SALT_BYTES {
            return Err(EnvelopeError::Salt);
        }
        let iv = decode(&wire.cipher.iv).ok_or(EnvelopeError::Iv)?;
        if iv.len() != IV_BYTES {
            return Err(EnvelopeError::Iv);
        }
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
            iterations: wire.kdf.iterations,
            salt,
            iv,
            ciphertext,
        })
    }

    pub fn to_wire(&self) -> EnvelopeWire {
        EnvelopeWire {
            version: VERSION,
            kdf: KdfWire {
                name: KDF_NAME.to_owned(),
                iterations: self.iterations,
                salt: BASE64_NOPAD.encode(&self.salt),
            },
            cipher: CipherWire {
                name: CIPHER_NAME.to_owned(),
                iv: BASE64_NOPAD.encode(&self.iv),
            },
            ciphertext: BASE64_NOPAD.encode(&self.ciphertext),
        }
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
            min_iterations: 1000,
            max_iterations: 10_000,
        }
    }

    fn good() -> EnvelopeWire {
        EnvelopeWire {
            version: 1,
            kdf: KdfWire {
                name: KDF_NAME.into(),
                iterations: 5000,
                salt: BASE64_NOPAD.encode(&[1u8; 16]),
            },
            cipher: CipherWire {
                name: CIPHER_NAME.into(),
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
            min_iterations: 1,
            max_iterations: 1,
        };
        let biggest = BASE64_NOPAD.encode(&vec![0u8; l.max_ciphertext_bytes()]);
        assert!(biggest.len() + 4096 <= l.max_request_body_bytes());
    }
}
