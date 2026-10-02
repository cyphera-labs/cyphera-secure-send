//! Property-based tests for the parsers that face untrusted input. None of
//! them may panic, and their acceptance must be stable under re-parsing.

use cyphera_secure_send::domain::envelope::{CipherWire, EnvelopeWire, KdfAlgorithm, KdfWire};
use cyphera_secure_send::domain::ids::Secret;
use cyphera_secure_send::domain::{Email, Envelope, EnvelopeLimits, MessageId, Verifier};
use proptest::prelude::*;

proptest! {
    #![proptest_config(ProptestConfig::with_cases(2000))]

    #[test]
    fn email_parse_never_panics_and_is_idempotent(s in "\\PC{0,300}") {
        if let Ok(e) = Email::parse(&s) {
            let again = Email::parse(e.as_str()).expect("normalized form must parse");
            prop_assert_eq!(again.as_str(), e.as_str());
            prop_assert!(e.as_str().len() <= 254);
            prop_assert!(e.as_str().contains('@'));
            prop_assert!(!e.as_str().chars().any(char::is_whitespace));
        }
    }

    #[test]
    fn email_domain_is_lowercased(local in "[a-z0-9]{1,20}", domain in "[A-Za-z0-9]{1,10}\\.[A-Za-z]{2,6}") {
        let e = Email::parse(&format!("{local}@{domain}")).unwrap();
        prop_assert_eq!(e.domain(), domain.to_ascii_lowercase());
    }

    #[test]
    fn message_id_parse_never_panics(s in "\\PC{0,64}") {
        let _ = MessageId::parse(&s);
    }

    #[test]
    fn message_id_accepts_only_its_own_output(bytes in proptest::array::uniform16(any::<u8>())) {
        let encoded = data_encoding::BASE32_NOPAD.encode(&bytes).to_ascii_lowercase();
        prop_assert!(MessageId::parse(&encoded).is_ok());
        prop_assert!(MessageId::parse(&encoded.to_ascii_uppercase()).is_err());
    }

    #[test]
    fn secret_and_verifier_parsing_never_panics(s in "\\PC{0,100}") {
        let _ = Secret::from_base64url(&s);
        let _ = Verifier::from_base64url(&s);
    }

    #[test]
    fn verifier_matches_only_its_secret(a in proptest::array::uniform32(any::<u8>()), b in proptest::array::uniform32(any::<u8>())) {
        let sa = Secret::from_base64url(&data_encoding::BASE64URL_NOPAD.encode(&a)).unwrap();
        let sb = Secret::from_base64url(&data_encoding::BASE64URL_NOPAD.encode(&b)).unwrap();
        prop_assert!(sa.hash().matches(&sa));
        prop_assert_eq!(sa.hash().matches(&sb), a == b);
    }

    #[test]
    fn envelope_validate_never_panics(
        version in any::<u32>(),
        kdf_name in "\\PC{0,20}",
        iterations in any::<u32>(),
        salt in "\\PC{0,40}",
        cipher_name in "\\PC{0,20}",
        iv in "\\PC{0,40}",
        ciphertext in "\\PC{0,200}",
    ) {
        let wire = EnvelopeWire {
            version,
            kdf: KdfWire { name: kdf_name, iterations, salt },
            cipher: CipherWire { name: cipher_name, iv },
            ciphertext,
        };
        let limits = EnvelopeLimits { max_plaintext_bytes: 64, kdf: KdfAlgorithm::Pbkdf2Sha256, min_iterations: 1000, max_iterations: 10_000 };
        let _ = Envelope::validate(&wire, &limits);
    }

    #[test]
    fn envelope_round_trips_through_wire(
        iterations in 1000u32..=10_000,
        salt in proptest::array::uniform16(any::<u8>()),
        iv in proptest::array::uniform12(any::<u8>()),
        ciphertext in proptest::collection::vec(any::<u8>(), 16..=80),
    ) {
        let limits = EnvelopeLimits { max_plaintext_bytes: 64, kdf: KdfAlgorithm::Pbkdf2Sha256, min_iterations: 1000, max_iterations: 10_000 };
        let wire = EnvelopeWire {
            version: 1,
            kdf: KdfWire { name: "PBKDF2-SHA256".into(), iterations, salt: data_encoding::BASE64_NOPAD.encode(&salt) },
            cipher: CipherWire { name: "AES-256-GCM".into(), iv: data_encoding::BASE64_NOPAD.encode(&iv) },
            ciphertext: data_encoding::BASE64_NOPAD.encode(&ciphertext),
        };
        let env = Envelope::validate(&wire, &limits).unwrap();
        prop_assert_eq!(&env.ciphertext, &ciphertext);
        let back = Envelope::validate(&env.to_wire(), &limits).unwrap();
        prop_assert_eq!(back.ciphertext, ciphertext);
        prop_assert_eq!(back.kdf.salt(), salt.as_slice());
        prop_assert_eq!(back.cipher.iv(), iv.as_slice());
    }
}
