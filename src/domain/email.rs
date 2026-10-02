//! Syntax-level ("validish") email addresses. No DNS, no mailbox probing, no
//! external service. Domain is lowercased; the local part is left alone.

use std::fmt;

const MAX_TOTAL: usize = 254;
const MAX_LOCAL: usize = 64;
const MAX_LABEL: usize = 63;

#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum EmailError {
    #[error("email address is empty")]
    Empty,
    #[error("email address is too long")]
    TooLong,
    #[error("email address is not well-formed")]
    Malformed,
}

#[derive(Clone, PartialEq, Eq, Hash)]
pub struct Email(String);

impl Email {
    pub fn parse(raw: &str) -> Result<Self, EmailError> {
        let s = raw.trim();
        if s.is_empty() {
            return Err(EmailError::Empty);
        }
        if s.len() > MAX_TOTAL {
            return Err(EmailError::TooLong);
        }
        if s.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(EmailError::Malformed);
        }
        let (local, domain) = s.rsplit_once('@').ok_or(EmailError::Malformed)?;
        if local.is_empty() || local.len() > MAX_LOCAL || local.contains('@') {
            return Err(EmailError::Malformed);
        }
        if local.starts_with('.') || local.ends_with('.') || local.contains("..") {
            return Err(EmailError::Malformed);
        }
        if !local.chars().all(is_local_char) {
            return Err(EmailError::Malformed);
        }
        let domain = domain.to_ascii_lowercase();
        if !domain.contains('.') {
            return Err(EmailError::Malformed);
        }
        for label in domain.split('.') {
            if label.is_empty() || label.len() > MAX_LABEL {
                return Err(EmailError::Malformed);
            }
            if label.starts_with('-') || label.ends_with('-') {
                return Err(EmailError::Malformed);
            }
            if !label
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-')
            {
                return Err(EmailError::Malformed);
            }
        }
        Ok(Self(format!("{local}@{domain}")))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn domain(&self) -> &str {
        self.0.rsplit_once('@').map(|(_, d)| d).unwrap_or("")
    }
}

fn is_local_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || "!#$%&'*+-/=?^_`{|}~.".contains(c)
}

impl fmt::Display for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

impl fmt::Debug for Email {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Email({})", self.0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn accepts_ordinary_addresses_and_normalizes_domain() {
        let e = Email::parse("  Leslie@Example.COM ").unwrap();
        assert_eq!(e.as_str(), "Leslie@example.com");
        assert_eq!(e.domain(), "example.com");
        assert!(Email::parse("a.b+tag@sub.example.co.uk").is_ok());
        assert!(Email::parse("o'neil@example.org").is_ok());
    }

    #[test]
    fn rejects_bad_shapes() {
        for bad in [
            "",
            "   ",
            "plain",
            "@example.com",
            "a@",
            "a@localhost",
            "a@.com",
            "a@example..com",
            "a@-example.com",
            "a@example-.com",
            ".a@example.com",
            "a.@example.com",
            "a..b@example.com",
            "a b@example.com",
            "a@exa mple.com",
            "a@@example.com",
            "a\n@example.com",
            "a@exam_ple.com",
        ] {
            assert!(Email::parse(bad).is_err(), "should reject {bad:?}");
        }
        let long_local = format!("{}@example.com", "a".repeat(65));
        assert_eq!(Email::parse(&long_local), Err(EmailError::Malformed));
        let too_long = format!("{}@example.com", "a".repeat(250));
        assert_eq!(Email::parse(&too_long), Err(EmailError::TooLong));
    }
}
