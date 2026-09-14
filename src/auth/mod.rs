//! Who is calling, and whether they may. The message core never inspects
//! identity itself; it asks a `ConsumeAuthorizer`. Standalone mode uses the
//! anonymous authorizer; OIDC mode uses one that enforces closed access,
//! allowed domains, and recipient binding.

pub mod oidc;
pub mod session;

use crate::domain::Email;
use crate::storage::TakePolicy;

/// The caller as established by the request layer.
#[derive(Clone, Debug, Default)]
pub struct RequestPrincipal {
    /// Stable identifier from an identity provider, when authenticated.
    pub subject: Option<String>,
    /// Verified email claim, when authenticated.
    pub email: Option<Email>,
    pub issuer: Option<String>,
}

impl RequestPrincipal {
    pub fn anonymous() -> Self {
        Self::default()
    }

    pub fn is_authenticated(&self) -> bool {
        self.email.is_some()
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decision {
    Allow,
    Deny,
}

pub trait ConsumeAuthorizer: Send + Sync {
    /// May this principal create a message from `sender` to `recipient`?
    fn authorize_create(
        &self,
        principal: &RequestPrincipal,
        sender: &Email,
        recipient: &Email,
    ) -> Decision;
    /// What this principal may take. Decided before the store is touched and
    /// enforced inside the store's atomic step.
    fn consume_policy(&self, principal: &RequestPrincipal) -> TakePolicy;
}

/// Standalone mode: anyone with the link and the password.
pub struct AnonymousAuthorizer;

impl ConsumeAuthorizer for AnonymousAuthorizer {
    fn authorize_create(&self, _: &RequestPrincipal, _: &Email, _: &Email) -> Decision {
        Decision::Allow
    }

    fn consume_policy(&self, _: &RequestPrincipal) -> TakePolicy {
        TakePolicy::allow_any()
    }
}

/// Enterprise mode. Closed unless configured otherwise.
pub struct OidcAuthorizer {
    pub allowed_domains: Vec<String>,
    pub require_recipient_match: bool,
    pub anonymous_create: bool,
    pub anonymous_consume: bool,
}

impl OidcAuthorizer {
    fn domain_allowed(&self, email: &Email) -> bool {
        self.allowed_domains.is_empty() || self.allowed_domains.iter().any(|d| d == email.domain())
    }
}

fn same_address(a: &Email, b: &Email) -> bool {
    a.as_str().eq_ignore_ascii_case(b.as_str())
}

impl ConsumeAuthorizer for OidcAuthorizer {
    fn authorize_create(
        &self,
        principal: &RequestPrincipal,
        sender: &Email,
        recipient: &Email,
    ) -> Decision {
        match &principal.email {
            None => {
                if self.anonymous_create && self.domain_allowed(recipient) {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
            Some(me) => {
                if same_address(me, sender)
                    && self.domain_allowed(sender)
                    && self.domain_allowed(recipient)
                {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
    }

    fn consume_policy(&self, principal: &RequestPrincipal) -> TakePolicy {
        match &principal.email {
            None => {
                if self.anonymous_consume {
                    TakePolicy::allow_any()
                } else {
                    TakePolicy::deny_all()
                }
            }
            Some(me) => {
                if !self.domain_allowed(me) {
                    return TakePolicy::deny_all();
                }
                if self.require_recipient_match {
                    TakePolicy::only(me.clone())
                } else {
                    TakePolicy::allow_any()
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(email: &str) -> RequestPrincipal {
        RequestPrincipal {
            subject: Some("sub".into()),
            email: Some(Email::parse(email).unwrap()),
            issuer: Some("https://idp.example".into()),
        }
    }

    fn e(s: &str) -> Email {
        Email::parse(s).unwrap()
    }

    fn closed() -> OidcAuthorizer {
        OidcAuthorizer {
            allowed_domains: vec!["acme.com".into()],
            require_recipient_match: true,
            anonymous_create: false,
            anonymous_consume: false,
        }
    }

    #[test]
    fn closed_mode_denies_anonymous_everything() {
        let a = closed();
        assert_eq!(
            a.authorize_create(
                &RequestPrincipal::anonymous(),
                &e("a@acme.com"),
                &e("b@acme.com")
            ),
            Decision::Deny
        );
        assert!(
            !a.consume_policy(&RequestPrincipal::anonymous())
                .permits(&e("b@acme.com"))
        );
    }

    #[test]
    fn sender_must_be_the_signed_in_user_and_domains_must_match() {
        let a = closed();
        assert_eq!(
            a.authorize_create(
                &p("alice@acme.com"),
                &e("alice@acme.com"),
                &e("bob@acme.com")
            ),
            Decision::Allow
        );
        assert_eq!(
            a.authorize_create(
                &p("Alice@ACME.com"),
                &e("alice@acme.com"),
                &e("bob@acme.com")
            ),
            Decision::Allow
        );
        assert_eq!(
            a.authorize_create(
                &p("alice@acme.com"),
                &e("mallory@acme.com"),
                &e("bob@acme.com")
            ),
            Decision::Deny
        );
        assert_eq!(
            a.authorize_create(
                &p("alice@acme.com"),
                &e("alice@acme.com"),
                &e("bob@other.com")
            ),
            Decision::Deny
        );
        assert_eq!(
            a.authorize_create(
                &p("alice@other.com"),
                &e("alice@other.com"),
                &e("bob@acme.com")
            ),
            Decision::Deny
        );
    }

    #[test]
    fn recipient_binding_admits_only_the_named_reader() {
        let a = closed();
        assert!(
            a.consume_policy(&p("bob@acme.com"))
                .permits(&e("bob@acme.com"))
        );
        assert!(
            a.consume_policy(&p("Bob@acme.com"))
                .permits(&e("bob@acme.com"))
        );
        assert!(
            !a.consume_policy(&p("carol@acme.com"))
                .permits(&e("bob@acme.com"))
        );
        let mut open = closed();
        open.require_recipient_match = false;
        assert!(
            open.consume_policy(&p("carol@acme.com"))
                .permits(&e("bob@acme.com"))
        );
        assert!(
            !open
                .consume_policy(&p("carol@other.com"))
                .permits(&e("bob@acme.com"))
        );
    }

    #[test]
    fn opening_anonymous_paths_is_explicit() {
        let mut a = closed();
        a.anonymous_consume = true;
        assert!(
            a.consume_policy(&RequestPrincipal::anonymous())
                .permits(&e("bob@acme.com"))
        );
        a.anonymous_create = true;
        assert_eq!(
            a.authorize_create(
                &RequestPrincipal::anonymous(),
                &e("x@any.com"),
                &e("bob@acme.com")
            ),
            Decision::Allow
        );
        assert_eq!(
            a.authorize_create(
                &RequestPrincipal::anonymous(),
                &e("x@any.com"),
                &e("bob@other.com")
            ),
            Decision::Deny
        );
    }

    #[test]
    fn empty_domain_list_means_any_domain() {
        let mut a = closed();
        a.allowed_domains.clear();
        assert_eq!(
            a.authorize_create(&p("alice@x.org"), &e("alice@x.org"), &e("bob@y.net")),
            Decision::Allow
        );
    }
}
