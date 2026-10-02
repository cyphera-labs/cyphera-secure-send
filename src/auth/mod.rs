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

/// Enterprise mode. Two independent questions: who may create a handoff, and
/// what the recipient must prove to consume one. Closed on both unless
/// configured otherwise.
pub struct OidcAuthorizer {
    /// Creating requires a signed-in user.
    pub creation_requires_oidc: bool,
    /// The organization's own domains. Empty allows any.
    pub allowed_domains: Vec<String>,
    /// Consuming requires a signed-in user.
    pub recipient_requires_oidc: bool,
    /// The signed-in reader's address must equal the message's recipient.
    pub require_identity_match: bool,
    /// A recipient outside `allowed_domains` is acceptable.
    pub external_recipients: bool,
}

impl OidcAuthorizer {
    fn is_internal(&self, email: &Email) -> bool {
        self.allowed_domains.is_empty() || self.allowed_domains.iter().any(|d| d == email.domain())
    }

    /// May a message be addressed here? Internal always; external only when
    /// the deployment allows it.
    fn recipient_allowed(&self, recipient: &Email) -> bool {
        self.is_internal(recipient) || self.external_recipients
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
        if !self.recipient_allowed(recipient) {
            return Decision::Deny;
        }
        match &principal.email {
            None => {
                if self.creation_requires_oidc {
                    Decision::Deny
                } else {
                    Decision::Allow
                }
            }
            // The sender is the signed-in identity, and must be one of ours.
            Some(me) => {
                if same_address(me, sender) && self.is_internal(me) {
                    Decision::Allow
                } else {
                    Decision::Deny
                }
            }
        }
    }

    fn consume_policy(&self, principal: &RequestPrincipal) -> TakePolicy {
        match &principal.email {
            // Nobody signed in: acceptable only where reading does not
            // require it, and then possession of the link and the password is
            // the whole authority, exactly as in standard mode.
            None => {
                if self.recipient_requires_oidc {
                    TakePolicy::deny_all()
                } else {
                    TakePolicy::allow_any()
                }
            }
            Some(me) => {
                if self.require_identity_match {
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

    /// The internal-to-internal shape: sign in to send, sign in as the named
    /// recipient to read, nobody outside the domain.
    fn closed() -> OidcAuthorizer {
        OidcAuthorizer {
            creation_requires_oidc: true,
            allowed_domains: vec!["acme.com".into()],
            recipient_requires_oidc: true,
            require_identity_match: true,
            external_recipients: false,
        }
    }

    /// The handoff to a customer: an authenticated employee creates it, and
    /// the customer presents the link and the password.
    fn external_handoff() -> OidcAuthorizer {
        OidcAuthorizer {
            creation_requires_oidc: true,
            allowed_domains: vec!["acme.com".into()],
            recipient_requires_oidc: false,
            require_identity_match: false,
            external_recipients: true,
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
    fn the_sender_is_the_signed_in_user_and_must_be_ours() {
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
        // A typed sender that is not the signed-in user.
        assert_eq!(
            a.authorize_create(
                &p("alice@acme.com"),
                &e("mallory@acme.com"),
                &e("bob@acme.com")
            ),
            Decision::Deny
        );
        // Signed in, but not one of ours.
        assert_eq!(
            a.authorize_create(&p("eve@other.com"), &e("eve@other.com"), &e("bob@acme.com")),
            Decision::Deny
        );
    }

    #[test]
    fn an_outside_recipient_needs_the_deployment_to_allow_it() {
        let a = closed();
        assert_eq!(
            a.authorize_create(
                &p("alice@acme.com"),
                &e("alice@acme.com"),
                &e("cust@other.com")
            ),
            Decision::Deny
        );
        let a = external_handoff();
        assert_eq!(
            a.authorize_create(
                &p("alice@acme.com"),
                &e("alice@acme.com"),
                &e("cust@other.com")
            ),
            Decision::Allow
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
    }

    #[test]
    fn the_external_handoff_lets_the_customer_read_without_signing_in() {
        let a = external_handoff();
        // No session: the link and the password are the whole authority.
        assert!(
            a.consume_policy(&RequestPrincipal::anonymous())
                .permits(&e("cust@other.com"))
        );
        // Signing in anyway does not narrow it, because binding is off.
        assert!(
            a.consume_policy(&p("alice@acme.com"))
                .permits(&e("cust@other.com"))
        );
    }

    #[test]
    fn creation_can_be_opened_without_opening_consumption() {
        let a = OidcAuthorizer {
            creation_requires_oidc: false,
            ..closed()
        };
        assert_eq!(
            a.authorize_create(
                &RequestPrincipal::anonymous(),
                &e("a@acme.com"),
                &e("b@acme.com")
            ),
            Decision::Allow
        );
        assert!(
            !a.consume_policy(&RequestPrincipal::anonymous())
                .permits(&e("b@acme.com"))
        );
    }

    #[test]
    fn an_empty_domain_list_means_any_domain() {
        let a = OidcAuthorizer {
            allowed_domains: Vec::new(),
            ..closed()
        };
        assert_eq!(
            a.authorize_create(&p("alice@x.org"), &e("alice@x.org"), &e("bob@y.net")),
            Decision::Allow
        );
    }
}
