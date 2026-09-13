//! Who is calling, and whether they may. The message core never inspects
//! identity itself; it asks a `ConsumeAuthorizer`. The standalone build ships
//! only the anonymous authorizer, so recipient binding and identity providers
//! can be added without touching the lifecycle code.

use crate::domain::Email;

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
    /// May this principal consume a message addressed to `recipient`?
    fn authorize_consume(&self, principal: &RequestPrincipal, recipient: &Email) -> Decision;
}

/// Standalone mode: anyone with the link and the password.
pub struct AnonymousAuthorizer;

impl ConsumeAuthorizer for AnonymousAuthorizer {
    fn authorize_create(&self, _: &RequestPrincipal, _: &Email, _: &Email) -> Decision {
        Decision::Allow
    }

    fn authorize_consume(&self, _: &RequestPrincipal, _: &Email) -> Decision {
        Decision::Allow
    }
}
