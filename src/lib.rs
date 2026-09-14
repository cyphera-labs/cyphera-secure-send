//! Cyphera SecureSend: one-time secret handoff for controlled environments.
//!
//! The browser encrypts; the server holds ciphertext in memory and hands it
//! over exactly once. See `docs/security-model.md` for the protocol.

pub mod api;
pub mod application;
pub mod audit;
pub mod auth;
pub mod config;
pub mod domain;
pub mod storage;

use std::sync::Arc;

use api::branding::{AssetError, BrandingAssets};
use api::ratelimit::Limiters;
use api::{AppState, SharedState};
use application::{MessageLimits, MessageService};
use audit::{AuditSink, DiscardSink, StdoutJsonSink};
use auth::oidc::{OidcError, OidcProvider};
use auth::{AnonymousAuthorizer, ConsumeAuthorizer, OidcAuthorizer};
use config::{AuditSinkKind, AuthMode, Settings, StorageBackend};
use domain::EnvelopeLimits;
use storage::MessageStore;
use storage::memory::MemoryStore;

#[derive(Debug, thiserror::Error)]
pub enum BuildError {
    #[error(transparent)]
    Asset(#[from] AssetError),
    #[error(transparent)]
    Oidc(#[from] OidcError),
}

/// Everything the listeners need, wired from settings. `audit_override`
/// lets tests capture events.
pub async fn build_state(
    settings: Settings,
    audit_override: Option<Arc<dyn AuditSink>>,
) -> Result<SharedState, BuildError> {
    let audit: Arc<dyn AuditSink> = match audit_override {
        Some(sink) => sink,
        None => match settings.audit.sink {
            AuditSinkKind::Stdout => Arc::new(StdoutJsonSink::new()),
            AuditSinkKind::Discard => Arc::new(DiscardSink),
        },
    };

    let store: Arc<dyn MessageStore> = match settings.storage.backend {
        StorageBackend::Memory => Arc::new(MemoryStore::new(
            settings.messages.memory_budget_bytes,
            settings.messages.max_failed_proofs,
            audit.clone(),
        )),
    };

    let (authorizer, oidc): (Arc<dyn ConsumeAuthorizer>, Option<Arc<OidcProvider>>) =
        match settings.auth.mode {
            AuthMode::Anonymous => (Arc::new(AnonymousAuthorizer), None),
            AuthMode::Oidc => {
                let o = &settings.auth.oidc;
                let base = settings
                    .server
                    .public_base_url
                    .as_deref()
                    .unwrap_or_default();
                let provider = OidcProvider::discover(o, base, settings.public_https()).await?;
                let authorizer = OidcAuthorizer {
                    allowed_domains: o.allowed_domains.clone(),
                    require_recipient_match: o.require_recipient_match,
                    anonymous_create: o.anonymous_create,
                    anonymous_consume: o.anonymous_consume,
                };
                (Arc::new(authorizer), Some(Arc::new(provider)))
            }
        };

    let limits = MessageLimits {
        min_ttl_seconds: settings.messages.min_ttl_seconds,
        max_ttl_seconds: settings.messages.max_ttl_seconds,
        envelope: EnvelopeLimits {
            max_plaintext_bytes: settings.messages.max_plaintext_bytes,
            min_iterations: settings.messages.kdf.min_iterations,
            max_iterations: settings.messages.kdf.max_iterations,
        },
    };

    let service = MessageService::new(store, authorizer, audit.clone(), limits);
    let limiters = Limiters::new(&settings.rate_limits);
    let branding = BrandingAssets::load(&settings.branding)?;

    Ok(Arc::new(AppState {
        settings,
        service,
        audit,
        limiters,
        branding,
        oidc,
    }))
}
