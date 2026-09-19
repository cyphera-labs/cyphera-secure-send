//! The OpenID Connect relying party: discovery, the authorization-code flow
//! with PKCE, state, and nonce, ID token verification, and the mapping from
//! claims to a session. Tokens never reach the browser.

use openidconnect::core::{CoreAuthenticationFlow, CoreClient, CoreProviderMetadata};
use openidconnect::{
    AuthorizationCode, ClientId, ClientSecret, CsrfToken, EndpointMaybeSet, EndpointNotSet,
    EndpointSet, IssuerUrl, Nonce, OAuth2TokenResponse, PkceCodeChallenge, PkceCodeVerifier,
    RedirectUrl, Scope, TokenResponse,
};
use std::time::{Duration, Instant};
use tokio::sync::{Mutex, RwLock};
use url::Url;

use super::session::{CookieSpec, MemorySessionStore, PendingLogin, Session, SessionStore};
use crate::config::{EmailClaim, OidcSettings, UnverifiedEmail};
use crate::domain::{Email, MessageId};
use std::sync::Arc;

type Client = CoreClient<
    EndpointSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointNotSet,
    EndpointMaybeSet,
    EndpointMaybeSet,
>;

/// Everything needed to build the provider client again when its signing
/// keys change.
struct Rebuild {
    issuer: IssuerUrl,
    client_id: ClientId,
    client_secret: ClientSecret,
    redirect: RedirectUrl,
}

#[derive(Debug, thiserror::Error)]
pub enum OidcError {
    #[error("identity provider configuration: {0}")]
    Config(String),
    #[error("identity provider discovery failed: {0}")]
    Discovery(String),
    #[error("login could not be started")]
    Start,
    #[error("login state is unknown or expired")]
    UnknownState,
    #[error("token exchange failed: {0}")]
    Exchange(String),
    #[error("the provider returned no ID token")]
    NoIdToken,
    #[error("ID token rejected: {0}")]
    IdToken(String),
    #[error("the ID token carries no usable email claim")]
    NoEmail,
    #[error("the ID token does not say the address has been verified")]
    UnverifiedEmail,
    #[error("the email claim is not a valid address")]
    BadEmail,
    #[error("session could not be created")]
    Session,
}

/// How often the provider's signing keys may be fetched again. Rotation is
/// routine, so an unrecognised key must be recoverable; fetching on every
/// failure would let a stream of bad tokens drive traffic at the provider.
const MIN_KEY_REFRESH_INTERVAL: Duration = Duration::from_secs(60);

pub struct OidcProvider {
    /// Replaced when the provider rotates its signing keys, which it will do
    /// on its own schedule and sometimes without warning.
    client: RwLock<Client>,
    /// What it takes to build that client again.
    rebuild: Rebuild,
    /// When the keys were last fetched again, rather than when they were
    /// first read at startup: a provider that rotates a minute after this
    /// process started still has to be recoverable. Held across the fetch so
    /// concurrent failures produce one request rather than a burst.
    last_key_refresh: Mutex<Option<Instant>>,
    http: reqwest::Client,
    issuer: String,
    scopes: Vec<String>,
    email_claim: EmailClaim,
    unverified_email: UnverifiedEmail,
    pub sessions: Arc<dyn SessionStore>,
    pub cookies: CookieSpec,
    login_ttl: Duration,
}

impl OidcProvider {
    /// Runs discovery against the issuer. Fails fast at startup if the
    /// provider is unreachable or the configuration is inconsistent.
    pub async fn discover(
        settings: &OidcSettings,
        public_base_url: &str,
        secure_cookies: bool,
    ) -> Result<Self, OidcError> {
        let secret = settings
            .resolve_client_secret()
            .map_err(|e| OidcError::Config(e.to_string()))?;
        let mut builder = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(15));
        if let Some(path) = &settings.trust_ca_path {
            let pem = std::fs::read(path)
                .map_err(|e| OidcError::Config(format!("trust_ca_path {}: {e}", path.display())))?;
            for cert in reqwest::Certificate::from_pem_bundle(&pem)
                .map_err(|e| OidcError::Config(format!("trust_ca_path: {e}")))?
            {
                builder = builder.add_root_certificate(cert);
            }
        }
        let http = builder
            .build()
            .map_err(|e| OidcError::Config(e.to_string()))?;

        let issuer = IssuerUrl::new(settings.issuer.clone())
            .map_err(|e| OidcError::Config(e.to_string()))?;
        let redirect = RedirectUrl::new(format!(
            "{}/auth/callback",
            public_base_url.trim_end_matches('/')
        ))
        .map_err(|e| OidcError::Config(e.to_string()))?;
        let rebuild = Rebuild {
            issuer,
            client_id: ClientId::new(settings.client_id.clone()),
            client_secret: ClientSecret::new(secret),
            redirect,
        };
        let client = build_client(&rebuild, &http).await?;

        Ok(Self {
            client: RwLock::new(client),
            rebuild,
            last_key_refresh: Mutex::new(None),
            http,
            issuer: settings.issuer.clone(),
            scopes: settings.scopes.clone(),
            email_claim: settings.email_claim,
            unverified_email: settings.unverified_email,
            sessions: Arc::new(MemorySessionStore::new(
                Duration::from_secs(settings.session_ttl_seconds),
                Duration::from_secs(settings.login_ttl_seconds),
            )),
            cookies: CookieSpec {
                secure: secure_cookies,
            },
            login_ttl: Duration::from_secs(settings.login_ttl_seconds),
        })
    }

    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// Verifies the token against the keys currently held and reads the one
    /// claim the operator nominated.
    fn extract(
        &self,
        id_token: &openidconnect::core::CoreIdToken,
        nonce: &Nonce,
    ) -> Result<Claimed, OidcError> {
        let client = self
            .client
            .try_read()
            .map_err(|_| OidcError::IdToken("provider keys are being refreshed".to_owned()))?;
        let claims = id_token
            .claims(&client.id_token_verifier(), nonce)
            .map_err(|e| OidcError::IdToken(e.to_string()))?;

        // The configured claim, and only it. The account is identified by
        // issuer and subject; the address is a separate assertion about that
        // account, and authorization rests on it, so it is taken from the one
        // place the operator nominated.
        let address = match self.email_claim {
            EmailClaim::Email => {
                let verified = claims.email_verified();
                if verified == Some(false)
                    || (verified.is_none() && self.unverified_email == UnverifiedEmail::Refuse)
                {
                    return Err(OidcError::UnverifiedEmail);
                }
                claims.email().map(|e| e.as_str().to_owned())
            }
            EmailClaim::PreferredUsername => {
                claims.preferred_username().map(|u| u.as_str().to_owned())
            }
        }
        .ok_or(OidcError::NoEmail)?;

        Ok(Claimed {
            subject: claims.subject().as_str().to_owned(),
            address,
        })
    }

    /// Fetches the provider's keys again, at most once per interval, so a
    /// rotation recovers on the next sign-in instead of on the next restart.
    /// Restarting is a poor remedy here: it also discards every pending
    /// message.
    async fn refresh_keys(&self) -> Result<(), OidcError> {
        let mut last = self.last_key_refresh.lock().await;
        if last.is_some_and(|at| at.elapsed() < MIN_KEY_REFRESH_INTERVAL) {
            return Err(OidcError::IdToken(
                "signing key is not one the provider published, and its keys were fetched too recently to try again".to_owned(),
            ));
        }
        let client = build_client(&self.rebuild, &self.http).await?;
        *self.client.write().await = client;
        *last = Some(Instant::now());
        tracing::info!("refreshed the identity provider's signing keys");
        Ok(())
    }

    pub fn login_ttl(&self) -> Duration {
        self.login_ttl
    }

    /// Starts a login. Returns the provider URL to send the browser to and
    /// the state value to bind to the browser through a cookie.
    pub async fn begin_login(&self, next: String) -> Result<(Url, String), OidcError> {
        let (challenge, verifier) = PkceCodeChallenge::new_random_sha256();
        let client = self.client.read().await;
        let mut request = client
            .authorize_url(
                CoreAuthenticationFlow::AuthorizationCode,
                CsrfToken::new_random,
                Nonce::new_random,
            )
            .set_pkce_challenge(challenge);
        for scope in &self.scopes {
            if scope != "openid" {
                request = request.add_scope(Scope::new(scope.clone()));
            }
        }
        let (url, state, nonce) = request.url();
        drop(client);
        let state = state.secret().clone();
        self.sessions
            .start_login(
                state.clone(),
                PendingLogin {
                    pkce_verifier: verifier.secret().clone(),
                    nonce: nonce.secret().clone(),
                    next,
                },
            )
            .await;
        Ok((url, state))
    }

    /// Finishes a login: the state must match a pending login started by this
    /// browser, the code is exchanged with the PKCE verifier, and the ID token
    /// is verified including the nonce. Returns the session id, the session,
    /// and where the user was headed.
    pub async fn complete_login(
        &self,
        state: &str,
        code: &str,
    ) -> Result<(String, Session, String), OidcError> {
        let pending = self
            .sessions
            .take_login(state)
            .await
            .ok_or(OidcError::UnknownState)?;
        let token = {
            let client = self.client.read().await;
            client
                .exchange_code(AuthorizationCode::new(code.to_owned()))
                .map_err(|e| OidcError::Exchange(e.to_string()))?
                .set_pkce_verifier(PkceCodeVerifier::new(pending.pkce_verifier))
                .request_async(&self.http)
                .await
                .map_err(|e| OidcError::Exchange(e.to_string()))?
        };
        let id_token = token.id_token().ok_or(OidcError::NoIdToken)?;
        let nonce = Nonce::new(pending.nonce);

        // A provider rotates its signing keys on its own schedule, so a token
        // signed by a key published after this process started is expected,
        // not suspicious. Fetch the keys again and check it once more; every
        // other part of the verification still has to pass.
        let claimed = match self.extract(id_token, &nonce) {
            Ok(claimed) => claimed,
            Err(OidcError::IdToken(first)) => {
                tracing::info!(
                    reason = %first,
                    "an ID token did not verify; refreshing the provider's keys and retrying once"
                );
                self.refresh_keys().await?;
                self.extract(id_token, &nonce)?
            }
            Err(other) => return Err(other),
        };
        let _ = token.access_token();

        let email = Email::parse(&claimed.address).map_err(|_| OidcError::BadEmail)?;
        let subject = claimed.subject;

        let (id, session) = self
            .sessions
            .create(subject, email, self.issuer.clone())
            .await
            .map_err(|_| OidcError::Session)?;
        Ok((id, session, pending.next))
    }
}

async fn build_client(rebuild: &Rebuild, http: &reqwest::Client) -> Result<Client, OidcError> {
    let metadata = CoreProviderMetadata::discover_async(rebuild.issuer.clone(), http)
        .await
        .map_err(|e| OidcError::Discovery(e.to_string()))?;
    Ok(CoreClient::from_provider_metadata(
        metadata,
        rebuild.client_id.clone(),
        Some(rebuild.client_secret.clone()),
    )
    .set_redirect_uri(rebuild.redirect.clone()))
}

/// What a verified ID token said, owned so the client lock is not held while
/// the rest of the sign-in proceeds.
struct Claimed {
    subject: String,
    address: String,
}

/// Where a completed sign-in may send the browser. The service has three
/// pages, so this accepts those and nothing else rather than trying to judge
/// an arbitrary string: a check that merely rejects a leading `//` is fooled
/// by a control character between the slashes, which the browser's URL parser
/// then strips, turning `/\t/elsewhere.example` into another origin.
pub fn safe_next(raw: Option<&str>) -> String {
    const HOME: &str = "/";
    let Some(candidate) = raw else {
        return HOME.to_owned();
    };
    if candidate == HOME {
        return HOME.to_owned();
    }
    let Some((prefix, id)) = candidate.split_at_checked(3) else {
        return HOME.to_owned();
    };
    if (prefix == "/m/" || prefix == "/r/") && MessageId::parse(id).is_ok() {
        return candidate.to_owned();
    }
    HOME.to_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn next_accepts_this_service_and_nothing_else() {
        let id = MessageId::generate().unwrap().to_string();
        assert_eq!(safe_next(Some(&format!("/m/{id}"))), format!("/m/{id}"));
        assert_eq!(safe_next(Some(&format!("/r/{id}"))), format!("/r/{id}"));
        assert_eq!(safe_next(Some("/")), "/");
        assert_eq!(safe_next(None), "/");
    }

    #[test]
    fn next_refuses_anything_that_could_leave_this_origin() {
        let id = MessageId::generate().unwrap().to_string();
        for hostile in [
            "//evil.example",
            "/\t/evil.example",
            "/\n/evil.example",
            "/\r\n/evil.example",
            "/ /evil.example",
            "/\u{0000}/evil.example",
            "https://evil.example",
            "http://evil.example",
            "/\\evil.example",
            "\\evil.example",
            "/m/../../evil",
            &format!("/m/{id}?next=//evil.example"),
            &format!("/m/{id}#//evil.example"),
            &format!("/x/{id}"),
            "/m/short",
            "m/abc",
            "",
        ] {
            assert_eq!(safe_next(Some(hostile)), "/", "should refuse {hostile:?}");
        }
    }
}
