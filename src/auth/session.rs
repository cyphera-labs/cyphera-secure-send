//! Server-side sessions and the cookies that reference them. Sessions live in
//! memory with a lifetime; the browser holds only an opaque random id.

use moka::future::Cache;
use std::time::Duration;
use time::OffsetDateTime;

use crate::domain::Email;
use crate::domain::ids::Secret;

#[derive(Clone, Debug)]
pub struct Session {
    pub subject: String,
    pub email: Email,
    pub issuer: String,
    pub expires_at: OffsetDateTime,
}

/// A login that has been started but not completed: what the callback needs
/// to finish it, keyed by the `state` value the provider echoes back.
#[derive(Clone, Debug)]
pub struct PendingLogin {
    pub pkce_verifier: String,
    pub nonce: String,
    pub next: String,
}

pub struct SessionStore {
    sessions: Cache<String, Session>,
    pending: Cache<String, PendingLogin>,
    session_ttl: Duration,
}

impl SessionStore {
    pub fn new(session_ttl: Duration, login_ttl: Duration) -> Self {
        Self {
            sessions: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(session_ttl)
                .build(),
            pending: Cache::builder()
                .max_capacity(100_000)
                .time_to_live(login_ttl)
                .build(),
            session_ttl,
        }
    }

    pub fn session_ttl(&self) -> Duration {
        self.session_ttl
    }

    pub async fn start_login(&self, state: String, pending: PendingLogin) {
        self.pending.insert(state, pending).await;
    }

    /// Removes and returns the pending login: a state value works once.
    pub async fn take_login(&self, state: &str) -> Option<PendingLogin> {
        self.pending.remove(state).await
    }

    pub async fn create(
        &self,
        subject: String,
        email: Email,
        issuer: String,
    ) -> Result<(String, Session), ()> {
        let id = Secret::generate().map_err(|_| ())?.to_base64url();
        let session = Session {
            subject,
            email,
            issuer,
            expires_at: OffsetDateTime::now_utc()
                + time::Duration::seconds(self.session_ttl.as_secs() as i64),
        };
        self.sessions.insert(id.clone(), session.clone()).await;
        Ok((id, session))
    }

    pub async fn get(&self, id: &str) -> Option<Session> {
        let session = self.sessions.get(id).await?;
        if session.expires_at <= OffsetDateTime::now_utc() {
            self.sessions.remove(id).await;
            return None;
        }
        Some(session)
    }

    pub async fn revoke(&self, id: &str) {
        self.sessions.remove(id).await;
    }
}

/// Cookie naming and attributes. Under HTTPS the `__Host-` prefix pins the
/// cookie to this host and path and requires Secure; over plain HTTP (local
/// development only) the prefix would make browsers reject the cookie.
#[derive(Clone, Debug)]
pub struct CookieSpec {
    pub secure: bool,
}

impl CookieSpec {
    pub fn session_name(&self) -> &'static str {
        if self.secure {
            "__Host-securesend_session"
        } else {
            "securesend_session"
        }
    }

    pub fn login_name(&self) -> &'static str {
        if self.secure {
            "__Host-securesend_login"
        } else {
            "securesend_login"
        }
    }

    fn build(
        &self,
        name: &'static str,
        value: String,
        max_age: Duration,
    ) -> axum_extra::extract::cookie::Cookie<'static> {
        let mut c = axum_extra::extract::cookie::Cookie::new(name, value);
        c.set_path("/");
        c.set_http_only(true);
        c.set_secure(self.secure);
        c.set_same_site(axum_extra::extract::cookie::SameSite::Lax);
        c.set_max_age(time::Duration::seconds(max_age.as_secs() as i64));
        c
    }

    pub fn session(
        &self,
        id: String,
        ttl: Duration,
    ) -> axum_extra::extract::cookie::Cookie<'static> {
        self.build(self.session_name(), id, ttl)
    }

    pub fn login(
        &self,
        state: String,
        ttl: Duration,
    ) -> axum_extra::extract::cookie::Cookie<'static> {
        self.build(self.login_name(), state, ttl)
    }

    pub fn removal(&self, name: &'static str) -> axum_extra::extract::cookie::Cookie<'static> {
        let mut c = self.build(name, String::new(), Duration::from_secs(0));
        c.make_removal();
        c.set_path("/");
        c
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn pending_logins_are_single_use_and_sessions_round_trip() {
        let store = SessionStore::new(Duration::from_secs(60), Duration::from_secs(60));
        store
            .start_login(
                "st".into(),
                PendingLogin {
                    pkce_verifier: "v".into(),
                    nonce: "n".into(),
                    next: "/".into(),
                },
            )
            .await;
        assert!(store.take_login("st").await.is_some());
        assert!(store.take_login("st").await.is_none());
        let (id, s) = store
            .create("sub".into(), Email::parse("a@b.co").unwrap(), "iss".into())
            .await
            .unwrap();
        assert_eq!(id.len(), 43);
        assert_eq!(
            store.get(&id).await.unwrap().email.as_str(),
            s.email.as_str()
        );
        store.revoke(&id).await;
        assert!(store.get(&id).await.is_none());
    }

    #[test]
    fn cookie_names_follow_the_scheme() {
        assert_eq!(
            CookieSpec { secure: true }.session_name(),
            "__Host-securesend_session"
        );
        assert_eq!(
            CookieSpec { secure: false }.session_name(),
            "securesend_session"
        );
        let c = CookieSpec { secure: true }.session("x".into(), Duration::from_secs(10));
        assert_eq!(c.secure(), Some(true));
        assert_eq!(c.http_only(), Some(true));
        assert_eq!(c.path(), Some("/"));
    }
}
