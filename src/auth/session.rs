//! Server-side sessions, pending logins, and the cookies that reference them.
//! The browser holds only an opaque random id. The store is a trait so that a
//! multi-instance deployment can keep this state in a shared store; the
//! default keeps it in process memory with a lifetime.

use async_trait::async_trait;
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

/// Where sessions and pending logins live. Every operation is atomic with
/// respect to the others for the same key; `take_login` in particular must
/// remove and return in one step so a state value can only be used once.
#[async_trait]
pub trait SessionStore: Send + Sync {
    fn session_ttl(&self) -> Duration;
    async fn start_login(&self, state: String, pending: PendingLogin);
    /// Removes and returns the pending login: a state value works once.
    async fn take_login(&self, state: &str) -> Option<PendingLogin>;
    async fn create(
        &self,
        subject: String,
        email: Email,
        issuer: String,
    ) -> Result<(String, Session), ()>;
    async fn get(&self, id: &str) -> Option<Session>;
    async fn revoke(&self, id: &str);
    /// Ends every session held by one account, and returns how many. This
    /// is what makes "disable them at the provider" take effect now rather
    /// than when their sessions would have expired: the provider stops the
    /// next sign-in, this stops the current ones.
    async fn revoke_account(&self, account: &AccountRef) -> u64;
}

/// One account, as an operator would name it: by the stable subject the
/// provider issued, or by the address it carried. The address is a
/// convenience for the operator, who usually knows it and rarely knows the
/// subject; a match on either ends the session.
#[derive(Clone, Debug)]
pub struct AccountRef {
    pub subject: Option<String>,
    pub email: Option<Email>,
}

impl AccountRef {
    pub fn matches(&self, session: &Session) -> bool {
        let by_subject = self
            .subject
            .as_deref()
            .is_some_and(|s| s == session.subject);
        let by_email = self
            .email
            .as_ref()
            .is_some_and(|e| e.as_str().eq_ignore_ascii_case(session.email.as_str()));
        by_subject || by_email
    }
}

pub struct MemorySessionStore {
    sessions: Cache<String, Session>,
    pending: Cache<String, PendingLogin>,
    session_ttl: Duration,
}

impl MemorySessionStore {
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
}

#[async_trait]
impl SessionStore for MemorySessionStore {
    fn session_ttl(&self) -> Duration {
        self.session_ttl
    }

    async fn start_login(&self, state: String, pending: PendingLogin) {
        self.pending.insert(state, pending).await;
    }

    async fn take_login(&self, state: &str) -> Option<PendingLogin> {
        self.pending.remove(state).await
    }

    async fn create(
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

    async fn get(&self, id: &str) -> Option<Session> {
        let session = self.sessions.get(id).await?;
        if session.expires_at <= OffsetDateTime::now_utc() {
            self.sessions.remove(id).await;
            return None;
        }
        Some(session)
    }

    async fn revoke(&self, id: &str) {
        self.sessions.remove(id).await;
    }

    async fn revoke_account(&self, account: &AccountRef) -> u64 {
        let ids: Vec<String> = self
            .sessions
            .iter()
            .filter(|(_, session)| account.matches(session))
            .map(|(id, _)| id.as_ref().clone())
            .collect();
        for id in &ids {
            self.sessions.remove(id).await;
        }
        ids.len() as u64
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
        let store = MemorySessionStore::new(Duration::from_secs(60), Duration::from_secs(60));
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

    /// Ending an account's sessions ends all of them, and no one else's,
    /// whether the operator names the subject or the address.
    #[tokio::test]
    async fn revoking_an_account_ends_every_session_it_holds_and_no_others() {
        let store = MemorySessionStore::new(Duration::from_secs(60), Duration::from_secs(60));
        let alice = Email::parse("alice@example.com").unwrap();
        let bob = Email::parse("bob@example.com").unwrap();
        let (a1, _) = store
            .create("alice-sub".into(), alice.clone(), "iss".into())
            .await
            .unwrap();
        let (a2, _) = store
            .create("alice-sub".into(), alice.clone(), "iss".into())
            .await
            .unwrap();
        let (b1, _) = store
            .create("bob-sub".into(), bob, "iss".into())
            .await
            .unwrap();

        let ended = store
            .revoke_account(&AccountRef {
                subject: Some("alice-sub".into()),
                email: None,
            })
            .await;
        assert_eq!(ended, 2);
        assert!(store.get(&a1).await.is_none());
        assert!(store.get(&a2).await.is_none());
        assert!(store.get(&b1).await.is_some());

        // By address, case-insensitively, and nothing left to end afterwards.
        let (a3, _) = store
            .create("alice-sub".into(), alice, "iss".into())
            .await
            .unwrap();
        let ended = store
            .revoke_account(&AccountRef {
                subject: None,
                email: Some(Email::parse("ALICE@example.com").unwrap()),
            })
            .await;
        assert_eq!(ended, 1);
        assert!(store.get(&a3).await.is_none());
        assert_eq!(
            store
                .revoke_account(&AccountRef {
                    subject: Some("alice-sub".into()),
                    email: None
                })
                .await,
            0
        );
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
