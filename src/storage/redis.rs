//! Shared store on Redis, for deployments that run more than one replica or
//! want messages to outlive a restart of the service.
//!
//! Every operation that decides something is one Lua script, so it runs
//! atomically on the server: the take verifies, counts, and removes in one
//! step exactly as the memory store does inside its cache, and two replicas
//! racing for the same message still produce one winner. The policy travels
//! into the script as plain arguments, which is what it was shaped for.
//!
//! What is stored: one hash per message holding the serialised record and,
//! beside it, the few fields the scripts read directly (verifier, revoke
//! token hash, recipient, failed count, weight), a sorted set of ids by
//! expiry for counting and reaping, and a byte counter for the budget. Keys
//! carry the message's expiry, so Redis removes them on time by itself.
//!
//! Not for Redis Cluster: the scripts touch keys under one prefix that are
//! not guaranteed to share a slot. A single instance, a replicated pair, or
//! a managed service in that shape is the intended target.

use async_trait::async_trait;
use redis::aio::ConnectionManager;
use redis::{AsyncCommands, Script};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use time::OffsetDateTime;

use super::record::MessageRecord;
use super::{MessageStore, RevokeOutcome, StoreError, StoreStats, TakeOutcome, TakePolicy};
use crate::audit::{AuditEvent, AuditEventType, AuditSink};
use crate::auth::session::{AccountRef, PendingLogin, Session, SessionStore};
use crate::domain::ids::Secret;
use crate::domain::{Email, MessageId, Proof, RevokeToken, StoredMessage, Verifier};

/// How many expired entries one housekeeping pass reaps from the index.
const REAP_BATCH: isize = 1000;

fn unavailable(e: redis::RedisError) -> StoreError {
    StoreError::Unavailable(e.to_string())
}

/// One connection to Redis, shared by the message store and the session
/// store, reconnecting on its own when the link drops.
#[derive(Clone)]
pub struct RedisConnection {
    manager: ConnectionManager,
    prefix: String,
}

impl RedisConnection {
    /// Connects and checks the server answers. Fails at startup rather than
    /// on the first request, so a wrong URL is a wrong configuration, not a
    /// mystery later.
    pub async fn connect(
        url: &str,
        key_prefix: &str,
        connect_timeout: Duration,
    ) -> Result<Self, StoreError> {
        let client = redis::Client::open(url).map_err(unavailable)?;
        let config = redis::aio::ConnectionManagerConfig::new()
            .set_connection_timeout(Some(connect_timeout))
            .set_response_timeout(Some(connect_timeout));
        let manager = tokio::time::timeout(
            connect_timeout,
            ConnectionManager::new_with_config(client, config),
        )
        .await
        .map_err(|_| StoreError::Unavailable("connecting to redis timed out".to_owned()))?
        .map_err(unavailable)?;
        let mut conn = manager.clone();
        let pong: String = redis::cmd("PING")
            .query_async(&mut conn)
            .await
            .map_err(unavailable)?;
        if pong != "PONG" {
            return Err(StoreError::Unavailable(format!(
                "redis answered {pong:?} to PING"
            )));
        }
        Ok(Self {
            manager,
            prefix: key_prefix.to_owned(),
        })
    }

    fn key(&self, kind: &str, id: &str) -> String {
        format!("{}:{kind}:{id}", self.prefix)
    }
}

// ---------------------------------------------------------------- messages

pub struct RedisStore {
    conn: RedisConnection,
    budget_bytes: u64,
    max_failed_proofs: u32,
    audit: Arc<dyn AuditSink>,
    /// Counted by this process's own housekeeping; each replica reaps and
    /// counts what it happened to reap.
    expired: AtomicU64,
    put: Script,
    take: Script,
    revoke: Script,
    reap: Script,
}

// KEYS: message, index, bytes
// ARGV: budget, weight, expires_ms, record, verifier, revoke, recipient, recipient_display, member
const PUT: &str = r#"
local used = tonumber(redis.call('GET', KEYS[3]) or '0')
if used + tonumber(ARGV[2]) > tonumber(ARGV[1]) then return 'full' end
if redis.call('EXISTS', KEYS[1]) == 1 then return 'exists' end
redis.call('HSET', KEYS[1],
  'record', ARGV[4], 'verifier', ARGV[5], 'revoke', ARGV[6],
  'recipient', ARGV[7], 'recipient_display', ARGV[8],
  'failed', '0', 'weight', ARGV[2])
redis.call('PEXPIREAT', KEYS[1], ARGV[3])
redis.call('ZADD', KEYS[2], ARGV[3], ARGV[9])
redis.call('INCRBY', KEYS[3], ARGV[2])
return 'ok'
"#;

// KEYS: message, index, bytes
// ARGV: proof_hash, deny, expected_recipient, max_failed, id
const TAKE: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return {'missing'} end
local recipient = redis.call('HGET', KEYS[1], 'recipient')
if ARGV[2] == '1' or (ARGV[3] ~= '' and recipient ~= ARGV[3]) then
  return {'denied', redis.call('HGET', KEYS[1], 'recipient_display')}
end
local w = redis.call('HGET', KEYS[1], 'weight')
if redis.call('HGET', KEYS[1], 'verifier') == ARGV[1] then
  local record = redis.call('HGET', KEYS[1], 'record')
  local failed = redis.call('HGET', KEYS[1], 'failed')
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[5] .. ':' .. w)
  redis.call('DECRBY', KEYS[3], w)
  return {'taken', record, failed}
end
local failed = redis.call('HINCRBY', KEYS[1], 'failed', 1)
if failed >= tonumber(ARGV[4]) then
  redis.call('DEL', KEYS[1])
  redis.call('ZREM', KEYS[2], ARGV[5] .. ':' .. w)
  redis.call('DECRBY', KEYS[3], w)
  return {'burned', tostring(failed)}
end
return {'wrong', tostring(failed)}
"#;

// KEYS: message, index, bytes
// ARGV: token_hash, id
const REVOKE: &str = r#"
if redis.call('EXISTS', KEYS[1]) == 0 then return 'missing' end
if redis.call('HGET', KEYS[1], 'revoke') ~= ARGV[1] then return 'wrong' end
local w = redis.call('HGET', KEYS[1], 'weight')
redis.call('DEL', KEYS[1])
redis.call('ZREM', KEYS[2], ARGV[2] .. ':' .. w)
redis.call('DECRBY', KEYS[3], w)
return 'revoked'
"#;

// Removes index entries whose message has expired, settling the byte
// counter for each, and returns their ids so they can be audited.
// KEYS: index, bytes
// ARGV: now_ms, batch, message_key_prefix
const REAP: &str = r#"
local due = redis.call('ZRANGEBYSCORE', KEYS[1], '-inf', ARGV[1], 'LIMIT', 0, ARGV[2])
local reaped = {}
for _, member in ipairs(due) do
  local sep = string.find(member, ':', 1, true)
  local id = string.sub(member, 1, sep - 1)
  local w = string.sub(member, sep + 1)
  if redis.call('EXISTS', ARGV[3] .. id) == 0 then
    if redis.call('ZREM', KEYS[1], member) == 1 then
      redis.call('DECRBY', KEYS[2], w)
      table.insert(reaped, id)
    end
  end
end
return reaped
"#;

impl RedisStore {
    pub fn new(
        conn: RedisConnection,
        budget_bytes: u64,
        max_failed_proofs: u32,
        audit: Arc<dyn AuditSink>,
    ) -> Self {
        Self {
            conn,
            budget_bytes,
            max_failed_proofs,
            audit,
            expired: AtomicU64::new(0),
            put: Script::new(PUT),
            take: Script::new(TAKE),
            revoke: Script::new(REVOKE),
            reap: Script::new(REAP),
        }
    }

    fn message_key(&self, id: &MessageId) -> String {
        self.conn.key("m", id.as_str())
    }

    fn index_key(&self) -> String {
        format!("{}:idx", self.conn.prefix)
    }

    fn bytes_key(&self) -> String {
        format!("{}:bytes", self.conn.prefix)
    }

    /// Reaps expired index entries and audits each, as the memory store's
    /// eviction listener does at the moment of expiry. Redis removed the
    /// message itself on time; this is the bookkeeping that follows.
    async fn reap(&self) -> Result<(), StoreError> {
        let now_ms = OffsetDateTime::now_utc().unix_timestamp_nanos() / 1_000_000;
        let mut conn = self.conn.manager.clone();
        let reaped: Vec<String> = self
            .reap
            .key(self.index_key())
            .key(self.bytes_key())
            .arg(now_ms as i64)
            .arg(REAP_BATCH)
            .arg(self.conn.key("m", ""))
            .invoke_async(&mut conn)
            .await
            .map_err(unavailable)?;
        for id in reaped {
            self.expired.fetch_add(1, Ordering::Relaxed);
            metrics::counter!("securesend_messages_expired_total").increment(1);
            if let Ok(id) = MessageId::parse(&id) {
                self.audit
                    .emit(AuditEvent::success(AuditEventType::MessageExpired).with_message(&id));
            }
        }
        Ok(())
    }
}

#[async_trait]
impl MessageStore for RedisStore {
    async fn put(&self, message: StoredMessage) -> Result<(), StoreError> {
        let weight = u64::from(message.weight());
        let expires_ms = message.expires_at.unix_timestamp_nanos() / 1_000_000;
        let record = MessageRecord::from_message(&message).to_json();
        let mut conn = self.conn.manager.clone();
        let outcome: String = self
            .put
            .key(self.message_key(&message.id))
            .key(self.index_key())
            .key(self.bytes_key())
            .arg(self.budget_bytes)
            .arg(weight)
            .arg(expires_ms as i64)
            .arg(record)
            .arg(message.verifier.to_base64url())
            .arg(message.revoke_token_hash.to_base64url())
            .arg(message.recipient.as_str().to_ascii_lowercase())
            .arg(message.recipient.as_str())
            .arg(format!("{}:{weight}", message.id.as_str()))
            .invoke_async(&mut conn)
            .await
            .map_err(unavailable)?;
        match outcome.as_str() {
            "ok" => Ok(()),
            "full" => Err(StoreError::Full),
            other => Err(StoreError::Unavailable(format!(
                "unexpected answer storing a message: {other}"
            ))),
        }
    }

    async fn take(
        &self,
        id: &MessageId,
        proof: &Proof,
        policy: &TakePolicy,
    ) -> Result<TakeOutcome, StoreError> {
        let mut conn = self.conn.manager.clone();
        let answer: Vec<String> = self
            .take
            .key(self.message_key(id))
            .key(self.index_key())
            .key(self.bytes_key())
            .arg(proof.hash().to_base64url())
            .arg(if policy.deny { "1" } else { "0" })
            .arg(
                policy
                    .expected_recipient
                    .as_ref()
                    .map(|e| e.as_str().to_ascii_lowercase())
                    .unwrap_or_default(),
            )
            .arg(self.max_failed_proofs)
            .arg(id.as_str())
            .invoke_async(&mut conn)
            .await
            .map_err(unavailable)?;
        let mut parts = answer.into_iter();
        let kind = parts.next().unwrap_or_default();
        let malformed = || StoreError::Unavailable("malformed answer from the store".to_owned());
        match kind.as_str() {
            "taken" => {
                let record = parts.next().ok_or_else(malformed)?;
                let failed: u32 = parts
                    .next()
                    .and_then(|f| f.parse().ok())
                    .ok_or_else(malformed)?;
                let mut message = MessageRecord::from_json(&record)
                    .and_then(MessageRecord::into_message)
                    .map_err(|e| StoreError::Unavailable(e.to_string()))?;
                message.failed_proofs = failed;
                Ok(TakeOutcome::Taken(Box::new(message)))
            }
            "denied" => {
                // The same work a miss costs, so a probe cannot tell them apart.
                Verifier::dummy().matches(proof);
                let recipient = parts
                    .next()
                    .and_then(|r| Email::parse(&r).ok())
                    .ok_or_else(malformed)?;
                Ok(TakeOutcome::Denied { recipient })
            }
            "missing" => {
                Verifier::dummy().matches(proof);
                Ok(TakeOutcome::Missing)
            }
            "wrong" | "burned" => {
                let failed_proofs: u32 = parts
                    .next()
                    .and_then(|f| f.parse().ok())
                    .ok_or_else(malformed)?;
                Ok(if kind == "wrong" {
                    TakeOutcome::WrongProof { failed_proofs }
                } else {
                    TakeOutcome::Burned { failed_proofs }
                })
            }
            _ => Err(malformed()),
        }
    }

    async fn revoke(
        &self,
        id: &MessageId,
        token: &RevokeToken,
    ) -> Result<RevokeOutcome, StoreError> {
        let mut conn = self.conn.manager.clone();
        let answer: String = self
            .revoke
            .key(self.message_key(id))
            .key(self.index_key())
            .key(self.bytes_key())
            .arg(token.hash().to_base64url())
            .arg(id.as_str())
            .invoke_async(&mut conn)
            .await
            .map_err(unavailable)?;
        Ok(match answer.as_str() {
            "revoked" => RevokeOutcome::Revoked,
            "wrong" => RevokeOutcome::WrongToken,
            _ => {
                Verifier::dummy().matches(token);
                RevokeOutcome::Missing
            }
        })
    }

    async fn stats(&self) -> Result<StoreStats, StoreError> {
        self.reap().await?;
        let mut conn = self.conn.manager.clone();
        let active: u64 = conn.zcard(self.index_key()).await.map_err(unavailable)?;
        let used: Option<i64> = conn.get(self.bytes_key()).await.map_err(unavailable)?;
        Ok(StoreStats {
            active_messages: active,
            weighted_bytes: used.unwrap_or(0).max(0) as u64,
            budget_bytes: self.budget_bytes,
            expired_total: self.expired.load(Ordering::Relaxed),
            evicted_total: 0,
        })
    }

    fn backend_name(&self) -> &'static str {
        "redis"
    }
}

// ---------------------------------------------------------------- sessions

/// Sessions and pending logins in the same Redis, so any replica can finish
/// a sign-in another started, and a session survives a restart.
pub struct RedisSessionStore {
    conn: RedisConnection,
    session_ttl: Duration,
    login_ttl: Duration,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct SessionRecord {
    subject: String,
    email: String,
    issuer: String,
    expires_at: String,
}

#[derive(serde::Serialize, serde::Deserialize)]
struct PendingRecord {
    pkce_verifier: String,
    nonce: String,
    next: String,
}

impl RedisSessionStore {
    pub fn new(conn: RedisConnection, session_ttl: Duration, login_ttl: Duration) -> Self {
        Self {
            conn,
            session_ttl,
            login_ttl,
        }
    }

    fn by_subject(&self, subject: &str) -> String {
        self.conn.key("acct:sub", subject)
    }

    fn by_email(&self, email: &Email) -> String {
        self.conn
            .key("acct:email", &email.as_str().to_ascii_lowercase())
    }

    async fn end_sessions(&self, ids: Vec<String>) -> Result<u64, StoreError> {
        let mut conn = self.conn.manager.clone();
        let mut ended = 0;
        for id in ids {
            let removed: u64 = conn
                .del(self.conn.key("sess", &id))
                .await
                .map_err(unavailable)?;
            ended += removed;
        }
        Ok(ended)
    }
}

#[async_trait]
impl SessionStore for RedisSessionStore {
    fn session_ttl(&self) -> Duration {
        self.session_ttl
    }

    async fn start_login(&self, state: String, pending: PendingLogin) -> Result<(), StoreError> {
        let record = serde_json::to_string(&PendingRecord {
            pkce_verifier: pending.pkce_verifier,
            nonce: pending.nonce,
            next: pending.next,
        })
        .unwrap_or_default();
        let mut conn = self.conn.manager.clone();
        let _: () = conn
            .set_ex(
                self.conn.key("login", &state),
                record,
                self.login_ttl.as_secs().max(1),
            )
            .await
            .map_err(unavailable)?;
        Ok(())
    }

    async fn take_login(&self, state: &str) -> Result<Option<PendingLogin>, StoreError> {
        let mut conn = self.conn.manager.clone();
        // GETDEL: read and remove in one step, so a state value works once
        // however many replicas see the callback.
        let raw: Option<String> = redis::cmd("GETDEL")
            .arg(self.conn.key("login", state))
            .query_async(&mut conn)
            .await
            .map_err(unavailable)?;
        Ok(raw
            .and_then(|r| serde_json::from_str::<PendingRecord>(&r).ok())
            .map(|r| PendingLogin {
                pkce_verifier: r.pkce_verifier,
                nonce: r.nonce,
                next: r.next,
            }))
    }

    async fn create(
        &self,
        subject: String,
        email: Email,
        issuer: String,
    ) -> Result<(String, Session), StoreError> {
        let id = Secret::generate()
            .map_err(|e| StoreError::Unavailable(e.to_string()))?
            .to_base64url();
        let expires_at =
            OffsetDateTime::now_utc() + time::Duration::seconds(self.session_ttl.as_secs() as i64);
        let session = Session {
            subject: subject.clone(),
            email: email.clone(),
            issuer: issuer.clone(),
            expires_at,
        };
        let record = serde_json::to_string(&SessionRecord {
            subject: subject.clone(),
            email: email.to_string(),
            issuer,
            expires_at: expires_at
                .format(&time::format_description::well_known::Rfc3339)
                .unwrap_or_default(),
        })
        .unwrap_or_default();
        let ttl = self.session_ttl.as_secs().max(1);
        let mut conn = self.conn.manager.clone();
        let _: () = redis::pipe()
            .atomic()
            .set_ex(self.conn.key("sess", &id), record, ttl)
            .ignore()
            .sadd(self.by_subject(&subject), &id)
            .ignore()
            .expire(self.by_subject(&subject), ttl as i64)
            .ignore()
            .sadd(self.by_email(&email), &id)
            .ignore()
            .expire(self.by_email(&email), ttl as i64)
            .ignore()
            .query_async(&mut conn)
            .await
            .map_err(unavailable)?;
        Ok((id, session))
    }

    async fn get(&self, id: &str) -> Result<Option<Session>, StoreError> {
        let mut conn = self.conn.manager.clone();
        let raw: Option<String> = conn
            .get(self.conn.key("sess", id))
            .await
            .map_err(unavailable)?;
        let Some(raw) = raw else {
            return Ok(None);
        };
        let Ok(r) = serde_json::from_str::<SessionRecord>(&raw) else {
            return Ok(None);
        };
        let (Ok(email), Ok(expires_at)) = (
            Email::parse(&r.email),
            OffsetDateTime::parse(
                &r.expires_at,
                &time::format_description::well_known::Rfc3339,
            ),
        ) else {
            return Ok(None);
        };
        if expires_at <= OffsetDateTime::now_utc() {
            return Ok(None);
        }
        Ok(Some(Session {
            subject: r.subject,
            email,
            issuer: r.issuer,
            expires_at,
        }))
    }

    async fn revoke(&self, id: &str) -> Result<(), StoreError> {
        let mut conn = self.conn.manager.clone();
        if let Some(session) = self.get(id).await? {
            let _: () = redis::pipe()
                .atomic()
                .del(self.conn.key("sess", id))
                .ignore()
                .srem(self.by_subject(&session.subject), id)
                .ignore()
                .srem(self.by_email(&session.email), id)
                .ignore()
                .query_async(&mut conn)
                .await
                .map_err(unavailable)?;
        }
        Ok(())
    }

    async fn revoke_account(&self, account: &AccountRef) -> Result<u64, StoreError> {
        let mut conn = self.conn.manager.clone();
        let mut ended = 0;
        if let Some(subject) = &account.subject {
            let key = self.by_subject(subject);
            let ids: Vec<String> = conn.smembers(&key).await.map_err(unavailable)?;
            ended += self.end_sessions(ids).await?;
            let _: () = conn.del(&key).await.map_err(unavailable)?;
        }
        if let Some(email) = &account.email {
            let key = self.by_email(email);
            let ids: Vec<String> = conn.smembers(&key).await.map_err(unavailable)?;
            ended += self.end_sessions(ids).await?;
            let _: () = conn.del(&key).await.map_err(unavailable)?;
        }
        Ok(ended)
    }
}
