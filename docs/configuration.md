# Configuration

SecureSend needs nothing to start. Every setting has a default.

Precedence, lowest to highest:

1. built-in defaults
2. a YAML file: `--config PATH`, else `$CYPHERA_SECURESEND_CONFIG`, else
   `./cyphera-secure-send.yaml` if it exists
3. environment variables: `CYPHERA_SECURESEND__<SECTION>__<KEY>`

Lists in the environment are comma-separated:
`CYPHERA_SECURESEND__MESSAGES__TTL_OPTIONS_SECONDS=300,3600`.

`cyphera-secure-send check-config` loads everything, validates it, and prints
the effective settings as JSON. Invalid configuration is refused at startup
with a message naming the key.

A complete annotated file is at `config/cyphera-secure-send.example.yaml`.

## mode

| Value | Meaning |
|---|---|
| `standard` (default) | Possession of the link and the password is the authority to retrieve. Sender and recipient are recorded but not verified, the interface says so, and audit events record `sender_authenticated: false`. A supported mode, recommended where reaching the service is itself controlled: an internal network, a VPN, a trusted team. |
| `enterprise` | Users sign in at your identity provider. Audit events carry the issuer and subject, and say separately whether the sender was authenticated, whether the reader was, and whether recipient binding was enforced. Requires `server.public_base_url`. See [identity.md](identity.md). |

Standard controls access through possession of the link and the password.
Enterprise additionally establishes who is allowed to create a handoff and,
when desired, who is allowed to consume it. The cryptography is the same in
both; what differs is identity assurance.

Enterprise mode is free and part of this open-source build. The Enterprise
subscription buys supported releases, certified deployments, and security
response, not features.

## server

| Key | Default | Notes |
|---|---|---|
| `bind` | `0.0.0.0:8080` | public listener |
| `public_base_url` | unset | the URL users reach the service at; required in enterprise mode |
| `management_bind` | `127.0.0.1:9090` | `/livez`, `/readyz`, `/metrics`. Keep it off the public network |
| `trusted_proxies` | `[]` | CIDRs. `X-Forwarded-For` is honored only when the peer is inside one |
| `trusted_hops` | `0` | how many proxies stand in front, when their addresses are not knowable. A proxy appends the address it received from, so one in front means the client is the **last** entry of `X-Forwarded-For`, two means second from the right. Reading from the right is what makes it safe. Mutually exclusive with `trusted_proxies`, and unsafe anywhere the service can be reached directly. Verify it by turning on `audit.include_client_ip` and checking a request from a known address |
| `hsts` | `false` | emit `Strict-Transport-Security`; enable once HTTPS is in place |
| `shutdown_timeout_seconds` | `10` | drain time on SIGTERM |
| `request_timeout_seconds` | `30` | how long a request may take to arrive in full, headers and body. A connection that opens and trickles, or stops, is dropped at this point rather than held |
| `tls.cert_path`, `tls.key_path` | unset | set both to terminate TLS in-process (PEM) |

## messages

| Key | Default | Notes |
|---|---|---|
| `ttl_options_seconds` | `[300, 900, 3600, 28800, 86400]` | the choices in the interface |
| `default_ttl_seconds` | `3600` | must be one of the options |
| `min_ttl_seconds` / `max_ttl_seconds` | `60` / `86400` | what the API accepts |
| `max_plaintext_bytes` | `65536` | the interface refuses larger text; the API refuses the corresponding ciphertext |
| `memory_budget_bytes` | `268435456` | the most the store will hold, counting each message at its payload plus roughly a kilobyte of overhead. A create that would exceed it is refused with a capacity error; nothing accepted is ever evicted. Must hold at least sixteen maximum-size messages |
| `max_failed_proofs` | `5` | wrong passwords before the message is destroyed |
| `kdf.algorithm` | `pbkdf2-sha256` | the password-stretching algorithm the interface uses, and the only one the API accepts. One choice today |
| `kdf.recommended_iterations` | `600000` | the work factor the interface uses. Raise it to make guessing slower for everyone, at the cost of the same wait for the sender and the reader |
| `kdf.min_iterations` / `kdf.max_iterations` | `100000` / `5000000` | what the API accepts |

## rate_limits

Token buckets, per minute. Per client address: `create_per_minute` (10),
`consume_per_minute` (30), `revoke_per_minute` (30), and in enterprise mode
`auth_per_minute` (20) for sign-in starts and callbacks together, since each
accepted callback costs a request to the identity provider. Behind a proxy,
set either `server.trusted_proxies` or `server.trusted_hops`, or every
client shares one bucket.

A caller over a limit is refused from the request head, before the body is
read, so the limit bounds what they cost the service as well as what they
achieve.

In enterprise mode a second bucket applies per signed-in identity, so a
caller is bounded however many addresses they come from:
`identity_create_per_minute` (30), `identity_consume_per_minute` (60).

## storage

| Key | Default | Notes |
|---|---|---|
| `backend` | `memory` | `memory`: messages live in this process, one replica, and vanish on restart. `redis`: messages and sessions live in a Redis you run or rent, any number of replicas, and survive a restart of the service |
| `redis.url` | unset | `redis://` or `rediss://`, password included, so keep it in a secret or use `url_file`. Never printed back by `check-config` |
| `redis.url_file` | unset | a file holding the URL, for deployments that mount secrets |
| `redis.key_prefix` | `securesend` | every key this service writes starts with it, so one Redis can serve more than one deployment |
| `redis.connect_timeout_seconds` | `5` | how long startup waits for Redis before refusing to start |

With Redis, `messages.memory_budget_bytes` is still the budget, enforced by
the store's own scripts, and Redis's own `maxmemory` is the backstop. Set
`maxmemory-policy noeviction` on it: this service never wants Redis to
discard an accepted message to make room, and refuses new ones itself
instead. Every operation that decides something runs as one script on the
server, so two replicas racing for one message still produce one reader.
Not for Redis Cluster; a single instance, a replicated pair, or a managed
service in that shape.

## audit

| Key | Default | Notes |
|---|---|---|
| `sink` | `stdout` | one JSON object per line; application logs go to stderr |
| `include_client_ip` | `false` | |
| `include_user_agent` | `false` | truncated to 256 characters |

## enterprise

Used when `mode` is `enterprise`; see [identity.md](identity.md) for the
walkthrough. The provider lives under `enterprise.oidc`, and the two rule
groups are deliberately separate.

| Key | Default | Notes |
|---|---|---|
| `oidc.issuer` | | the provider's issuer URL, as in its discovery document |
| `oidc.client_id` | | |
| `oidc.client_secret` | | set as `CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_SECRET`; never printed back |
| `oidc.client_secret_file` | | alternative: a file containing the secret |
| `oidc.scopes` | `[openid, profile, email]` | |
| `oidc.email_claim` | `email` | or `preferred_username`. There is no fallback between them: they mean different things |
| `oidc.unverified_email` | `refuse` | what to do when the token does not say the address is verified. `accept` states that your directory is authoritative for its addresses; a token saying "not verified" is refused either way |
| `oidc.session_ttl_seconds` | `28800` | |
| `oidc.login_ttl_seconds` | `600` | how long a started login stays valid |
| `oidc.trust_ca_path` | unset | PEM bundle of extra authorities for reaching the provider |

**Who may send**

| Key | Default | Notes |
|---|---|---|
| `creation.require_oidc` | `true` | creating needs a session, and the sender is that identity rather than a typed field |
| `creation.allowed_domains` | `[]` | your own domains; the signed-in sender must belong to one. Empty allows any |

**What the recipient must prove**

| Key | Default | Notes |
|---|---|---|
| `recipient.require_oidc` | `true` | consuming needs a session |
| `recipient.require_identity_match` | `true` | the reader's address must equal the message's recipient; needs `require_oidc` |
| `recipient.external_recipients` | `false` | allow a recipient outside `creation.allowed_domains`; only bites when that list is non-empty |

## branding

See [branding.md](branding.md).
