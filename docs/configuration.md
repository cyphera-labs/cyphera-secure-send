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

## server

| Key | Default | Notes |
|---|---|---|
| `bind` | `0.0.0.0:8080` | public listener |
| `public_base_url` | unset | the URL users reach the service at; required in OIDC mode |
| `management_bind` | `127.0.0.1:9090` | `/livez`, `/readyz`, `/metrics`. Keep it off the public network |
| `trusted_proxies` | `[]` | CIDRs. `X-Forwarded-For` is honored only when the peer is inside one |
| `hsts` | `false` | emit `Strict-Transport-Security`; enable once HTTPS is in place |
| `shutdown_timeout_seconds` | `10` | drain time on SIGTERM |
| `tls.cert_path`, `tls.key_path` | unset | set both to terminate TLS in-process (PEM) |

## messages

| Key | Default | Notes |
|---|---|---|
| `ttl_options_seconds` | `[300, 900, 3600, 28800, 86400]` | the choices in the interface |
| `default_ttl_seconds` | `3600` | must be one of the options |
| `min_ttl_seconds` / `max_ttl_seconds` | `60` / `86400` | what the API accepts |
| `max_plaintext_bytes` | `65536` | the interface refuses larger text; the API refuses the corresponding ciphertext |
| `memory_budget_bytes` | `268435456` | total ciphertext held before eviction; must hold at least sixteen maximum-size messages |
| `max_failed_proofs` | `5` | wrong passwords before the message is destroyed |
| `kdf.recommended_iterations` | `600000` | what the interface uses |
| `kdf.min_iterations` / `kdf.max_iterations` | `100000` / `5000000` | what the API accepts |

## rate_limits

Per client address, token bucket, per minute: `create_per_minute` (10),
`consume_per_minute` (30), `revoke_per_minute` (30). Behind a proxy, set
`server.trusted_proxies` or every client shares one bucket.

## storage

`backend: memory` is the only backend today. Messages live in process memory
and vanish on restart.

## audit

| Key | Default | Notes |
|---|---|---|
| `sink` | `stdout` | one JSON object per line; application logs go to stderr |
| `include_client_ip` | `false` | |
| `include_user_agent` | `false` | truncated to 256 characters |

## auth

`mode: anonymous` (default) is anyone with the link and the password.
`mode: oidc` puts your identity provider in front of both ends; see
[identity.md](identity.md).

| Key | Default | Notes |
|---|---|---|
| `oidc.issuer` | | the provider's issuer URL, as in its discovery document |
| `oidc.client_id` | | |
| `oidc.client_secret` | | set as `CYPHERA_SECURESEND__AUTH__OIDC__CLIENT_SECRET`; never printed back |
| `oidc.client_secret_file` | | alternative: a file containing the secret |
| `oidc.scopes` | `[openid, profile, email]` | |
| `oidc.email_claim` | `email` | or `preferred_username`; the other is the fallback |
| `oidc.allowed_domains` | `[]` | when set, both sender and recipient must belong to one |
| `oidc.require_recipient_match` | `true` | the reader must be the named recipient |
| `oidc.anonymous_create` | `false` | |
| `oidc.anonymous_consume` | `false` | |
| `oidc.session_ttl_seconds` | `28800` | |
| `oidc.login_ttl_seconds` | `600` | how long a started login stays valid |
| `oidc.trust_ca_path` | unset | PEM bundle of extra CAs for reaching the provider |

## branding

See [branding.md](branding.md).
