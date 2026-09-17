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
| `eval` (default) | Anyone with the link and the password. Sender and recipient are typed and **not verified**; audit events mark them `asserted`. For trying the product, labs, and cloud evaluation. The interface shows an evaluation banner. |
| `enterprise` | Users sign in at your identity provider (`auth.oidc`). The sender is the signed-in identity, only the named recipient can read, senders and recipients can be limited to your domains, and audit events mark identities `verified`. Requires `server.public_base_url`. See [identity.md](identity.md). |

Eval mode records who users say they are. Enterprise mode verifies who they
are.

## server

| Key | Default | Notes |
|---|---|---|
| `bind` | `0.0.0.0:8080` | public listener |
| `public_base_url` | unset | the URL users reach the service at; required in enterprise mode |
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

Token buckets, per minute. Per client address: `create_per_minute` (10),
`consume_per_minute` (30), `revoke_per_minute` (30). Behind a proxy, set
`server.trusted_proxies` or every client shares one bucket.

In enterprise mode a second bucket applies per signed-in identity, so a
caller is bounded however many addresses they come from:
`identity_create_per_minute` (30), `identity_consume_per_minute` (60).

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

Used in enterprise mode; see [identity.md](identity.md).

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
