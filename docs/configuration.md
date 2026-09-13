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

`mode: anonymous` is the only mode today: anyone with the link and the
password.

## branding

See [branding.md](branding.md).
