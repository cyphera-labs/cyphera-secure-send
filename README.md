# Cyphera SecureSend

[![ci](https://github.com/cyphera-labs/cyphera-secure-send/actions/workflows/ci.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-secure-send/actions/workflows/ci.yml)
[![security](https://github.com/cyphera-labs/cyphera-secure-send/actions/workflows/security.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-secure-send/actions/workflows/security.yml)
[![codeql](https://github.com/cyphera-labs/cyphera-secure-send/actions/workflows/codeql.yml/badge.svg)](https://github.com/cyphera-labs/cyphera-secure-send/actions/workflows/codeql.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/cyphera-labs/cyphera-secure-send/badge)](https://scorecard.dev/viewer/?uri=github.com/cyphera-labs/cyphera-secure-send)
[![Quality gate](https://sonarcloud.io/api/project_badges/measure?project=cyphera-labs_cyphera-secure-send&metric=alert_status)](https://sonarcloud.io/summary/new_code?id=cyphera-labs_cyphera-secure-send)
[![Coverage](https://sonarcloud.io/api/project_badges/measure?project=cyphera-labs_cyphera-secure-send&metric=coverage)](https://sonarcloud.io/summary/new_code?id=cyphera-labs_cyphera-secure-send)
[![Release](https://img.shields.io/github/v/release/cyphera-labs/cyphera-secure-send?include_prereleases&sort=semver)](https://github.com/cyphera-labs/cyphera-secure-send/releases)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![Rust](https://img.shields.io/badge/rust-1.88%2B-orange.svg)](Cargo.toml)

One-time secret handoff for controlled environments.

Somebody has to give Bob the temporary password, the API key, the initial
admin credential. It ends up in chat or email, where it lives in searchable
retention for years. SecureSend is the moment in between: the sender types the
secret, sets a password and an expiry, and gets a link. The link and the
password travel on different channels. Bob opens the link, enters the
password, reads the message once, and it is gone.

Not a password manager. Not a vault. It handles the handoff.

## What makes it different

- **The server never sees the secret.** Encryption happens in the browser
  with Web Crypto. The server stores ciphertext and a hash it cannot invert.
- **A wrong password does not destroy the message, and a stolen link alone
  cannot read or burn it.** The recipient proves possession of both the link
  and the password before the server hands anything over.
- **One binary, no database.** Messages live in bounded process memory and
  vanish on restart. That is a feature.
- **Exactly once.** Consumption is an atomic take. Two readers racing get one
  message and one "unavailable".
- **Nothing leaks by shape.** Every failure looks the same. No secret ever
  appears in a URL path, a log line, or an audit event.
- **Yours in ten minutes.** Name, logo, colors, footer, support link: a few
  lines of configuration, no rebuild.
- **Enterprise posture from day one.** Structured audit events, Prometheus
  metrics, JSON health and stats, liveness and readiness, graceful shutdown,
  strict CSP, no third-party origins, nonroot container, signed releases with
  SBOMs.

## Run it

```
docker run --rm -p 8080:8080 ghcr.io/cyphera-labs/cyphera-secure-send:latest
```

or download the binary from a release and:

```
./cyphera-secure-send serve
```

Open `http://localhost:8080`.

Brand it:

```
docker run --rm -p 8080:8080 \
  -e CYPHERA_SECURESEND__BRANDING__COMPANY_NAME=Acme \
  -e CYPHERA_SECURESEND__BRANDING__COLORS__PRIMARY=#0057b8 \
  ghcr.io/cyphera-labs/cyphera-secure-send:latest
```

## How it works

```
sender's browser                       server                     recipient's browser
────────────────                       ──────                     ───────────────────
password + random link secret
  → PBKDF2 → HKDF → K_enc, K_proof
encrypt with AES-256-GCM
                     ciphertext, SHA-256(K_proof) ─►  store in memory
                     ◄─ id, revoke token
link = /m/<id>#<link secret…>
                                                                   open link, enter password
                                                                   derive K_proof
                                                   verify + remove  ◄─ proof
                                                   (one atomic step)
                                                   ciphertext ─►    decrypt, show once
```

The part after `#` never leaves the browser. Full protocol, invariants, and
threat model: [docs/security-model.md](docs/security-model.md).

## Documentation

- [Security model](docs/security-model.md)
- [Configuration](docs/configuration.md)
- [Branding](docs/branding.md)
- [Deployment](docs/deployment.md): container, Kubernetes, metrics, audit, air-gap, verifying releases

## API

| | |
|---|---|
| `POST /v1/messages` | create; returns `id`, `revoke_token`, `expires_at` once |
| `POST /v1/messages/{id}/consume` | body `{proof}`; returns the envelope exactly once, or `404 {"error":"unavailable"}` |
| `POST /v1/messages/{id}/revoke` | body `{revoke_token}`; always `204` |
| `GET /v1/ui-config` | branding and limits for the interface |
| `GET /v1/health` | `{"status":"ok"}` |
| `GET /livez`, `/readyz` | management listener: liveness and readiness |
| `GET /v1/health`, `/v1/stats` | management listener: JSON health with store occupancy; lifecycle totals, occupancy, and limits |
| `GET /metrics` | management listener: Prometheus |

## Supply chain and quality

Every push runs the same gates a release does, and every release ships what a
security review asks for.

| | |
|---|---|
| **Tests** | Rust unit and HTTP tests, property-based tests on every parser that sees untrusted input, browser tests in Chromium including the double-read race |
| **Static analysis** | Clippy with warnings denied, CodeQL for Rust and TypeScript, Semgrep, SonarQube quality gate with coverage from `cargo llvm-cov` and Vitest |
| **Dependencies** | `cargo-deny` for advisories, licenses, and sources; `npm audit`; Dependabot weekly across Cargo, npm, Actions, and Docker; dependency review on pull requests |
| **Secrets** | Trufflehog and Gitleaks over the full history on every push |
| **Workflows** | Every action pinned to a commit SHA, `actionlint` on every change, least-privilege tokens, OpenSSF Scorecard weekly |
| **Releases** | Binaries for amd64 and arm64, multi-arch image on a digest-pinned minimal base, CycloneDX and SPDX SBOMs, Sigstore signatures on every artifact, SLSA build provenance attestations |
| **Container** | Single binary, `nonroot`, no shell, read-only filesystem and dropped capabilities supported |

The verification commands are in every release's notes and in
[docs/deployment.md](docs/deployment.md).

## Building

```
cd web && npm ci && npm run build && cd ..
cargo build --release
```

Node is a build dependency only. The interface is compiled into the binary.

Tests:

```
cargo test
cd web && npm test && npx playwright install chromium && npm run e2e
```

## Status

Alpha. The API and configuration keys may still change before 1.0. Planned
next: an OIDC mode that closes anonymous use and binds recipients to an
identity, a Redis backend for clustering, and syslog and webhook audit sinks.
The core is built so those arrive as adapters, not rewrites.

## License

Apache-2.0. See [LICENSE](LICENSE).
