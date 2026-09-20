# Changelog

## Unreleased

- Shared store on Redis: any number of replicas, messages and sessions that
  survive a restart, the same one-time guarantees enforced by atomic
  scripts, a store contract test run against both backends, and a chart
  that rolls normally when the store is shared.
- An operator can end an account's sessions immediately through the
  management listener, pairing with disabling the account at the provider.
- The envelope's algorithms are variants with their own bounds, so a second
  key derivation is an addition; the interface is told the algorithm by name.
- Every store call carries an error channel, so a store that cannot be
  reached is a "try again", never a "gone".
- Interface strings live in one module.

## 0.1.0 - 2026-09-18

First release.

- Browser-side encryption: PBKDF2-SHA256 and HKDF into AES-256-GCM, with a
  link secret in the URL fragment and a proof-of-password consume.
- In-memory message store with per-message expiry, a byte budget, atomic
  take, failed-proof burning, and sender revocation.
- Uniform failure responses, strict security headers, size and rate limits per address and, in enterprise mode, per signed-in identity,
  trusted-proxy client address resolution.
- JSON audit events on stdout, Prometheus metrics, liveness and readiness,
  JSON health and stats on the management listener, graceful shutdown,
  optional in-process TLS.
- Branding through configuration: name, logo, favicon, colors, footer,
  support link.
- Container image on a minimal nonroot base; release workflow with signed
  artifacts, SBOMs, and provenance.
- Two modes. Standard, the default, where possession of the link and the password is the authority and addresses are recorded but not verified. Enterprise: OpenID Connect sign-in with PKCE, state, and nonce;
  server-side sessions; the sender is the signed-in identity; recipient
  binding enforced inside the atomic take; allowed domains; closed by default.
  Entra ID documented first, any standards-compliant provider works.
- Security workflow: actionlint, Trufflehog, Gitleaks, cargo-deny, npm audit,
  Semgrep, dependency review; CodeQL for both languages; OpenSSF Scorecard;
  every action pinned to a commit; Dependabot monthly and grouped with a
  cooldown; property-based tests on every parser that sees untrusted input.
