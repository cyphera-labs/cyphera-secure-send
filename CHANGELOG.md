# Changelog

## 0.1.0 - 2026-10-01

First release.

- Browser-side encryption: PBKDF2-SHA256 and HKDF into AES-256-GCM, with a
  link secret in the URL fragment and a proof-of-password consume. The
  envelope names its algorithms and carries their parameters, so a second
  key derivation can be added without invalidating links already made.
- Message store with per-message expiry, a byte budget enforced at the door,
  an atomic take that delivers at most once, failed-proof burning, and
  sender revocation. In process memory by default; on a Redis you run or
  rent when you want more than one replica or messages that outlive a
  restart of the service, with the same guarantees enforced by atomic
  scripts and one contract test run against both.
- Uniform failure responses, strict security headers, size limits, and rate
  limits per client address and, in enterprise mode, per signed-in identity.
  Client addresses resolved from trusted proxy networks or a count of hops.
- JSON audit events on stdout written by their own thread, Prometheus
  metrics, liveness and readiness, JSON health and stats on the management
  listener, graceful shutdown, optional in-process TLS.
- Branding through configuration: name, logo, favicon, colors, footer,
  support link.
- Container image on a minimal nonroot base; release workflow with signed
  artifacts, SBOMs, and provenance.
- Two modes. Standard, the default, where possession of the link and the
  password is the authority and addresses are recorded but not verified.
  Enterprise: OpenID Connect sign-in with PKCE, state, and nonce;
  server-side sessions an operator can end immediately for one account;
  signing-key rotation handled without a restart; the sender is the
  signed-in identity; recipient binding enforced inside the atomic take;
  allowed domains; closed by default. Entra ID documented first, any
  standards-compliant provider works.
- Security workflow: actionlint, Trufflehog, Gitleaks, cargo-deny, npm audit,
  Semgrep, dependency review; CodeQL for both languages; OpenSSF Scorecard;
  every action pinned to a commit; Dependabot monthly and grouped with a
  cooldown; property-based tests on every parser that sees untrusted input.
