# Changelog

## Unreleased

Initial implementation.

- Browser-side encryption: PBKDF2-SHA256 and HKDF into AES-256-GCM, with a
  link secret in the URL fragment and a proof-of-password consume.
- In-memory message store with per-message expiry, a byte budget, atomic
  take, failed-proof burning, and sender revocation.
- Uniform failure responses, strict security headers, size and rate limits,
  trusted-proxy client address resolution.
- JSON audit events on stdout, Prometheus metrics, liveness and readiness,
  JSON health and stats on the management listener, graceful shutdown,
  optional in-process TLS.
- Branding through configuration: name, logo, favicon, colors, footer,
  support link.
- Container image on a minimal nonroot base; release workflow with signed
  artifacts, SBOMs, and provenance.
- Enterprise mode: OpenID Connect sign-in with PKCE, state, and nonce;
  server-side sessions; the sender is the signed-in identity; recipient
  binding enforced inside the atomic take; allowed domains; closed by default.
  Entra ID documented first, any standards-compliant provider works.
- Security workflow: actionlint, Trufflehog, Gitleaks, cargo-deny, npm audit,
  Semgrep, dependency review; CodeQL for both languages; OpenSSF Scorecard;
  SonarQube with coverage from cargo-llvm-cov and Vitest; every action pinned
  to a commit; Dependabot with a cooldown; property-based tests on every
  parser that sees untrusted input.
