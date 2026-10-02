# Security

## Reporting a vulnerability

Email **security@cyphera.io**. Include what you found, how to reproduce it, and
what you think the impact is. You will get an acknowledgement within three
business days and a status update at least every two weeks until it is
resolved.

Please do not open a public issue for a vulnerability.

## Scope

- The service in this repository: the Rust server and the browser interface.
- The container image and the release artifacts.

Out of scope: the deployer's TLS termination, identity provider, or network;
vulnerabilities in a user's browser or endpoint; findings that require a
compromised server (see the threat model, which states that limit openly).

## What we consider a vulnerability

Anything that breaks an invariant in [docs/security-model.md](docs/security-model.md):
plaintext or key material reaching the server, a message delivered twice, a
secret in a log or audit event, a way to tell whether a message exists, a
bypass of size or rate limits, or a header or CSP regression.

## Accepted advisories

Dependency advisories that apply to a code path this service does not use
are recorded in `deny.toml` with the reason, so the audit stays green
without hiding anything. At present:

- **RUSTSEC-2023-0071** (`rsa`, Marvin timing attack). Reached only through
  the OpenID Connect library's signature verification, a public-key
  operation. The attack targets private-key operations, and no RSA private
  key exists in the process.

## Supported versions

The latest release. Fixes are not backported.

## Verifying releases

Every release is signed with Sigstore and carries a build provenance
attestation and SBOMs. See [docs/deployment.md](docs/deployment.md).
