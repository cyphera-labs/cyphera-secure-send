# Identity: enterprise mode with OpenID Connect

Standard mode is anyone with the link and the password, with typed,
unverified addresses. Enterprise mode puts your identity provider in front of
the handoff and asks two questions that are configured separately, because
they are genuinely different questions:

- **Who may create a handoff?** By default a signed-in user, and the sender
  is that identity rather than a typed field. This is the control that
  matters most: the service cannot inspect an encrypted message and never
  claims to, so what it offers instead is accountability. Every message is
  attributable to an authenticated organizational identity, and an
  administrator can restrict, audit, rate-limit, or revoke that ability.
- **What must the recipient prove?** By default, that they are signed in as
  the address the message names. That can be relaxed independently, which is
  what makes the handoff to someone outside your directory possible.

The cryptography is identical to standard mode. What enterprise adds is
identity assurance and abuse control. It is free and part of this
open-source build.

## Two shapes worth knowing

**Internal to internal**, the default. Alice signs in, addresses Bob, and only
Bob can read it:

```yaml
mode: enterprise

enterprise:
  creation:
    require_oidc: true
    allowed_domains: [example.com]
  recipient:
    require_oidc: true
    require_identity_match: true
    external_recipients: false
```

**Internal to a customer or vendor.** Only authenticated staff may create, and
the recipient, who has no account with you, reads with the link and the
password like any standard-mode recipient. This is the helpdesk, managed
service provider, and vendor case:

```yaml
mode: enterprise

enterprise:
  creation:
    require_oidc: true
    allowed_domains: [example.com]
  recipient:
    require_oidc: false
    require_identity_match: false
    external_recipients: true
```

Both keep the property that matters: nobody outside the organization can use
your instance to create anything.

## Microsoft Entra ID

**1. Register the application.** In the Entra admin center, *App
registrations → New registration*.

- Supported account types: *Accounts in this organizational directory only*.
- Redirect URI, platform **Web**: `https://send.example.com/auth/callback`
  (your public base URL plus `/auth/callback`).

**2. Client secret.** *Certificates & secrets → New client secret*. Copy the
value once; it goes into the environment, never into a file you commit.

**3. Email claim.** Under *Token configuration → Add optional claim → ID*,
add `email`. Work accounts then carry the user's address in the `email`
claim. If your tenant cannot emit it, set `email_claim: preferred_username`,
which is the user principal name.

**4. Configure SecureSend.**

```yaml
mode: enterprise

server:
  public_base_url: https://send.example.com
  hsts: true

enterprise:
  oidc:
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    client_id: <application (client) id>
  creation:
    allowed_domains: [example.com]
```

```
CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_SECRET=<the secret value>
```

Use the tenant-specific issuer with your directory (tenant) id, not
`common` or `organizations`: the issuer in the ID token must match the
discovery document, and only the tenant-specific one does.

**5. Start it.** SecureSend runs discovery against the issuer at startup and
refuses to start if the provider is unreachable or the configuration is
inconsistent; the message names the problem.

## What users see

A person opening the service is sent to sign in, then returned to where they
were going. The compose form shows their address as the sender and cannot
change it. A recipient opening a link signs in, and if they are not the
person the message names, they get the same "unavailable" answer as anyone
else; the message stays intact for the right person.

The part of the link after `#` never leaves the browser, so it survives the
round trip to the provider: the page parks it in session storage before
redirecting and restores it on return. If storage is unavailable, opening the
full link again after signing in works too.

## How it works

Authorization-code flow with PKCE, state, and nonce. The server runs it;
the browser never holds a token.

1. `GET /auth/login?next=/m/…` generates PKCE verifier and challenge, a
   `state`, and a `nonce`, stores them under the state for ten minutes, sets
   a short-lived login cookie carrying the state, and redirects to the
   provider.
2. The provider authenticates the user and redirects to `/auth/callback`
   with `code` and `state`.
3. The callback requires the state in the URL to equal the one in this
   browser's login cookie, and requires it to match a stored, not yet used
   login. Both stop a login started elsewhere from being completed here.
4. The code is exchanged at the token endpoint with the PKCE verifier and the
   client secret. The ID token's signature is checked against the provider's
   published keys, and its issuer, audience, expiry, and nonce are verified.
5. A session is created in memory, identified by a random 256-bit id in a
   cookie, and the browser is redirected to `next`, which must be a path on
   this service.

Cookies are `HttpOnly` and `SameSite=Lax`. When the public base URL is
HTTPS they are `Secure` and carry the `__Host-` prefix, which pins them to
this host and path. Sessions expire after `session_ttl_seconds` (eight
hours by default) and, like everything else, disappear on restart.

`POST /auth/logout` ends the session. `GET /v1/session` tells the interface
whether there is one and for whom.

## Rules

| Setting | Default | Effect |
|---|---|---|
| `creation.require_oidc` | `true` | creating requires a session; the sender is the signed-in identity |
| `creation.allowed_domains` | `[]` (any) | the signed-in sender must belong to one of your domains |
| `recipient.require_oidc` | `true` | reading requires a session |
| `recipient.require_identity_match` | `true` | the reader's address must equal the message's recipient |
| `recipient.external_recipients` | `false` | a recipient outside your domains is acceptable |

Addresses are compared case-insensitively. The defaults are closed: nobody
outside the directory can use the service, every message is attributable to a
sender, and each is readable by exactly one named person.

The recipient check runs inside the same atomic step as the password proof,
and before it, so a reader who is not the named recipient gets the same
"unavailable" answer as anyone else and the message stays intact for the
right person.

## Revoking a sender

Audit events carry the issuer and the subject alongside the address. The
subject is the stable identifier; addresses change. To stop someone creating
handoffs, disable or remove them at the identity provider, or drop them from
whichever group or domain your configuration admits. Per-identity rate limits
apply on top, keyed on the subject, so switching networks does not widen what
one account can do.

## Other providers

| Provider | Issuer | Notes |
|---|---|---|
| Okta | `https://<org>.okta.com` or a custom authorization server URL | add the `email` scope; the `email` claim is standard |
| Keycloak | `https://<host>/realms/<realm>` | enable the `email` client scope |
| Ping | your environment's issuer URL | ensure the `email` claim is mapped |
| Google Workspace | `https://accounts.google.com` | `email` is standard; use `allowed_domains` to restrict to your domain |

## Private certificate authorities

If the provider's certificate is issued by a private CA, point
`auth.oidc.trust_ca_path` at a PEM bundle. It is trusted in addition to the
system roots.
