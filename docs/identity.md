# Identity: enterprise mode with OpenID Connect

Eval mode is anyone with the link and the password, with typed, unverified
sender and recipient addresses. Enterprise mode puts your identity provider
in front of both ends of the handoff:

- creating a message requires signing in, and the sender is the signed-in
  user, not a typed field;
- reading a message requires signing in **as the recipient it was sent to**;
- senders and recipients can be limited to your domains;
- every audit event carries the subject and the issuer.

It is generic OpenID Connect. Microsoft Entra ID is the example throughout
because it is the common case; Okta, Keycloak, Ping, and any other
standards-compliant provider work the same way.

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

auth:
  oidc:
    issuer: https://login.microsoftonline.com/<tenant-id>/v2.0
    client_id: <application (client) id>
    allowed_domains: [example.com]
```

```
CYPHERA_SECURESEND__AUTH__OIDC__CLIENT_SECRET=<the secret value>
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
| `require_recipient_match` | `true` | the reader's email must equal the message's recipient |
| `allowed_domains` | `[]` (any) | both the sender and every recipient must belong to one of these |
| `anonymous_create` | `false` | allow creating without signing in |
| `anonymous_consume` | `false` | allow reading without signing in |

Addresses are compared case-insensitively. The defaults are closed: nobody
outside the directory can use the service, and every message is attributable
to a sender and readable by exactly one named person.

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
