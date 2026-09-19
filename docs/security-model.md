# Security model

What SecureSend protects, how, and what it does not protect. Read this before
deploying it anywhere that matters.

## The protocol

Everything cryptographic happens in the browser with Web Crypto. The server
does two things with secrets: hash them and compare them in constant time.

```
password                  chosen by the sender, shared out of band
linkSecret   (256 bit)    generated in the browser, travels in the URL fragment
salt         (128 bit)    generated in the browser, public
iv           (96 bit)     generated in the browser, public

pwKey      = PBKDF2-HMAC-SHA256(password, salt, iterations)
ikm        = pwKey || linkSecret
K_enc      = HKDF-SHA256(ikm, salt, "cyphera-securesend/v1/enc")
K_proof    = HKDF-SHA256(ikm, salt, "cyphera-securesend/v1/proof")
verifier   = SHA-256(K_proof)
ciphertext = AES-256-GCM(K_enc, iv, plaintext, aad = "cyphera-securesend/v1")
```

**Create.** The browser sends `{sender, recipient, ttl, verifier, envelope}`
where the envelope is `{version, kdf: {name, iterations, salt}, cipher: {name, iv}, ciphertext}`.
The server generates a public 128-bit message id and a 256-bit revoke token,
stores the envelope with `verifier` and `SHA-256(revokeToken)`, and returns
`{id, revokeToken, expiresAt}` once. The browser builds the link:

```
https://host/m/<id>#<linkSecret>.<salt>.<iterations>
```

The part after `#` never leaves the browser: browsers do not send fragments,
so it is absent from the server's access log, every proxy's log, and the
`Referer` header (the interface also sets `Referrer-Policy: no-referrer`).

**Consume.** The recipient's browser reads the fragment, asks for the
password, derives `K_proof`, and sends `{proof: K_proof}` to
`POST /v1/messages/<id>/consume`. The server computes `SHA-256(proof)` and
compares it to the stored verifier in constant time, inside the same atomic
operation that removes the message. Match: the envelope is returned and the
message no longer exists. No match: a failure counter advances; at the
configured limit the message is destroyed.

**Revoke.** `POST /v1/messages/<id>/revoke` with the revoke token. The
response is `204` whether or not anything was revoked.

## Why the server verifies a proof

A pure "server stores ciphertext, browser tries the password" design has two
consequences under strict one-time delivery: a typo by the recipient destroys
the message, and anyone who has only the link can burn it and take the
ciphertext offline to guess the password at leisure.

The proof fixes both without giving the server the password. `K_proof` is an
independent HKDF output; knowing it reveals nothing about `K_enc`. The server
stores only its hash, so a memory dump does not yield a usable proof either.

## Why the link carries a secret

Mixing a 256-bit link secret into the key derivation means that:

- ciphertext obtained from the server (a memory dump, or a copy of any store)
  cannot be attacked without the link, however weak the password;
- a captured link is useless without the password;
- the verifier cannot be used to guess the password without the link.

Each artifact on its own is worthless. Password strength only matters against
an attacker who holds both the link and the ciphertext.

## Invariants

Each of these is enforced by a test.

1. Plaintext, password, `K_enc`, and the link secret never reach the server.
2. No secret ever appears in a URL path, query string, or header.
3. The store holds only hashes of the revoke token; the link secret is never
   seen at all; the verifier is a hash.
4. `take` is atomic. Under concurrent correct proofs exactly one caller gets
   the message.
5. Every consume failure (unknown id, malformed id, wrong proof, expired,
   revoked, already consumed, burned) returns the same status, body, and
   headers, and runs a comparison even when there is nothing to compare.
6. The configured number of wrong proofs destroys the message. Someone who
   holds the link but not the password can therefore spend those attempts to
   deny delivery, without ever reading anything. The limit is configurable,
   and the alternative, unlimited attempts, hands that same person an offline
   guessing target instead.
7. Removal happens before the response is built, which makes delivery **at
   most once**, not exactly once: a connection that drops after that point
   loses the message, and nothing can recover it. That is the deliberate
   trade for never handing the same message over twice.
8. Memory is bounded. When the budget is exceeded the least valuable entries
   are evicted and each eviction is audited.
9. A restart discards every pending message. Nothing is written to disk.
10. Audit events carry no message secret: the event type has no field for
    plaintext, password, proof, verifier, link secret, or revoke token, and
    no free-text field a diagnostic could leak through. It does carry
    addresses and, when the operator asks for them, the client address and
    user agent, which are strings an operator chooses to record.
11. Every response, including static files and 404s, carries `no-store`,
    `no-referrer`, `nosniff`, and a Content Security Policy with no
    `unsafe-*` source.
12. Nothing is loaded from a third-party origin.
13. Request bodies are size-limited before they are parsed.
14. Only JSON bodies with `Content-Type: application/json` are accepted, and
    there is no CORS policy, so a cross-origin page cannot make the API do
    anything: the preflight fails.
15. In enterprise mode, what a caller may take is decided from the caller alone,
    before the store is touched, as plain data (deny, or the recipient the
    message must name), and enforced inside the same atomic step as the
    proof check and before it: a caller who is not the named recipient gets
    the generic answer, the message is untouched, and no proof attempt is
    counted. Being data rather than code, the rule can travel into a shared
    store's own atomic operation unchanged.
16. The sender of a message is the signed-in identity whenever there is one;
    the typed field is ignored.
17. A login completes only in the browser that started it (state bound to a
    cookie), only once (state is consumed), and only to a path on this
    service.

## Threat model

| Threat | Covered | How |
|---|---|---|
| Passive observer on the network | yes | TLS, and nothing useful in URLs anyway |
| Server operator, memory dump, copy of the store | yes | ciphertext, hashes, and a verifier that cannot be attacked without the link |
| Link intercepted, password not | partly | the proof cannot be derived, so the message cannot be read; but the holder can spend the failed-attempt limit and destroy it, denying delivery |
| Password intercepted, link not | yes | nothing to attack |
| Link and ciphertext both obtained | partly | bounded by password strength and PBKDF2 cost; the interface offers a generated password |
| Recipient double-read, replay | yes | atomic take |
| Two recipients racing | yes | one wins, one gets the generic response |
| Probing whether an id exists | yes | identical responses; 2^128 id space |
| Flooding to exhaust memory | yes | per-client create limit, weight budget, eviction |
| Spoofed client address | yes | `X-Forwarded-For` honored only from configured proxy networks |
| Cross-site request forgery | yes | JSON-only API, no CORS; session cookies are `SameSite=Lax` |
| Login CSRF and authorization-code injection | yes | state bound to a login cookie, single-use, PKCE, nonce in the ID token |
| Stolen or forged ID token | yes | signature against the provider's keys, issuer, audience, expiry, and nonce all verified; tokens never reach the browser |
| Reading someone else's message with a valid link and password | yes, in enterprise mode | recipient binding inside the atomic take |
| Cross-site scripting | yes | no inline script or style, all text set via DOM APIs |
| Hosting malware or phishing content | partly | text only, small size limit; enterprise mode closes anonymous creation by default, so every message is attributable to an authenticated identity an administrator can revoke |
| Compromised server serving modified JavaScript | **no** | this is the honest limit of browser-side encryption: a malicious server can attack *future* users. Mitigations: signed releases, reproducible interface build, strict CSP, and deploying behind an identity boundary |
| Compromised endpoint or browser | no | out of scope |
| A malicious sender | no | the product moves what the sender typed |

## What the audit log reveals

Sender, recipient, timestamps, TTL, outcome, and reason codes. That is the
communication graph, and it is there on purpose: enterprise deployments need
it. It is sensitive. Treat the audit stream as confidential.

Never present: plaintext, ciphertext, password, keys, proof, verifier, link
secret, revoke token, or anything from which a usable link could be rebuilt.

## Delivery is strict

Once the server has handed a message to one caller it is gone. If that
caller's connection drops before the bytes arrive, the message is lost. This
is deliberate: the alternatives (acknowledge-then-delete, grace windows)
all create a way for a message to be read twice.
