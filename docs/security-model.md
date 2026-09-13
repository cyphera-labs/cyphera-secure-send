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

- ciphertext obtained from the server (memory dump, a future Redis snapshot)
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
6. The configured number of wrong proofs destroys the message.
7. Removal happens before the response is built. A connection that drops
   after that point loses the message.
8. Memory is bounded. When the budget is exceeded the least valuable entries
   are evicted and each eviction is audited.
9. A restart discards every pending message. Nothing is written to disk.
10. Audit events cannot carry secrets: the event type has no field for them.
11. Every response, including static files and 404s, carries `no-store`,
    `no-referrer`, `nosniff`, and a Content Security Policy with no
    `unsafe-*` source.
12. Nothing is loaded from a third-party origin.
13. Request bodies are size-limited before they are parsed.
14. Only JSON bodies with `Content-Type: application/json` are accepted, and
    there is no CORS policy, so a cross-origin page cannot make the API do
    anything: the preflight fails.

## Threat model

| Threat | Covered | How |
|---|---|---|
| Passive observer on the network | yes | TLS, and nothing useful in URLs anyway |
| Server operator, memory dump, future Redis snapshot | yes | ciphertext, hashes, and a verifier that cannot be attacked without the link |
| Link intercepted, password not | yes | the proof cannot be derived; wrong proofs are counted and the message burns |
| Password intercepted, link not | yes | nothing to attack |
| Link and ciphertext both obtained | partly | bounded by password strength and PBKDF2 cost; the interface offers a generated password |
| Recipient double-read, replay | yes | atomic take |
| Two recipients racing | yes | one wins, one gets the generic response |
| Probing whether an id exists | yes | identical responses; 2^128 id space |
| Flooding to exhaust memory | yes | per-client create limit, weight budget, eviction |
| Spoofed client address | yes | `X-Forwarded-For` honored only from configured proxy networks |
| Cross-site request forgery | yes | JSON-only API, no CORS |
| Cross-site scripting | yes | no inline script or style, all text set via DOM APIs |
| Hosting malware or phishing content | partly | text only, small size limit; enterprise mode will close anonymous creation |
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
