# Deployment

A vanilla deployment needs a process and memory. Nothing else.

**What kind of thing you are running.** SecureSend is diskless and ephemeral,
but it is not stateless: every pending message lives in the RAM of one
process. That is the design, and it has one consequence you must plan for:
anything that stops or replaces that process, a deploy, a restart, a platform
maintenance event, discards every message that has not been read yet. Senders
create a new link; nothing is recoverable. This document calls that shape a
**standalone deployment**, and everything below describes it.

## Binary

```
./cyphera-secure-send serve
```

Listens on `:8080` for users and `127.0.0.1:9090` for probes and metrics.
Audit events go to stdout as JSON lines; logs go to stderr.

## Container

```
docker run --rm -p 8080:8080 ghcr.io/cyphera-labs/cyphera-secure-send:latest
```

The image is a single binary on a minimal glibc base with no shell, running as
`nonroot`. It works with a read-only root filesystem, dropped capabilities, and
`no-new-privileges`. See `compose.yaml` for a hardened example with branding
mounted from `./config`.

## Kubernetes

The Helm chart at [`deploy/helm/securesend`](../deploy/helm/securesend/),
also published as `oci://ghcr.io/cyphera-labs/charts/securesend`, encodes
everything below and refuses more than one replica with the memory backend:

```
helm install securesend oci://ghcr.io/cyphera-labs/charts/securesend \
  --set config.server.public_base_url=https://send.example.com
```

Rolling your own instead: a single-replica Deployment with a `Recreate`
strategy. What matters:

- **Probes.** `GET /livez` and `GET /readyz` on the management port (9090 in
  the image). Readiness turns to 503 the moment shutdown starts. Note that
  the image binds that port on all interfaces, not the loopback default the
  configuration reference gives, because a probe from outside the container
  cannot reach loopback. It is still a private port: publish or route only
  8080, and keep 9090 to the pod network. `/metrics` and `/v1/stats` carry
  no secrets but describe the service to anyone who can reach them.
- **Shutdown.** SIGTERM drains for `server.shutdown_timeout_seconds`, then
  exits. Pending messages are discarded on every restart, by design, so
  a rolling deploy loses messages that have not been read. Say so in your
  runbook.
- **Memory.** `messages.memory_budget_bytes` bounds ciphertext; the process
  needs roughly that plus 64 MiB. Set the container limit accordingly.
- **Replicas.** One, with the memory backend: it is per-process, a second
  replica has its own separate set of messages, and a load balancer would
  send the recipient to the wrong one. Set minimum and maximum replicas both
  to 1 and use a `Recreate` strategy, because a rolling update runs two
  copies for a moment and the old one takes its messages with it. For more
  than one replica, see the shared store below. One process covers a
  large organization: the default budget holds thousands of maximum-size
  messages, and a restart takes well under a second.
- **Proxy.** Set `server.trusted_proxies` to your ingress's address range so
  rate limiting and audit see the real client address. Where those addresses
  are not knowable, as on a managed platform, set `server.trusted_hops` to
  the number of entries your own infrastructure appends instead.
- **TLS.** Terminate at the ingress, or set `server.tls.cert_path` and
  `server.tls.key_path` to terminate in-process. Enable `server.hsts` once
  HTTPS is in place.

## Shared store

Point the service at a Redis and it stops being one process: any number of
replicas serve the same messages and sessions, a message created on one is
read on another, and a restart of the service loses nothing. Use a Redis you
already operate or rent, such as Azure Cache for Redis, Amazon ElastiCache,
or Google Memorystore, over `rediss://` where the network is not yours.

```sh
helm install securesend oci://ghcr.io/cyphera-labs/charts/securesend \
  --set storage.backend=redis \
  --set storage.redis.existingSecret=redis-url \
  --set replicaCount=3
```

That names a Secret, here called `redis-url`, holding the URL under the key
`url`, password included. The chart switches to a rolling update, since
replicas are now interchangeable.

What to know:

- **Configure Redis with `maxmemory-policy noeviction`.** The service
  enforces its own budget and refuses a message that does not fit; it never
  wants Redis to discard one it accepted.
- **Rate limits are per replica.** Each process keeps its own buckets, so
  three replicas allow three times the configured rate in aggregate. Divide
  accordingly, or leave the per-message and per-identity limits to do the
  work.
- **Statistics are per replica** for lifecycle totals; the store figures
  (active messages, bytes) are shared and the same from every replica.
- **Expiry is Redis's.** Keys carry the message's expiry and Redis removes
  them on time. The `message.expired` audit event is emitted by whichever
  replica's housekeeping notices, and carries the message id only, since
  the message itself is already gone.
- **Not Redis Cluster.** The store's scripts touch keys under one prefix
  that do not share a slot. A single instance, a replicated pair with
  failover, or a managed service in that shape.
- **The URL is a secret.** It carries the password. Use `url_file` or the
  environment, and `rediss://` on any network you do not own.

## Health and stats

All on the management port. None of these are reachable from the public listener,
because they reveal how much traffic the service carries.

| Endpoint | What it is for |
|---|---|
| `GET /livez` | process is alive; always `200` |
| `GET /readyz` | `200` while serving, `503` once shutdown has begun; wire this to the orchestrator |
| `GET /v1/health` | JSON: status, readiness, version, uptime, and store occupancy (active messages, used and budget bytes, percent) |
| `GET /v1/stats` | JSON: the same store view plus lifecycle totals since start (created, consumed, consume_failed, burned, revoked, expired, evicted, access_denied, rate_limited) and the effective limits |
| `POST /v1/sessions/revoke` | enterprise mode: ends every session one account holds, now. Body `{"subject": "..."}` or `{"email": "..."}`; answers with how many were ended. Pair it with disabling the account at the provider, which stops the next sign-in |
| `GET /metrics` | Prometheus text format |

`/v1/stats` is what a dashboard or a runbook check should read. Totals reset when the process restarts, like everything else here.

The public listener's `GET /v1/health` answers only `{"status":"ok"}`.

## Managed container platforms

Ready-made templates for each, all pinned to one instance:
[Azure Container Apps](../deploy/azure/) with a Deploy to Azure button,
[AWS ECS Fargate](../deploy/aws/) as CloudFormation, and
[Google Cloud Run](../deploy/gcp/) as a scripted deploy.

The same single-process rule applies, and each platform has a default that
works against it:

| Platform | Default to change | Why |
|---|---|---|
| Azure Container Apps | min replicas 0, max 10 | scale-to-zero discards messages; scale-out splits them; the platform may briefly run extra replicas during maintenance |
| Google Cloud Run | scales to zero; max instances is a soft limit | same: pin min and max instances to 1, and accept that a revision rollout replaces the instance |
| AWS ECS on Fargate | service deployments start the replacement before stopping the old task | set minimum healthy percent to 0 and maximum to 100 so only one task ever runs, and expect task replacement on platform maintenance |

Whichever platform, serve it over HTTPS on a name you own: the browser does
the encryption, and the Web Crypto API is unavailable outside a secure
context, so a plain HTTP deployment cannot work at all beyond localhost.

In enterprise mode, sessions and in-progress sign-ins live in the same process
memory, so the single-instance rule covers them too: a second instance would
not know who signed in at the first.

On all three, pending messages are lost on every deploy and every platform
replacement. That is acceptable for the handoff use case, where a message
lives minutes to hours, but say so in your runbook.

## Metrics

`GET /metrics` on the management port, Prometheus text format.

| Metric | Type |
|---|---|
| `securesend_messages_created_total` | counter |
| `securesend_messages_consumed_total` | counter |
| `securesend_messages_consume_failed_total` | counter |
| `securesend_messages_burned_total` | counter |
| `securesend_messages_revoked_total` | counter |
| `securesend_messages_expired_total` | counter |
| `securesend_messages_evicted_total` | counter | should stay at zero: the store refuses at the door rather than evicting |
| `securesend_audit_dropped_total` | counter | audit lines dropped because the output could not keep up; anything above zero means the collector stalled |
| `securesend_auth_logins_total` | counter | enterprise mode: completed sign-ins |
| `securesend_auth_failures_total` | counter | enterprise mode: sign-ins refused |
| `securesend_sessions_revoked_total` | counter | enterprise mode: sessions ended by an operator |
| `securesend_messages_access_denied_total` | counter |
| `securesend_rate_limited_total{endpoint}` | counter |
| `securesend_messages_active` | gauge |
| `securesend_store_bytes` | gauge |
| `securesend_store_budget_bytes` | gauge |

## Audit events

One JSON object per line on stdout. Types:

`message.created`, `message.consumed`, `message.consume_failed`,
`message.burned`, `message.revoked`, `message.expired`, `message.evicted`,
`auth.sessions_revoked`,
`message.access_denied`, `rate_limited`, `server.started`, `server.stopping`.

Fields (present when relevant): `event_id`, `type`, `time`, `outcome`,
`reason`, `message_id`, `sender`, `recipient`, `ttl_seconds`, `expires_at`,
`failed_proofs`, `client_ip`, `user_agent`, `active_messages`, and in
enterprise mode `subject` and `issuer`.

Three fields say what each party proved rather than lumping them together:
`sender_authenticated` is whether the sender's address came from the identity
provider, carried on the message so a retrieval reports it truthfully;
`reader_authenticated` is whether the reader signed in; and
`recipient_binding_enforced` is whether the reader had to be the address the
message names.

`reason` values: `not_found`, `wrong_proof`, `wrong_revoke_token`, `burned`,
`unauthorized`, `create`, `consume`, `revoke`.

## Air-gapped

The binary and the image have no runtime network dependencies of their own.
The interface loads nothing from outside the service.

## Verifying a release

Every release ships signed binaries, a signed multi-architecture image, a
signed Helm chart, CycloneDX and SPDX SBOMs, and build provenance
attestations. Each signed file has a `.sigstore.json` bundle beside it; the
release notes carry the exact `cosign verify-blob` command, the image
digest, and the chart digest with the `cosign verify` command for each.
Install the chart by the digest you verified rather than by version:

```sh
helm install securesend oci://ghcr.io/cyphera-labs/charts/securesend@sha256:<digest>
```
