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
  the image). Readiness turns to 503 the moment shutdown starts.
- **Shutdown.** SIGTERM drains for `server.shutdown_timeout_seconds`, then
  exits. Pending messages are discarded on every restart, by design, so
  a rolling deploy loses messages that have not been read. Say so in your
  runbook.
- **Memory.** `messages.memory_budget_bytes` bounds ciphertext; the process
  needs roughly that plus 64 MiB. Set the container limit accordingly.
- **Replicas.** One. The memory backend is per-process; a second replica has
  its own, separate set of messages, and a load balancer would send the
  recipient to the wrong one. Set minimum and maximum replicas both to 1 and
  use a `Recreate` strategy, because a rolling update runs two copies for a
  moment and the old one takes its messages with it. One process covers a
  large organization: the default budget holds thousands of maximum-size
  messages, and a restart takes well under a second.
- **Proxy.** Set `server.trusted_proxies` to your ingress's address range so
  rate limiting and audit see the real client address.
- **TLS.** Terminate at the ingress, or set `server.tls.cert_path` and
  `server.tls.key_path` to terminate in-process. Enable `server.hsts` once
  HTTPS is in place.

## Health and stats

All on the management port. None of these are reachable from the public listener,
because they reveal how much traffic the service carries.

| Endpoint | What it is for |
|---|---|
| `GET /livez` | process is alive; always `200` |
| `GET /readyz` | `200` while serving, `503` once shutdown has begun; wire this to the orchestrator |
| `GET /v1/health` | JSON: status, readiness, version, uptime, and store occupancy (active messages, used and budget bytes, percent) |
| `GET /v1/stats` | JSON: the same store view plus lifecycle totals since start (created, consumed, consume_failed, burned, revoked, expired, evicted, access_denied, rate_limited) and the effective limits |
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
| `securesend_messages_evicted_total` | counter |
| `securesend_messages_access_denied_total` | counter |
| `securesend_rate_limited_total{endpoint}` | counter |
| `securesend_messages_active` | gauge |
| `securesend_store_bytes` | gauge |
| `securesend_store_budget_bytes` | gauge |

## Audit events

One JSON object per line on stdout. Types:

`message.created`, `message.consumed`, `message.consume_failed`,
`message.burned`, `message.revoked`, `message.expired`, `message.evicted`,
`message.access_denied`, `rate_limited`, `server.started`, `server.stopping`.

Fields (present when relevant): `event_id`, `type`, `time`, `outcome`,
`reason`, `message_id`, `sender`, `recipient`, `ttl_seconds`, `expires_at`,
`failed_proofs`, `client_ip`, `user_agent`, `active_messages`.

`reason` values: `not_found`, `wrong_proof`, `wrong_revoke_token`, `burned`,
`unauthorized`, `create`, `consume`, `revoke`.

## Air-gapped

The binary and the image have no runtime network dependencies of their own.
The interface loads nothing from outside the service.

## Verifying a release

Every release ships signed binaries, a signed multi-architecture image,
CycloneDX and SPDX SBOMs, and build provenance attestations. Each signed file
has a `.sigstore.json` bundle beside it; the release notes carry the exact
`cosign verify-blob` command and the image digest.
