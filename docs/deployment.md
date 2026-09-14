# Deployment

A vanilla deployment needs a process and memory. Nothing else.

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

Run it like any stateless service. What matters:

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
  recipient to the wrong one. Clustering arrives with the Redis backend.
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

Every release ships signed binaries, a signed multi-arch image, CycloneDX and
SPDX SBOMs, and build provenance attestations. The release notes carry the
`cosign verify-blob` command and the image digest.
