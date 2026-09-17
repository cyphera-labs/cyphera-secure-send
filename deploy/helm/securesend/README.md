# SecureSend Helm chart

Deploys Cyphera SecureSend in its standalone shape: one replica, messages in
process memory, `Recreate` strategy, the management port kept off the public
Service, and a hardened pod (non-root, read-only root filesystem, no
capabilities).

```
helm install securesend oci://ghcr.io/cyphera-labs/charts/securesend \
  --set config.server.public_base_url=https://send.example.com \
  --set config.branding.company_name=Acme
```

## Values that matter

| Value | Default | Notes |
|---|---|---|
| `config.*` | see `values.yaml` | rendered into the configuration file; every key in [docs/configuration.md](../../../docs/configuration.md) |
| `config.server.public_base_url` | `""` | required for OIDC; decides Secure cookies |
| `config.server.trusted_proxies` | `[]` | ingress and pod CIDRs, so rate limits and audit see the client address |
| `config.auth.mode` | `anonymous` | `oidc` for enterprise mode; see [docs/identity.md](../../../docs/identity.md) |
| `oidc.existingSecret` / `oidc.clientSecret` | `""` | Secret with key `client-secret`, or an inline value (stored in a chart-managed Secret) |
| `branding.existingConfigMap` + `logoFile` / `faviconFile` | `""` | ConfigMap holding the files, mounted at `/branding` |
| `ingress.*` | disabled | standard Ingress; terminate TLS there |
| `management.service.enabled` | `false` | ClusterIP for the management port; `serviceMonitor.enabled` adds a Prometheus Operator target |
| `resources.limits.memory` | `512Mi` | keep headroom above `config.messages.memory_budget_bytes` |

## Rules the chart enforces

- `replicaCount` must be 1 with the memory backend. A second replica would
  hold its own, separate messages, and a load balancer would send recipients
  to the wrong one. The chart fails to render otherwise.
- `auth.mode: oidc` requires `config.server.public_base_url` and a client
  secret from one of the two sources.
- A configuration change rolls the pod (checksum annotation). Pending
  messages are lost on every roll; messages live minutes to hours, so plan
  upgrades accordingly.

## Verify

```
helm lint deploy/helm/securesend
helm template securesend deploy/helm/securesend --set config.server.public_base_url=https://send.example.com
```
