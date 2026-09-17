# Deploying SecureSend

All of these deploy the same image in the standalone shape: one instance,
messages in its memory. Pick by where you run things.

| Target | Path |
|---|---|
| Docker or a VM | the [quick start](../README.md#run-it) and [docs/deployment.md](../docs/deployment.md) |
| Docker Compose | [`compose.yaml`](../compose.yaml) at the repository root |
| Kubernetes | [`helm/securesend`](helm/securesend/), also published as `oci://ghcr.io/cyphera-labs/charts/securesend` |
| Azure | [`azure/`](azure/): Deploy to Azure button, Bicep source, Container Apps |
| AWS | [`aws/`](aws/): CloudFormation, ECS Fargate behind an ALB |
| Google Cloud | [`gcp/`](gcp/): Cloud Run, scripted |
