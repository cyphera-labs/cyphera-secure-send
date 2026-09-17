# Deploy on AWS

ECS Fargate behind an Application Load Balancer, standalone shape, eval mode by default: exactly
one task, messages in its memory, deployments that replace rather than
overlap, the management port bound to the task's loopback only.

```
aws cloudformation deploy \
  --stack-name securesend \
  --template-file securesend-standalone.yaml \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    VpcId=vpc-0123456789abcdef0 \
    PublicSubnetIds=subnet-aaaa,subnet-bbbb \
    CertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/... \
    CompanyName=Acme PrimaryColor='#0057b8'
```

Outputs give the URL and the OIDC redirect URI. Point your own domain at the
load balancer for production; the certificate must cover that name.

Enterprise mode, with Entra ID (see [docs/identity.md](../../docs/identity.md)):

```
    Mode=enterprise \
    OidcIssuer=https://login.microsoftonline.com/<tenant-id>/v2.0 \
    OidcClientId=<application-id> \
    OidcClientSecret=<secret> \
    AllowedDomains=example.com
```

The template refuses enterprise mode without a certificate, an issuer, a client id,
and a secret. The secret is stored in Secrets Manager and injected into the
task; it never appears in the task definition.

## Launch Stack button

CloudFormation's quick-create link needs the template in an S3 bucket, so a
button appears here once the release process publishes the template to one.
Until then, the command above is the path.

## What the template pins, and why

- `DesiredCount: 1` with `MinimumHealthyPercent: 0` and `MaximumPercent: 100`:
  a deployment stops the old task before starting the new one, so two
  memory-backed tasks never run at once.
- HTTP redirects to HTTPS when a certificate is given; without one the stack
  serves plain HTTP for evaluation only.
- Task security group accepts traffic from the load balancer only; the
  container runs read-only as a non-root user.
- Trusted proxies cover the VPC's private ranges, which is where the load
  balancer's addresses live.

Every deployment or task replacement discards pending messages. Messages live
minutes to hours, so that is acceptable for the handoff use case; say so in
your runbook.
