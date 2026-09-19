# Deploy on AWS

ECS Fargate behind an Application Load Balancer, standalone shape, standard mode by default: exactly
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
    PublicHostname=send.example.com \
    CertificateArn=arn:aws:acm:us-east-1:123456789012:certificate/... \
    CompanyName=Acme PrimaryColor='#0057b8'
```

A hostname you own and a certificate covering it are both required. The
browser performs the encryption and the Web Crypto API is unavailable outside
a secure context, so there is no useful plain HTTP deployment to offer. After
the stack is created, point that name at the load balancer using the
`PointThisNameAtTheLoadBalancer` output; the service answers on it, and the
`OidcRedirectUri` output is what you register with your identity provider.

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
- HTTP redirects to HTTPS, always.
- Task security group accepts traffic from the load balancer only; the
  container runs read-only as a non-root user.
- Trusted proxies cover the VPC's private ranges, which is where the load
  balancer's addresses live.

Every deployment or task replacement discards pending messages. Messages live
minutes to hours, so that is acceptable for the handoff use case; say so in
your runbook.
