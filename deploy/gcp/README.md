# Deploy on Google Cloud

Cloud Run, standalone shape, eval mode by default: exactly one instance, never scaled to zero,
messages in its memory.

```
gcloud run deploy securesend \
  --image ghcr.io/cyphera-labs/cyphera-secure-send:latest \
  --region us-central1 \
  --platform managed \
  --port 8080 \
  --min-instances 1 --max-instances 1 \
  --concurrency 80 \
  --memory 512Mi --cpu 1 \
  --allow-unauthenticated \
  --set-env-vars "CYPHERA_SECURESEND__SERVER__HSTS=true,\
CYPHERA_SECURESEND__SERVER__MANAGEMENT_BIND=127.0.0.1:9090,\
CYPHERA_SECURESEND__SERVER__TRUSTED_PROXIES=0.0.0.0/0,\
CYPHERA_SECURESEND__BRANDING__COMPANY_NAME=Acme"
```

Then set the public base URL to the URL the deploy printed and redeploy with
`--update-env-vars CYPHERA_SECURESEND__SERVER__PUBLIC_BASE_URL=https://...`,
or map a custom domain first and use that.

Cloud Run terminates TLS and forwards the client address in
`X-Forwarded-For` from its own front end, which is why trusted proxies is set
to everything here: the only peer the container ever sees is Cloud Run's
proxy. Do not use that setting anywhere the container is reachable directly.

Enterprise mode: store the client secret in Secret Manager and reference it:

```
  --set-secrets "CYPHERA_SECURESEND__AUTH__OIDC__CLIENT_SECRET=securesend-oidc-secret:latest" \
  --set-env-vars "CYPHERA_SECURESEND__MODE=enterprise,\
CYPHERA_SECURESEND__AUTH__OIDC__ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0,\
CYPHERA_SECURESEND__AUTH__OIDC__CLIENT_ID=<application-id>,\
CYPHERA_SECURESEND__AUTH__OIDC__ALLOWED_DOMAINS=example.com"
```

`--allow-unauthenticated` refers to Cloud Run's own IAM check on the
endpoint, not to SecureSend's sign-in; the service still requires sign-in
in enterprise mode.

## Why one instance and no scale-to-zero

Messages live in process memory. A second instance would hold its own set,
and scaling to zero would discard everything pending. `--min-instances 1
--max-instances 1` pins both. Cloud Run may still replace the instance on a
new revision or during maintenance; pending messages are lost then. Messages
live minutes to hours, so that is acceptable for the handoff use case.
