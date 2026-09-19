# Deploy on Google Cloud

Cloud Run, standalone shape, standard mode by default: exactly one instance, never scaled to zero,
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
CYPHERA_SECURESEND__SERVER__TRUSTED_HOPS=1,\
CYPHERA_SECURESEND__BRANDING__COMPANY_NAME=Acme"
```

Then set the public base URL to the URL the deploy printed and redeploy with
`--update-env-vars CYPHERA_SECURESEND__SERVER__PUBLIC_BASE_URL=https://...`,
or map a custom domain first and use that.

Cloud Run terminates TLS and appends its own entry to `X-Forwarded-For`, and
its front-end addresses are not published, so there is no network to name as
trusted. `TRUSTED_HOPS=1` says instead that exactly one entry at the end of
that header was added by infrastructure in front of this service, and the
client is the entry before it. Trusting every address would have the opposite
effect: the resolver would skip the whole chain and fall back to the platform
proxy, putting every client in one rate-limit bucket.

Set this only where the container cannot be reached directly. Anywhere a
client can connect straight to it, a forged header would be believed.

Enterprise mode: store the client secret in Secret Manager and reference it:

```
  --set-secrets "CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_SECRET=securesend-oidc-secret:latest" \
  --set-env-vars "CYPHERA_SECURESEND__MODE=enterprise,\
CYPHERA_SECURESEND__ENTERPRISE__OIDC__ISSUER=https://login.microsoftonline.com/<tenant-id>/v2.0,\
CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_ID=<application-id>,\
CYPHERA_SECURESEND__ENTERPRISE__CREATION__ALLOWED_DOMAINS=example.com"
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
