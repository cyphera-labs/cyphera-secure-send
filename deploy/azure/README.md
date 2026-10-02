# Deploy to Azure

Azure Container Apps, standalone shape, standard mode by default: exactly one
instance, messages in its memory, HTTPS from the platform, the management
port private. Try the whole product in your own subscription without an
identity provider; switch to enterprise mode when it is real.

[![Deploy to Azure](https://aka.ms/deploytoazurebutton)](https://portal.azure.com/#create/Microsoft.Template/uri/https%3A%2F%2Fraw.githubusercontent.com%2Fcyphera-labs%2Fcyphera-secure-send%2Fmain%2Fdeploy%2Fazure%2Fazuredeploy.json)

The button opens the portal with `azuredeploy.json`. Fill in a resource
group, a region, a name, and optionally branding and identity settings. It
creates a Log Analytics workspace, a Container Apps environment, and the app,
and prints the URL and the OIDC redirect URI in the outputs.

From the command line instead:

```
az group create -n securesend -l eastus2
az deployment group create -g securesend -f main.bicep \
  -p companyName=Acme primaryColor='#0057b8'
```

Enterprise mode, with Entra ID (see [docs/identity.md](../../docs/identity.md)):

```
az deployment group create -g securesend -f main.bicep \
  -p mode=enterprise \
     oidcIssuer=https://login.microsoftonline.com/<tenant-id>/v2.0 \
     oidcClientId=<application-id> \
     oidcClientSecret=<secret> \
     allowedDomains=example.com
```

Register the `oidcRedirectUri` output at the app registration afterwards;
the URL is only known once the app exists. To use your own domain, add a
custom domain to the Container App and set `public_base_url` to it by
redeploying with the same parameters (the template derives it from the
default domain).

## What the template pins, and why

- `minReplicas: 1`, `maxReplicas: 1`, single revision mode: the memory
  backend cannot be shared and must not scale to zero.
- `allowInsecure: false`: HTTPS only, HSTS on.
- Trusted proxies cover the environment's internal ranges so rate limiting
  and audit see real client addresses.
- The client secret is a Container Apps secret, referenced by the
  environment variable, never a plain value.

Every deployment or platform replacement of the instance discards pending
messages. Messages live minutes to hours, so that is acceptable for the
handoff use case; say so in your runbook.

## Keeping `azuredeploy.json` current

`main.bicep` is the source. The button needs ARM JSON, so the compiled file
is committed and CI checks it matches:

```
bicep build main.bicep --outfile azuredeploy.json
```
