# Branding

Make it look like yours in a few lines. No CSS, no rebuild.

```yaml
branding:
  product_name: SecureSend
  company_name: Acme
  tagline: Share credentials with colleagues, once.
  logo_path: /config/logo.svg
  favicon_path: /config/favicon.png
  support_url: https://help.acme.example/securesend
  footer_text: For authorized Acme personnel only.
  show_powered_by: true
  colors:
    primary: "#0057b8"
    on_primary: "#ffffff"
    secondary: "#00a9ce"
    surface: "#ffffff"
    on_surface: "#1a1c1e"
    surface_variant: "#e0e3e7"
    error: "#ba1a1a"
```

Or with environment variables:

```
CYPHERA_SECURESEND__BRANDING__COMPANY_NAME=Acme
CYPHERA_SECURESEND__BRANDING__COLORS__PRIMARY=#0057b8
CYPHERA_SECURESEND__BRANDING__LOGO_PATH=/config/logo.svg
```

The header shows the logo (if any), then `company_name product_name`. The
browser tab uses the same. `tagline` sits under the heading on the compose
page. The footer shows `footer_text`, a `Help` link to `support_url`, and
`Powered by Cyphera SecureSend` unless `show_powered_by` is false.

## Colors

Seven Material 3 roles. Values must be `#rgb` or `#rrggbb`; anything else is
refused at startup. Container and outline tones are derived from these, so
setting `primary`, `surface`, and `on_surface` is usually enough.

| Role | Used for |
|---|---|
| `primary` / `on_primary` | the main button, links, the company name |
| `secondary` | tonal buttons and the warning notices |
| `surface` / `on_surface` | page background and text |
| `surface_variant` | reserved for future use |
| `error` | validation and failure notices |

## Logo and favicon

`logo_path` and `favicon_path` point at files on the server's filesystem.
Allowed types: SVG, PNG, JPEG, WebP, ICO. Limit 2 MiB each. They are read
once at startup and served from memory at `/brand/logo` and `/brand/favicon`;
no other file on disk is reachable. Mount them read-only:

```yaml
volumes:
  - ./branding:/config:ro
```
