#!/usr/bin/env bash
# Proves that what the deployment templates generate is configuration the
# service actually accepts. Rendering valid YAML is not the same thing, which
# is how an empty string reached a field that wants a URL.
#
#   deploy/check-recipes.sh path/to/cyphera-secure-send
set -euo pipefail

binary="${1:?usage: check-recipes.sh PATH_TO_BINARY}"
root="$(cd "$(dirname "$0")/.." && pwd)"
# Falls back to a container when helm is not installed, so the check runs the
# same way on a workstation and on a runner.
# shellcheck disable=SC2317
helm() {
  # type -P finds an executable only, so the function does not find itself.
  if type -P helm > /dev/null 2>&1; then
    command helm "$@"
  else
    docker run --rm -v "$root:/src" -w /src alpine/helm:latest "$@"
  fi
}
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
failures=0

note() { printf '  %s\n' "$*"; }

check_config_file() {
  local name="$1" file="$2"
  # The client secret never travels in the configuration file; it arrives as
  # an environment variable or a mounted Secret, so supply one here.
  if CYPHERA_SECURESEND__ENTERPRISE__OIDC__CLIENT_SECRET=secret \
      "$binary" check-config --config "$file" > /dev/null 2>"$work/err"; then
    note "ok    $name"
  else
    note "FAIL  $name: $(head -1 "$work/err")"
    failures=$((failures + 1))
  fi
}

# --- the chart, in both profiles it advertises -----------------------------
render() {
  local name="$1"; shift
  helm template securesend "deploy/helm/securesend" "$@" > "$work/rendered.yaml"
  python3 - "$work/rendered.yaml" "$work/$name.yaml" <<'PY'
import sys, yaml
docs = [d for d in yaml.safe_load_all(open(sys.argv[1])) if d]
cm = next(d for d in docs if d["kind"] == "ConfigMap")
open(sys.argv[2], "w").write(cm["data"]["cyphera-secure-send.yaml"])
PY
  check_config_file "chart: $name" "$work/$name.yaml"
}

echo "Chart output"
render default
render enterprise \
  --set mode=enterprise \
  --set config.server.public_base_url=https://send.example.com \
  --set config.enterprise.oidc.issuer=https://login.example.com/tenant/v2.0 \
  --set config.enterprise.oidc.client_id=app \
  --set config.enterprise.creation.allowed_domains='{example.com}' \
  --set oidc.clientSecret=secret
render external-handoff \
  --set mode=enterprise \
  --set config.server.public_base_url=https://send.example.com \
  --set config.enterprise.oidc.issuer=https://login.example.com/tenant/v2.0 \
  --set config.enterprise.oidc.client_id=app \
  --set config.enterprise.creation.allowed_domains='{example.com}' \
  --set config.enterprise.recipient.require_oidc=false \
  --set config.enterprise.recipient.require_identity_match=false \
  --set config.enterprise.recipient.external_recipients=true \
  --set oidc.clientSecret=secret

# --- every environment variable the cloud templates set --------------------
# An unknown key is refused by the configuration loader, so simply offering
# each name with a plausible value proves the name is real and the shape fits.
echo "Cloud template environment variables"
# SECTION and KEY are the placeholders the configuration guide uses to describe
# the naming scheme, not settings.
mapfile -t names < <(grep -rhoE 'CYPHERA_SECURESEND__[A-Z0-9_]+' "$root/deploy" "$root/docs" "$root/README.md" \
  | grep -vE '__(SECTION|KEY)(__|$)' | sort -u)
for name in "${names[@]}"; do
  case "$name" in
    *ALLOWED_DOMAINS) value="example.com,example.org" ;;
    *SCOPES) value="openid,profile,email" ;;
    *TRUSTED_PROXIES) value="10.0.0.0/8" ;;
    *TTL_OPTIONS_SECONDS) value="300,3600" ;;
    *_BIND) value="127.0.0.1:9091" ;;
    *PUBLIC_BASE_URL) value="https://send.example.com" ;;
    *__MODE) value="standard" ;;
    *EMAIL_CLAIM) value="email" ;;
    *__SINK) value="stdout" ;;
    *BACKEND) value="memory" ;;
    *COLORS__*) value="#0057b8" ;;
    *DEFAULT_TTL_SECONDS) value="3600" ;;
    *MEMORY_BUDGET_BYTES) value="134217728" ;;
    *MAX_PLAINTEXT_BYTES) value="65536" ;;
    *_SECONDS|*_BYTES|*_PROOFS|*_PER_MINUTE|*ITERATIONS) value="600" ;;
    *HSTS|*REQUIRE_*|*EXTERNAL_RECIPIENTS|*INCLUDE_*|*SHOW_*) value="true" ;;
    *) value="text" ;;
  esac
  if env "$name=$value" "$binary" check-config > /dev/null 2>"$work/err"; then
    note "ok    $name"
  else
    note "FAIL  $name=$value: $(head -1 "$work/err")"
    failures=$((failures + 1))
  fi
done

if [ "$failures" -gt 0 ]; then
  echo "$failures generated configuration(s) the service will not accept" >&2
  exit 1
fi
echo "All generated configurations load."
