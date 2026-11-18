#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Manage RPC gateway API keys. Only SHA-256 hashes are stored; the plaintext
# key is shown exactly once, at creation.
#
#   scripts/manage-api-keys.sh <env> add    <tenant>   # prints the new key once
#   scripts/manage-api-keys.sh <env> revoke <tenant>   # removes all keys of tenant
#   scripts/manage-api-keys.sh <env> list              # tenant names only
#
# Gateways pick up changes within ~2.5 minutes (CSI rotation 2m + reload 30s),
# no restart required. Requires: aws, jq, openssl.
# -----------------------------------------------------------------------------
set -euo pipefail

env_name="${1:?usage: $0 <env> add|revoke|list [tenant]}"
action="${2:?usage: $0 <env> add|revoke|list [tenant]}"
tenant="${3:-}"
region="${AWS_REGION:-eu-west-1}"
secret_id="eth-${env_name}/rpc-gateway/api-keys"

sha256() {
  if command -v sha256sum >/dev/null; then sha256sum | cut -d' ' -f1; else shasum -a 256 | cut -d' ' -f1; fi
}

errf="$(mktemp)"
trap 'rm -f "$errf"' EXIT

# Treat ONLY "no value stored yet" as empty. Any other failure (expired creds,
# AccessDenied, throttling) must abort - otherwise the next write would
# silently replace every tenant's keys with a single new one.
current() {
  if aws secretsmanager get-secret-value --region "$region" --secret-id "$secret_id" \
    --query SecretString --output text 2>"$errf"; then
    return 0
  fi
  if grep -q 'ResourceNotFoundException' "$errf"; then
    echo '{}'
    return 0
  fi
  cat "$errf" >&2
  return 1
}

store() {
  jq -c . | aws secretsmanager put-secret-value --region "$region" --secret-id "$secret_id" \
    --secret-string "file:///dev/stdin" >/dev/null
}

case "$action" in
  add)
    [[ "$tenant" =~ ^[a-z0-9][a-z0-9-]{1,62}$ ]] || { echo "tenant must match ^[a-z0-9][a-z0-9-]{1,62}$" >&2; exit 2; }
    key="rpc_$(openssl rand -hex 24)"
    hash="$(printf '%s' "$key" | sha256)"
    current | jq --arg h "$hash" --arg n "$tenant" '. + {($h): $n}' | store
    echo "API key for '${tenant}' (shown once, store it in the tenant's secret manager):" >&2
    echo "$key"
    ;;
  revoke)
    [[ -n "$tenant" ]] || { echo "tenant required" >&2; exit 2; }
    current | jq --arg n "$tenant" 'with_entries(select(.value != $n))' | store
    echo "revoked all keys of '${tenant}'" >&2
    ;;
  list)
    current | jq -r '[.[]] | group_by(.) | map("\(.[0])\t\(length) key(s)") | .[]'
    ;;
  *)
    echo "unknown action: $action" >&2
    exit 2
    ;;
esac
