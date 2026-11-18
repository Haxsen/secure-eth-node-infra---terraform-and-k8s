#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Generate a fresh 32-byte Engine API JWT secret and store it in Secrets Manager.
#
#   scripts/put-jwt-secret.sh <env> [region]
#
# The value is generated and streamed straight into the AWS CLI: it is never
# printed, written to disk, or passed on argv. geth and Lighthouse read the
# file only at start-up, so restart the eth-node pods after rotating:
#   kubectl -n eth-nodes rollout restart statefulset/eth-node
# -----------------------------------------------------------------------------
set -euo pipefail

env_name="${1:?usage: $0 <env> [region]}"
region="${2:-${AWS_REGION:-eu-west-1}}"

openssl rand -hex 32 | tr -d '\n' | aws secretsmanager put-secret-value --region "$region" \
  --secret-id "eth-${env_name}/jwt-secret" \
  --secret-string "file:///dev/stdin" >/dev/null

echo "stored new JWT secret in eth-${env_name}/jwt-secret (${region})"
