#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Render Terraform outputs into the overlay's cluster-config.env so kustomize
# can inject IRSA role ARNs, the WAF ACL, certificate and ALB subnet CIDRs.
#
#   scripts/sync-tf-outputs.sh <env>
#
# Run after `terraform apply` for that environment (backend already initialised).
# -----------------------------------------------------------------------------
set -euo pipefail

env_name="${1:?usage: $0 <env>}"
root="$(cd "$(dirname "$0")/.." && pwd)"
out="$root/k8s/overlays/${env_name}/cluster-config/cluster-config.env"

[[ -d "$(dirname "$out")" ]] || { echo "no overlay for '${env_name}'" >&2; exit 1; }

terraform -chdir="$root/terraform/platform" output -json k8s_cluster_config |
  jq -r 'to_entries | sort_by(.key) | .[] | "\(.key)=\(.value)"' >"$out.tmp"

grep -q '^ACM_CERTIFICATE_ARN=arn:' "$out.tmp" ||
  echo "warning: ACM_CERTIFICATE_ARN is empty - set acm_certificate_arn in envs/${env_name}.tfvars" >&2

mv "$out.tmp" "$out"
echo "wrote ${out#"$root"/}"
echo "review with: kubectl kustomize k8s/overlays/${env_name} | less"
