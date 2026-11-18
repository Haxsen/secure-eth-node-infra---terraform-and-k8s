#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Load validator keystores + password into Secrets Manager (custodian flow).
#
#   scripts/load-validator-keys.sh --env hoodi --keystores ./validator_keys
#   scripts/load-validator-keys.sh --keystores ./validator_keys --bundle-only out.b64
#
# Security properties:
#   * Secret material is never passed on argv (visible in `ps`/audit logs) or
#     echoed: values are streamed to the AWS CLI via file:///dev/stdin.
#   * Only EIP-2335 keystore-*.json files are bundled. Deposit data, mnemonics
#     and anything else in the directory are ignored.
#   * Custodians need secretsmanager:PutSecretValue + kms:GenerateDataKey only.
#     The KMS key policy denies them kms:Decrypt, so they cannot read keys back.
#   * Run on an air-gapped / hardened workstation for mainnet keys.
# -----------------------------------------------------------------------------
set -euo pipefail
umask 077

usage() {
  sed -n '3,6p' "$0" | sed 's/^# \{0,1\}//'
  echo "Options: --env <name> --keystores <dir> [--region <r>] [--password-file <f>] [--bundle-only <out>] [--yes]"
  exit 2
}

env_name=""
keystore_dir=""
region="${AWS_REGION:-eu-west-1}"
password_file="${KEYSTORE_PASSWORD_FILE:-}"
bundle_only=""
assume_yes=0

while [[ $# -gt 0 ]]; do
  case "$1" in
    --env) env_name="$2"; shift 2 ;;
    --keystores) keystore_dir="$2"; shift 2 ;;
    --region) region="$2"; shift 2 ;;
    --password-file) password_file="$2"; shift 2 ;;
    --bundle-only) bundle_only="$2"; shift 2 ;;
    --yes) assume_yes=1; shift ;;
    -h | --help) usage ;;
    *) echo "unknown argument: $1" >&2; usage ;;
  esac
done

[[ -d "$keystore_dir" ]] || { echo "--keystores must be a directory" >&2; exit 2; }
[[ -n "$bundle_only" || -n "$env_name" ]] || { echo "--env is required (or --bundle-only)" >&2; exit 2; }

work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT

# --- collect and sanity-check keystores ------------------------------------------
shopt -s nullglob
files=()
for f in "$keystore_dir"/keystore-*.json; do
  name="$(basename "$f")"
  [[ "$name" =~ ^keystore-[A-Za-z0-9_.-]+\.json$ ]] || { echo "skipping oddly named file: $name" >&2; continue; }
  grep -q '"crypto"' "$f" && grep -qE '"pubkey"[[:space:]]*:[[:space:]]*"(0x)?[0-9a-fA-F]{96}"' "$f" ||
    { echo "not an EIP-2335 keystore: $name" >&2; exit 1; }
  files+=("$name")
done
((${#files[@]} > 0)) || { echo "no keystore-*.json files in $keystore_dir" >&2; exit 1; }

# --- bundle: base64(tar.gz) - the format prepare-keys.sh expects ------------------------
tar -czf "$work/bundle.tgz" -C "$keystore_dir" "${files[@]}"
base64 <"$work/bundle.tgz" | tr -d '\n' >"$work/bundle.b64"
size="$(wc -c <"$work/bundle.b64" | tr -d ' ')"
if ((size > 65536)); then
  echo "bundle is ${size} bytes; Secrets Manager's limit is 65536. Split validators across environments or load fewer keys." >&2
  exit 1
fi
echo "bundled ${#files[@]} keystore(s), ${size} bytes"

if [[ -n "$bundle_only" ]]; then
  cp "$work/bundle.b64" "$bundle_only"
  echo "wrote $bundle_only (no upload)"
  exit 0
fi

secret_prefix="eth-${env_name}"
if ((assume_yes == 0)); then
  read -r -p "Upload ${#files[@]} validator key(s) to ${secret_prefix}/validator/* in ${region}? Type the env name to confirm: " confirm
  [[ "$confirm" == "$env_name" ]] || { echo "aborted" >&2; exit 1; }
fi

# --- password: file or no-echo prompt; never on argv --------------------------------------
if [[ -n "$password_file" ]]; then
  password="$(cat "$password_file")"
else
  read -r -s -p "Keystore password: " password
  echo
fi
[[ -n "$password" ]] || { echo "empty password" >&2; exit 1; }

aws secretsmanager put-secret-value --region "$region" \
  --secret-id "${secret_prefix}/validator/keystores" \
  --secret-string "file:///dev/stdin" <"$work/bundle.b64" >/dev/null

printf '%s' "$password" | aws secretsmanager put-secret-value --region "$region" \
  --secret-id "${secret_prefix}/validator/keystore-password" \
  --secret-string "file:///dev/stdin" >/dev/null
unset password

echo "uploaded. Restart the validator to load the new set:"
echo "  kubectl -n eth-validator rollout restart statefulset/validator"
