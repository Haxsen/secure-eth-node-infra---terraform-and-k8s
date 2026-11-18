#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Init container: turn the CSI-mounted secret bundle into a Lighthouse
# validator_definitions.yml without keystores ever touching persistent disk.
#
# In  (tmpfs, read-only, from Secrets Manager via Secrets Store CSI):
#   /secrets/keystores.tar.gz.b64   base64( tar.gz of keystore-*.json )
#   /secrets/keystore-password      password shared by the keystores
# Out:
#   /keys/keystores/*.json          EIP-2335 keystores on an in-memory emptyDir
#   /data/validators/validator_definitions.yml
#                                   on the PVC; holds only public keys + paths
#
# What persists on the (CMK-encrypted) PVC:
#   - this definitions file (public keys + tmpfs paths)
#   - Lighthouse's slashing-protection database
#   - Lighthouse's validator_key_cache.json: the keys re-encrypted with the
#     keystore password (scrypt n=2^18 + AES-128-CTR, i.e. EIP-2335 strength).
#     Lighthouse writes it atomically and has no switch to disable it; the
#     password that unlocks it exists only in Secrets Manager and tmpfs.
# Plaintext keys and the keystore files themselves never reach the PVC
# (asserted by tests/validator/run.sh).
# -----------------------------------------------------------------------------
set -euo pipefail
umask 077

readonly BUNDLE=/secrets/keystores.tar.gz.b64
readonly PASSWORD_FILE=/secrets/keystore-password
readonly KEY_DIR=/keys/keystores
readonly ARCHIVE=/keys/bundle.tar.gz
readonly DEFS_DIR=/data/validators
readonly DEFS_FILE="${DEFS_DIR}/validator_definitions.yml"

die() {
  echo "prepare-keys: $*" >&2
  exit 1
}

[[ -s "$BUNDLE" ]] || die "keystore bundle missing or empty - has scripts/load-validator-keys.sh been run?"
[[ -s "$PASSWORD_FILE" ]] || die "keystore password missing or empty"

mkdir -p "$KEY_DIR" "$DEFS_DIR"
base64 -d "$BUNDLE" >"$ARCHIVE" 2>/dev/null || die "keystore bundle is not valid base64"

# Defence against a tampered bundle: only a flat list of regular files named
# keystore-*.json may come out of it. No directories, symlinks, hard links,
# devices, absolute paths or "..".
while IFS= read -r entry; do
  [[ "${entry:0:1}" == "-" ]] || die "bundle contains a non-regular file: ${entry}"
done < <(tar -tvzf "$ARCHIVE")

while IFS= read -r name; do
  [[ "$name" =~ ^keystore-[A-Za-z0-9_.-]+\.json$ ]] || die "unexpected entry in bundle: ${name}"
done < <(tar -tzf "$ARCHIVE")

tar -xzf "$ARCHIVE" -C "$KEY_DIR" --no-same-owner --no-same-permissions
rm -f "$ARCHIVE"

declare -A seen=()
count=0
tmp="$(mktemp "${DEFS_DIR}/.validator_definitions.XXXXXX")"

{
  echo "---"
  for keystore in "$KEY_DIR"/keystore-*.json; do
    [[ -f "$keystore" ]] || continue

    pubkey="$(grep -oE '"pubkey"[[:space:]]*:[[:space:]]*"(0x)?[0-9a-fA-F]{96}"' "$keystore" |
      grep -oE '[0-9a-fA-F]{96}' | head -n1 || true)"
    [[ -n "$pubkey" ]] || die "no BLS pubkey found in $(basename "$keystore")"

    pubkey="${pubkey,,}"
    [[ -z "${seen[$pubkey]:-}" ]] || die "duplicate keystore for 0x${pubkey:0:12}... - refusing to load the same key twice"
    seen[$pubkey]=1

    printf -- '- enabled: true\n'
    printf -- '  type: local_keystore\n'
    printf -- '  voting_public_key: "0x%s"\n' "$pubkey"
    printf -- '  voting_keystore_path: "%s"\n' "$keystore"
    printf -- '  voting_keystore_password_path: "%s"\n' "$PASSWORD_FILE"

    count=$((count + 1))
  done
} >"$tmp"

((count > 0)) || die "bundle contained no keystore-*.json files"

mv -f "$tmp" "$DEFS_FILE"
echo "prepare-keys: rendered ${count} validator definition(s); keystores are held in memory only"
