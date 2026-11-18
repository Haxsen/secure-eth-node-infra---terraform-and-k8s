#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# End-to-end test of the validator key path, using the exact pinned Lighthouse
# image and the pod's hardening (uid 10001, read-only rootfs, no capabilities):
#
#   1. Generate real EIP-2335 keystores (public BIP-39 *test* mnemonic).
#   2. Bundle them with scripts/load-validator-keys.sh --bundle-only.
#   3. Run prepare-keys.sh as the init container would.
#   4. Start the validator client with keys on a READ-ONLY in-memory volume and
#      check it decrypts and enables every key.
#   5. Check the fail-safe: a fresh data volume WITHOUT the explicit
#      INIT_SLASHING_PROTECTION toggle must refuse to start.
#   6. Check tampered bundles are rejected (symlink, foreign file, duplicate key).
#
# Requires: docker, bash. Usage: tests/validator/run.sh
# -----------------------------------------------------------------------------
set -euo pipefail
export MSYS_NO_PATHCONV=1

abs() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }
here="$(abs "$(dirname "$0")")"
root="$(abs "$here/../..")"
image="$(grep -oE 'sigp/lighthouse:[^[:space:]]+' "$root/k8s/base/validator/statefulset.yaml" | head -n1)"
gw_image="$(grep -oE 'openresty/openresty:[^[:space:]]+' "$root/k8s/base/rpc-gateway/deployment.yaml" | head -n1)"
scripts="$root/k8s/base/validator/scripts"
id="vtest-$$"
password="ci-test-password-not-secret"
mnemonic="abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about"

work="$here/.work"
mkdir -p "$work"
for d in gen keystores secrets tamper out; do
  mkdir -p "$work/$d"
  find "$work/$d" -mindepth 1 -delete
done

cleanup() {
  docker rm -f "$id-pod" >/dev/null 2>&1 || true
  docker volume rm -f "$id-keys" "$id-data" "$id-data2" >/dev/null 2>&1 || true
}
trap cleanup EXIT

pass=0
fail=0
check() {
  if [[ "$2" == "$3" ]]; then
    pass=$((pass + 1))
    printf '  ok    %-64s %s\n' "$1" "$3"
  else
    fail=$((fail + 1))
    printf '  FAIL  %-64s expected %s, got %s\n' "$1" "$2" "$3"
  fi
}
yn() { if "$@"; then echo yes; else echo no; fi; }

hardened=(--user 10001:10001 --read-only --tmpfs "/tmp:rw,size=64m" --cap-drop ALL --security-opt no-new-privileges)

# Volumes standing in for the pod's emptyDir{medium: Memory} and the PVC.
new_tmpfs_volume() { docker volume create --driver local --opt type=tmpfs --opt device=tmpfs --opt "o=size=16m,uid=10001,gid=10001,mode=0700" "$1" >/dev/null; }
new_data_volume() {
  docker volume create "$1" >/dev/null
  docker run --rm --user 0 -v "$1:/data" --entrypoint chown "$image" 10001:10001 /data
}

echo "image: $image"
echo "== 1. generate test keystores"
printf '%s' "$mnemonic" >"$work/gen/mnemonic.txt"
printf '%s\n%s\n' "$password" "$password" | docker run --rm -i -v "$work/gen:/gen" "$image" \
  lighthouse validator-manager create --network hoodi --first-index 0 --count 2 \
  --eth1-withdrawal-address 0x1111111111111111111111111111111111111111 \
  --mnemonic-path /gen/mnemonic.txt --output-path /gen \
  --specify-voting-keystore-password --stdin-inputs >"$work/out/keygen.log" 2>&1

# validators.json -> keystore-m_12381_3600_<i>_0_0.json (split with OpenResty's Lua + cjson)
docker run --rm -v "$work/gen:/gen:ro" -v "$work/keystores:/ks" --entrypoint /usr/local/openresty/luajit/bin/luajit "$gw_image" -e '
  package.cpath = "/usr/local/openresty/lualib/?.so;" .. package.cpath
  local cjson = require "cjson"
  local f = assert(io.open("/gen/validators.json")); local v = cjson.decode(f:read("*a")); f:close()
  for i, entry in ipairs(v) do
    local out = assert(io.open(string.format("/ks/keystore-m_12381_3600_%d_0_0.json", i - 1), "w"))
    out:write(entry.voting_keystore); out:close()
  end'
check "generated keystores" 2 "$(find "$work/keystores" -name 'keystore-*.json' | wc -l | tr -d ' ')"

echo "== 2. bundle with scripts/load-validator-keys.sh"
bash "$root/scripts/load-validator-keys.sh" --keystores "$work/keystores" --bundle-only "$work/secrets/keystores.tar.gz.b64" >/dev/null
printf '%s' "$password" >"$work/secrets/keystore-password"
check "bundle written" yes "$(yn test -s "$work/secrets/keystores.tar.gz.b64")"

echo "== 3. init container: prepare-keys.sh"
new_tmpfs_volume "$id-keys"
new_data_volume "$id-data"
# A Docker tmpfs volume is torn down when its last container exits, whereas an
# emptyDir lives as long as the pod. Hold it mounted, like the pod sandbox does.
docker run -d --name "$id-pod" --user 10001:10001 -v "$id-keys:/keys" --entrypoint sleep "$image" infinity >/dev/null
run_init() { # <secrets dir> <data volume> -> exit code
  docker run --rm "${hardened[@]}" \
    -v "$1:/secrets:ro" -v "$id-keys:/keys" -v "$2:/data" -v "$scripts:/scripts:ro" \
    --entrypoint /bin/bash "$image" /scripts/prepare-keys.sh >"$work/out/init.log" 2>&1 && echo 0 || echo $?
}
check "prepare-keys.sh exits 0" 0 "$(run_init "$work/secrets" "$id-data")"
defs="$(docker run --rm --user 10001:10001 -v "$id-data:/data:ro" --entrypoint cat "$image" /data/validators/validator_definitions.yml)"
check "definitions list 2 validators" 2 "$(grep -c 'voting_public_key' <<<"$defs")"
check "definitions point at in-memory /keys" 2 "$(grep -c 'voting_keystore_path: "/keys/keystores/' <<<"$defs")"
check "no keystore JSON on the persistent volume" 0 "$(docker run --rm --user 10001:10001 -v "$id-data:/data:ro" --entrypoint sh "$image" -c 'grep -rl "\"crypto\"" /data | wc -l' | tr -d ' ')"

echo "== 4. validator client (keys in memory only)"
run_vc() { # <data volume> <INIT_SLASHING_PROTECTION> <log> [keys mount mode]
  local cid
  cid="$(docker run -d "${hardened[@]}" \
    -e INIT_SLASHING_PROTECTION="$2" -e HOME=/tmp \
    -v "$work/secrets:/secrets:ro" -v "$id-keys:/keys:${4:-rw}" -v "$1:/data" -v "$scripts:/scripts:ro" \
    --entrypoint /bin/bash "$image" /scripts/start-validator.sh validator_client \
    --network=hoodi --datadir=/data --beacon-nodes=http://127.0.0.1:5052 \
    --suggested-fee-recipient=0x1111111111111111111111111111111111111111 \
    --enable-doppelganger-protection --disable-auto-discover --logfile-max-number=0)"
  # Wait for a definitive outcome: slashing DB opened (success) or the process exited.
  for _ in $(seq 1 60); do
    sleep 1
    docker logs "$cid" 2>&1 | grep -q 'Completed pruning of slashing protection DB' && break
    [[ "$(docker inspect -f '{{.State.Running}}' "$cid")" == "false" ]] && break
  done
  docker logs "$cid" >"$3" 2>&1 || true
  docker rm -f "$cid" >/dev/null 2>&1 || true
}
pvc() { docker run --rm --user 10001:10001 -v "$1:/data:ro" --entrypoint sh "$image" -c "$2"; }
# Regression guard for the manifest: Lighthouse writes <keystore>.lock files,
# so a read-only /keys mount must fail. (This caught a real bug.)
run_vc "$id-data" true "$work/out/vc-readonly.log" ro
check "read-only /keys is rejected by Lighthouse (lockfiles)" yes "$(yn grep -q 'ReadOnlyFilesystem' "$work/out/vc-readonly.log")"

run_vc "$id-data" true "$work/out/vc-first.log"
check "start-validator.sh warns about INIT_SLASHING_PROTECTION" yes "$(yn grep -q 'WARNING: --init-slashing-protection' "$work/out/vc-first.log")"
check "validator enabled both keys" yes "$(yn grep -qE 'Initialized validators.*enabled: 2' "$work/out/vc-first.log")"
check "slashing protection DB opened" yes "$(yn grep -q 'Completed pruning of slashing protection DB' "$work/out/vc-first.log")"
check "lockfiles live on tmpfs, not the PVC" 0 "$(pvc "$id-data" 'find /data -name "*.lock" | wc -l' | tr -d ' ')"
# Lighthouse persists an encrypted key cache (no switch to disable it). Assert
# it is the ONLY key-derived file on the PVC and that it is scrypt-protected.
check "only key-derived file on PVC is Lighthouse's key cache" "/data/validators/validator_key_cache.json" \
  "$(pvc "$id-data" 'grep -rls "\"crypto\"" /data')"
check "key cache is scrypt-encrypted (EIP-2335 strength)" yes \
  "$(pvc "$id-data" 'grep -q "\"function\":\"scrypt\"" /data/validators/validator_key_cache.json && echo yes || echo no')"
check "no keystore files on the PVC" 0 "$(pvc "$id-data" 'find /data -name "keystore-*" | wc -l' | tr -d ' ')"
check "no log files on the PVC" 0 "$(pvc "$id-data" 'find /data -name "*.log" | wc -l' | tr -d ' ')"

run_vc "$id-data" false "$work/out/vc-restart.log"
check "restart with existing slashing DB, no init flag" yes "$(yn grep -qE 'Initialized validators.*enabled: 2' "$work/out/vc-restart.log")"

echo "== 5. fail-safe: lost slashing DB"
new_data_volume "$id-data2"
run_init "$work/secrets" "$id-data2" >/dev/null
run_vc "$id-data2" false "$work/out/vc-lost-db.log"
check "refuses to sign without slashing DB" no "$(yn grep -q 'Completed pruning of slashing protection DB' "$work/out/vc-lost-db.log")"
check "fails closed: 'Failed to open slashing protection database'" yes "$(yn grep -q 'Failed to open slashing protection database' "$work/out/vc-lost-db.log")"

echo "== 6. tampered bundles are rejected"
# Malicious bundles are built inside a Linux container (symlinks, exec bits).
tamper() { # <slug> <description> <bash snippet run in /src> <expected log fragment>
  local dir="$work/tamper/$1"
  mkdir -p "$dir/secrets"
  docker run --rm --user 0 -v "$work/keystores:/ks:ro" -v "$dir/secrets:/out" --entrypoint /bin/bash "$image" -c "
    set -e; mkdir /tmp/src; cd /tmp/src; $3
    tar -czf /tmp/b.tgz *; base64 -w0 /tmp/b.tgz > /out/keystores.tar.gz.b64"
  printf '%s' "$password" >"$dir/secrets/keystore-password"
  local rc
  rc="$(run_init "$dir/secrets" "$id-data2")"
  check "reject $2 (non-zero exit)" yes "$([[ "$rc" != 0 ]] && echo yes || echo no)"
  check "reject $2 (reason logged)" yes "$(yn grep -q "$4" "$work/out/init.log")"
}
tamper symlink "symlink to /etc/passwd" 'cp /ks/*_0_0_0.json .; ln -s /etc/passwd keystore-evil.json' "non-regular file"
tamper foreign "non-keystore file" 'cp /ks/*_0_0_0.json .; echo "echo pwned" > run.sh' "unexpected entry"
tamper duplicate "same key twice" 'cp /ks/*_0_0_0.json keystore-a.json; cp /ks/*_0_0_0.json keystore-b.json' "duplicate keystore"

echo
echo "validator tests: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
