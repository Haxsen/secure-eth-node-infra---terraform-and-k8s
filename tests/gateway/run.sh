#!/usr/bin/env bash
# -----------------------------------------------------------------------------
# Functional tests for the public RPC gateway.
#
# Runs the real k8s/base/rpc-gateway/config/{nginx.conf,rpc_guard.lua} in the
# exact pinned OpenResty image from the Deployment, with the same hardening the
# pod gets (uid 10001, read-only rootfs, all capabilities dropped,
# no-new-privileges), in front of a mock execution client, and asserts the
# auth / firewall / rate-limit / hot-reload behaviour end to end.
#
# Requires: docker, curl. Usage: tests/gateway/run.sh
# -----------------------------------------------------------------------------
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash on Windows: don't mangle container paths

abs() { (cd "$1" && (pwd -W 2>/dev/null || pwd)); }
here="$(abs "$(dirname "$0")")"
root="$(abs "$here/../..")"
config="$root/k8s/base/rpc-gateway/config"
image="$(grep -oE 'openresty/openresty:[^[:space:]]+' "$root/k8s/base/rpc-gateway/deployment.yaml" | head -n1)"
port="${GATEWAY_TEST_PORT:-18080}"
url="http://127.0.0.1:${port}"
name="rpcgw-test-$$"

# Test-only credentials. The second key is added mid-run to test hot reload.
key_a="tk_test_alpha_0123456789abcdef"
key_b="tk_test_bravo_0123456789abcdef"

work="$here/.work"
mkdir -p "$work/secrets" "$work/out"
hash_of() { printf '%s' "$1" | sha256sum | cut -d' ' -f1; }
printf '{"%s":"ci-tenant-alpha"}\n' "$(hash_of "$key_a")" >"$work/secrets/api-keys.json"

cleanup() {
  if [[ "${KEEP:-0}" != "1" ]]; then
    docker logs "$name-gw" >"$work/out/gateway.log" 2>&1 || true
    docker rm -f "$name-gw" "$name-node" >/dev/null 2>&1 || true
    docker network rm "$name" >/dev/null 2>&1 || true
  fi
}
trap cleanup EXIT

hardened=(--user 10001:10001 --read-only --tmpfs "/tmp:rw,size=64m" --cap-drop ALL --security-opt no-new-privileges)
openresty=(/usr/local/openresty/bin/openresty -p /tmp/ -c /etc/openresty/nginx.conf -e stderr -g "daemon off;")

echo "image: $image"
docker network create "$name" >/dev/null

docker run -d --name "$name-node" --network "$name" \
  --network-alias eth-node-rpc.eth-nodes.svc.cluster.local \
  "${hardened[@]}" \
  -v "$here/mock-node.conf:/etc/openresty/nginx.conf:ro" \
  "$image" "${openresty[@]}" >/dev/null

docker run -d --name "$name-gw" --network "$name" -p "127.0.0.1:${port}:8080" \
  "${hardened[@]}" \
  -v "$config/nginx.conf:/etc/openresty/nginx.conf:ro" \
  -v "$config/rpc_guard.lua:/etc/openresty/lua/rpc_guard.lua:ro" \
  -v "$work/secrets:/secrets:ro" \
  "$image" "${openresty[@]}" >/dev/null

for _ in $(seq 1 30); do
  [[ "$(curl -s -o /dev/null -w '%{http_code}' "$url/healthz" || true)" == "200" ]] && break
  sleep 1
done

# ---------------------------------------------------------------------------
pass=0
fail=0
check() { # description expected actual
  if [[ "$2" == "$3" ]]; then
    pass=$((pass + 1))
    printf '  ok    %-62s %s\n' "$1" "$3"
  else
    fail=$((fail + 1))
    printf '  FAIL  %-62s expected %s, got %s\n' "$1" "$2" "$3"
  fi
}

# rpc <body> [curl args...] -> HTTP status; body saved to $work/out/resp
rpc() {
  local body="$1"
  shift
  curl -s -o "$work/out/resp" -w '%{http_code}' -X POST "$url/" \
    -H 'Content-Type: application/json' "$@" --data-binary "$body"
}
call() { printf '{"jsonrpc":"2.0","id":1,"method":"%s","params":%s}' "$1" "${2:-[]}"; }
auth=(-H "X-Api-Key: $key_a")

echo "== health & authentication"
check "GET /healthz" 200 "$(curl -s -o /dev/null -w '%{http_code}' "$url/healthz")"
check "no API key" 401 "$(rpc "$(call eth_blockNumber)")"
check "wrong API key" 401 "$(rpc "$(call eth_blockNumber)" -H 'X-Api-Key: nope')"
check "valid key: eth_blockNumber" 200 "$(rpc "$(call eth_blockNumber)" "${auth[@]}")"

echo "== upstream hygiene"
rpc "$(call eth_chainId)" "${auth[@]}" -H 'Authorization: Bearer leak-me' >/dev/null
check "geth sees internal Host (vhosts)" yes "$(grep -q '"host":"eth-node-rpc.eth-nodes.svc.cluster.local"' "$work/out/resp" && echo yes || echo no)"
check "API key stripped before upstream" yes "$(grep -q '"api_key":""' "$work/out/resp" && echo yes || echo no)"
check "Authorization stripped before upstream" yes "$(grep -q '"authorization":""' "$work/out/resp" && echo yes || echo no)"
check "no Server version disclosure" no "$(curl -sI "$url/healthz" | grep -qi '^server:' && echo yes || echo no)"

echo "== method allowlist"
for m in admin_peers admin_addPeer debug_traceTransaction personal_sign miner_start txpool_content engine_forkchoiceUpdatedV3 eth_sendTransaction eth_sign; do
  check "deny $m" 403 "$(rpc "$(call "$m")" "${auth[@]}")"
done
check "allow eth_sendRawTransaction" 200 "$(rpc "$(call eth_sendRawTransaction '["0x02"]')" "${auth[@]}")"

echo "== batches"
check "batch of 2 allowed calls" 200 "$(rpc "[$(call eth_blockNumber),$(call eth_chainId)]" "${auth[@]}")"
check "batch smuggling admin_peers" 403 "$(rpc "[$(call eth_blockNumber),$(call admin_peers)]" "${auth[@]}")"
big="$(for _ in $(seq 1 21); do printf '%s,' "$(call eth_blockNumber)"; done)"
check "batch of 21 (> 20)" 400 "$(rpc "[${big%,}]" "${auth[@]}")"
check "empty batch" 400 "$(rpc '[]' "${auth[@]}")"

echo "== request validation"
check "malformed JSON" 400 "$(rpc '{"jsonrpc":' "${auth[@]}")"
deep="$(printf '%.0s[' $(seq 1 20))$(printf '%.0s]' $(seq 1 20))"
check "JSON nested 20 deep (> 16)" 400 "$(rpc "$(call eth_call "$deep")" "${auth[@]}")"
check "missing jsonrpc version" 400 "$(rpc '{"id":1,"method":"eth_chainId"}' "${auth[@]}")"
check "Content-Type text/plain" 415 "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$url/" "${auth[@]}" \
  -H 'Content-Type: text/plain' --data-binary "$(call eth_chainId)")"
check "GET with valid key" 405 "$(curl -s -o /dev/null -w '%{http_code}' "${auth[@]}" "$url/")"
check "unknown path" 404 "$(curl -s -o /dev/null -w '%{http_code}' "${auth[@]}" "$url/admin")"
head -c 200000 /dev/zero | tr '\0' 'a' >"$work/out/big"
check "200 KB body (> 128 KB)" 413 "$(curl -s -o /dev/null -w '%{http_code}' -X POST "$url/" "${auth[@]}" \
  -H 'Content-Type: application/json' --data-binary @"$work/out/big")"

echo "== eth_getLogs DoS guards"
check "range 0x1..0x2001 (> 5000 blocks)" 400 "$(rpc "$(call eth_getLogs '[{"fromBlock":"0x1","toBlock":"0x2001"}]')" "${auth[@]}")"
check "fromBlock earliest" 400 "$(rpc "$(call eth_getLogs '[{"fromBlock":"earliest","toBlock":"latest"}]')" "${auth[@]}")"
check "inverted range" 400 "$(rpc "$(call eth_getLogs '[{"fromBlock":"0x100","toBlock":"0x1"}]')" "${auth[@]}")"
check "range 0x1..0x100" 200 "$(rpc "$(call eth_getLogs '[{"fromBlock":"0x1","toBlock":"0x100"}]')" "${auth[@]}")"
check "blockHash filter" 200 "$(rpc "$(call eth_getLogs '[{"blockHash":"0xabc"}]')" "${auth[@]}")"

echo "== rate limiting (per-IP limit applies BEFORE auth rejection)"
# One multiplexed curl process (URL glob + --parallel) so the client, not
# process spawning, is fast enough to exceed 50 req/s + burst 100.
curl -s --parallel --parallel-max 64 -o /dev/null -w '%{http_code}\n' -X POST "$url/?n=[1-400]" \
  -H 'Content-Type: application/json' -H 'X-Api-Key: brute-force-guess' \
  --data-binary '{"jsonrpc":"2.0","id":1,"method":"eth_chainId"}' >"$work/out/flood" || true
limited="$(grep -c '^429$' "$work/out/flood" || true)"
check "invalid-key flood is throttled (429s seen)" yes "$([[ "$limited" -gt 0 ]] && echo yes || echo no)"
echo "        ($limited of 400 brute-force requests rate limited)"

echo "== API key hot reload (no restart)"
printf '{"%s":"ci-tenant-alpha","%s":"ci-tenant-bravo"}\n' "$(hash_of "$key_a")" "$(hash_of "$key_b")" >"$work/secrets/api-keys.json"
status=""
for _ in $(seq 1 45); do
  sleep 1
  status="$(rpc "$(call eth_chainId)" -H "X-Api-Key: $key_b")"
  [[ "$status" == "200" ]] && break
done
check "newly added key accepted within reload interval" 200 "$status"
printf '{"%s":"ci-tenant-bravo"}\n' "$(hash_of "$key_b")" >"$work/secrets/api-keys.json"
for _ in $(seq 1 45); do
  sleep 1
  status="$(rpc "$(call eth_chainId)" "${auth[@]}")"
  [[ "$status" == "401" ]] && break
done
check "revoked key rejected within reload interval" 401 "$status"

echo
echo "gateway tests: ${pass} passed, ${fail} failed"
[[ "$fail" -eq 0 ]]
