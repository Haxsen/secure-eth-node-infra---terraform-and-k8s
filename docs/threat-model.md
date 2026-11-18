# Threat model

What this platform defends against, how, where the control lives, and what proves it works.
"Verified by" points at an automated check that fails if the control regresses.

## Assets

| Asset | Why it matters |
|---|---|
| Validator BLS signing keys | Theft = attacker can get the validator slashed or hold it hostage. Keys cannot be rotated; the only remedy is exiting the validator. |
| Slashing-protection database | Losing it while keys stay live is the most common way operators slash themselves. |
| Engine API (EL ↔ CL, JWT) | Whoever can call it can steer fork choice for that node. |
| Public JSON-RPC capacity | The product: availability for paying tenants. |
| AWS control plane (IAM, KMS, EKS API) | Root of trust for everything above. |

## Trust zones

| Zone | Runs | Exposure |
|---|---|---|
| **system** node group | Cluster controllers (ALB controller, autoscaler, CoreDNS, CSI controllers) | No internet-facing workloads |
| **edge** node group | geth + Lighthouse BN (P2P), rpc-gateway (HTTP) | Internet egress (P2P); HTTP only via WAF → ALB |
| **signing** node group | Lighthouse validator client, alone | No internet in or out; only beacon API egress |

A container escape in an internet-facing client lands on an edge node: there are no keys there, and the node's IMDS credentials are out of reach of pods.

## Threats and controls

| # | Threat | Controls | Where | Verified by |
|---|---|---|---|---|
| T1 | **L7 flood against the RPC endpoint** | WAF per-IP rate rule (60s window) → gateway per-IP *and* per-API-key `limit_req` → geth `--rpc.*` caps → HPA on ready replicas | `terraform/modules/waf`, `k8s/base/rpc-gateway/config/nginx.conf`, `k8s/base/eth-node/hpa.yaml` | `tests/gateway` (flood → 429s); Rego `test_waf_without_rate_limit_is_denied` |
| T2 | **Expensive-query DoS** (`eth_getLogs` over all history, gas-bomb `eth_call`, giant batches, deeply nested JSON) | Lua firewall: block range ≤ 5000, no `earliest`, batch ≤ 20, JSON depth ≤ 16, body ≤ 128 KB; geth `--rpc.rangelimit`, `--rpc.gascap`, `--rpc.evmtimeout`, `--rpc.batch-*` | `rpc_guard.lua`, `eth-node/statefulset.yaml` | `tests/gateway` (9 checks); Rego warn on missing geth caps |
| T3 | **Dangerous RPC namespaces reachable** (`admin_addPeer` for eclipse attacks, `debug_*` for resource exhaustion, `personal_*`, `engine_*`) | Default-deny method allowlist at the gateway; geth `--http.api=eth,net,web3`; CI policy rejects any manifest exposing those namespaces | `rpc_guard.lua`, `policies/kubernetes/ethereum.rego` | `tests/gateway` (9 namespaces denied, incl. batch smuggling); Rego tests |
| T4 | **Engine API exposure** | geth and Lighthouse share a pod, Engine API bound to `127.0.0.1`, JWT from Secrets Manager; policy rejects any non-loopback `--authrpc.addr` | `eth-node/statefulset.yaml`, `ethereum.rego` | Rego `test_engine_api_on_network_is_denied`; mutation test |
| T5 | **API key theft** | Only SHA-256 hashes stored; keys never logged (only tenant name); WAF log redacts `x-api-key`; key and `Authorization` stripped before upstream; hot revocation without restart | `rpc_guard.lua`, `waf/main.tf`, `scripts/manage-api-keys.sh` | `tests/gateway` (header stripping, hot add + revoke) |
| T6 | **Key exfiltration from a compromised validator pod** | Pod egress limited to beacon API (no internet, no AWS endpoints, no IMDS); no AWS creds in containers (`eks.amazonaws.com/skip-containers`); keystores on tmpfs only; dedicated nodes; PSS restricted | `validator/statefulset.yaml`, `validator/networkpolicies.yaml` | Combined Rego policy (default-deny per namespace); `tests/validator` |
| T7 | **Key exfiltration by a cloud insider / over-privileged role** | KMS key policy *denies* `kms:Decrypt` to everyone but the named workload roles + custodians; per-secret resource policy denies `GetSecretValue` to all but the one reader; custodians are write-only for validator keys | `terraform/modules/kms`, `terraform/modules/secrets`, `platform/main.tf` | Terraform validate + Checkov; reviewed policy statements |
| T8 | **Slashing by double signing** | Validator is a `StatefulSet` with `replicas: 1` (a Deployment surge would run two signers); doppelganger protection; autoscaling forbidden by policy; Cluster Autoscaler told not to evict it; never force-delete (runbook) | `validator/statefulset.yaml`, `ethereum.rego` | Rego tests (Deployment / replicas 2 / no doppelganger / HPA all denied); mutation test |
| T9 | **Slashing via a lost slashing-protection DB** | `--init-slashing-protection` is never in the manifest; it's an explicit, policy-warned ConfigMap toggle for first boot only; DB on a `Retain` CMK-encrypted PVC | `start-validator.sh`, `eth-gp3-retain` StorageClass | `tests/validator`: fresh volume without the toggle **fails closed** ("Failed to open slashing protection database") |
| T10 | **Tampered key bundle** (symlink / path traversal / foreign files / duplicate keys) | Init container accepts only a flat list of regular `keystore-*.json` files and rejects duplicate pubkeys | `prepare-keys.sh` | `tests/validator` (3 tamper cases) |
| T11 | **Container escape from a P2P client** | Bottlerocket (immutable, SELinux), PSS restricted, non-root uid 10001, read-only rootfs, all caps dropped, seccomp RuntimeDefault, no SA token; trust-zone isolation | `eks/main.tf`, every workload | `policies/kubernetes/security.rego` + Checkov (564 checks) |
| T12 | **SSRF → node credential theft** | IMDSv2 required, hop limit 1; NetworkPolicies deny `169.254.0.0/16`; no CNI permissions on the node role (moved to IRSA) | `eks/main.tf`, `eth-node/networkpolicies.yaml` | Rego `test_imds_hop_limit_two_is_denied` on plans |
| T13 | **Lateral movement from a compromised client** | Default-deny NetworkPolicies everywhere (enforced by the VPC CNI policy agent); eth-node egress allowed to public IPs only (all RFC 1918 / CGNAT / link-local excluded) | `*/networkpolicies.yaml`, `vpc-cni` add-on config | Combined Rego policy; mutation test removes a default-deny → CI fails |
| T14 | **Kubernetes API exposure** | Private endpoint by default; public access requires an explicit CIDR list and rejects `0.0.0.0/0`; access entries instead of `aws-auth`; no implicit creator-admin | `eks/main.tf`, `eks/variables.tf` | Variable validation; Rego plan tests |
| T15 | **Secrets in Terraform state** | Terraform creates secret *containers* only; values loaded by scripts over stdin; plan policy rejects any `aws_secretsmanager_secret_version`; state bucket KMS-encrypted, TLS-only, versioned | `modules/secrets`, `bootstrap/`, `policies/terraform` | Rego `test_secret_version_is_denied` |
| T16 | **Supply-chain compromise** (re-tagged image, hijacked action) | Every image pinned by digest; every action pinned by SHA; Renovate with 7-day minimum release age and no automerge for client upgrades; Helm charts pinned; upstream IAM policy vendored at the chart's version | all manifests, `.github/workflows`, `renovate.json` | Rego `must be pinned by digest`; zizmor in CI |
| T17 | **CI/CD credential compromise** | GitHub OIDC → AWS (no stored keys); `permissions: {}` by default; `persist-credentials: false`; harden-runner egress audit; plan files never uploaded as artifacts | `.github/workflows` | actionlint + zizmor (0 findings) |
| T18 | **Secrets committed to git** | gitleaks on full history in CI; `.gitignore` blocks keystores, mnemonics, deposit data, state | `.github/workflows/ci.yml`, `.gitignore` | gitleaks job |
| T19 | **HTTP request smuggling / desync** | ALB `desync_mitigation_mode=strictest`, invalid header fields dropped, HTTPS-only listener with TLS 1.2+/1.3 policy | `rpc-gateway/ingress.yaml` | Rego (HTTPS-only, WAF/cert/ssl-policy annotations required) |

## Residual risks and conscious trade-offs

- **Lighthouse key cache on disk.** Lighthouse persists `validator_key_cache.json` next to the slashing DB. It is scrypt (n=2¹⁸) + AES-128-CTR encrypted with the keystore password, which only exists in Secrets Manager and tmpfs, and it sits on a CMK-encrypted volume attachable only in the signing zone. Lighthouse has no switch to disable it, and it writes atomically, so it can't be redirected with a symlink (`tests/validator` documents this).
- **Shared beacon nodes.** The validator uses the same beacon nodes that back public RPC. A heavy RPC load could delay duties. Production option: a dedicated, non-public EL/CL pair for the validator.
- **No remote signer.** Keys are loaded into the validator process. Web3Signer with slashing-protection DB, or a DVT cluster (Obol/SSV), removes single-key-holder risk.
- **P2P egress on all ports to the public internet.** Peers listen on arbitrary ports. The control that matters (no private/link-local destinations) is enforced; this does allow HTTPS egress from a compromised client to arbitrary public hosts.
- **Checkpoint sync trust.** Each beacon node trusts one checkpoint provider at first boot. Cross-check the finalized root against a second provider before trusting a new deployment.
- **Per-IP WAF limits vs. distributed botnets.** Per-API-key limits at the gateway are the backstop.
- **No runtime threat detection yet.** GuardDuty EKS Runtime Monitoring or Falco is on the roadmap.
