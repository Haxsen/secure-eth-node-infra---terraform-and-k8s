# Architecture

## Layers

```mermaid
flowchart TB
  subgraph tf["Terraform (terraform/)"]
    direction LR
    boot[bootstrap<br/>KMS-encrypted S3 state<br/>native lockfile]
    net[network<br/>VPC · flow logs · VPC endpoints]
    kms[kms<br/>4 CMKs · deny guardrails]
    eks[eks<br/>private API · Bottlerocket · IMDSv2 hop 1<br/>3 trust-zone node groups]
    add[cluster-addons<br/>ALB controller · Secrets Store CSI<br/>Cluster Autoscaler · metrics-server]
    sec[secrets<br/>containers + resource policies<br/>no values in state]
    waf[waf<br/>reputation · bad inputs · rate · geo]
  end
  subgraph k8s["Kustomize (k8s/)"]
    direction LR
    base[base<br/>eth-node · validator · rpc-gateway]
    comp[components/aws-wiring<br/>Terraform outputs → manifests]
    ovl[overlays<br/>hoodi · mainnet]
  end
  subgraph gate["Policy & tests (policies/, tests/)"]
    direction LR
    rego[OPA/Rego<br/>k8s + Terraform plan]
    gwt[gateway tests]
    vt[validator tests]
  end
  tf -->|"terraform output → scripts/sync-tf-outputs.sh"| k8s
  k8s --> gate
  tf --> gate
```

## Request path (public JSON-RPC)

```mermaid
flowchart LR
  c([client]) -->|"HTTPS · X-Api-Key"| waf["AWS WAF<br/>IP reputation · known-bad inputs<br/>per-IP rate (60s) · optional geo"]
  waf --> alb["ALB<br/>TLS 1.2/1.3 · desync=strictest<br/>drop invalid headers · IP targets"]
  alb -->|"NetworkPolicy: ALB subnets → :8080 only"| gw
  subgraph edge["edge node group"]
    gw["rpc-gateway (OpenResty)<br/>① identify key (rewrite)<br/>② per-IP + per-key limit_req<br/>③ authn + JSON-RPC firewall (access)"]
    subgraph pod["eth-node pod × N (StatefulSet + HPA)"]
      geth["geth :8545<br/>eth,net,web3 only<br/>gascap · evmtimeout · rangelimit"]
      lh["Lighthouse BN :5052"]
      geth <-->|"Engine API 127.0.0.1:8551 + JWT"| lh
    end
  end
  gw -->|"NetworkPolicy: :8545 only"| geth
```

Each layer assumes the one before it failed. The WAF can't see API keys, so the gateway enforces per-tenant limits. The gateway can be bypassed only from inside the cluster, which NetworkPolicies prevent. geth's own resource caps bound the cost of any request that gets through.

## Validator key path

```mermaid
sequenceDiagram
  autonumber
  actor C as Key custodian
  participant SM as Secrets Manager
  participant KMS as KMS (secrets CMK)
  participant CSI as Secrets Store CSI + ASCP
  participant I as init: prepare-keys.sh
  participant V as Lighthouse VC

  C->>SM: PutSecretValue (bundle via stdin, never argv)
  SM->>KMS: GenerateDataKey ✔ (custodian may write…)
  Note over C,KMS: …but kms:Decrypt is DENIED to the custodian by key policy
  CSI->>SM: GetSecretValue as eth-validator/validator (IRSA, exact ns:sa)
  SM->>KMS: Decrypt ✔ (named workload role, via Secrets Manager only)
  CSI-->>I: tmpfs files (no Kubernetes Secret, no etcd)
  I->>I: validate bundle (regular keystore-*.json only, no dup keys)
  I-->>V: keystores on emptyDir{medium: Memory}<br/>definitions + slashing DB on PVC
  V->>V: refuses to start if slashing DB missing (fail closed)
```

The validator containers themselves get **no** AWS credentials (`eks.amazonaws.com/skip-containers`). Only the CSI driver uses the pod identity. Validator egress is limited to the beacon API: no internet, no AWS endpoints, no IMDS.

## Autoscaling design

| Layer | Scales on | Why |
|---|---|---|
| rpc-gateway | CPU, 2–10 replicas, fast scale-up | Stateless; absorbs spikes immediately |
| eth-node | CPU of the **geth container** of **ready** pods, 2–4 (hoodi) / 3–6 (mainnet), slow both ways | A new replica must sync before serving |
| Nodes | Cluster Autoscaler (tag-scoped IAM) | Adds edge nodes for new eth-node pods |
| validator | **Never** | Two signers = slashing |

Two details make CPU-based autoscaling of blockchain nodes workable:

1. **Readiness means "synced".** geth reports ready only when `!eth.syncing && eth.blockNumber > 0`, and Lighthouse only on `/eth/v1/node/health` = `200`. The HPA treats unready pods as 0% CPU when scaling up, so a syncing replica's heavy CPU never triggers further scale-ups.
2. **`persistentVolumeClaimRetentionPolicy.whenScaled: Retain`.** Scaling down keeps the synced volume, so the next scale-up re-attaches it and only catches up the missed blocks instead of doing a full sync.

## Decision log

| Decision | Alternatives | Why |
|---|---|---|
| Secrets Store CSI (tmpfs) with `syncSecret` off | External Secrets Operator → K8s Secret | Keys never enter etcd; each pod fetches with its *own* IRSA role instead of one cluster-wide operator identity |
| AWS Secrets Manager + KMS | HashiCorp Vault | No extra stateful system to secure and operate; KMS key policies give a hard deny guardrail; CloudTrail on every decrypt |
| EL + CL in one pod | Separate StatefulSets | Engine API never leaves loopback; the pair scales as one unit |
| Validator as single-replica StatefulSet on a dedicated node group | Deployment; shared nodes | Deployment surge = double signing; shared kernel with P2P clients = escape risk |
| OpenResty + Lua gateway | eRPC / dshackle / Envoy | Small, auditable firewall (~280 lines of Lua) with full control of phase ordering; tested end-to-end in CI |
| Bottlerocket | AL2023 | Immutable, dm-verity root, SELinux enforcing, minimal userland |
| VPC CNI network policy agent | Calico / Cilium | Native to EKS, no extra CNI; standard `NetworkPolicy` semantics are enough here |
| Kustomize component for AWS wiring | Helm chart; hand-edited ARNs | Plain YAML that policies can read; Terraform outputs flow in without copy-paste |
| Access entries, `bootstrap_cluster_creator_admin_permissions = false` | `aws-auth` ConfigMap | Auditable, API-managed cluster access; the Terraform principal is added explicitly |
| No CPU limits (memory limits required) | CPU limits everywhere | CFS throttling delays block processing and attestations |
