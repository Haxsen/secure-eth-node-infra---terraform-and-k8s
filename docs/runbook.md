# Runbook

Operational procedures for the platform. Commands assume the repo root and an
environment called `hoodi`; substitute `mainnet` as needed.

## 1. First deployment

**Prerequisites:** AWS account (one per environment for mainnet), Terraform ≥ 1.10, AWS CLI v2, kubectl, jq, openssl, and an ACM certificate for your RPC hostname.

```bash
# 1. Remote state (once per account)
terraform -chdir=terraform/bootstrap init
terraform -chdir=terraform/bootstrap apply -var state_bucket_name=<globally-unique-name>
#    -> copy the outputs into terraform/platform/envs/hoodi.s3.tfbackend

# 2. Edit terraform/platform/envs/hoodi.tfvars:
#    cluster_admin_principal_arns, key_custodian_principal_arns,
#    acm_certificate_arn, rpc_hostname

# 3. Platform
terraform -chdir=terraform/platform init -backend-config=envs/hoodi.s3.tfbackend
terraform -chdir=terraform/platform plan  -var-file=envs/hoodi.tfvars -out=plan.out
terraform -chdir=terraform/platform show -json plan.out > plan.json
conftest test --namespace terraform.security --policy policies/terraform plan.json
terraform -chdir=terraform/platform apply plan.out
```

> The EKS API endpoint is **private**. Run Terraform from inside the VPC (SSM
> session on a bastion, VPN, or a self-hosted runner) so the Helm/Kubernetes
> providers can reach it. For a throwaway testnet bootstrap from a laptop you
> may temporarily set `api_public_access_cidrs = ["<your-ip>/32"]`, then
> remove it and re-apply.

```bash
# 4. Secret material (values never pass through Terraform or argv)
scripts/put-jwt-secret.sh hoodi
scripts/load-validator-keys.sh --env hoodi --keystores ./validator_keys
scripts/manage-api-keys.sh hoodi add my-first-dapp     # prints the key ONCE

# 5. Wire Terraform outputs into the overlay
scripts/sync-tf-outputs.sh hoodi
#    set FEE_RECIPIENT in k8s/overlays/hoodi/kustomization.yaml

# 6. FIRST boot of a brand-new validator set only:
#    add  - INIT_SLASHING_PROTECTION=true  to the validator-config literals.
#    CI will warn while it is set.

# 7. Validate and deploy
make lint
aws eks update-kubeconfig --region eu-west-1 --name eth-hoodi
kubectl apply -k k8s/overlays/hoodi

# 8. Watch
kubectl -n eth-nodes get pods -w                 # Ready = fully synced
kubectl -n eth-validator logs -f statefulset/validator
#    expect "Initialized validators ... enabled: N", then ~2-3 epochs of
#    doppelganger checks before the first attestation.

# 9. Immediately remove INIT_SLASHING_PROTECTION=true and re-apply.
```

## 2. Routine operations

### Add / revoke an RPC API key
```bash
scripts/manage-api-keys.sh hoodi add acme-wallet
scripts/manage-api-keys.sh hoodi revoke acme-wallet
scripts/manage-api-keys.sh hoodi list
```
Gateways converge within about 2.5 minutes (CSI rotation 2m + Lua reload 30s). No restart is needed.

### Rotate the Engine API JWT
```bash
scripts/put-jwt-secret.sh hoodi
kubectl -n eth-nodes rollout restart statefulset/eth-node
```
Both clients read the JWT only at start-up, so the restart is required.

### Upgrade geth / Lighthouse (hard forks)
1. Renovate opens a PR bumping tag **and** digest; client PRs never automerge.
2. Read the release notes for the fork epoch and any required flags.
3. Roll a testnet overlay first. `eth-node` rolls one pod at a time; the PDB keeps one synced replica serving.
4. The validator restarts once (StatefulSet: old pod terminates **before** the new one starts).

### Expand chain-data volumes
`volumeClaimTemplates` are immutable. Edit each PVC directly (the StorageClass allows expansion):
```bash
kubectl -n eth-nodes patch pvc geth-data-eth-node-0 -p '{"spec":{"resources":{"requests":{"storage":"600Gi"}}}}'
```

## 3. Validator safety rules

1. **Never** run `kubectl delete pod --force` / `--grace-period=0` on the validator. A force delete removes the pod from the API before the kubelet has confirmed the process is dead. If the node is partitioned, the old process can keep signing while a new one starts.
2. **Never** change the validator to a Deployment or more than one replica. CI rejects both.
3. **Never** run these keys anywhere else at the same time (e.g. a "temporary" machine during migration). Doppelganger protection is a seatbelt, not a guarantee.
4. A node drain evicts the validator. Expect a few missed attestations, not slashing.

### Migrate validators to a new cluster / account
1. Stop the old validator and **confirm** it is gone:
   `kubectl -n eth-validator scale statefulset/validator --replicas=0` and wait for the pod to disappear.
2. Export the EIP-3076 slashing-protection interchange from the old data volume:
   `lighthouse account validator slashing-protection export interchange.json --datadir /data --network <net>`
3. Import it on the new data volume **before** the new validator first starts:
   `lighthouse account validator slashing-protection import interchange.json --datadir /data --network <net>`
4. Wait at least 2 epochs, then start the new validator with doppelganger protection on (the default here).

## 4. Incident response

### Suspected validator key compromise
1. **Contain:** `kubectl -n eth-validator scale statefulset/validator --replicas=0`.
2. **Preserve evidence:** snapshot the validator PVC and node volume. Export CloudTrail for `secretsmanager:GetSecretValue` and `kms:Decrypt` on the secrets key, and VPC flow logs for the signing subnet.
3. **Decide quickly:** BLS keys cannot be rotated. If compromise is plausible, submit a **voluntary exit** signed offline, before an attacker can use the keys to get you slashed.
4. Generate new keys on an air-gapped machine, deposit, and load them with `scripts/load-validator-keys.sh`.

### RPC abuse / DDoS
1. WAF metrics/logs (`aws-waf-logs-eth-<env>-rpc`) show the offending IPs and rule hits.
2. Gateway access logs (JSON on stdout) show the offending **tenant** by name, never by key.
3. Revoke the tenant (`manage-api-keys.sh revoke`), tighten `waf_rate_limit_per_ip`, or add a geo/IP-set rule.
4. The HPA adds synced RPC replicas only after sustained load; capacity for spikes comes from the gateway and WAF layers.

### Lost slashing-protection database
The validator fails closed (`Failed to open slashing protection database`). **Do not** "fix" it by setting `INIT_SLASHING_PROTECTION=true`. Restore the PVC from snapshot, or import an interchange file from your last export, then start the validator.
