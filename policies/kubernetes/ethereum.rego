# Ethereum-specific guardrails: the misconfigurations that actually get node
# operators drained or slashed.
package kubernetes.ethereum

import data.lib.kubernetes as k8s
import rego.v1

# JSON-RPC namespaces that must never be reachable over the network.
dangerous_api_namespaces := {"admin", "debug", "personal", "miner", "txpool", "engine", "clique", "les"}

zero_address := "0x0000000000000000000000000000000000000000"

geth_containers contains c if {
	some c in k8s.containers
	contains(c.image, "ethereum/client-go")
}

validator_containers contains c if {
	some c in k8s.containers
	contains(c.image, "sigp/lighthouse")
	c.args[0] in {"vc", "validator_client", "validator"}
}

# ================================= geth ======================================

deny contains msg if {
	some c in geth_containers
	some flag in ["--http.api", "--ws.api"]
	some api in split(k8s.flag_value(c.args, flag), ",")
	lower(trim_space(api)) in dangerous_api_namespaces
	msg := sprintf("%s: geth %s exposes the %q namespace on a network listener", [k8s.name, flag, api])
}

deny contains msg if {
	some c in geth_containers
	some flag in ["--http.vhosts", "--http.corsdomain", "--ws.origins"]
	"*" in split(k8s.flag_value(c.args, flag), ",")
	msg := sprintf("%s: geth %s must not be a wildcard", [k8s.name, flag])
}

# The Engine API can drive fork choice; it must stay on loopback.
deny contains msg if {
	some c in geth_containers
	addr := k8s.flag_value(c.args, "--authrpc.addr")
	not addr in {"127.0.0.1", "localhost"}
	msg := sprintf("%s: geth --authrpc.addr=%s exposes the Engine API beyond the pod", [k8s.name, addr])
}

deny contains msg if {
	some c in geth_containers
	some flag in ["--allow-insecure-unlock", "--unlock", "--password"]
	k8s.has_flag(c.args, flag)
	msg := sprintf("%s: geth must not hold or unlock accounts (%s)", [k8s.name, flag])
}

warn contains msg if {
	some c in geth_containers
	k8s.has_flag(c.args, "--http")
	some flag in ["--rpc.gascap", "--rpc.evmtimeout", "--rpc.rangelimit", "--rpc.batch-request-limit"]
	not k8s.has_flag(c.args, flag)
	msg := sprintf("%s: public geth RPC without %s is easier to DoS", [k8s.name, flag])
}

# =============================== validator ===================================

# A Deployment rolling update surges a second pod before the first stops:
# two signers with the same keys = slashable double vote.
deny contains msg if {
	count(validator_containers) > 0
	input.kind != "StatefulSet"
	msg := sprintf("%s: validator clients must run as a StatefulSet, never a %s", [k8s.name, input.kind])
}

deny contains msg if {
	count(validator_containers) > 0
	input.kind == "StatefulSet"
	not input.spec.replicas == 1
	msg := sprintf("%s: validator StatefulSet must declare exactly replicas: 1", [k8s.name])
}

deny contains msg if {
	some c in validator_containers
	not k8s.has_flag(c.args, "--enable-doppelganger-protection")
	msg := sprintf("%s: validator must run with --enable-doppelganger-protection", [k8s.name])
}

deny contains msg if {
	some c in validator_containers
	k8s.has_flag(c.args, "--init-slashing-protection")
	msg := sprintf("%s: --init-slashing-protection must not be hardcoded (it masks a lost slashing DB)", [k8s.name])
}

deny contains msg if {
	some c in validator_containers
	k8s.has_flag(c.args, "--http")
	msg := sprintf("%s: the validator keymanager HTTP API must stay disabled", [k8s.name])
}

deny contains msg if {
	count(validator_containers) > 0
	not k8s.pod_spec.nodeSelector["trust-zone"] == "signing"
	msg := sprintf("%s: validator must be pinned to the dedicated signing node group", [k8s.name])
}

deny contains msg if {
	input.kind == "HorizontalPodAutoscaler"
	input.spec.scaleTargetRef.name == "validator"
	msg := "HorizontalPodAutoscaler/validator: validators must never be autoscaled"
}

deny contains msg if {
	input.kind == "ConfigMap"
	startswith(input.metadata.name, "validator-config")
	fee_recipient_is_zero
	msg := sprintf("ConfigMap/%s: FEE_RECIPIENT is the zero address; execution rewards would be burned", [input.metadata.name])
}

deny contains msg if {
	input.kind == "ConfigMap"
	startswith(input.metadata.name, "validator-config")
	not fee_recipient_is_zero
	not valid_address(input.data.FEE_RECIPIENT)
	msg := sprintf("ConfigMap/%s: FEE_RECIPIENT is not a valid address", [input.metadata.name])
}

fee_recipient_is_zero if lower(input.data.FEE_RECIPIENT) == zero_address

# Rendered YAML is unquoted, and YAML resolves "0x000...0" to the integer 0.
fee_recipient_is_zero if input.data.FEE_RECIPIENT == 0

valid_address(a) if {
	is_string(a)
	regex.match(`^0x[0-9a-fA-F]{40}$`, a)
}

warn contains msg if {
	input.kind == "ConfigMap"
	startswith(input.metadata.name, "validator-config")
	input.data.INIT_SLASHING_PROTECTION == "true"
	msg := sprintf("ConfigMap/%s: INIT_SLASHING_PROTECTION=true - only valid for the first start of a new validator set", [input.metadata.name])
}
