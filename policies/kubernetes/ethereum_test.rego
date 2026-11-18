package kubernetes.ethereum_test

import data.kubernetes.ethereum
import rego.v1

geth_image := "ethereum/client-go:v1@sha256:abc"

lighthouse_image := "sigp/lighthouse:v8@sha256:abc"

workload(kind, replicas, node_zone, container) := {
	"kind": kind,
	"metadata": {"name": "test"},
	"spec": {
		"replicas": replicas,
		"template": {"spec": {
			"nodeSelector": {"trust-zone": node_zone},
			"containers": [container],
		}},
	},
}

geth(args) := workload("StatefulSet", 2, "edge", {"name": "geth", "image": geth_image, "args": args})

validator(kind, replicas, args) := workload(kind, replicas, "signing", {"name": "validator", "image": lighthouse_image, "args": args})

good_vc_args := ["validator_client", "--network=hoodi", "--enable-doppelganger-protection"]

# --- geth -------------------------------------------------------------------------

test_safe_geth_passes if {
	count(ethereum.deny) == 0 with input as geth(["--http", "--http.api=eth,net,web3", "--authrpc.addr=127.0.0.1"])
}

test_geth_admin_api_is_denied if {
	some msg in ethereum.deny with input as geth(["--http.api=eth,admin"])
	contains(msg, "admin")
}

test_geth_debug_ws_api_is_denied if {
	some msg in ethereum.deny with input as geth(["--ws.api=eth,DEBUG"])
	contains(msg, "DEBUG")
}

test_geth_wildcard_vhosts_is_denied if {
	some msg in ethereum.deny with input as geth(["--http.vhosts=*"])
	contains(msg, "wildcard")
}

test_engine_api_on_network_is_denied if {
	some msg in ethereum.deny with input as geth(["--authrpc.addr=0.0.0.0"])
	contains(msg, "Engine API")
}

test_unlocked_account_is_denied if {
	some msg in ethereum.deny with input as geth(["--unlock=0xabc", "--allow-insecure-unlock"])
	contains(msg, "unlock")
}

test_geth_without_rpc_caps_warns if {
	some msg in ethereum.warn with input as geth(["--http"])
	contains(msg, "--rpc.gascap")
}

# --- validator ----------------------------------------------------------------------

test_good_validator_passes if {
	count(ethereum.deny) == 0 with input as validator("StatefulSet", 1, good_vc_args)
}

test_validator_deployment_is_denied if {
	some msg in ethereum.deny with input as validator("Deployment", 1, good_vc_args)
	contains(msg, "never a Deployment")
}

test_two_validator_replicas_are_denied if {
	some msg in ethereum.deny with input as validator("StatefulSet", 2, good_vc_args)
	contains(msg, "replicas: 1")
}

test_validator_without_doppelganger_is_denied if {
	some msg in ethereum.deny with input as validator("StatefulSet", 1, ["vc", "--network=hoodi"])
	contains(msg, "doppelganger")
}

test_hardcoded_init_slashing_protection_is_denied if {
	args := array.concat(good_vc_args, ["--init-slashing-protection"])
	some msg in ethereum.deny with input as validator("StatefulSet", 1, args)
	contains(msg, "init-slashing-protection")
}

test_keymanager_api_is_denied if {
	args := array.concat(good_vc_args, ["--http"])
	some msg in ethereum.deny with input as validator("StatefulSet", 1, args)
	contains(msg, "keymanager")
}

test_validator_on_edge_nodes_is_denied if {
	vc := workload("StatefulSet", 1, "edge", {"name": "validator", "image": lighthouse_image, "args": good_vc_args})
	some msg in ethereum.deny with input as vc
	contains(msg, "signing node group")
}

test_autoscaled_validator_is_denied if {
	hpa := {"kind": "HorizontalPodAutoscaler", "metadata": {"name": "v"}, "spec": {"scaleTargetRef": {"name": "validator"}}}
	some msg in ethereum.deny with input as hpa
	contains(msg, "autoscaled")
}

test_zero_fee_recipient_is_denied if {
	cm := {"kind": "ConfigMap", "metadata": {"name": "validator-config-abc"}, "data": {"FEE_RECIPIENT": "0x0000000000000000000000000000000000000000"}}
	some msg in ethereum.deny with input as cm
	contains(msg, "zero address")
}

test_invalid_fee_recipient_is_denied if {
	cm := {"kind": "ConfigMap", "metadata": {"name": "validator-config-abc"}, "data": {"FEE_RECIPIENT": "0x1234"}}
	some msg in ethereum.deny with input as cm
	contains(msg, "not a valid address")
}
