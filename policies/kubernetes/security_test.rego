package kubernetes.security_test

import data.kubernetes.security
import rego.v1

hardened_container := {
	"name": "app",
	"image": "example/app:1.0@sha256:abc",
	"resources": {"requests": {"cpu": "100m", "memory": "64Mi"}, "limits": {"memory": "128Mi"}},
	"securityContext": {
		"allowPrivilegeEscalation": false,
		"readOnlyRootFilesystem": true,
		"capabilities": {"drop": ["ALL"]},
	},
}

deployment(container) := {
	"kind": "Deployment",
	"metadata": {"name": "app"},
	"spec": {"template": {"spec": {
		"automountServiceAccountToken": false,
		"securityContext": {"runAsNonRoot": true, "seccompProfile": {"type": "RuntimeDefault"}},
		"containers": [container],
	}}},
}

test_hardened_deployment_passes if {
	count(security.deny) == 0 with input as deployment(hardened_container)
}

test_tag_only_image_is_denied if {
	c := object.union(hardened_container, {"image": "example/app:latest"})
	some msg in security.deny with input as deployment(c)
	contains(msg, "digest")
}

test_writable_root_fs_is_denied if {
	c := json.patch(hardened_container, [{"op": "remove", "path": "/securityContext/readOnlyRootFilesystem"}])
	some msg in security.deny with input as deployment(c)
	contains(msg, "readOnlyRootFilesystem")
}

test_added_capability_is_denied if {
	c := object.union(hardened_container, {"securityContext": object.union(hardened_container.securityContext, {"capabilities": {"drop": ["ALL"], "add": ["NET_ADMIN"]}})})
	some msg in security.deny with input as deployment(c)
	contains(msg, "add capabilities")
}

test_container_overriding_non_root_is_denied if {
	c := object.union(hardened_container, {"securityContext": object.union(hardened_container.securityContext, {"runAsNonRoot": false})})
	some msg in security.deny with input as deployment(c)
	contains(msg, "non-root")
}

test_missing_memory_limit_is_denied if {
	c := json.patch(hardened_container, [{"op": "remove", "path": "/resources/limits"}])
	some msg in security.deny with input as deployment(c)
	contains(msg, "limits.memory")
}

test_host_network_is_denied if {
	d := deployment(hardened_container)
	bad := json.patch(d, [{"op": "add", "path": "/spec/template/spec/hostNetwork", "value": true}])
	some msg in security.deny with input as bad
	contains(msg, "hostNetwork")
}

test_loadbalancer_service_is_denied if {
	some msg in security.deny with input as {"kind": "Service", "metadata": {"name": "rpc"}, "spec": {"type": "LoadBalancer"}}
	contains(msg, "bypasses the WAF")
}

test_ingress_without_waf_is_denied if {
	ing := {"kind": "Ingress", "metadata": {"name": "rpc", "annotations": {
		"alb.ingress.kubernetes.io/certificate-arn": "arn",
		"alb.ingress.kubernetes.io/ssl-policy": "p",
		"alb.ingress.kubernetes.io/listen-ports": "[{\"HTTPS\":443}]",
	}}}
	some msg in security.deny with input as ing
	contains(msg, "wafv2-acl-arn")
}

test_plain_http_listener_is_denied if {
	ing := {"kind": "Ingress", "metadata": {"name": "rpc", "annotations": {
		"alb.ingress.kubernetes.io/wafv2-acl-arn": "arn",
		"alb.ingress.kubernetes.io/certificate-arn": "arn",
		"alb.ingress.kubernetes.io/ssl-policy": "p",
		"alb.ingress.kubernetes.io/listen-ports": "[{\"HTTP\":80},{\"HTTPS\":443}]",
	}}}
	some msg in security.deny with input as ing
	contains(msg, "only HTTPS")
}

test_namespace_without_psa_is_denied if {
	some msg in security.deny with input as {"kind": "Namespace", "metadata": {"name": "x", "labels": {}}}
	contains(msg, "restricted")
}
