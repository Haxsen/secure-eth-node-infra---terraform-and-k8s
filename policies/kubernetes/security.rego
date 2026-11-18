# Generic workload hardening. Mirrors (and goes beyond) Pod Security
# "restricted" so violations fail in CI, not at admission time.
package kubernetes.security

import data.lib.kubernetes as k8s
import rego.v1

# --- Pod-level --------------------------------------------------------------------

deny contains msg if {
	k8s.is_workload
	not k8s.pod_spec.automountServiceAccountToken == false
	msg := sprintf("%s: automountServiceAccountToken must be false (no pod needs the Kubernetes API)", [k8s.name])
}

deny contains msg if {
	some field in ["hostNetwork", "hostPID", "hostIPC"]
	k8s.pod_spec[field] == true
	msg := sprintf("%s: %s is forbidden", [k8s.name, field])
}

deny contains msg if {
	some v in k8s.pod_spec.volumes
	v.hostPath
	msg := sprintf("%s: hostPath volume %q is forbidden", [k8s.name, v.name])
}

# --- Container-level ----------------------------------------------------------------

deny contains msg if {
	some c in k8s.containers
	c.securityContext.privileged == true
	msg := sprintf("%s: container %q must not be privileged", [k8s.name, c.name])
}

deny contains msg if {
	some c in k8s.containers
	not c.securityContext.allowPrivilegeEscalation == false
	msg := sprintf("%s: container %q must set allowPrivilegeEscalation: false", [k8s.name, c.name])
}

deny contains msg if {
	some c in k8s.containers
	not c.securityContext.readOnlyRootFilesystem == true
	msg := sprintf("%s: container %q must set readOnlyRootFilesystem: true", [k8s.name, c.name])
}

deny contains msg if {
	some c in k8s.containers
	not "ALL" in object.get(c, ["securityContext", "capabilities", "drop"], [])
	msg := sprintf("%s: container %q must drop ALL capabilities", [k8s.name, c.name])
}

deny contains msg if {
	some c in k8s.containers
	count(object.get(c, ["securityContext", "capabilities", "add"], [])) > 0
	msg := sprintf("%s: container %q must not add capabilities", [k8s.name, c.name])
}

deny contains msg if {
	some c in k8s.containers
	not runs_as_non_root(c)
	msg := sprintf("%s: container %q must run as non-root (runAsNonRoot: true)", [k8s.name, c.name])
}

deny contains msg if {
	some c in k8s.containers
	not has_seccomp(c)
	msg := sprintf("%s: container %q needs a RuntimeDefault or Localhost seccomp profile", [k8s.name, c.name])
}

# Supply chain: tags are mutable, digests are not.
deny contains msg if {
	some c in k8s.containers
	not contains(c.image, "@sha256:")
	msg := sprintf("%s: container %q image %q must be pinned by digest", [k8s.name, c.name, c.image])
}

deny contains msg if {
	some c in k8s.containers
	some r in ["cpu", "memory"]
	not c.resources.requests[r]
	msg := sprintf("%s: container %q must set resources.requests.%s", [k8s.name, c.name, r])
}

# Memory limits prevent one noisy client from OOM-ing its neighbours. CPU limits
# are deliberately NOT required: CFS throttling hurts block-processing latency.
deny contains msg if {
	some c in k8s.containers
	not c.resources.limits.memory
	msg := sprintf("%s: container %q must set resources.limits.memory", [k8s.name, c.name])
}

# --- Exposure ----------------------------------------------------------------------

deny contains msg if {
	input.kind == "Service"
	input.spec.type in {"LoadBalancer", "NodePort"}
	msg := sprintf("Service/%s: type %s bypasses the WAF; expose only via the rpc-gateway Ingress", [input.metadata.name, input.spec.type])
}

deny contains msg if {
	input.kind == "Ingress"
	annotations := object.get(input.metadata, "annotations", {})
	some required in [
		"alb.ingress.kubernetes.io/wafv2-acl-arn",
		"alb.ingress.kubernetes.io/certificate-arn",
		"alb.ingress.kubernetes.io/ssl-policy",
	]
	not annotations[required]
	msg := sprintf("Ingress/%s: missing %s", [input.metadata.name, required])
}

deny contains msg if {
	input.kind == "Ingress"
	ports := json.unmarshal(input.metadata.annotations["alb.ingress.kubernetes.io/listen-ports"])
	some p in ports
	some proto, _ in p
	proto != "HTTPS"
	msg := sprintf("Ingress/%s: only HTTPS listeners are allowed, found %s", [input.metadata.name, proto])
}

deny contains msg if {
	input.kind == "Namespace"
	not input.metadata.labels["pod-security.kubernetes.io/enforce"] == "restricted"
	msg := sprintf("Namespace/%s: must enforce Pod Security 'restricted'", [input.metadata.name])
}

# --- helpers -------------------------------------------------------------------------

runs_as_non_root(c) if c.securityContext.runAsNonRoot == true

runs_as_non_root(c) if {
	not c.securityContext.runAsNonRoot == false
	k8s.pod_spec.securityContext.runAsNonRoot == true
}

allowed_seccomp := {"RuntimeDefault", "Localhost"}

has_seccomp(c) if c.securityContext.seccompProfile.type in allowed_seccomp

has_seccomp(c) if {
	not c.securityContext.seccompProfile
	k8s.pod_spec.securityContext.seccompProfile.type in allowed_seccomp
}
