# Shared helpers for per-document Kubernetes policies.
package lib.kubernetes

import rego.v1

pod_controllers := {"Deployment", "StatefulSet", "DaemonSet", "ReplicaSet", "Job"}

pod_spec := input.spec.template.spec if input.kind in pod_controllers

pod_spec := input.spec.jobTemplate.spec.template.spec if input.kind == "CronJob"

pod_spec := input.spec if input.kind == "Pod"

is_workload if {
	pod_spec
}

containers contains c if {
	some c in pod_spec.containers
}

containers contains c if {
	some c in pod_spec.initContainers
}

name := sprintf("%s/%s", [input.kind, input.metadata.name])

# Value of "--flag=value" in an args list.
flag_value(args, flag) := v if {
	some a in args
	prefix := concat("", [flag, "="])
	startswith(a, prefix)
	v := substring(a, count(prefix), -1)
}

has_flag(args, flag) if {
	some a in args
	a == flag
}

has_flag(args, flag) if {
	flag_value(args, flag)
}
