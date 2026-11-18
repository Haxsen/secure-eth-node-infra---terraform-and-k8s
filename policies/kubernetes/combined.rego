# Cross-document invariants. Run with: conftest test --combine --namespace kubernetes.combined
# (input is a list of {path, contents}; contents is a list for multi-doc YAML).
package kubernetes.combined

import rego.v1

documents contains doc if {
	some file in input
	is_array(file.contents)
	some doc in file.contents
	is_object(doc)
}

documents contains doc if {
	some file in input
	is_object(file.contents)
	doc := file.contents
}

namespaces contains ns if {
	some d in documents
	d.kind == "Namespace"
	ns := d.metadata.name
}

has_default_deny(ns) if {
	some d in documents
	d.kind == "NetworkPolicy"
	d.metadata.namespace == ns
	d.spec.podSelector == {}
	"Ingress" in d.spec.policyTypes
	"Egress" in d.spec.policyTypes
	not d.spec.ingress
	not d.spec.egress
}

deny contains msg if {
	some ns in namespaces
	not has_default_deny(ns)
	msg := sprintf("Namespace/%s: has no default-deny (ingress+egress) NetworkPolicy", [ns])
}

workloads contains d if {
	some d in documents
	d.kind in {"Deployment", "StatefulSet", "DaemonSet"}
}

deny contains msg if {
	some w in workloads
	not w.metadata.namespace in namespaces
	msg := sprintf("%s/%s: deployed into namespace %q which is not managed (and thus not policed) here", [w.kind, w.metadata.name, w.metadata.namespace])
}

deny contains msg if {
	some w in workloads
	sa := w.spec.template.spec.serviceAccountName
	not service_account_exists(w.metadata.namespace, sa)
	msg := sprintf("%s/%s: ServiceAccount %q is not defined", [w.kind, w.metadata.name, sa])
}

deny contains msg if {
	some w in workloads
	some v in w.spec.template.spec.volumes
	spc := v.csi.volumeAttributes.secretProviderClass
	not secret_provider_class_exists(w.metadata.namespace, spc)
	msg := sprintf("%s/%s: SecretProviderClass %q is not defined", [w.kind, w.metadata.name, spc])
}

service_account_exists(ns, name) if {
	some d in documents
	d.kind == "ServiceAccount"
	d.metadata.namespace == ns
	d.metadata.name == name
}

secret_provider_class_exists(ns, name) if {
	some d in documents
	d.kind == "SecretProviderClass"
	d.metadata.namespace == ns
	d.metadata.name == name
}
