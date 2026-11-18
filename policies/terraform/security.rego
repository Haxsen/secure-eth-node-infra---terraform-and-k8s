# Guardrails evaluated against `terraform show -json plan.out`.
# They complement Checkov with rules specific to this platform's threat model.
package terraform.security

import rego.v1

# Resources being created or updated.
changes contains rc if {
	some rc in input.resource_changes
	some action in rc.change.actions
	action in {"create", "update"}
}

of_type(t) := {rc | some rc in changes; rc.type == t}

addr(rc) := rc.address

# Attribute known at plan time OR computed during apply (e.g. a KMS ARN of a
# key created in the same run) counts as "set".
is_set(rc, attr) if rc.change.after[attr] != null

is_set(rc, attr) if rc.change.after_unknown[attr] == true

as_array(x) := x if is_array(x)

as_array(x) := [x] if not is_array(x)

# =============================== secrets =====================================

# Secret *values* must never be managed by Terraform: they would be written to
# state and plan files in plaintext.
deny contains msg if {
	some rc in input.resource_changes
	rc.type == "aws_secretsmanager_secret_version"
	msg := sprintf("%s: secret values must be loaded out-of-band (scripts/), never via Terraform state", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_secretsmanager_secret")
	not is_set(rc, "kms_key_id")
	msg := sprintf("%s: secrets must be encrypted with a customer-managed KMS key", [addr(rc)])
}

# ================================ KMS ========================================

deny contains msg if {
	some rc in of_type("aws_kms_key")
	not rc.change.after.enable_key_rotation == true
	msg := sprintf("%s: KMS key rotation must be enabled", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_kms_key")
	rc.change.after.deletion_window_in_days < 14
	msg := sprintf("%s: KMS deletion window must be >= 14 days", [addr(rc)])
}

# ================================ EKS ========================================

deny contains msg if {
	some rc in of_type("aws_eks_cluster")
	count(object.get(rc.change.after, "encryption_config", [])) == 0
	msg := sprintf("%s: Kubernetes Secrets must be envelope-encrypted with KMS", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_eks_cluster")
	some vpc in rc.change.after.vpc_config
	vpc.endpoint_public_access == true
	some cidr in object.get(vpc, "public_access_cidrs", ["0.0.0.0/0"])
	cidr == "0.0.0.0/0"
	msg := sprintf("%s: public API endpoint must not be open to 0.0.0.0/0", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_eks_cluster")
	enabled := {t | some t in object.get(rc.change.after, "enabled_cluster_log_types", [])}
	missing := {"api", "audit", "authenticator"} - enabled
	count(missing) > 0
	msg := sprintf("%s: control plane log types missing: %v", [addr(rc), missing])
}

deny contains msg if {
	some rc in of_type("aws_eks_cluster")
	some ac in rc.change.after.access_config
	ac.bootstrap_cluster_creator_admin_permissions == true
	msg := sprintf("%s: use explicit access entries instead of implicit creator admin", [addr(rc)])
}

# ============================ Compute / IMDS =================================

deny contains msg if {
	some rc in of_type("aws_launch_template")
	not imdsv2_hop_limited(rc)
	msg := sprintf("%s: require IMDSv2 (http_tokens=required) with hop limit 1 so pods cannot steal node credentials", [addr(rc)])
}

imdsv2_hop_limited(rc) if {
	some m in rc.change.after.metadata_options
	m.http_tokens == "required"
	m.http_put_response_hop_limit == 1
}

deny contains msg if {
	some rc in of_type("aws_launch_template")
	some bdm in rc.change.after.block_device_mappings
	some ebs in bdm.ebs
	not ebs.encrypted == "true"
	not ebs.encrypted == true
	msg := sprintf("%s: EBS volume %s must be encrypted", [addr(rc), bdm.device_name])
}

deny contains msg if {
	some rc in of_type("aws_eks_node_group")
	rc.change.after.labels["trust-zone"] == "signing"
	rc.change.after.capacity_type == "SPOT"
	msg := sprintf("%s: the validator signing zone must not run on Spot", [addr(rc)])
}

# ============================== Network ======================================

open_cidrs := {"0.0.0.0/0", "::/0"}

deny contains msg if {
	some rc in of_type("aws_vpc_security_group_ingress_rule")
	some f in ["cidr_ipv4", "cidr_ipv6"]
	rc.change.after[f] in open_cidrs
	msg := sprintf("%s: security group ingress from the internet is forbidden (the ALB SG is owned by the LB controller)", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_security_group")
	some rule in object.get(rc.change.after, "ingress", [])
	some cidr in array.concat(object.get(rule, "cidr_blocks", []), object.get(rule, "ipv6_cidr_blocks", []))
	cidr in open_cidrs
	msg := sprintf("%s: security group ingress from the internet is forbidden", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_subnet")
	rc.change.after.map_public_ip_on_launch == true
	msg := sprintf("%s: subnets must not auto-assign public IPs", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_s3_bucket_public_access_block")
	some f in ["block_public_acls", "block_public_policy", "ignore_public_acls", "restrict_public_buckets"]
	not rc.change.after[f] == true
	msg := sprintf("%s: %s must be true", [addr(rc), f])
}

# =============================== Logging =====================================

deny contains msg if {
	some rc in of_type("aws_cloudwatch_log_group")
	not is_set(rc, "kms_key_id")
	msg := sprintf("%s: log groups must be KMS-encrypted", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_cloudwatch_log_group")
	object.get(rc.change.after, "retention_in_days", 0) == 0
	msg := sprintf("%s: set an explicit log retention", [addr(rc)])
}

# ================================= IAM =======================================

policy_types := {"aws_iam_policy", "aws_iam_role_policy", "aws_iam_user_policy", "aws_iam_group_policy"}

deny contains msg if {
	some rc in changes
	rc.type in policy_types
	doc := json.unmarshal(rc.change.after.policy)
	some st in as_array(doc.Statement)
	st.Effect == "Allow"
	"*" in as_array(st.Action)
	"*" in as_array(object.get(st, "Resource", []))
	msg := sprintf("%s: Allow * on * is forbidden", [addr(rc)])
}

deny contains msg if {
	some rc in of_type("aws_iam_role")
	doc := json.unmarshal(rc.change.after.assume_role_policy)
	some st in as_array(doc.Statement)
	st.Effect == "Allow"
	st.Principal == "*"
	msg := sprintf("%s: role trust policy allows any principal", [addr(rc)])
}

# ================================= WAF =======================================

deny contains msg if {
	some rc in of_type("aws_wafv2_web_acl")
	not has_rate_limit(rc)
	msg := sprintf("%s: the public RPC web ACL must include a rate-based rule", [addr(rc)])
}

has_rate_limit(rc) if {
	some rule in rc.change.after.rule
	some st in rule.statement
	count(object.get(st, "rate_based_statement", [])) > 0
}
