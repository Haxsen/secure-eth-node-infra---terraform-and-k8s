package terraform.security_test

import data.terraform.security
import rego.v1

plan(changes) := {"resource_changes": changes}

change(type, after) := {
	"address": sprintf("%s.test", [type]),
	"type": type,
	"change": {"actions": ["create"], "after": after, "after_unknown": {}},
}

# --- secrets ----------------------------------------------------------------------

test_secret_version_is_denied if {
	some msg in security.deny with input as plan([change("aws_secretsmanager_secret_version", {"secret_string": "x"})])
	contains(msg, "out-of-band")
}

test_secret_kms_known_after_apply_is_allowed if {
	rc := {
		"address": "aws_secretsmanager_secret.jwt",
		"type": "aws_secretsmanager_secret",
		"change": {"actions": ["create"], "after": {"name": "jwt"}, "after_unknown": {"kms_key_id": true}},
	}
	count(security.deny) == 0 with input as plan([rc])
}

# --- EKS ------------------------------------------------------------------------

good_cluster := {
	"enabled_cluster_log_types": ["api", "audit", "authenticator", "controllerManager", "scheduler"],
	"encryption_config": [{"resources": ["secrets"], "provider": [{}]}],
	"access_config": [{"authentication_mode": "API", "bootstrap_cluster_creator_admin_permissions": false}],
	"vpc_config": [{"endpoint_public_access": false, "endpoint_private_access": true}],
}

test_hardened_cluster_passes if {
	count(security.deny) == 0 with input as plan([change("aws_eks_cluster", good_cluster)])
}

test_cluster_without_encryption_is_denied if {
	after := object.remove(good_cluster, ["encryption_config"])
	some msg in security.deny with input as plan([change("aws_eks_cluster", after)])
	contains(msg, "envelope-encrypted")
}

test_world_open_api_endpoint_is_denied if {
	after := object.union(good_cluster, {"vpc_config": [{"endpoint_public_access": true, "public_access_cidrs": ["0.0.0.0/0"]}]})
	some msg in security.deny with input as plan([change("aws_eks_cluster", after)])
	contains(msg, "0.0.0.0/0")
}

test_allowlisted_api_endpoint_passes if {
	after := object.union(good_cluster, {"vpc_config": [{"endpoint_public_access": true, "public_access_cidrs": ["203.0.113.10/32"]}]})
	count(security.deny) == 0 with input as plan([change("aws_eks_cluster", after)])
}

test_missing_audit_logs_denied if {
	after := object.union(good_cluster, {"enabled_cluster_log_types": ["api"]})
	some msg in security.deny with input as plan([change("aws_eks_cluster", after)])
	contains(msg, "log types missing")
}

# --- IMDS ---------------------------------------------------------------------------

test_imds_hop_limit_two_is_denied if {
	lt := {"metadata_options": [{"http_tokens": "required", "http_put_response_hop_limit": 2}], "block_device_mappings": []}
	some msg in security.deny with input as plan([change("aws_launch_template", lt)])
	contains(msg, "IMDSv2")
}

test_imds_v1_is_denied if {
	lt := {"metadata_options": [{"http_tokens": "optional", "http_put_response_hop_limit": 1}], "block_device_mappings": []}
	some msg in security.deny with input as plan([change("aws_launch_template", lt)])
	contains(msg, "IMDSv2")
}

test_unencrypted_ebs_is_denied if {
	lt := {
		"metadata_options": [{"http_tokens": "required", "http_put_response_hop_limit": 1}],
		"block_device_mappings": [{"device_name": "/dev/xvda", "ebs": [{"encrypted": "false"}]}],
	}
	some msg in security.deny with input as plan([change("aws_launch_template", lt)])
	contains(msg, "must be encrypted")
}

test_spot_signing_zone_is_denied if {
	ng := {"labels": {"trust-zone": "signing"}, "capacity_type": "SPOT"}
	some msg in security.deny with input as plan([change("aws_eks_node_group", ng)])
	contains(msg, "Spot")
}

# --- network / IAM / KMS / WAF ---------------------------------------------------------

test_world_ingress_rule_is_denied if {
	some msg in security.deny with input as plan([change("aws_vpc_security_group_ingress_rule", {"cidr_ipv4": "0.0.0.0/0"})])
	contains(msg, "internet")
}

test_admin_policy_is_denied if {
	p := json.marshal({"Version": "2012-10-17", "Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]})
	some msg in security.deny with input as plan([change("aws_iam_role_policy", {"policy": p})])
	contains(msg, "Allow * on *")
}

test_kms_without_rotation_is_denied if {
	some msg in security.deny with input as plan([change("aws_kms_key", {"enable_key_rotation": false, "deletion_window_in_days": 30})])
	contains(msg, "rotation")
}

test_waf_without_rate_limit_is_denied if {
	acl := {"rule": [{"statement": [{"managed_rule_group_statement": [{}], "rate_based_statement": []}]}]}
	some msg in security.deny with input as plan([change("aws_wafv2_web_acl", acl)])
	contains(msg, "rate-based")
}

test_waf_with_rate_limit_passes if {
	acl := {"rule": [{"statement": [{"rate_based_statement": [{"limit": 1200}]}]}]}
	count(security.deny) == 0 with input as plan([change("aws_wafv2_web_acl", acl)])
}
