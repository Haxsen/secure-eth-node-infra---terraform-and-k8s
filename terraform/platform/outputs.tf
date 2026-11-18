output "cluster_name" {
  value = module.eks.cluster_name
}

output "kubeconfig_command" {
  value = "aws eks update-kubeconfig --region ${local.region} --name ${module.eks.cluster_name}"
}

output "workload_role_arns" {
  value = { for k, m in module.workload_irsa : k => m.role_arn }
}

output "secret_names" {
  description = "Secret containers to populate with scripts/ (values are never managed by Terraform)."
  value       = module.secrets.secret_names
}

output "waf_web_acl_arn" {
  value = module.waf.web_acl_arn
}

output "storage_class_name" {
  value = module.cluster_addons.storage_class_name
}

# Consumed by scripts/sync-tf-outputs.sh to render k8s/overlays/<env>/cluster-config.env.
output "k8s_cluster_config" {
  value = {
    AWS_REGION           = local.region
    SECRET_PREFIX        = local.name
    ETH_NODE_ROLE_ARN    = module.workload_irsa["eth-node"].role_arn
    VALIDATOR_ROLE_ARN   = module.workload_irsa["validator"].role_arn
    RPC_GATEWAY_ROLE_ARN = module.workload_irsa["rpc-gateway"].role_arn
    WAF_WEB_ACL_ARN      = module.waf.web_acl_arn
    ACM_CERTIFICATE_ARN  = var.acm_certificate_arn
    RPC_HOSTNAME         = var.rpc_hostname
    PUBLIC_SUBNET_CIDR_A = module.network.public_subnet_cidrs[0]
    PUBLIC_SUBNET_CIDR_B = module.network.public_subnet_cidrs[1]
    PUBLIC_SUBNET_CIDR_C = try(module.network.public_subnet_cidrs[2], module.network.public_subnet_cidrs[0])
  }
}
