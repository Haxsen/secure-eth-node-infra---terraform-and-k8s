output "cluster_name" {
  value = aws_eks_cluster.this.name
}

output "cluster_endpoint" {
  value = aws_eks_cluster.this.endpoint
}

output "cluster_certificate_authority_data" {
  value = aws_eks_cluster.this.certificate_authority[0].data
}

output "cluster_version" {
  value = aws_eks_cluster.this.version
}

output "oidc_provider_arn" {
  value = aws_iam_openid_connect_provider.this.arn
}

output "oidc_issuer" {
  description = "Issuer without scheme, for IRSA trust conditions."
  value       = local.oidc_issuer
}

output "node_role_arn" {
  value = aws_iam_role.node.arn
}

output "node_group_names" {
  value = { for k, v in aws_eks_node_group.this : k => v.node_group_name }
}
