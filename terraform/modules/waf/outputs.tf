output "web_acl_arn" {
  description = "Set as alb.ingress.kubernetes.io/wafv2-acl-arn on the rpc-gateway Ingress."
  value       = aws_wafv2_web_acl.this.arn
}
