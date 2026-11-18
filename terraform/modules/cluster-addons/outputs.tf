output "storage_class_name" {
  value = kubernetes_storage_class_v1.eth_gp3.metadata[0].name
}

output "alb_controller_role_arn" {
  value = module.alb_controller_irsa.role_arn
}
