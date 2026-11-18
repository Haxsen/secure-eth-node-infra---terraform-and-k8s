output "secret_arns" {
  description = "Map of secret suffix => ARN."
  value       = { for k, v in aws_secretsmanager_secret.this : k => v.arn }
}

output "secret_names" {
  description = "Map of secret suffix => full secret name (used in SecretProviderClass objects)."
  value       = { for k, v in aws_secretsmanager_secret.this : k => v.name }
}
