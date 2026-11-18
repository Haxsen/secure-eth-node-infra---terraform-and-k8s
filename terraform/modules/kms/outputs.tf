output "key_arns" {
  description = "Map of purpose => key ARN (eks, ebs, logs, secrets)."
  value       = { for k, v in aws_kms_key.this : k => v.arn }
}
