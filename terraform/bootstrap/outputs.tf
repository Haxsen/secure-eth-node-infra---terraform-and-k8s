output "state_bucket" {
  description = "Use as `bucket` in envs/<env>.s3.tfbackend."
  value       = aws_s3_bucket.state.id
}

output "state_kms_key_arn" {
  description = "Use as `kms_key_id` in envs/<env>.s3.tfbackend."
  value       = aws_kms_key.state.arn
}
