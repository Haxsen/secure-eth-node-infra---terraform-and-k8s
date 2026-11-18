variable "name" {
  description = "Name prefix for key aliases."
  type        = string
}

variable "key_admin_arns" {
  description = "IAM principals allowed to administer (not use) the keys. Must already exist."
  type        = list(string)
  default     = []
}

variable "secrets_decrypt_principal_arns" {
  description = "The only principals allowed kms:Decrypt on the secrets key (workload roles + custodians). Need not exist yet."
  type        = list(string)

  validation {
    condition     = length(var.secrets_decrypt_principal_arns) > 0
    error_message = "At least one principal must be able to decrypt secrets, otherwise workloads cannot start."
  }
}

variable "deletion_window_in_days" {
  description = "Waiting period before a scheduled key deletion completes."
  type        = number
  default     = 30
}

variable "tags" {
  type    = map(string)
  default = {}
}
