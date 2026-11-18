variable "name_prefix" {
  description = "Path prefix for secret names, e.g. eth-hoodi."
  type        = string
}

variable "kms_key_arn" {
  description = "CMK used to encrypt every secret."
  type        = string
}

variable "secrets" {
  description = "Map of secret suffix => description and the principals allowed to read it."
  type = map(object({
    description = string
    reader_arns = list(string)
  }))

  validation {
    condition     = alltrue([for s in values(var.secrets) : length(s.reader_arns) > 0])
    error_message = "Every secret needs at least one reader."
  }
}

variable "recovery_window_in_days" {
  description = "Days a deleted secret stays recoverable. Keep this > 0 for validator keys."
  type        = number
  default     = 30

  validation {
    condition     = var.recovery_window_in_days >= 7
    error_message = "Validator secrets must remain recoverable for at least 7 days after deletion."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
