variable "name" {
  type = string
}

variable "rate_limit_per_ip" {
  description = "Max requests per source IP per 60s window before WAF blocks with 429."
  type        = number
  default     = 1200

  validation {
    condition     = var.rate_limit_per_ip >= 10 && var.rate_limit_per_ip <= 2000000000
    error_message = "WAF rate limits must be between 10 and 2,000,000,000."
  }
}

variable "blocked_country_codes" {
  description = "ISO 3166-1 alpha-2 country codes to block at the edge."
  type        = list(string)
  default     = []
}

variable "logs_kms_key_arn" {
  type = string
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "tags" {
  type    = map(string)
  default = {}
}
