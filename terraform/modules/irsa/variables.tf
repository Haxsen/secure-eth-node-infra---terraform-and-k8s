variable "role_name" {
  type = string
}

variable "description" {
  type    = string
  default = "IRSA role managed by Terraform"
}

variable "oidc_provider_arn" {
  type = string
}

variable "oidc_issuer" {
  description = "Issuer host/path without the https:// scheme."
  type        = string

  validation {
    condition     = !startswith(var.oidc_issuer, "https://")
    error_message = "Pass the issuer without the https:// prefix."
  }
}

variable "service_accounts" {
  description = "List of \"namespace:serviceaccount\" pairs allowed to assume the role."
  type        = list(string)

  validation {
    condition     = alltrue([for sa in var.service_accounts : can(regex("^[a-z0-9-]+:[a-z0-9-]+$", sa))])
    error_message = "Each entry must be namespace:serviceaccount. Wildcards are deliberately not allowed."
  }
}

variable "inline_policies" {
  description = "Map of policy name => policy JSON."
  type        = map(string)
  default     = {}
}

variable "managed_policy_arns" {
  type    = list(string)
  default = []
}

variable "tags" {
  type    = map(string)
  default = {}
}
