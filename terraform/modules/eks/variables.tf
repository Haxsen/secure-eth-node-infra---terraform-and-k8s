variable "name" {
  description = "Cluster name."
  type        = string
}

variable "kubernetes_version" {
  description = "EKS Kubernetes minor version."
  type        = string
}

variable "vpc_id" {
  type = string
}

variable "private_subnet_ids" {
  description = "Subnets for the control plane ENIs and all nodes."
  type        = list(string)
}

variable "api_public_access_cidrs" {
  description = "If non-empty, enables the public API endpoint for exactly these CIDRs. Empty = private only."
  type        = list(string)
  default     = []

  validation {
    condition     = !contains(var.api_public_access_cidrs, "0.0.0.0/0")
    error_message = "Refusing to expose the Kubernetes API to 0.0.0.0/0."
  }
}

variable "api_private_access_cidrs" {
  description = "Extra in-VPC/VPN CIDRs allowed to reach the private API endpoint."
  type        = list(string)
  default     = []
}

variable "cluster_admin_principal_arns" {
  description = "IAM roles/users granted cluster-admin via EKS access entries."
  type        = list(string)
  default     = []
}

variable "secrets_kms_key_arn" {
  description = "CMK for Kubernetes Secrets envelope encryption."
  type        = string
}

variable "ebs_kms_key_arn" {
  description = "CMK for node volumes."
  type        = string
}

variable "logs_kms_key_arn" {
  description = "CMK for the control plane log group."
  type        = string
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "node_groups" {
  description = "Managed node groups keyed by trust zone (the key becomes the trust-zone label)."
  type = map(object({
    instance_types = list(string)
    capacity_type  = optional(string, "ON_DEMAND")
    min_size       = number
    max_size       = number
    desired_size   = number
    disk_size_gb   = optional(number, 50)
    labels         = optional(map(string), {})
    taints = optional(list(object({
      key    = string
      value  = string
      effect = string
    })), [])
  }))

  validation {
    condition = alltrue(flatten([
      for ng in values(var.node_groups) : [
        for t in ng.taints : contains(["NO_SCHEDULE", "NO_EXECUTE", "PREFER_NO_SCHEDULE"], t.effect)
      ]
    ]))
    error_message = "Taint effect must be NO_SCHEDULE, NO_EXECUTE or PREFER_NO_SCHEDULE."
  }
}

variable "tags" {
  type    = map(string)
  default = {}
}
