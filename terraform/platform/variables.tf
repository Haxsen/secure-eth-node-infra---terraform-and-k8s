variable "region" {
  description = "AWS region."
  type        = string
}

variable "environment" {
  description = "Environment name; also the resource name suffix (eth-<environment>)."
  type        = string

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,15}$", var.environment))
    error_message = "environment must be lowercase alphanumeric/dash, max 16 chars."
  }
}

variable "eth_network" {
  description = "Ethereum network the clients join."
  type        = string

  validation {
    condition     = contains(["mainnet", "hoodi", "sepolia"], var.eth_network)
    error_message = "eth_network must be mainnet, hoodi or sepolia."
  }
}

variable "vpc_cidr" {
  type    = string
  default = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "Explicit AZs (pinned, so subnets never shift when AWS adds a zone). EBS-backed StatefulSets are AZ-bound."
  type        = list(string)

  validation {
    condition     = length(var.availability_zones) >= 2 && length(var.availability_zones) <= 3
    error_message = "Use two or three availability zones."
  }
}

variable "single_nat_gateway" {
  type    = bool
  default = false
}

variable "enable_interface_endpoints" {
  type    = bool
  default = true
}

variable "kubernetes_version" {
  type    = string
  default = "1.36"
}

variable "api_public_access_cidrs" {
  description = "Operator CIDRs allowed to reach the public EKS endpoint. Empty = private endpoint only."
  type        = list(string)
  default     = []
}

variable "api_private_access_cidrs" {
  description = "VPN / peered CIDRs allowed to reach the private EKS endpoint."
  type        = list(string)
  default     = []
}

variable "cluster_admin_principal_arns" {
  description = "IAM role ARNs granted cluster-admin. The principal running Terraform is added automatically."
  type        = list(string)
  default     = []
}

variable "kms_key_admin_arns" {
  description = "IAM principals that administer (not use) the CMKs."
  type        = list(string)
  default     = []
}

variable "key_custodian_principal_arns" {
  description = "Humans/CI roles that load secret material. They can write validator secrets but cannot read them back."
  type        = list(string)
  default     = []
}

variable "enable_ebs_encryption_by_default" {
  description = "Account/region-wide: force EBS encryption with the platform CMK. Disable in shared accounts."
  type        = bool
  default     = true
}

variable "node_groups" {
  description = "Node groups keyed by trust zone. See envs/*.tfvars."
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
    condition     = alltrue([for z in ["system", "edge", "signing"] : contains(keys(var.node_groups), z)])
    error_message = "node_groups must define the system, edge and signing trust zones."
  }

  validation {
    condition     = !contains(keys(var.node_groups), "signing") || try(var.node_groups["signing"].capacity_type == "ON_DEMAND", false)
    error_message = "The signing (validator) zone must use ON_DEMAND capacity; a Spot reclaim mid-duty means missed attestations."
  }
}

variable "waf_rate_limit_per_ip" {
  type    = number
  default = 1200
}

variable "waf_blocked_country_codes" {
  type    = list(string)
  default = []
}

variable "log_retention_days" {
  type    = number
  default = 365
}

variable "rpc_hostname" {
  description = "Public hostname of the RPC endpoint (must match the ACM certificate)."
  type        = string
  default     = "rpc.example.com"
}

variable "acm_certificate_arn" {
  description = "ACM certificate for rpc_hostname, used by the ALB HTTPS listener."
  type        = string
  default     = ""
}

variable "tags" {
  type    = map(string)
  default = {}
}
