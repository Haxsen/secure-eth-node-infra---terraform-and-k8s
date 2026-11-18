variable "cluster_name" {
  type = string
}

variable "kubernetes_version" {
  type = string
}

variable "region" {
  type = string
}

variable "vpc_id" {
  type = string
}

variable "oidc_provider_arn" {
  type = string
}

variable "oidc_issuer" {
  type = string
}

variable "ebs_kms_key_arn" {
  description = "CMK for the eth-gp3-retain StorageClass."
  type        = string
}

variable "tags" {
  type    = map(string)
  default = {}
}
