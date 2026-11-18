# -----------------------------------------------------------------------------
# Hardened Ethereum node platform - root stack.
#
#   network -> kms -> eks -> cluster-addons
#                 \-> secrets (+ per-workload IRSA)
#                 \-> waf
#
# Workload IAM role ARNs are computed from deterministic names so that KMS key
# policies and Secrets Manager resource policies can reference them before the
# roles exist, without a dependency cycle.
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  name       = "eth-${var.environment}"
  account_id = data.aws_caller_identity.current.account_id
  partition  = data.aws_partition.current.partition
  region     = data.aws_region.current.region

  # Project / Environment / ManagedBy come from provider default_tags.
  tags = merge(var.tags, { EthNetwork = var.eth_network })

  # namespace / service account / secrets each workload may read.
  workloads = {
    eth-node = {
      namespace       = "eth-nodes"
      service_account = "eth-node"
      secrets         = ["jwt-secret"]
    }
    validator = {
      namespace       = "eth-validator"
      service_account = "validator"
      secrets         = ["validator/keystores", "validator/keystore-password"]
    }
    rpc-gateway = {
      namespace       = "rpc-gateway"
      service_account = "rpc-gateway"
      secrets         = ["rpc-gateway/api-keys"]
    }
  }

  workload_role_arns = {
    for k, _ in local.workloads : k => "arn:${local.partition}:iam::${local.account_id}:role/${local.name}-${k}"
  }

  secrets = {
    "jwt-secret" = {
      description = "Engine API JWT shared by geth and the Lighthouse beacon node"
      reader_arns = [local.workload_role_arns["eth-node"]]
    }
    "validator/keystores" = {
      description = "EIP-2335 validator keystores (base64 tar.gz bundle)"
      reader_arns = [local.workload_role_arns["validator"]]
    }
    "validator/keystore-password" = {
      description = "Password that unlocks the validator keystores"
      reader_arns = [local.workload_role_arns["validator"]]
    }
    "rpc-gateway/api-keys" = {
      description = "SHA-256 hashes of RPC gateway API keys (no plaintext keys)"
      # Custodians may read the hash list so they can add/revoke keys.
      reader_arns = concat([local.workload_role_arns["rpc-gateway"]], var.key_custodian_principal_arns)
    }
  }
}

# --- Network -----------------------------------------------------------------------

module "network" {
  source = "../modules/network"

  name                       = local.name
  cluster_name               = local.name
  vpc_cidr                   = var.vpc_cidr
  azs                        = var.availability_zones
  single_nat_gateway         = var.single_nat_gateway
  enable_interface_endpoints = var.enable_interface_endpoints
  flow_log_kms_key_arn       = module.kms.key_arns["logs"]
  flow_log_retention_days    = var.log_retention_days
  tags                       = local.tags
}

# --- Encryption keys ------------------------------------------------------------------

module "kms" {
  source = "../modules/kms"

  name           = local.name
  key_admin_arns = var.kms_key_admin_arns
  secrets_decrypt_principal_arns = concat(
    values(local.workload_role_arns),
    var.key_custodian_principal_arns,
  )
  tags = local.tags
}

# Any EBS volume created in this account/region without explicit encryption
# settings is still encrypted with our CMK.
resource "aws_ebs_encryption_by_default" "this" {
  count   = var.enable_ebs_encryption_by_default ? 1 : 0
  enabled = true
}

resource "aws_ebs_default_kms_key" "this" {
  count   = var.enable_ebs_encryption_by_default ? 1 : 0
  key_arn = module.kms.key_arns["ebs"]
}

# --- EKS --------------------------------------------------------------------------------

module "eks" {
  source = "../modules/eks"

  name                         = local.name
  kubernetes_version           = var.kubernetes_version
  vpc_id                       = module.network.vpc_id
  private_subnet_ids           = module.network.private_subnet_ids
  api_public_access_cidrs      = var.api_public_access_cidrs
  api_private_access_cidrs     = var.api_private_access_cidrs
  cluster_admin_principal_arns = var.cluster_admin_principal_arns
  secrets_kms_key_arn          = module.kms.key_arns["eks"]
  ebs_kms_key_arn              = module.kms.key_arns["ebs"]
  logs_kms_key_arn             = module.kms.key_arns["logs"]
  log_retention_days           = var.log_retention_days
  node_groups                  = var.node_groups
  tags                         = local.tags
}

module "cluster_addons" {
  source = "../modules/cluster-addons"

  cluster_name       = module.eks.cluster_name
  kubernetes_version = module.eks.cluster_version
  region             = local.region
  vpc_id             = module.network.vpc_id
  oidc_provider_arn  = module.eks.oidc_provider_arn
  oidc_issuer        = module.eks.oidc_issuer
  ebs_kms_key_arn    = module.kms.key_arns["ebs"]
  tags               = local.tags

  depends_on = [module.eks]
}

# --- Secrets + workload identities --------------------------------------------------

module "secrets" {
  source = "../modules/secrets"

  name_prefix = local.name
  kms_key_arn = module.kms.key_arns["secrets"]
  secrets     = local.secrets
  tags        = local.tags
}

data "aws_iam_policy_document" "workload" {
  for_each = local.workloads

  statement {
    sid       = "ReadOwnSecretsOnly"
    actions   = ["secretsmanager:GetSecretValue", "secretsmanager:DescribeSecret"]
    resources = [for s in each.value.secrets : module.secrets.secret_arns[s]]
  }

  statement {
    sid       = "DecryptViaSecretsManagerOnly"
    actions   = ["kms:Decrypt"]
    resources = [module.kms.key_arns["secrets"]]
    condition {
      test     = "StringEquals"
      variable = "kms:ViaService"
      values   = ["secretsmanager.${local.region}.amazonaws.com"]
    }
  }
}

module "workload_irsa" {
  source   = "../modules/irsa"
  for_each = local.workloads

  role_name         = "${local.name}-${each.key}"
  description       = "Secrets access for ${each.value.namespace}/${each.value.service_account}"
  oidc_provider_arn = module.eks.oidc_provider_arn
  oidc_issuer       = module.eks.oidc_issuer
  service_accounts  = ["${each.value.namespace}:${each.value.service_account}"]
  inline_policies   = { "read-secrets" = data.aws_iam_policy_document.workload[each.key].json }
  tags              = local.tags
}

# --- Edge protection --------------------------------------------------------------------

module "waf" {
  source = "../modules/waf"

  name                  = local.name
  rate_limit_per_ip     = var.waf_rate_limit_per_ip
  blocked_country_codes = var.waf_blocked_country_codes
  logs_kms_key_arn      = module.kms.key_arns["logs"]
  log_retention_days    = var.log_retention_days
  tags                  = local.tags
}
