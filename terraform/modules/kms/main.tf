# -----------------------------------------------------------------------------
# Customer-managed KMS keys, one per purpose, so a compromise or mis-grant of
# one key does not expose the others and CloudTrail shows exactly which data
# class was touched.
#
#   eks     - envelope encryption of Kubernetes Secrets in etcd
#   ebs     - node root volumes and chain-data / slashing-protection volumes
#   logs    - CloudWatch log groups (control plane, flow logs, WAF)
#   secrets - Secrets Manager: validator keystores, keystore password, JWT, API key hashes
# -----------------------------------------------------------------------------

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_region" "current" {}

locals {
  partition    = data.aws_partition.current.partition
  account_id   = data.aws_caller_identity.current.account_id
  region       = data.aws_region.current.region
  account_root = "arn:${local.partition}:iam::${local.account_id}:root"

  # Managed node groups launch instances through EC2 Auto Scaling, whose
  # service-linked role must be able to use the CMK for encrypted root volumes.
  autoscaling_slr_arn = "arn:${local.partition}:iam::${local.account_id}:role/aws-service-role/autoscaling.amazonaws.com/AWSServiceRoleForAutoScaling"
}

# --- Statements shared by every key ------------------------------------------

data "aws_iam_policy_document" "base" {
  #checkov:skip=CKV_AWS_109:Key policy - Resource "*" means "this key"; root statement is the AWS-required delegation to IAM.
  #checkov:skip=CKV_AWS_111:Key policy - Resource "*" means "this key"; root statement is the AWS-required delegation to IAM.
  #checkov:skip=CKV_AWS_356:Key policy - Resource "*" means "this key", not all resources.
  # Delegates authorisation to IAM. Without this the key is unmanageable.
  statement {
    sid = "EnableIAMPolicies"
    principals {
      type        = "AWS"
      identifiers = [local.account_root]
    }
    actions   = ["kms:*"]
    resources = ["*"]
  }

  dynamic "statement" {
    for_each = length(var.key_admin_arns) > 0 ? [1] : []
    content {
      sid = "AllowKeyAdministration"
      principals {
        type        = "AWS"
        identifiers = var.key_admin_arns
      }
      actions = [
        "kms:CancelKeyDeletion",
        "kms:Create*",
        "kms:Delete*",
        "kms:Describe*",
        "kms:Disable*",
        "kms:Enable*",
        "kms:Get*",
        "kms:List*",
        "kms:Put*",
        "kms:Revoke*",
        "kms:RotateKeyOnDemand",
        "kms:ScheduleKeyDeletion",
        "kms:TagResource",
        "kms:UntagResource",
        "kms:Update*",
      ]
      resources = ["*"]
    }
  }
}

# --- Per-purpose key policies -------------------------------------------------

data "aws_iam_policy_document" "eks" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]
}

data "aws_iam_policy_document" "ebs" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]

  # Principal "*" + aws:PrincipalArn (instead of naming the role as principal)
  # keeps this policy valid in fresh accounts where the Auto Scaling
  # service-linked role does not exist yet.
  statement {
    sid = "AllowAutoScalingServiceLinkedRoleUse"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [local.autoscaling_slr_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
  }

  statement {
    sid = "AllowAutoScalingServiceLinkedRoleGrants"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:CreateGrant"]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:PrincipalArn"
      values   = [local.autoscaling_slr_arn]
    }
    condition {
      test     = "StringEquals"
      variable = "kms:CallerAccount"
      values   = [local.account_id]
    }
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }
}

data "aws_iam_policy_document" "logs" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]

  statement {
    sid = "AllowCloudWatchLogs"
    principals {
      type        = "Service"
      identifiers = ["logs.${local.region}.amazonaws.com"]
    }
    actions = [
      "kms:Decrypt*",
      "kms:Describe*",
      "kms:Encrypt*",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = ["*"]
    condition {
      test     = "ArnLike"
      variable = "kms:EncryptionContext:aws:logs:arn"
      values   = ["arn:${local.partition}:logs:${local.region}:${local.account_id}:log-group:*"]
    }
  }
}

data "aws_iam_policy_document" "secrets" {
  source_policy_documents = [data.aws_iam_policy_document.base.json]

  # Guardrail, not a grant: even an account admin with kms:* in IAM cannot
  # decrypt validator material unless they are one of the named principals.
  # Writes (PutSecretValue -> kms:GenerateDataKey) are unaffected, so key
  # custodians can load keys without being able to read them back.
  statement {
    sid    = "DenyDecryptExceptAuthorizedPrincipals"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["kms:Decrypt"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = var.secrets_decrypt_principal_arns
    }
  }
}

# --- Keys ---------------------------------------------------------------------

locals {
  keys = {
    eks = {
      description = "EKS envelope encryption for Kubernetes Secrets (${var.name})"
      policy      = data.aws_iam_policy_document.eks.json
    }
    ebs = {
      description = "EBS volumes: node disks, chain data, slashing protection (${var.name})"
      policy      = data.aws_iam_policy_document.ebs.json
    }
    logs = {
      description = "CloudWatch Logs: control plane, VPC flow, WAF (${var.name})"
      policy      = data.aws_iam_policy_document.logs.json
    }
    secrets = {
      description = "Secrets Manager: validator keys, JWT, API key hashes (${var.name})"
      policy      = data.aws_iam_policy_document.secrets.json
    }
  }
}

resource "aws_kms_key" "this" {
  for_each = local.keys

  description             = each.value.description
  policy                  = each.value.policy
  enable_key_rotation     = true
  rotation_period_in_days = 365
  deletion_window_in_days = var.deletion_window_in_days
  tags                    = merge(var.tags, { Name = "${var.name}-${each.key}" })
}

resource "aws_kms_alias" "this" {
  for_each = local.keys

  name          = "alias/${var.name}-${each.key}"
  target_key_id = aws_kms_key.this[each.key].key_id
}
