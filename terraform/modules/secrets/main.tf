# -----------------------------------------------------------------------------
# Secrets Manager containers for node/validator secret material.
#
# Terraform creates the secret *containers* and their access policies only.
# Secret values are written out-of-band by scripts/ so that validator keys,
# the keystore password and the Engine API JWT never appear in Terraform
# state or plan output. (A policy in policies/terraform enforces this by
# rejecting any aws_secretsmanager_secret_version resource.)
# -----------------------------------------------------------------------------

resource "aws_secretsmanager_secret" "this" {
  #checkov:skip=CKV2_AWS_57:Validator BLS keys cannot be rotated by Secrets Manager; rotation means a voluntary exit and re-deposit (see docs/runbook.md).
  for_each = var.secrets

  name                    = "${var.name_prefix}/${each.key}"
  description             = each.value.description
  kms_key_id              = var.kms_key_arn
  recovery_window_in_days = var.recovery_window_in_days
  tags                    = var.tags
}

# Resource policy: an explicit Deny on reads for everyone except the named
# readers. IAM grants are still required on the reader side; this closes the
# "someone attached SecretsManagerReadWrite to a random role" path.
data "aws_iam_policy_document" "this" {
  for_each = var.secrets

  statement {
    sid    = "DenyReadExceptAuthorizedPrincipals"
    effect = "Deny"
    principals {
      type        = "AWS"
      identifiers = ["*"]
    }
    actions   = ["secretsmanager:GetSecretValue"]
    resources = ["*"]
    condition {
      test     = "StringNotEquals"
      variable = "aws:PrincipalArn"
      values   = each.value.reader_arns
    }
  }
}

resource "aws_secretsmanager_secret_policy" "this" {
  for_each = var.secrets

  secret_arn          = aws_secretsmanager_secret.this[each.key].arn
  policy              = data.aws_iam_policy_document.this[each.key].json
  block_public_policy = true
}
