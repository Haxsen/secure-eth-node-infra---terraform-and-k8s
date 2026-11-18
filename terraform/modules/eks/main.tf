# -----------------------------------------------------------------------------
# EKS cluster
#
#  - API endpoint private by default; public access only with an explicit
#    CIDR allow-list (0.0.0.0/0 rejected by variable validation).
#  - Kubernetes Secrets envelope-encrypted with a dedicated CMK.
#  - All control plane log types shipped to an encrypted log group.
#  - Access entries (authentication_mode = API) instead of the aws-auth ConfigMap.
#  - Bottlerocket nodes, IMDSv2 only with hop limit 1 (pods cannot reach node creds).
#  - Node groups map to trust zones: system / edge (internet-facing) / signing (validator).
# -----------------------------------------------------------------------------

data "aws_partition" "current" {}
data "aws_caller_identity" "current" {}

data "aws_iam_session_context" "current" {
  arn = data.aws_caller_identity.current.arn
}

locals {
  partition = data.aws_partition.current.partition

  # Always include the principal running Terraform so the apply that creates
  # the cluster can also install add-ons, without the opaque implicit
  # "cluster creator is admin" bootstrap permission.
  admin_principal_arns = toset(distinct(concat(
    var.cluster_admin_principal_arns,
    [data.aws_iam_session_context.current.issuer_arn],
  )))
}

# --- Control plane IAM --------------------------------------------------------

data "aws_iam_policy_document" "cluster_assume" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["eks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "cluster" {
  name               = "${var.name}-cluster"
  assume_role_policy = data.aws_iam_policy_document.cluster_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "cluster" {
  role       = aws_iam_role.cluster.name
  policy_arn = "arn:${local.partition}:iam::aws:policy/AmazonEKSClusterPolicy"
}

data "aws_iam_policy_document" "cluster_kms" {
  statement {
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:ListGrants",
    ]
    resources = [var.secrets_kms_key_arn]
  }
}

resource "aws_iam_role_policy" "cluster_kms" {
  name   = "envelope-encryption"
  role   = aws_iam_role.cluster.id
  policy = data.aws_iam_policy_document.cluster_kms.json
}

resource "aws_cloudwatch_log_group" "cluster" {
  # EKS writes to this exact name; creating it first lets us own retention + KMS.
  name              = "/aws/eks/${var.name}/cluster"
  retention_in_days = var.log_retention_days
  kms_key_id        = var.logs_kms_key_arn
  tags              = var.tags
}

# Optional extra ingress to the private API endpoint (VPN / bastion CIDRs).
resource "aws_security_group" "cluster_api" {
  name        = "${var.name}-cluster-api"
  description = "Additional private access to the EKS API endpoint"
  vpc_id      = var.vpc_id
  tags        = merge(var.tags, { Name = "${var.name}-cluster-api" })
}

resource "aws_vpc_security_group_ingress_rule" "cluster_api" {
  for_each = toset(var.api_private_access_cidrs)

  security_group_id = aws_security_group.cluster_api.id
  description       = "Kubernetes API from operator network"
  cidr_ipv4         = each.value
  ip_protocol       = "tcp"
  from_port         = 443
  to_port           = 443
}

resource "aws_eks_cluster" "this" {
  #checkov:skip=CKV_AWS_339:Checkov's version list lags EKS releases; upgrade_policy STANDARD below rejects versions outside standard support.
  name     = var.name
  version  = var.kubernetes_version
  role_arn = aws_iam_role.cluster.arn

  enabled_cluster_log_types = ["api", "audit", "authenticator", "controllerManager", "scheduler"]

  access_config {
    authentication_mode                         = "API"
    bootstrap_cluster_creator_admin_permissions = false
  }

  vpc_config {
    subnet_ids              = var.private_subnet_ids
    security_group_ids      = [aws_security_group.cluster_api.id]
    endpoint_private_access = true
    endpoint_public_access  = length(var.api_public_access_cidrs) > 0
    public_access_cidrs     = length(var.api_public_access_cidrs) > 0 ? var.api_public_access_cidrs : null
  }

  encryption_config {
    resources = ["secrets"]
    provider {
      key_arn = var.secrets_kms_key_arn
    }
  }

  kubernetes_network_config {
    ip_family         = "ipv4"
    service_ipv4_cidr = "172.20.0.0/16"
  }

  # Fail loudly on unsupported versions instead of silently paying for
  # extended support.
  upgrade_policy {
    support_type = "STANDARD"
  }

  tags = var.tags

  depends_on = [
    aws_cloudwatch_log_group.cluster,
    aws_iam_role_policy_attachment.cluster,
    aws_iam_role_policy.cluster_kms,
  ]
}

# --- Cluster access -----------------------------------------------------------

resource "aws_eks_access_entry" "admin" {
  for_each = local.admin_principal_arns

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  type          = "STANDARD"
  tags          = var.tags
}

resource "aws_eks_access_policy_association" "admin" {
  for_each = local.admin_principal_arns

  cluster_name  = aws_eks_cluster.this.name
  principal_arn = each.value
  policy_arn    = "arn:${local.partition}:eks::aws:cluster-access-policy/AmazonEKSClusterAdminPolicy"

  access_scope {
    type = "cluster"
  }

  depends_on = [aws_eks_access_entry.admin]
}

# --- OIDC provider for IRSA -----------------------------------------------------

data "tls_certificate" "oidc" {
  url = aws_eks_cluster.this.identity[0].oidc[0].issuer
}

resource "aws_iam_openid_connect_provider" "this" {
  url             = aws_eks_cluster.this.identity[0].oidc[0].issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.oidc.certificates[0].sha1_fingerprint]
  tags            = var.tags
}

locals {
  oidc_issuer = replace(aws_eks_cluster.this.identity[0].oidc[0].issuer, "https://", "")
}

# --- Node IAM -------------------------------------------------------------------
# Deliberately minimal: no CNI policy (moved to IRSA on aws-node), pull-only
# ECR access, SSM for break-glass shell access instead of SSH keys.

data "aws_iam_policy_document" "node_assume" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ec2.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "node" {
  name               = "${var.name}-node"
  assume_role_policy = data.aws_iam_policy_document.node_assume.json
  tags               = var.tags
}

resource "aws_iam_role_policy_attachment" "node" {
  for_each = toset([
    "arn:${local.partition}:iam::aws:policy/AmazonEKSWorkerNodePolicy",
    "arn:${local.partition}:iam::aws:policy/AmazonEC2ContainerRegistryPullOnly",
    "arn:${local.partition}:iam::aws:policy/AmazonSSMManagedInstanceCore",
  ])

  role       = aws_iam_role.node.name
  policy_arn = each.value
}

# --- Launch templates -----------------------------------------------------------

resource "aws_launch_template" "node" {
  for_each = var.node_groups

  name_prefix            = "${var.name}-${each.key}-"
  description            = "Hardened Bottlerocket nodes for the ${each.key} node group"
  update_default_version = true

  # IMDSv2 only, and hop limit 1 so containers on the pod network cannot
  # reach the node's instance credentials (SSRF -> node role theft).
  metadata_options {
    http_endpoint               = "enabled"
    http_tokens                 = "required"
    http_put_response_hop_limit = 1
    instance_metadata_tags      = "disabled"
  }

  # Bottlerocket: /dev/xvda is the immutable OS volume, /dev/xvdb holds
  # container images and ephemeral storage.
  block_device_mappings {
    device_name = "/dev/xvda"
    ebs {
      volume_size           = 4
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  block_device_mappings {
    device_name = "/dev/xvdb"
    ebs {
      volume_size           = each.value.disk_size_gb
      volume_type           = "gp3"
      encrypted             = true
      kms_key_id            = var.ebs_kms_key_arn
      delete_on_termination = true
    }
  }

  monitoring {
    enabled = true
  }

  tag_specifications {
    resource_type = "instance"
    tags          = merge(var.tags, { Name = "${var.name}-${each.key}", "trust-zone" = each.key })
  }

  tag_specifications {
    resource_type = "volume"
    tags          = merge(var.tags, { Name = "${var.name}-${each.key}" })
  }

  tags = var.tags
}

# --- Managed node groups --------------------------------------------------------

resource "aws_eks_node_group" "this" {
  for_each = var.node_groups

  cluster_name           = aws_eks_cluster.this.name
  node_group_name_prefix = "${each.key}-"
  node_role_arn          = aws_iam_role.node.arn
  subnet_ids             = var.private_subnet_ids
  ami_type               = "BOTTLEROCKET_x86_64"
  capacity_type          = each.value.capacity_type
  instance_types         = each.value.instance_types
  labels                 = merge({ "trust-zone" = each.key }, each.value.labels)

  scaling_config {
    min_size     = each.value.min_size
    max_size     = each.value.max_size
    desired_size = each.value.desired_size
  }

  update_config {
    max_unavailable = 1
  }

  launch_template {
    id      = aws_launch_template.node[each.key].id
    version = aws_launch_template.node[each.key].latest_version
  }

  dynamic "taint" {
    for_each = each.value.taints
    content {
      key    = taint.value.key
      value  = taint.value.value
      effect = taint.value.effect
    }
  }

  tags = merge(var.tags, { "trust-zone" = each.key })

  lifecycle {
    create_before_destroy = true
    # Cluster Autoscaler owns desired_size at runtime.
    ignore_changes = [scaling_config[0].desired_size]
  }

  depends_on = [
    aws_iam_role_policy_attachment.node,
    aws_eks_addon.vpc_cni,
    aws_eks_addon.kube_proxy,
  ]
}

# --- Add-ons ----------------------------------------------------------------------

module "vpc_cni_irsa" {
  source = "../irsa"

  role_name           = "${var.name}-vpc-cni"
  description         = "aws-node (VPC CNI) - moved off the node role"
  oidc_provider_arn   = aws_iam_openid_connect_provider.this.arn
  oidc_issuer         = local.oidc_issuer
  service_accounts    = ["kube-system:aws-node"]
  managed_policy_arns = ["arn:${local.partition}:iam::aws:policy/AmazonEKS_CNI_Policy"]
  tags                = var.tags
}

data "aws_iam_policy_document" "ebs_csi_kms" {
  statement {
    actions = [
      "kms:CreateGrant",
      "kms:ListGrants",
      "kms:RevokeGrant",
    ]
    resources = [var.ebs_kms_key_arn]
    condition {
      test     = "Bool"
      variable = "kms:GrantIsForAWSResource"
      values   = ["true"]
    }
  }

  statement {
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey*",
      "kms:ReEncrypt*",
    ]
    resources = [var.ebs_kms_key_arn]
  }
}

module "ebs_csi_irsa" {
  source = "../irsa"

  role_name           = "${var.name}-ebs-csi"
  description         = "EBS CSI controller - provisions CMK-encrypted volumes"
  oidc_provider_arn   = aws_iam_openid_connect_provider.this.arn
  oidc_issuer         = local.oidc_issuer
  service_accounts    = ["kube-system:ebs-csi-controller-sa"]
  managed_policy_arns = ["arn:${local.partition}:iam::aws:policy/service-role/AmazonEBSCSIDriverPolicy"]
  inline_policies     = { "cmk-access" = data.aws_iam_policy_document.ebs_csi_kms.json }
  tags                = var.tags
}

data "aws_eks_addon_version" "this" {
  for_each = toset(["vpc-cni", "kube-proxy", "coredns", "aws-ebs-csi-driver"])

  addon_name         = each.key
  kubernetes_version = aws_eks_cluster.this.version
  most_recent        = true
}

resource "aws_eks_addon" "vpc_cni" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "vpc-cni"
  addon_version               = data.aws_eks_addon_version.this["vpc-cni"].version
  service_account_role_arn    = module.vpc_cni_irsa.role_arn
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"

  # Turns on the eBPF network policy agent, which is what enforces every
  # NetworkPolicy in k8s/. Without this they are silently ignored.
  configuration_values = jsonencode({
    enableNetworkPolicy = "true"
    nodeAgent = {
      enablePolicyEventLogs = "true"
    }
  })

  tags = var.tags
}

resource "aws_eks_addon" "kube_proxy" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "kube-proxy"
  addon_version               = data.aws_eks_addon_version.this["kube-proxy"].version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = var.tags
}

resource "aws_eks_addon" "coredns" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "coredns"
  addon_version               = data.aws_eks_addon_version.this["coredns"].version
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = var.tags

  depends_on = [aws_eks_node_group.this]
}

resource "aws_eks_addon" "ebs_csi" {
  cluster_name                = aws_eks_cluster.this.name
  addon_name                  = "aws-ebs-csi-driver"
  addon_version               = data.aws_eks_addon_version.this["aws-ebs-csi-driver"].version
  service_account_role_arn    = module.ebs_csi_irsa.role_arn
  resolve_conflicts_on_create = "OVERWRITE"
  resolve_conflicts_on_update = "OVERWRITE"
  tags                        = var.tags

  depends_on = [aws_eks_node_group.this]
}
