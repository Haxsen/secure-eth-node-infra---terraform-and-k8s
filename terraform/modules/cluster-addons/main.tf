# -----------------------------------------------------------------------------
# In-cluster platform add-ons. Every controller that talks to AWS gets its own
# IRSA role; nothing relies on the node instance profile (which pods cannot
# reach anyway because of IMDS hop limit 1).
# -----------------------------------------------------------------------------

locals {
  system_node_selector = { "trust-zone" = "system" }

  # Node-level CSI components must run on every zone, including tainted ones.
  tolerate_all_trust_zones = [{ key = "trust-zone", operator = "Exists", effect = "NoSchedule" }]

  # Cluster Autoscaler must match the cluster's Kubernetes minor version.
  cluster_autoscaler_tags = {
    "1.35" = "v1.35.3"
    "1.36" = "v1.36.2"
    "1.37" = "v1.37.0"
  }
}

# --- AWS Load Balancer Controller --------------------------------------------------

module "alb_controller_irsa" {
  source = "../irsa"

  role_name         = "${var.cluster_name}-alb-controller"
  description       = "AWS Load Balancer Controller"
  oidc_provider_arn = var.oidc_provider_arn
  oidc_issuer       = var.oidc_issuer
  service_accounts  = ["kube-system:aws-load-balancer-controller"]
  # Upstream policy, vendored and pinned to the chart's app version.
  inline_policies = {
    "aws-load-balancer-controller" = file("${path.module}/policies/aws-load-balancer-controller-v3.6.3.json")
  }
  tags = var.tags
}

resource "helm_release" "alb_controller" {
  name       = "aws-load-balancer-controller"
  namespace  = "kube-system"
  repository = "https://aws.github.io/eks-charts"
  chart      = "aws-load-balancer-controller"
  version    = "3.6.3"
  wait       = true
  timeout    = 600

  values = [yamlencode({
    clusterName  = var.cluster_name
    region       = var.region
    vpcId        = var.vpc_id
    replicaCount = 2
    nodeSelector = local.system_node_selector
    # We only expose HTTP(S) through Ingress + WAF; never mutate Services into NLBs.
    enableServiceMutatorWebhook = false
    serviceAccount = {
      create = true
      name   = "aws-load-balancer-controller"
      annotations = {
        "eks.amazonaws.com/role-arn" = module.alb_controller_irsa.role_arn
      }
    }
  })]
}

# --- Secrets Store CSI driver + AWS provider (ASCP) --------------------------------
# Secrets are mounted as tmpfs files straight from Secrets Manager into the pod
# using the *pod's* IRSA identity. syncSecret is disabled, so validator keys are
# never copied into Kubernetes Secrets / etcd.

resource "helm_release" "secrets_store_csi" {
  name       = "secrets-store-csi-provider-aws"
  namespace  = "kube-system"
  repository = "https://aws.github.io/secrets-store-csi-driver-provider-aws"
  chart      = "secrets-store-csi-driver-provider-aws"
  version    = "3.1.4"
  wait       = true
  timeout    = 600

  values = [yamlencode({
    awsRegion   = var.region
    tolerations = local.tolerate_all_trust_zones
    "secrets-store-csi-driver" = {
      install              = true
      syncSecret           = { enabled = false }
      enableSecretRotation = true
      rotationPollInterval = "2m"
      linux = {
        tolerations = local.tolerate_all_trust_zones
      }
    }
  })]
}

# --- Cluster Autoscaler ---------------------------------------------------------------

data "aws_iam_policy_document" "cluster_autoscaler" {
  #checkov:skip=CKV_AWS_356:Describe* APIs do not support resource-level scoping; mutating actions are tag-conditioned below.
  statement {
    sid = "Discover"
    actions = [
      "autoscaling:DescribeAutoScalingGroups",
      "autoscaling:DescribeAutoScalingInstances",
      "autoscaling:DescribeLaunchConfigurations",
      "autoscaling:DescribeScalingActivities",
      "autoscaling:DescribeTags",
      "ec2:DescribeImages",
      "ec2:DescribeInstanceTypes",
      "ec2:DescribeLaunchTemplateVersions",
      "ec2:GetInstanceTypesFromInstanceRequirements",
      "eks:DescribeNodegroup",
    ]
    resources = ["*"]
  }

  # Mutations only on ASGs owned by *this* cluster.
  statement {
    sid = "ScaleOwnedGroupsOnly"
    actions = [
      "autoscaling:SetDesiredCapacity",
      "autoscaling:TerminateInstanceInAutoScalingGroup",
    ]
    resources = ["*"]
    condition {
      test     = "StringEquals"
      variable = "aws:ResourceTag/k8s.io/cluster-autoscaler/${var.cluster_name}"
      values   = ["owned"]
    }
  }
}

module "cluster_autoscaler_irsa" {
  source = "../irsa"

  role_name         = "${var.cluster_name}-cluster-autoscaler"
  description       = "Cluster Autoscaler"
  oidc_provider_arn = var.oidc_provider_arn
  oidc_issuer       = var.oidc_issuer
  service_accounts  = ["kube-system:cluster-autoscaler"]
  inline_policies   = { "cluster-autoscaler" = data.aws_iam_policy_document.cluster_autoscaler.json }
  tags              = var.tags
}

resource "helm_release" "cluster_autoscaler" {
  name       = "cluster-autoscaler"
  namespace  = "kube-system"
  repository = "https://kubernetes.github.io/autoscaler"
  chart      = "cluster-autoscaler"
  version    = "9.60.0"
  wait       = true
  timeout    = 600

  values = [yamlencode({
    cloudProvider = "aws"
    awsRegion     = var.region
    autoDiscovery = { clusterName = var.cluster_name }
    image         = { tag = lookup(local.cluster_autoscaler_tags, var.kubernetes_version, "v${var.kubernetes_version}.0") }
    nodeSelector  = local.system_node_selector
    extraArgs = {
      "balance-similar-node-groups" = true
      "expander"                    = "least-waste"
    }
    rbac = {
      serviceAccount = {
        create = true
        name   = "cluster-autoscaler"
        annotations = {
          "eks.amazonaws.com/role-arn" = module.cluster_autoscaler_irsa.role_arn
        }
      }
    }
  })]
}

# --- metrics-server (HPA input) ---------------------------------------------------------

resource "helm_release" "metrics_server" {
  name       = "metrics-server"
  namespace  = "kube-system"
  repository = "https://kubernetes-sigs.github.io/metrics-server"
  chart      = "metrics-server"
  version    = "3.14.0"
  wait       = true
  timeout    = 600

  values = [yamlencode({
    nodeSelector = local.system_node_selector
  })]
}

# --- Storage ------------------------------------------------------------------------------
# Chain data and slashing-protection databases. Retain on delete: losing a
# validator's slashing DB is a slashing risk; losing chain data costs a resync.

resource "kubernetes_storage_class_v1" "eth_gp3" {
  metadata {
    name = "eth-gp3-retain"
  }

  storage_provisioner    = "ebs.csi.aws.com"
  reclaim_policy         = "Retain"
  volume_binding_mode    = "WaitForFirstConsumer"
  allow_volume_expansion = true

  parameters = {
    type                        = "gp3"
    encrypted                   = "true"
    kmsKeyId                    = var.ebs_kms_key_arn
    iops                        = "6000"
    throughput                  = "500"
    "csi.storage.k8s.io/fstype" = "ext4"
  }
}
