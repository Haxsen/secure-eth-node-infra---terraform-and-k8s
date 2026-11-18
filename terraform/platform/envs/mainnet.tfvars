# Mainnet - run this in its own AWS account (separate blast radius, separate
# KMS keys, separate CloudTrail). Values below are a production starting point.
region      = "eu-west-1"
environment = "mainnet"
eth_network = "mainnet"

vpc_cidr           = "10.50.0.0/16"
availability_zones = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
single_nat_gateway = false

kubernetes_version = "1.36"

api_public_access_cidrs = []
api_private_access_cidrs = [
  # "10.255.0.0/16", # corporate VPN
]

cluster_admin_principal_arns = [
  # "arn:aws:iam::222222222222:role/platform-admins",
]

kms_key_admin_arns = [
  # "arn:aws:iam::222222222222:role/security-key-admins",
]

key_custodian_principal_arns = [
  # "arn:aws:iam::222222222222:role/validator-key-custodians",
]

node_groups = {
  system = {
    instance_types = ["m7i.large"]
    min_size       = 2
    max_size       = 4
    desired_size   = 3
  }

  edge = {
    instance_types = ["r7i.2xlarge"]
    min_size       = 3
    max_size       = 6
    desired_size   = 3
    disk_size_gb   = 80
    taints         = [{ key = "trust-zone", value = "edge", effect = "NO_SCHEDULE" }]
  }

  signing = {
    instance_types = ["m7i.large"]
    min_size       = 1
    max_size       = 1
    desired_size   = 1
    taints         = [{ key = "trust-zone", value = "signing", effect = "NO_SCHEDULE" }]
  }
}

waf_rate_limit_per_ip     = 3000
waf_blocked_country_codes = [] # e.g. ["KP", "IR", "CU", "SY"] per your sanctions policy

log_retention_days = 400

rpc_hostname        = "rpc.example.com"
acm_certificate_arn = ""
