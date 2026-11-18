# Hoodi testnet - the environment you can actually afford to run for a demo.
region      = "eu-west-1"
environment = "hoodi"
eth_network = "hoodi"

vpc_cidr           = "10.40.0.0/16"
availability_zones = ["eu-west-1a", "eu-west-1b", "eu-west-1c"]
single_nat_gateway = true # cost trade-off acceptable on testnet

kubernetes_version = "1.36"

# Leave empty for a private-only API endpoint (reach it via VPN/SSM).
# For a first bootstrap from a laptop, temporarily set your /32 here.
api_public_access_cidrs = []

cluster_admin_principal_arns = [
  # "arn:aws:iam::111111111111:role/platform-admins",
]

key_custodian_principal_arns = [
  # "arn:aws:iam::111111111111:role/validator-key-custodians",
]

node_groups = {
  # Cluster controllers only. No internet-facing workloads.
  system = {
    instance_types = ["m7i.large"]
    min_size       = 2
    max_size       = 3
    desired_size   = 2
  }

  # Internet-exposed: geth/lighthouse P2P + the public RPC gateway.
  edge = {
    instance_types = ["m7i.2xlarge"]
    min_size       = 2
    max_size       = 4
    desired_size   = 2
    disk_size_gb   = 50
    taints         = [{ key = "trust-zone", value = "edge", effect = "NO_SCHEDULE" }]
  }

  # Validator client only. No inbound from the internet, no egress except the
  # beacon API. Sized for one pod; never shares a kernel with P2P workloads.
  signing = {
    instance_types = ["m7i.large"]
    min_size       = 1
    max_size       = 1
    desired_size   = 1
    taints         = [{ key = "trust-zone", value = "signing", effect = "NO_SCHEDULE" }]
  }
}

waf_rate_limit_per_ip = 1200

rpc_hostname        = "rpc.hoodi.example.com"
acm_certificate_arn = "" # arn:aws:acm:eu-west-1:111111111111:certificate/...
