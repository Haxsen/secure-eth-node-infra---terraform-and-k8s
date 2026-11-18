output "vpc_id" {
  value = aws_vpc.this.id
}

output "vpc_cidr" {
  value = aws_vpc.this.cidr_block
}

output "private_subnet_ids" {
  value = [for az in var.azs : aws_subnet.private[az].id]
}

output "public_subnet_ids" {
  value = [for az in var.azs : aws_subnet.public[az].id]
}

output "public_subnet_cidrs" {
  description = "Source ranges of ALB traffic; the rpc-gateway NetworkPolicy admits only these."
  value       = [for az in var.azs : aws_subnet.public[az].cidr_block]
}
