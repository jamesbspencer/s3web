# ============================================================================
# Private-Only VPC (No Internet Gateway, No Public Subnets — VPN Access Only)
# ============================================================================

locals {
  name_prefix = "${var.project_name}-${var.environment}"
  vpc_id      = var.create_vpc ? aws_vpc.private[0].id : var.existing_vpc_id
  private_subnet_ids = var.create_vpc ? [
    for s in aws_subnet.private : s.id
  ] : var.existing_private_subnet_ids
  private_route_table_ids = var.create_vpc ? [
    aws_route_table.private[0].id
  ] : var.existing_private_route_table_ids
}

resource "aws_vpc" "private" {
  count                = var.create_vpc ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_support   = true
  enable_dns_hostnames = true

  tags = {
    Name = "${local.name_prefix}-private-vpc"
  }
}

resource "aws_subnet" "private" {
  count                   = var.create_vpc ? length(var.private_subnet_cidrs) : 0
  vpc_id                  = aws_vpc.private[0].id
  cidr_block              = var.private_subnet_cidrs[count.index]
  availability_zone       = var.availability_zones[count.index]
  map_public_ip_on_launch = false

  tags = {
    Name = "${local.name_prefix}-private-${var.availability_zones[count.index]}"
    Tier = "Private"
  }
}

resource "aws_route_table" "private" {
  count  = var.create_vpc ? 1 : 0
  vpc_id = aws_vpc.private[0].id

  tags = {
    Name = "${local.name_prefix}-private-rt"
  }
}

resource "aws_route_table_association" "private" {
  count          = var.create_vpc ? length(aws_subnet.private) : 0
  subnet_id      = aws_subnet.private[count.index].id
  route_table_id = aws_route_table.private[0].id
}

# --- Corporate VPN Connectivity (Virtual Private Gateway & Route Propagation) ---

resource "aws_vpn_gateway" "this" {
  count           = var.create_vpc && var.enable_vpn_gateway ? 1 : 0
  vpc_id          = aws_vpc.private[0].id
  amazon_side_asn = var.vpn_gateway_amazon_side_asn

  tags = {
    Name = "${local.name_prefix}-vgw"
  }
}

resource "aws_vpn_gateway_route_propagation" "private" {
  count          = var.create_vpc && var.enable_vpn_gateway ? 1 : 0
  vpn_gateway_id = aws_vpn_gateway.this[0].id
  route_table_id = aws_route_table.private[0].id
}

# Optional Transit Gateway Route for Corporate VPN CIDRs
resource "aws_route" "transit_gateway_vpn" {
  count                  = var.create_vpc && var.transit_gateway_id != "" ? length(var.vpn_allowed_cidr_blocks) : 0
  route_table_id         = aws_route_table.private[0].id
  destination_cidr_block = var.vpn_allowed_cidr_blocks[count.index]
  transit_gateway_id     = var.transit_gateway_id
}

# ============================================================================
# VPC Endpoints (Zero-Internet-Hairpin Data Plane & Private ECS Control Plane)
# ============================================================================

# 1. Free S3 Gateway VPC Endpoint (Used for Multi-GB ISO Streaming & ECR Layers)
resource "aws_vpc_endpoint" "s3" {
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.s3"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.private_route_table_ids

  tags = {
    Name = "${local.name_prefix}-s3-gateway-vpce"
  }
}

# 2. Free DynamoDB Gateway VPC Endpoint (Used for Hashes, Access Logs & In-App RBAC)
resource "aws_vpc_endpoint" "dynamodb" {
  vpc_id            = local.vpc_id
  service_name      = "com.amazonaws.${var.aws_region}.dynamodb"
  vpc_endpoint_type = "Gateway"
  route_table_ids   = local.private_route_table_ids

  tags = {
    Name = "${local.name_prefix}-dynamodb-gateway-vpce"
  }
}

# Security Group for AWS PrivateLink Interface Endpoints
resource "aws_security_group" "vpce" {
  name        = "${local.name_prefix}-vpce-sg"
  description = "Allow HTTPS (:443) from private subnets to AWS PrivateLink Interface Endpoints"
  vpc_id      = local.vpc_id

  ingress {
    description = "HTTPS from ECS Tasks in Private Subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = [var.vpc_cidr]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-vpce-sg"
  }
}

# 3. Interface VPC Endpoints required for Private-Only ECS Fargate Tasks
locals {
  interface_endpoints = toset([
    "ecr.api",
    "ecr.dkr",
    "logs",
    "secretsmanager",
    "sqs",
    "kms"
  ])
}

resource "aws_vpc_endpoint" "interface" {
  for_each            = local.interface_endpoints
  vpc_id              = local.vpc_id
  service_name        = "com.amazonaws.${var.aws_region}.${each.key}"
  vpc_endpoint_type   = "Interface"
  subnet_ids          = local.private_subnet_ids
  security_group_ids  = [aws_security_group.vpce.id]
  private_dns_enabled = true

  tags = {
    Name = "${local.name_prefix}-${replace(each.key, ".", "-")}-vpce"
  }
}

