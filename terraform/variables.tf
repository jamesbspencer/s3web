variable "project_name" {
  description = "Name prefix for all s3web resources."
  type        = string
  default     = "s3web"
}

variable "environment" {
  description = "Deployment environment (e.g., prod, staging, internal)."
  type        = string
  default     = "prod"
}

variable "aws_region" {
  description = "AWS Region for the VPC, S3 bucket, DynamoDB table, and ECS cluster."
  type        = string
  default     = "us-east-1"
}

# --- VPC & Private Network (VPN-Only) ---

variable "create_vpc" {
  description = "Whether to create a new private-only VPC (no IGW, no public subnets) or deploy into an existing VPC."
  type        = bool
  default     = true
}

variable "existing_vpc_id" {
  description = "Existing VPC ID when create_vpc = false."
  type        = string
  default     = ""
}

variable "existing_private_subnet_ids" {
  description = "Existing private subnet IDs (minimum 2 AZs for Internal ALB) when create_vpc = false."
  type        = list(string)
  default     = []
}

variable "existing_private_route_table_ids" {
  description = "Existing private route table IDs to attach S3 and DynamoDB Gateway VPC Endpoints when create_vpc = false."
  type        = list(string)
  default     = []
}

variable "vpc_cidr" {
  description = "CIDR block for the private-only VPC when create_vpc = true."
  type        = string
  default     = "10.42.0.0/16"
}

variable "availability_zones" {
  description = "Availability Zones for the private subnets (multi-AZ)."
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for the private subnets (one per AZ)."
  type        = list(string)
  default     = ["10.42.1.0/24", "10.42.2.0/24"]
}

variable "vpn_allowed_cidr_blocks" {
  description = "Corporate / VPN CIDR blocks permitted to reach the Internal ALB on HTTPS :443 (e.g., VPN pool, internal automation subnet, self-hosted CI runner subnet)."
  type        = list(string)
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]
}

variable "enable_vpn_gateway" {
  description = "Attach an AWS Virtual Private Gateway (VGW) with route propagation to the private route tables."
  type        = bool
  default     = true
}

variable "vpn_gateway_amazon_side_asn" {
  description = "BGP ASN for the Virtual Private Gateway."
  type        = number
  default     = 64512
}

variable "transit_gateway_id" {
  description = "Optional AWS Transit Gateway ID (if VPN terminates on a Transit Gateway instead of VGW)."
  type        = string
  default     = ""
}

# --- DNS & TLS ---

variable "internal_domain_name" {
  description = "Private Route 53 DNS hostname for s3web (used by browsers over VPN, HTML Raw Access, and CI OIDC audience)."
  type        = string
  default     = "s3web.internal.corp"
}

variable "private_hosted_zone_name" {
  description = "Route 53 Private Hosted Zone name."
  type        = string
  default     = "internal.corp"
}

variable "create_private_hosted_zone" {
  description = "Whether to create a Route 53 Private Hosted Zone associated with the VPC."
  type        = bool
  default     = true
}

variable "acm_certificate_arn" {
  description = "ACM Certificate ARN for HTTPS (:443) on the Internal ALB. If empty, an HTTP (:80) listener is created for initial testing."
  type        = string
  default     = ""
}

# --- S3 Bucket & Intelligent-Tiering ---

variable "s3_bucket_name" {
  description = "Globally unique name for the S3 artifact bucket storing ISOs and compressed archives."
  type        = string
  default     = "corp-iso-artifacts-prod"
}

variable "enable_intelligent_tiering_archive_tiers" {
  description = "Enable optional S3 Intelligent-Tiering asynchronous Archive Access (AA) and Deep Archive Access (DAA) tiers."
  type        = bool
  default     = true
}

variable "intelligent_tiering_archive_days" {
  description = "Days of no access before transitioning to S3 Intelligent-Tiering Archive Access (minimum 90)."
  type        = number
  default     = 90
}

variable "intelligent_tiering_deep_archive_days" {
  description = "Days of no access before transitioning to S3 Intelligent-Tiering Deep Archive Access (minimum 180)."
  type        = number
  default     = 180
}

# --- ECS Fargate Service ---

variable "ecs_desired_count" {
  description = "Number of s3web tasks running across Availability Zones."
  type        = number
  default     = 2
}

variable "ecs_task_cpu" {
  description = "ECS Fargate CPU units (1024 = 1 vCPU)."
  type        = number
  default     = 1024
}

variable "ecs_task_memory" {
  description = "ECS Fargate Memory in MiB."
  type        = number
  default     = 2048
}

variable "container_image_tag" {
  description = "Container image tag in ECR to deploy."
  type        = string
  default     = "latest"
}

# --- Authentication (OIDC SSO & GitHub Actions OIDC JWT) ---

variable "oidc_enabled" {
  description = "Enable OIDC Authorization Code + PKCE login for browser users."
  type        = bool
  default     = true
}

variable "oidc_issuer_url" {
  description = "OIDC Identity Provider Issuer URL (Okta, Entra ID, Keycloak)."
  type        = string
  default     = "https://idp.internal.corp/oauth2/default"
}

variable "oidc_client_id" {
  description = "OIDC Client ID."
  type        = string
  default     = "s3web-client"
}

variable "oidc_groups_claim" {
  description = "JWT claim containing the user's OIDC group memberships."
  type        = string
  default     = "groups"
}

variable "github_oidc_issuer_url" {
  description = "GitHub Actions OIDC JWT Issuer URL (https://token.actions.githubusercontent.com or GitHub Enterprise Server URL)."
  type        = string
  default     = "https://token.actions.githubusercontent.com"
}

variable "github_pinned_jwks_json" {
  description = "Optional pinned JWKS JSON string for GitHub Actions OIDC verification when the private VPC has no internet egress."
  type        = string
  default     = ""
}

variable "bootstrap_admin_email" {
  description = "Initial SSO Admin email seeded in DynamoDB."
  type        = string
  default     = "admin@example.com"
}

variable "bootstrap_admin_oidc_group" {
  description = "Initial OIDC Group granted full in-app Admin, Upload, and Delete permissions."
  type        = string
  default     = "platform-admins"
}

variable "bootstrap_raw_account_id" {
  description = "Default Service Account ID created for HTML Raw Access."
  type        = string
  default     = "svc-raw-access"
}

variable "access_log_retention_days" {
  description = "Number of days to retain per-item access logs in DynamoDB (via TTL)."
  type        = number
  default     = 90
}

variable "tags" {
  description = "Additional tags to apply to all resources."
  type        = map(string)
  default     = {}
}

