output "vpc_id" {
  description = "ID of the Private-Only VPC."
  value       = local.vpc_id
}

output "private_subnet_ids" {
  description = "IDs of the multi-AZ private subnets."
  value       = local.private_subnet_ids
}

output "vpn_gateway_id" {
  description = "ID of the Virtual Private Gateway (if enabled)."
  value       = try(aws_vpn_gateway.this[0].id, null)
}

output "s3_gateway_vpc_endpoint_id" {
  description = "ID of the free S3 Gateway VPC Endpoint."
  value       = aws_vpc_endpoint.s3.id
}

output "dynamodb_gateway_vpc_endpoint_id" {
  description = "ID of the free DynamoDB Gateway VPC Endpoint."
  value       = aws_vpc_endpoint.dynamodb.id
}

output "s3_bucket_name" {
  description = "Name of the S3 Intelligent-Tiering artifact bucket."
  value       = aws_s3_bucket.artifacts.id
}

output "dynamodb_table_name" {
  description = "Name of the DynamoDB single-table store."
  value       = aws_dynamodb_table.metadata.name
}

output "sqs_event_queue_url" {
  description = "URL of the SQS queue receiving S3 ObjectCreated, IntelligentTiering, and ObjectRestore events."
  value       = aws_sqs_queue.s3_events.id
}

output "ecr_repository_url" {
  description = "ECR repository URL to push the s3web Go container image."
  value       = aws_ecr_repository.s3web.repository_url
}

output "internal_alb_dns_name" {
  description = "Internal Application Load Balancer DNS name."
  value       = aws_lb.internal.dns_name
}

output "s3web_internal_url" {
  description = "Internal Web UI URL accessible over VPN."
  value       = local.base_url
}

output "html_raw_access_url" {
  description = "HTML Raw Access URL (/raw/)."
  value       = "${local.base_url}/raw/"
}

output "secrets_manager_arn" {
  description = "ARN of the Secrets Manager secret storing session secret, admin password, OIDC secret, and default service account credentials."
  value       = aws_secretsmanager_secret.app_secrets.arn
}

output "bootstrap_admin_email" {
  description = "Default bootstrap admin email/username."
  value       = var.bootstrap_admin_email
}

output "bootstrap_admin_password" {
  description = "Generated default admin password for initial installation (retrieve with: terraform output -raw bootstrap_admin_password)."
  value       = random_password.admin_password.result
  sensitive   = true
}

output "bootstrap_demo_username" {
  description = "Generated demo local user account username."
  value       = "demo"
}

output "bootstrap_demo_password" {
  description = "Generated demo local user password for initial installation (retrieve with: terraform output -raw bootstrap_demo_password)."
  value       = random_password.demo_password.result
  sensitive   = true
}

output "bootstrap_service_account_secret" {
  description = "Generated default HTML Raw Access service account secret."
  value       = "s3w_${random_password.raw_service_account_secret.result}"
  sensitive   = true
}

