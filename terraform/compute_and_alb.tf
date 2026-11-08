# ============================================================================
# ECR, Secrets Manager, IAM Roles, Internal ALB, Route 53 & ECS Fargate
# ============================================================================

# --- Amazon ECR Repository for the Single-Binary Go Image ---

resource "aws_ecr_repository" "s3web" {
  name                 = local.name_prefix
  image_tag_mutability = "MUTABLE"
  force_delete         = true

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "KMS"
    kms_key         = aws_kms_key.s3web.arn
  }
}

# --- AWS Secrets Manager (Session Signing Key, Default Admin Password, OIDC Secret & Service Account Secret) ---

resource "random_password" "session_secret" {
  length  = 48
  special = false
}

resource "random_password" "admin_password" {
  length           = 24
  special          = true
  override_special = "!@#%^&*-_=+"
}

resource "random_password" "demo_password" {
  length           = 20
  special          = true
  override_special = "!@#%^&*-_=+"
}

resource "random_password" "raw_service_account_secret" {
  length  = 36
  special = false
}

resource "aws_secretsmanager_secret" "app_secrets" {
  name                    = "${local.name_prefix}/app-secrets"
  kms_key_id              = aws_kms_key.s3web.id
  recovery_window_in_days = 0
}

resource "aws_secretsmanager_secret_version" "app_secrets" {
  secret_id = aws_secretsmanager_secret.app_secrets.id
  secret_string = jsonencode({
    S3WEB_SESSION_SECRET           = random_password.session_secret.result
    S3WEB_BOOTSTRAP_ADMIN_PASSWORD = random_password.admin_password.result
    S3WEB_BOOTSTRAP_DEMO_PASSWORD  = random_password.demo_password.result
    S3WEB_OIDC_CLIENT_SECRET       = "replace-with-oidc-client-secret-in-secrets-manager"
    S3WEB_BOOTSTRAP_RAW_SECRET     = "s3w_${random_password.raw_service_account_secret.result}"
  })

  lifecycle {
    ignore_changes = [secret_string]
  }
}

# --- IAM Roles for ECS Fargate Execution & Application Task ---

data "aws_iam_policy_document" "ecs_assume_role" {
  statement {
    actions = ["sts:AssumeRole"]
    principals {
      type        = "Service"
      identifiers = ["ecs-tasks.amazonaws.com"]
    }
  }
}

resource "aws_iam_role" "ecs_execution" {
  name               = "${local.name_prefix}-ecs-execution-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}

resource "aws_iam_role_policy_attachment" "ecs_execution_managed" {
  role       = aws_iam_role.ecs_execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "ecs_execution_secrets" {
  name = "${local.name_prefix}-ecs-exec-secrets"
  role = aws_iam_role.ecs_execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue",
          "kms:Decrypt"
        ]
        Resource = [
          aws_secretsmanager_secret.app_secrets.arn,
          aws_kms_key.s3web.arn
        ]
      }
    ]
  })
}

# Application Task IAM Role (Least-Privilege S3, DynamoDB, SQS, KMS via VPC Endpoints)
resource "aws_iam_role" "ecs_task" {
  name               = "${local.name_prefix}-ecs-task-role"
  assume_role_policy = data.aws_iam_policy_document.ecs_assume_role.json
}

resource "aws_iam_role_policy" "ecs_task_data_plane" {
  name = "${local.name_prefix}-data-plane-policy"
  role = aws_iam_role.ecs_task.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid    = "S3ArtifactBucketAccess"
        Effect = "Allow"
        Action = [
          "s3:ListBucket",
          "s3:GetBucketLocation",
          "s3:GetObject",
          "s3:GetObjectVersion",
          "s3:GetObjectAttributes",
          "s3:PutObject",
          "s3:DeleteObject",
          "s3:RestoreObject",
          "s3:AbortMultipartUpload",
          "s3:ListMultipartUploadParts"
        ]
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
      },
      {
        Sid    = "DynamoDBSingleTableAccess"
        Effect = "Allow"
        Action = [
          "dynamodb:GetItem",
          "dynamodb:PutItem",
          "dynamodb:UpdateItem",
          "dynamodb:DeleteItem",
          "dynamodb:Query",
          "dynamodb:Scan",
          "dynamodb:BatchWriteItem",
          "dynamodb:BatchGetItem"
        ]
        Resource = [
          aws_dynamodb_table.metadata.arn,
          "${aws_dynamodb_table.metadata.arn}/index/*"
        ]
      },
      {
        Sid    = "SQSEventConsumerAccess"
        Effect = "Allow"
        Action = [
          "sqs:ReceiveMessage",
          "sqs:DeleteMessage",
          "sqs:GetQueueAttributes",
          "sqs:ChangeMessageVisibility"
        ]
        Resource = [aws_sqs_queue.s3_events.arn]
      },
      {
        Sid    = "KMSDataKeyAccess"
        Effect = "Allow"
        Action = [
          "kms:Encrypt",
          "kms:Decrypt",
          "kms:ReEncrypt*",
          "kms:GenerateDataKey*",
          "kms:DescribeKey"
        ]
        Resource = [aws_kms_key.s3web.arn]
      }
    ]
  })
}

# ============================================================================
# Security Groups & Internal Application Load Balancer (VPN Access Only)
# ============================================================================

resource "aws_security_group" "alb_internal" {
  name        = "${local.name_prefix}-internal-alb-sg"
  description = "Allow HTTPS/HTTP from Corporate VPN, HTML Raw Access, and Self-Hosted GitHub Runners"
  vpc_id      = local.vpc_id

  ingress {
    description = "HTTPS from VPN & Private Subnets"
    from_port   = 443
    to_port     = 443
    protocol    = "tcp"
    cidr_blocks = distinct(concat(var.vpn_allowed_cidr_blocks, [var.vpc_cidr]))
  }

  ingress {
    description = "HTTP from VPN & Private Subnets"
    from_port   = 80
    to_port     = 80
    protocol    = "tcp"
    cidr_blocks = distinct(concat(var.vpn_allowed_cidr_blocks, [var.vpc_cidr]))
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = [var.vpc_cidr]
  }

  tags = {
    Name = "${local.name_prefix}-internal-alb-sg"
  }
}

resource "aws_security_group" "ecs_tasks" {
  name        = "${local.name_prefix}-ecs-tasks-sg"
  description = "Allow traffic from Internal ALB and outbound to VPC Endpoints / VPN IdP"
  vpc_id      = local.vpc_id

  ingress {
    description     = "HTTP 8080 from Internal ALB"
    from_port       = 8080
    to_port         = 8080
    protocol        = "tcp"
    security_groups = [aws_security_group.alb_internal.id]
  }

  egress {
    description = "Outbound to S3/DynamoDB Gateway Endpoints, PrivateLink Endpoints, and Corporate OIDC IdP over VPN"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "${local.name_prefix}-ecs-tasks-sg"
  }
}

resource "aws_lb" "internal" {
  name               = "${local.name_prefix}-internal-alb"
  internal           = true # Strictly internal private ALB (no public IP)
  load_balancer_type = "application"
  security_groups    = [aws_security_group.alb_internal.id]
  subnets            = local.private_subnet_ids

  # 1-hour idle timeout for streaming multi-GB ISOs over VPN / HTML Raw Access
  idle_timeout = 3600

  tags = {
    Name = "${local.name_prefix}-internal-alb"
  }
}

resource "aws_lb_target_group" "s3web" {
  name                 = "${local.name_prefix}-tg"
  port                 = 8080
  protocol             = "HTTP"
  vpc_id               = local.vpc_id
  target_type          = "ip"
  deregistration_delay = 60

  health_check {
    enabled             = true
    path                = "/healthz"
    matcher             = "200"
    interval            = 30
    timeout             = 5
    healthy_threshold   = 2
    unhealthy_threshold = 3
  }
}

resource "aws_lb_listener" "https" {
  count             = var.acm_certificate_arn != "" ? 1 : 0
  load_balancer_arn = aws_lb.internal.arn
  port              = 443
  protocol          = "HTTPS"
  ssl_policy        = "ELBSecurityPolicy-TLS13-1-2-2021-06"
  certificate_arn   = var.acm_certificate_arn

  default_action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.s3web.arn
  }
}

resource "aws_lb_listener" "http" {
  load_balancer_arn = aws_lb.internal.arn
  port              = 80
  protocol          = "HTTP"

  default_action {
    type = var.acm_certificate_arn != "" ? "redirect" : "forward"

    dynamic "redirect" {
      for_each = var.acm_certificate_arn != "" ? [1] : []
      content {
        port        = "443"
        protocol    = "HTTPS"
        status_code = "HTTP_301"
      }
    }

    target_group_arn = var.acm_certificate_arn == "" ? aws_lb_target_group.s3web.arn : null
  }
}

# --- Route 53 Private Hosted Zone & DNS Alias Record ---

resource "aws_route53_zone" "private" {
  count = var.create_private_hosted_zone ? 1 : 0
  name  = var.private_hosted_zone_name

  vpc {
    vpc_id = local.vpc_id
  }
}

resource "aws_route53_record" "s3web" {
  count   = var.create_private_hosted_zone ? 1 : 0
  zone_id = aws_route53_zone.private[0].zone_id
  name    = var.internal_domain_name
  type    = "A"

  alias {
    name                   = aws_lb.internal.dns_name
    zone_id                = aws_lb.internal.zone_id
    evaluate_target_health = true
  }
}

# ============================================================================
# ECS Fargate Cluster, CloudWatch Logs & Multi-AZ Service
# ============================================================================

resource "aws_cloudwatch_log_group" "s3web" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = 90
  kms_key_id        = aws_kms_key.s3web.arn
}

resource "aws_ecs_cluster" "s3web" {
  name = "${local.name_prefix}-cluster"

  setting {
    name  = "containerInsights"
    value = "enabled"
  }
}

locals {
  scheme   = var.acm_certificate_arn != "" ? "https" : "http"
  base_url = "${local.scheme}://${var.internal_domain_name}"
}

resource "aws_ecs_task_definition" "s3web" {
  family                   = local.name_prefix
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.ecs_task_cpu)
  memory                   = tostring(var.ecs_task_memory)
  execution_role_arn       = aws_iam_role.ecs_execution.arn
  task_role_arn            = aws_iam_role.ecs_task.arn

  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "ARM64"
  }

  container_definitions = jsonencode([
    {
      name      = "s3web"
      image     = "${aws_ecr_repository.s3web.repository_url}:${var.container_image_tag}"
      essential = true
      portMappings = [
        {
          containerPort = 8080
          hostPort      = 8080
          protocol      = "tcp"
        }
      ]
      environment = [
        { name = "S3WEB_LISTEN_ADDR", value = ":8080" },
        { name = "S3WEB_BASE_URL", value = local.base_url },
        { name = "S3WEB_BACKEND_MODE", value = "aws" },
        { name = "AWS_REGION", value = var.aws_region },
        { name = "S3WEB_S3_BUCKET", value = aws_s3_bucket.artifacts.id },
        { name = "S3WEB_DYNAMODB_TABLE", value = aws_dynamodb_table.metadata.name },
        { name = "S3WEB_SQS_QUEUE_URL", value = aws_sqs_queue.s3_events.id },
        { name = "S3WEB_COOKIE_SECURE", value = tostring(var.acm_certificate_arn != "") },
        { name = "S3WEB_OIDC_ENABLED", value = tostring(var.oidc_enabled) },
        { name = "S3WEB_OIDC_ISSUER_URL", value = var.oidc_issuer_url },
        { name = "S3WEB_OIDC_CLIENT_ID", value = var.oidc_client_id },
        { name = "S3WEB_OIDC_REDIRECT_URL", value = "${local.base_url}/auth/callback" },
        { name = "S3WEB_OIDC_GROUPS_CLAIM", value = var.oidc_groups_claim },
        { name = "S3WEB_GITHUB_OIDC_ENABLED", value = "true" },
        { name = "S3WEB_GITHUB_OIDC_ISSUER", value = var.github_oidc_issuer_url },
        { name = "S3WEB_GITHUB_OIDC_AUDIENCE", value = local.base_url },
        { name = "S3WEB_GITHUB_PINNED_JWKS_JSON", value = var.github_pinned_jwks_json },
        { name = "S3WEB_BOOTSTRAP_ADMIN_EMAIL", value = var.bootstrap_admin_email },
        { name = "S3WEB_BOOTSTRAP_ADMIN_GROUP", value = var.bootstrap_admin_oidc_group },
        { name = "S3WEB_BOOTSTRAP_RAW_ID", value = var.bootstrap_raw_account_id },
        { name = "S3WEB_ALLOWED_EXTENSIONS", value = var.allowed_file_extensions },
        { name = "S3WEB_LOG_RETENTION_DAYS", value = tostring(var.access_log_retention_days) }
      ]
      secrets = [
        {
          name      = "S3WEB_SESSION_SECRET"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:S3WEB_SESSION_SECRET::"
        },
        {
          name      = "S3WEB_BOOTSTRAP_ADMIN_PASSWORD"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:S3WEB_BOOTSTRAP_ADMIN_PASSWORD::"
        },
        {
          name      = "S3WEB_BOOTSTRAP_DEMO_PASSWORD"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:S3WEB_BOOTSTRAP_DEMO_PASSWORD::"
        },
        {
          name      = "S3WEB_OIDC_CLIENT_SECRET"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:S3WEB_OIDC_CLIENT_SECRET::"
        },
        {
          name      = "S3WEB_BOOTSTRAP_RAW_SECRET"
          valueFrom = "${aws_secretsmanager_secret.app_secrets.arn}:S3WEB_BOOTSTRAP_RAW_SECRET::"
        }
      ]
      logConfiguration = {
        logDriver = "awslogs"
        options = {
          awslogs-group         = aws_cloudwatch_log_group.s3web.name
          awslogs-region        = var.aws_region
          awslogs-stream-prefix = "s3web"
        }
      }
    }
  ])
}

resource "aws_ecs_service" "s3web" {
  name            = "${local.name_prefix}-service"
  cluster         = aws_ecs_cluster.s3web.id
  task_definition = aws_ecs_task_definition.s3web.arn
  desired_count   = var.ecs_desired_count
  launch_type     = "FARGATE"

  network_configuration {
    subnets          = local.private_subnet_ids
    security_groups  = [aws_security_group.ecs_tasks.id]
    assign_public_ip = false # Strictly private subnets only
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.s3web.arn
    container_name   = "s3web"
    container_port   = 8080
  }

  depends_on = [
    aws_lb_listener.http,
    aws_vpc_endpoint.s3,
    aws_vpc_endpoint.dynamodb,
    aws_vpc_endpoint.interface
  ]
}

