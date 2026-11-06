# ============================================================================
# KMS Encryption, S3 Intelligent-Tiering Bucket, SQS Event Queue & DynamoDB
# ============================================================================

data "aws_caller_identity" "current" {}

# --- Customer-Managed KMS Key for S3, DynamoDB, SQS & Secrets Manager ---

resource "aws_kms_key" "s3web" {
  description             = "KMS Key for ${local.name_prefix} S3 bucket, DynamoDB table, SQS queue, and Secrets"
  deletion_window_in_days = 30
  enable_key_rotation     = true

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "EnableIAMUserPermissions"
        Effect    = "Allow"
        Principal = { AWS = "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root" }
        Action    = "kms:*"
        Resource  = "*"
      },
      {
        Sid       = "AllowS3NotificationsToEncryptSQS"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action = [
          "kms:GenerateDataKey*",
          "kms:Decrypt"
        ]
        Resource = "*"
      }
    ]
  })

  tags = {
    Name = "${local.name_prefix}-kms"
  }
}

resource "aws_kms_alias" "s3web" {
  name          = "alias/${local.name_prefix}"
  target_key_id = aws_kms_key.s3web.key_id
}

# ============================================================================
# Amazon S3 Bucket (ISOs & Compressed Archives with Intelligent-Tiering)
# ============================================================================

resource "aws_s3_bucket" "artifacts" {
  bucket = var.s3_bucket_name

  tags = {
    Name = var.s3_bucket_name
  }
}

resource "aws_s3_bucket_public_access_block" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_ownership_controls" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  rule {
    object_ownership = "BucketOwnerEnforced"
  }
}

resource "aws_s3_bucket_versioning" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = aws_kms_key.s3web.arn
      sse_algorithm     = "aws:kms"
    }
    bucket_key_enabled = true
  }
}

# Default Lifecycle Rule: Ensure all objects use S3 INTELLIGENT_TIERING and abort incomplete multipart uploads
resource "aws_s3_bucket_lifecycle_configuration" "artifacts" {
  bucket = aws_s3_bucket.artifacts.id

  rule {
    id     = "ensure-intelligent-tiering-and-clean-multipart"
    status = "Enabled"

    filter {}

    transition {
      days          = 0
      storage_class = "INTELLIGENT_TIERING"
    }

    abort_incomplete_multipart_upload {
      days_after_initiation = 2
    }
  }
}

# S3 Intelligent-Tiering Configuration (Optional Archive Access & Deep Archive Access Sub-Tiers)
resource "aws_s3_bucket_intelligent_tiering_configuration" "archive_tiers" {
  count  = var.enable_intelligent_tiering_archive_tiers ? 1 : 0
  bucket = aws_s3_bucket.artifacts.id
  name   = "${local.name_prefix}-intelligent-tiering"
  status = "Enabled"

  tiering {
    access_tier = "ARCHIVE_ACCESS"
    days        = var.intelligent_tiering_archive_days
  }

  tiering {
    access_tier = "DEEP_ARCHIVE_ACCESS"
    days        = var.intelligent_tiering_deep_archive_days
  }
}

# Strict S3 Bucket Policy: Enforce TLS and restrict data-plane access to the VPC S3 Gateway Endpoint / Task Role
resource "aws_s3_bucket_policy" "artifacts" {
  bucket     = aws_s3_bucket.artifacts.id
  depends_on = [aws_s3_bucket_public_access_block.artifacts]

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "DenyNonTLSRequests"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource = [
          aws_s3_bucket.artifacts.arn,
          "${aws_s3_bucket.artifacts.arn}/*"
        ]
        Condition = {
          Bool = { "aws:SecureTransport" = "false" }
        }
      },
      {
        Sid       = "DenyObjectAccessOutsideVPCGatewayEndpoint"
        Effect    = "Deny"
        Principal = "*"
        Action = [
          "s3:GetObject*",
          "s3:PutObject*",
          "s3:DeleteObject*"
        ]
        Resource = "${aws_s3_bucket.artifacts.arn}/*"
        Condition = {
          StringNotEquals = {
            "aws:SourceVpce" = aws_vpc_endpoint.s3.id
          }
          ArnNotEquals = {
            "aws:PrincipalArn" = [
              aws_iam_role.ecs_task.arn,
              "arn:aws:iam::${data.aws_caller_identity.current.account_id}:root"
            ]
          }
        }
      }
    ]
  })
}

# ============================================================================
# SQS Event Queue (Out-of-Band S3 Uploads, Intelligent-Tiering & Restore Events)
# ============================================================================

resource "aws_sqs_queue" "s3_events_dlq" {
  name              = "${local.name_prefix}-s3-events-dlq"
  kms_master_key_id = aws_kms_key.s3web.id
}

resource "aws_sqs_queue" "s3_events" {
  name                       = "${local.name_prefix}-s3-events"
  visibility_timeout_seconds = 900 # 15 minutes for hashing multi-GB out-of-band ISOs
  message_retention_seconds  = 345600
  receive_wait_time_seconds  = 20
  kms_master_key_id          = aws_kms_key.s3web.id

  redrive_policy = jsonencode({
    deadLetterTargetArn = aws_sqs_queue.s3_events_dlq.arn
    maxReceiveCount     = 5
  })
}

resource "aws_sqs_queue_policy" "s3_events" {
  queue_url = aws_sqs_queue.s3_events.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "AllowS3BucketNotifications"
        Effect    = "Allow"
        Principal = { Service = "s3.amazonaws.com" }
        Action    = "sqs:SendMessage"
        Resource  = aws_sqs_queue.s3_events.arn
        Condition = {
          ArnEquals = { "aws:SourceArn" = aws_s3_bucket.artifacts.arn }
        }
      }
    ]
  })
}

resource "aws_s3_bucket_notification" "s3_events" {
  bucket     = aws_s3_bucket.artifacts.id
  depends_on = [aws_sqs_queue_policy.s3_events]

  queue {
    queue_arn = aws_sqs_queue.s3_events.arn
    events = [
      "s3:ObjectCreated:*",
      "s3:ObjectRemoved:*",
      "s3:IntelligentTiering",
      "s3:ObjectRestore:Post",
      "s3:ObjectRestore:Completed"
    ]
  }
}

# ============================================================================
# Amazon DynamoDB Single-Table Store (Metadata, Hashes, Access Logs, RBAC)
# ============================================================================

resource "aws_dynamodb_table" "metadata" {
  name         = "${local.name_prefix}-metadata"
  billing_mode = "PAY_PER_REQUEST"
  hash_key     = "PK"
  range_key    = "SK"

  attribute {
    name = "PK"
    type = "S"
  }

  attribute {
    name = "SK"
    type = "S"
  }

  attribute {
    name = "GSI1PK"
    type = "S"
  }

  attribute {
    name = "GSI1SK"
    type = "S"
  }

  # GSI1: Enables instant lookup by SHA-256 / SHA-1 digest and Principal Audit queries
  global_secondary_index {
    name            = "GSI1"
    hash_key        = "GSI1PK"
    range_key       = "GSI1SK"
    projection_type = "ALL"
  }

  ttl {
    attribute_name = "expires_at"
    enabled        = true
  }

  point_in_time_recovery {
    enabled = true
  }

  server_side_encryption {
    enabled     = true
    kms_key_arn = aws_kms_key.s3web.arn
  }

  tags = {
    Name = "${local.name_prefix}-metadata"
  }
}

