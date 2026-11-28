check "distinct_operator_host" {
  assert {
    condition     = local.normalized_operator_host != local.normalized_ingress_host
    error_message = "D-70 requires operator_host to differ from ingress_host."
  }
}

locals {
  create_vpc               = var.vpc_id == null
  vpc_id                   = local.create_vpc ? aws_vpc.this[0].id : var.vpc_id
  private_subnet_ids       = local.create_vpc ? aws_subnet.private[*].id : var.private_subnet_ids
  kms_key_arn              = var.kms_key_arn == null ? aws_kms_key.this[0].arn : var.kms_key_arn
  data_bucket_name         = "${var.name_prefix}-lake-data-${data.aws_caller_identity.current.account_id}-${var.region}"
  backup_bucket_name       = "${var.name_prefix}-backups-${data.aws_caller_identity.current.account_id}-${var.region}"
  db_fallback_cidrs        = length(var.db_allowed_cidr_blocks) > 0 ? var.db_allowed_cidr_blocks : (local.create_vpc ? aws_subnet.private[*].cidr_block : [])
  normalized_ingress_host  = trimsuffix(lower(trimspace(var.ingress_host)), ".")
  normalized_operator_host = trimsuffix(lower(trimspace(var.operator_host)), ".")
}

data "aws_caller_identity" "current" {}
data "aws_partition" "current" {}
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_kms_key" "this" {
  count                   = var.kms_key_arn == null ? 1 : 0
  description             = "${var.name_prefix} Guardrails ADR envelope and storage encryption key"
  enable_key_rotation     = true
  deletion_window_in_days = 30
}

resource "aws_kms_alias" "this" {
  count         = var.kms_key_arn == null ? 1 : 0
  name          = "alias/${var.name_prefix}-grdr"
  target_key_id = aws_kms_key.this[0].key_id
}

resource "aws_vpc" "this" {
  count                = local.create_vpc ? 1 : 0
  cidr_block           = var.vpc_cidr
  enable_dns_hostnames = true
  enable_dns_support   = true
  tags                 = { Name = "${var.name_prefix}-vpc" }
}

resource "aws_subnet" "private" {
  count             = local.create_vpc ? 2 : 0
  vpc_id            = aws_vpc.this[0].id
  cidr_block        = cidrsubnet(var.vpc_cidr, 4, count.index)
  availability_zone = data.aws_availability_zones.available.names[count.index]
  tags              = { Name = "${var.name_prefix}-private-${count.index}" }
}

resource "aws_security_group" "postgres" {
  name_prefix = "${var.name_prefix}-pg-"
  description = "Private access to Guardrails ADR PostgreSQL 18"
  vpc_id      = local.vpc_id

  dynamic "ingress" {
    for_each = length(var.eks_node_security_group_ids) > 0 ? [1] : []
    content {
      from_port       = 5432
      to_port         = 5432
      protocol        = "tcp"
      security_groups = var.eks_node_security_group_ids
    }
  }

  dynamic "ingress" {
    for_each = length(local.db_fallback_cidrs) > 0 && length(var.eks_node_security_group_ids) == 0 ? [1] : []
    content {
      from_port   = 5432
      to_port     = 5432
      protocol    = "tcp"
      cidr_blocks = local.db_fallback_cidrs
    }
  }
}

resource "aws_db_subnet_group" "this" {
  name       = "${var.name_prefix}-db-subnets"
  subnet_ids = local.private_subnet_ids
}

resource "aws_db_parameter_group" "pg18" {
  name_prefix = "${var.name_prefix}-pg18-"
  family      = "postgres18"

  parameter {
    name  = "rds.force_ssl"
    value = "1"
  }
}

resource "aws_db_instance" "this" {
  identifier                    = "${var.name_prefix}-postgres"
  engine                        = "postgres"
  engine_version                = var.postgresql_version
  instance_class                = var.db_instance_class
  allocated_storage             = 100
  max_allocated_storage         = 1000
  storage_encrypted             = true
  kms_key_id                    = local.kms_key_arn
  db_name                       = "grdr"
  username                      = "grdr"
  manage_master_user_password   = true
  master_user_secret_kms_key_id = local.kms_key_arn
  multi_az                      = true
  publicly_accessible           = false
  db_subnet_group_name          = aws_db_subnet_group.this.name
  vpc_security_group_ids        = [aws_security_group.postgres.id]
  parameter_group_name          = aws_db_parameter_group.pg18.name
  backup_retention_period       = var.backup_retention_days
  deletion_protection           = var.enable_deletion_protection
  skip_final_snapshot           = !var.enable_deletion_protection
}

resource "aws_s3_bucket" "data" {
  bucket = local.data_bucket_name
}

resource "aws_s3_bucket_versioning" "data" {
  bucket = aws_s3_bucket.data.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "data" {
  bucket                  = aws_s3_bucket.data.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_lifecycle_configuration" "data" {
  bucket = aws_s3_bucket.data.id
  rule {
    id     = "expire-noncurrent-past-pitr"
    status = "Enabled"
    noncurrent_version_expiration {
      noncurrent_days = var.backup_retention_days
    }
  }
}

resource "aws_s3_bucket" "backup" {
  bucket              = local.backup_bucket_name
  object_lock_enabled = true
}

resource "aws_s3_bucket_versioning" "backup" {
  bucket = aws_s3_bucket.backup.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm     = "aws:kms"
      kms_master_key_id = local.kms_key_arn
    }
    bucket_key_enabled = true
  }
}

resource "aws_s3_bucket_public_access_block" "backup" {
  bucket                  = aws_s3_bucket.backup.id
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_object_lock_configuration" "backup" {
  bucket = aws_s3_bucket.backup.id
  rule {
    default_retention {
      mode = "COMPLIANCE"
      days = var.backup_retention_days
    }
  }
}

data "aws_iam_policy_document" "data_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.data.arn, "${aws_s3_bucket.data.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "data_tls" {
  bucket = aws_s3_bucket.data.id
  policy = data.aws_iam_policy_document.data_tls_only.json
}

data "aws_iam_policy_document" "backup_tls_only" {
  statement {
    sid       = "DenyInsecureTransport"
    effect    = "Deny"
    actions   = ["s3:*"]
    resources = [aws_s3_bucket.backup.arn, "${aws_s3_bucket.backup.arn}/*"]
    principals {
      type        = "*"
      identifiers = ["*"]
    }
    condition {
      test     = "Bool"
      variable = "aws:SecureTransport"
      values   = ["false"]
    }
  }
}

resource "aws_s3_bucket_policy" "backup_tls" {
  bucket = aws_s3_bucket.backup.id
  policy = data.aws_iam_policy_document.backup_tls_only.json
}

data "aws_iam_policy_document" "pod_trust" {
  statement {
    actions = ["sts:AssumeRole", "sts:TagSession"]
    principals {
      type        = "Service"
      identifiers = ["pods.eks.amazonaws.com"]
    }
    condition {
      test     = "StringEquals"
      variable = "aws:SourceAccount"
      values   = [data.aws_caller_identity.current.account_id]
    }
    condition {
      test     = "ArnLike"
      variable = "aws:SourceArn"
      values   = ["arn:${data.aws_partition.current.partition}:eks:${var.region}:${data.aws_caller_identity.current.account_id}:cluster/${var.eks_cluster_name}"]
    }
  }
}

resource "aws_iam_role" "server" {
  name_prefix        = "${var.name_prefix}-server-"
  assume_role_policy = data.aws_iam_policy_document.pod_trust.json
}

data "aws_iam_policy_document" "server_permissions" {
  statement {
    sid = "LakeAndBackupBucketsMetadata"
    actions = [
      "s3:GetBucketLocation",
      "s3:GetBucketVersioning",
      "s3:ListBucket",
      "s3:ListBucketVersions",
    ]
    resources = [aws_s3_bucket.data.arn, aws_s3_bucket.backup.arn]
  }
  statement {
    sid = "LakeDataObjectsReadWriteDelete"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
      "s3:DeleteObject",
      "s3:DeleteObjectVersion",
    ]
    resources = ["${aws_s3_bucket.data.arn}/*"]
  }
  statement {
    sid = "BackupObjectsAppendAndReadOnly"
    actions = [
      "s3:GetObject",
      "s3:GetObjectVersion",
      "s3:PutObject",
    ]
    resources = ["${aws_s3_bucket.backup.arn}/*"]
  }
  statement {
    sid = "KmsEnvelopeAndDataKeys"
    actions = [
      "kms:Decrypt",
      "kms:DescribeKey",
      "kms:Encrypt",
      "kms:GenerateDataKey",
      "kms:GenerateDataKeyWithoutPlaintext",
    ]
    resources = [local.kms_key_arn]
  }
}

resource "aws_iam_role_policy" "server" {
  name_prefix = "${var.name_prefix}-server-"
  role        = aws_iam_role.server.id
  policy      = data.aws_iam_policy_document.server_permissions.json
}

resource "aws_eks_pod_identity_association" "server" {
  cluster_name    = var.eks_cluster_name
  namespace       = var.kubernetes_namespace
  service_account = var.service_account_name
  role_arn        = aws_iam_role.server.arn
}

resource "helm_release" "grdr_server" {
  name             = "${var.name_prefix}-server"
  namespace        = var.kubernetes_namespace
  create_namespace = true
  chart            = var.helm_chart_path

  values = [
    yamlencode({
      profile = "ha"
      image   = { digest = var.server_image_digest }
      serviceAccount = {
        name = var.service_account_name
      }
      storage = {
        database = {
          existingSecret = var.database_existing_secret
          sslMode        = "verify-full"
        }
        objectStore = {
          provider       = "s3"
          dir            = "/var/lib/grdr-objects"
          endpoint       = "https://s3.${var.region}.amazonaws.com"
          bucket         = aws_s3_bucket.data.id
          backupBucket   = aws_s3_bucket.backup.id
          region         = var.region
          existingSecret = var.object_store_existing_secret
        }
      }
      secrets = {
        bootstrapExistingSecret = var.bootstrap_existing_secret
      }
      networkPolicy = {
        enabled                    = true
        allowIngressFromNamespaces = var.api_ingress_namespaces
      }
      ingress = {
        enabled = true
        host    = var.ingress_host
        tls = {
          enabled    = true
          secretName = var.ingress_tls_secret_name
        }
      }
      operator = {
        enabled        = true
        existingSecret = var.operator_existing_secret
        clientCA = {
          existingSecret = var.operator_client_ca_existing_secret
        }
        ingress = {
          enabled    = true
          host       = var.operator_host
          allowCidrs = var.operator_allow_cidrs
          tls = {
            enabled    = true
            secretName = var.operator_tls_secret_name
          }
        }
      }
      metrics = {
        enabled = true
        port    = 9090
      }
    })
  ]

  lifecycle {
    precondition {
      condition     = local.normalized_operator_host != local.normalized_ingress_host
      error_message = "D-70 requires operator_host to differ from ingress_host."
    }
  }

  depends_on = [
    aws_db_instance.this,
    aws_eks_pod_identity_association.server,
  ]
}
