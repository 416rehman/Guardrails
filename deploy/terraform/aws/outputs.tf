output "vpc_id" {
  value       = local.vpc_id
  description = "VPC hosting PostgreSQL and private subnets."
}

output "postgres_endpoint" {
  value       = aws_db_instance.this.endpoint
  description = "PostgreSQL 18 Multi-AZ writer endpoint."
}

output "data_bucket_name" {
  value       = aws_s3_bucket.data.id
  description = "Primary encrypted versioned S3 lake bucket."
}

output "backup_bucket_name" {
  value       = aws_s3_bucket.backup.id
  description = "Object-locked S3 backup bucket."
}

output "kms_key_arn" {
  value       = local.kms_key_arn
  description = "KMS key ARN protecting storage and envelope keys."
}

output "workload_identity_role_arn" {
  value       = aws_iam_role.server.arn
  description = "IAM role bound via EKS Pod Identity."
}

output "operator_host" {
  value       = var.operator_host
  description = "Isolated D-70 operator hostname."
}

output "helm_release_name" {
  value       = helm_release.grdr_server.name
  description = "Deployed grdr-server Helm release name."
}
