output "network_self_link" {
  value       = local.network_self_link
  description = "VPC network self_link hosting Cloud SQL and GKE workloads."
}

output "postgres_connection_name" {
  value       = google_sql_database_instance.this.connection_name
  description = "Cloud SQL PostgreSQL 18 instance connection name."
}

output "data_bucket_name" {
  value       = google_storage_bucket.data.name
  description = "Encrypted versioned GCS lake bucket."
}

output "backup_bucket_name" {
  value       = google_storage_bucket.backup.name
  description = "Retention-locked GCS backup bucket."
}

output "kms_crypto_key_id" {
  value       = google_kms_crypto_key.this.id
  description = "Cloud KMS crypto key resource id."
}

output "workload_identity_service_account" {
  value       = google_service_account.server.email
  description = "GCP service account bound via Workload Identity Federation."
}

output "operator_host" {
  value       = var.operator_host
  description = "Isolated D-70 operator hostname."
}

output "helm_release_name" {
  value       = helm_release.grdr_server.name
  description = "Deployed grdr-server Helm release name."
}
