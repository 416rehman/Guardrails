mock_provider "google" {}
mock_provider "helm" {}

run "valid_ha_defaults" {
  command = plan

  variables {
    project_id          = "grdr-example-project"
    ingress_host        = "grdr.example.invalid"
    operator_host       = "ops.grdr.example.invalid"
    server_image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  assert {
    condition     = var.postgresql_version == "POSTGRES_18"
    error_message = "Default Cloud SQL PostgreSQL version must remain POSTGRES_18."
  }

  assert {
    condition     = google_storage_bucket.data.public_access_prevention == "enforced"
    error_message = "GCS lake bucket must enforce public access prevention."
  }

  assert {
    condition     = google_storage_bucket.backup.retention_policy[0].is_locked == true
    error_message = "GCS backup bucket retention policy must be locked."
  }

  assert {
    condition     = google_sql_database_instance.this.settings[0].ip_configuration[0].ipv4_enabled == false
    error_message = "Cloud SQL instance must disable public IPv4."
  }
}
