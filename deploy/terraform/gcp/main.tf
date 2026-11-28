check "distinct_operator_host" {
  assert {
    condition     = local.normalized_operator_host != local.normalized_ingress_host
    error_message = "D-70 requires operator_host to differ from ingress_host."
  }
}

locals {
  create_network           = var.network_self_link == null
  network_self_link        = local.create_network ? google_compute_network.this[0].self_link : var.network_self_link
  data_bucket_name         = "${var.project_id}-${var.name_prefix}-lake-data"
  backup_bucket_name       = "${var.project_id}-${var.name_prefix}-backups"
  wif_member               = "serviceAccount:${var.project_id}.svc.id.goog[${var.kubernetes_namespace}/${var.service_account_name}]"
  normalized_ingress_host  = trimsuffix(lower(trimspace(var.ingress_host)), ".")
  normalized_operator_host = trimsuffix(lower(trimspace(var.operator_host)), ".")
}

data "google_project" "current" {
  project_id = var.project_id
}

data "google_storage_project_service_account" "gcs" {
  project = var.project_id
}

resource "google_project_service_identity" "cloudsql" {
  project = var.project_id
  service = "sqladmin.googleapis.com"
}

resource "google_compute_network" "this" {
  count                   = local.create_network ? 1 : 0
  name                    = "${var.name_prefix}-vpc"
  project                 = var.project_id
  auto_create_subnetworks = false
}

resource "google_compute_subnetwork" "private" {
  count                    = local.create_network ? 1 : 0
  name                     = "${var.name_prefix}-private"
  project                  = var.project_id
  region                   = var.region
  network                  = google_compute_network.this[0].id
  ip_cidr_range            = "10.44.0.0/20"
  private_ip_google_access = true
}

resource "google_kms_key_ring" "this" {
  name     = "${var.name_prefix}-keyring"
  project  = var.project_id
  location = var.region
}

resource "google_kms_crypto_key" "this" {
  name            = "${var.name_prefix}-key"
  key_ring        = google_kms_key_ring.this.id
  rotation_period = "31536000s"

  lifecycle {
    prevent_destroy = true
  }
}

resource "google_kms_crypto_key_iam_member" "gcs_cmek" {
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${data.google_storage_project_service_account.gcs.email_address}"
}

resource "google_kms_crypto_key_iam_member" "cloudsql_cmek" {
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = google_project_service_identity.cloudsql.member
}

resource "google_sql_database_instance" "this" {
  name                = "${var.name_prefix}-postgres"
  project             = var.project_id
  region              = var.region
  database_version    = var.postgresql_version
  deletion_protection = var.enable_deletion_protection

  encryption_key_name = google_kms_crypto_key.this.id

  settings {
    tier              = var.db_tier
    availability_type = "REGIONAL"

    ip_configuration {
      ipv4_enabled    = false
      private_network = local.network_self_link
      ssl_mode        = "ENCRYPTED_ONLY"
    }

    backup_configuration {
      enabled                        = true
      point_in_time_recovery_enabled = true
      transaction_log_retention_days = 7
      backup_retention_settings {
        retained_backups = var.backup_retention_days
      }
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.cloudsql_cmek]
}

resource "google_sql_database" "grdr" {
  name     = "grdr"
  project  = var.project_id
  instance = google_sql_database_instance.this.name
}

resource "google_storage_bucket" "data" {
  name                        = local.data_bucket_name
  project                     = var.project_id
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.this.id
  }

  lifecycle_rule {
    condition {
      days_since_noncurrent_time = var.backup_retention_days
      with_state                 = "ARCHIVED"
    }
    action {
      type = "Delete"
    }
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_cmek]
}

resource "google_storage_bucket" "backup" {
  name                        = local.backup_bucket_name
  project                     = var.project_id
  location                    = var.region
  uniform_bucket_level_access = true
  public_access_prevention    = "enforced"

  versioning {
    enabled = true
  }

  retention_policy {
    is_locked        = true
    retention_period = var.backup_retention_days * 86400
  }

  encryption {
    default_kms_key_name = google_kms_crypto_key.this.id
  }

  depends_on = [google_kms_crypto_key_iam_member.gcs_cmek]
}

resource "google_service_account" "server" {
  account_id   = "${var.name_prefix}-server"
  project      = var.project_id
  display_name = "Guardrails ADR server workload identity"
}

resource "google_storage_bucket_iam_member" "data_admin" {
  bucket = google_storage_bucket.data.name
  role   = "roles/storage.objectUser"
  member = "serviceAccount:${google_service_account.server.email}"
}

resource "google_storage_bucket_iam_member" "backup_admin" {
  bucket = google_storage_bucket.backup.name
  role   = "roles/storage.objectCreator"
  member = "serviceAccount:${google_service_account.server.email}"
}

resource "google_storage_bucket_iam_member" "backup_viewer" {
  bucket = google_storage_bucket.backup.name
  role   = "roles/storage.objectViewer"
  member = "serviceAccount:${google_service_account.server.email}"
}

resource "google_kms_crypto_key_iam_member" "server_kms" {
  crypto_key_id = google_kms_crypto_key.this.id
  role          = "roles/cloudkms.cryptoKeyEncrypterDecrypter"
  member        = "serviceAccount:${google_service_account.server.email}"
}

resource "google_service_account_iam_member" "gke_wif" {
  service_account_id = google_service_account.server.name
  role               = "roles/iam.workloadIdentityUser"
  member             = local.wif_member
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
        annotations = {
          "iam.gke.io/gcp-service-account" = google_service_account.server.email
        }
      }
      storage = {
        database = {
          existingSecret = var.database_existing_secret
          sslMode        = "verify-full"
        }
        objectStore = {
          provider       = "gcs"
          dir            = "/var/lib/grdr-objects"
          endpoint       = "https://storage.googleapis.com"
          bucket         = google_storage_bucket.data.name
          backupBucket   = google_storage_bucket.backup.name
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
    google_sql_database_instance.this,
    google_service_account_iam_member.gke_wif,
  ]
}
