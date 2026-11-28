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

  assert {
    condition     = google_service_account_iam_member.gke_wif.member == "serviceAccount:grdr-example-project.svc.id.goog[grdr-system/grdr-server]"
    error_message = "GCP WIF binding must be scoped strictly to the grdr-server KSA."
  }

  assert {
    condition     = google_storage_bucket_iam_member.backup_viewer.role == "roles/storage.objectViewer"
    error_message = "GCP backup bucket must grant objectViewer alongside objectCreator for restore drills."
  }
}

run "reject_wildcard_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["0.0.0.0/0"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_same_operator_host_d70" {
  command = plan

  variables {
    project_id          = "grdr-example-project"
    ingress_host        = "shared.example.invalid"
    operator_host       = "shared.example.invalid"
    server_image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [helm_release.grdr_server]
}

run "reject_empty_operator_secret" {
  command = plan

  variables {
    project_id               = "grdr-example-project"
    ingress_host             = "grdr.example.invalid"
    operator_host            = "ops.grdr.example.invalid"
    operator_existing_secret = ""
    server_image_digest      = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_existing_secret]
}

run "reject_case_normalized_operator_host_d70" {
  command = plan

  variables {
    project_id          = "grdr-example-project"
    ingress_host        = "Shared.Example.Invalid."
    operator_host       = "shared.example.invalid"
    server_image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [helm_release.grdr_server]
}

run "reject_imds_ipv6_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["fd00:ec2::254/128"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_leading_zero_imds_ipv6_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["fd00:0ec2::254/128"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_expanded_ipv6_wildcard_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["0000::/0"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_169_supernet_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["169.240.0.0/12"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_fd00_supernet_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["fd00:ec0::/30"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_fe00_supernet_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["fe00::/8"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_v4_mapped_supernet_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["0:0:0:0:0:fffe:0:0/95"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_loopback_ipv6_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["::1/128"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_loopback_ipv6_expanded_operator_cidr" {
  command = plan

  variables {
    project_id           = "grdr-example-project"
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["::0:1/128"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}
