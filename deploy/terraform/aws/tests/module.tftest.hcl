mock_provider "aws" {}
mock_provider "helm" {}

run "valid_ha_defaults" {
  command = plan

  variables {
    ingress_host        = "grdr.example.invalid"
    operator_host       = "ops.grdr.example.invalid"
    server_image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  assert {
    condition     = var.postgresql_version == "18"
    error_message = "Default PostgreSQL version must remain 18."
  }

  assert {
    condition     = aws_db_instance.this.publicly_accessible == false
    error_message = "PostgreSQL RDS must never be publicly accessible."
  }

  assert {
    condition     = aws_s3_bucket_object_lock_configuration.backup.rule[0].default_retention[0].mode == "COMPLIANCE"
    error_message = "Backup S3 bucket must use COMPLIANCE object lock."
  }

  assert {
    condition     = aws_s3_bucket_public_access_block.data.block_public_policy == true
    error_message = "Lake S3 bucket must block all public access."
  }

  assert {
    condition     = aws_s3_bucket_policy.data_tls.bucket == aws_s3_bucket.data.id && aws_s3_bucket_policy.backup_tls.bucket == aws_s3_bucket.backup.id
    error_message = "Both S3 buckets must enforce TLS-only transport policies."
  }
}

run "reject_wildcard_operator_cidr" {
  command = plan

  variables {
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
    ingress_host        = "shared.example.invalid"
    operator_host       = "shared.example.invalid"
    server_image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [helm_release.grdr_server]
}

run "reject_empty_operator_secret" {
  command = plan

  variables {
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
    ingress_host        = "Shared.Example.Invalid."
    operator_host       = "shared.example.invalid"
    server_image_digest = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [helm_release.grdr_server]
}

run "reject_imds_supernet_operator_cidr" {
  command = plan

  variables {
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["169.252.0.0/14"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_expanded_ipv6_wildcard_operator_cidr" {
  command = plan

  variables {
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["0000::/0"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_v4_mapped_hex_imds_operator_cidr" {
  command = plan

  variables {
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["::ffff:a9fe:a9fe/128"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_169_supernet_operator_cidr" {
  command = plan

  variables {
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["128.0.0.0/2"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_169_supernet_db_cidr" {
  command = plan

  variables {
    ingress_host            = "grdr.example.invalid"
    operator_host           = "ops.grdr.example.invalid"
    db_allowed_cidr_blocks  = ["169.128.0.0/9"]
    server_image_digest     = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.db_allowed_cidr_blocks]
}

run "reject_fd00_supernet_operator_cidr" {
  command = plan

  variables {
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["fd00:e00::/24"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_fe00_supernet_operator_cidr" {
  command = plan

  variables {
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
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["0:0:0:0:0:8000:0:0/81"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_loopback_ipv6_operator_cidr" {
  command = plan

  variables {
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
    ingress_host         = "grdr.example.invalid"
    operator_host        = "ops.grdr.example.invalid"
    operator_allow_cidrs = ["::0:1/128"]
    server_image_digest  = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}
