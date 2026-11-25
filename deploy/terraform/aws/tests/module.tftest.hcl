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
