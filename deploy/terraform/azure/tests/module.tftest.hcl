mock_provider "azurerm" {}
mock_provider "helm" {}

run "valid_ha_defaults" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  assert {
    condition     = var.postgresql_version == "18"
    error_message = "Default Azure PostgreSQL version must remain 18."
  }

  assert {
    condition     = azurerm_key_vault_key.cmk.key_size == 4096
    error_message = "Azure Key Vault CMK must use 4096-bit RSA."
  }

  assert {
    condition     = azurerm_storage_container_immutability_policy.backup.locked == true
    error_message = "Azure backup container immutability policy must be locked."
  }

  assert {
    condition     = azurerm_storage_account.this.public_network_access_enabled == false
    error_message = "Azure Storage Account must disable public network access."
  }

  assert {
    condition     = azurerm_postgresql_flexible_server.this.public_network_access_enabled == false
    error_message = "Azure PostgreSQL Flexible Server must disable public network access."
  }

  assert {
    condition     = azurerm_role_assignment.backup_blob_contributor.role_definition_name == "Storage Blob Data Contributor"
    error_message = "Azure server identity must hold Storage Blob Data Contributor on locked backup container."
  }
}

run "reject_wildcard_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["0.0.0.0/0"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_same_operator_host_d70" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "shared.example.invalid"
    operator_host                    = "shared.example.invalid"
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [helm_release.grdr_server]
}

run "reject_empty_operator_secret" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_existing_secret         = ""
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_existing_secret]
}

run "reject_case_normalized_operator_host_d70" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "Shared.Example.Invalid."
    operator_host                    = "shared.example.invalid"
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [helm_release.grdr_server]
}

run "reject_loopback_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["127.0.0.1/32"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_expanded_ipv6_wildcard_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["::000/0"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_v4_mapped_hex_imds_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["::ffff:a9fe:a9fe/128"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_169_supernet_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["169.224.0.0/11"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_fd00_supernet_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["fd00::/8"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_fe00_supernet_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["fe00::/8"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_v4_mapped_supernet_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["::fffe:0:0/95"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_loopback_ipv6_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["::1/128"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}

run "reject_loopback_ipv6_expanded_operator_cidr" {
  command = plan

  variables {
    aks_oidc_issuer_url              = "https://oidc.example.invalid/tenant/issuer"
    postgres_administrator_object_id = "00000000-0000-0000-0000-000000000001"
    ingress_host                     = "grdr.example.invalid"
    operator_host                    = "ops.grdr.example.invalid"
    operator_allow_cidrs             = ["::0:1/128"]
    server_image_digest              = "sha256:1111111111111111111111111111111111111111111111111111111111111111"
  }

  expect_failures = [var.operator_allow_cidrs]
}
