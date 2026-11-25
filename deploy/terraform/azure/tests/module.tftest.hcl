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
}
