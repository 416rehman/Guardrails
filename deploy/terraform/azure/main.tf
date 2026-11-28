check "distinct_operator_host" {
  assert {
    condition     = local.normalized_operator_host != local.normalized_ingress_host
    error_message = "D-70 requires operator_host to differ from ingress_host."
  }
}

data "azurerm_client_config" "current" {}

resource "azurerm_resource_group" "this" {
  count    = var.resource_group_name == null ? 1 : 0
  name     = "${var.name_prefix}-rg"
  location = var.location
}

locals {
  rg_name                  = var.resource_group_name == null ? azurerm_resource_group.this[0].name : var.resource_group_name
  normalized_ingress_host  = trimsuffix(lower(trimspace(var.ingress_host)), ".")
  normalized_operator_host = trimsuffix(lower(trimspace(var.operator_host)), ".")
}

resource "azurerm_virtual_network" "this" {
  name                = "${var.name_prefix}-vnet"
  location            = var.location
  resource_group_name = local.rg_name
  address_space       = [var.vnet_cidr]
}

resource "azurerm_subnet" "postgres" {
  name                 = "postgres"
  resource_group_name  = local.rg_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 10)]

  delegation {
    name = "postgres-flexible"
    service_delegation {
      name = "Microsoft.DBforPostgreSQL/flexibleServers"
      actions = [
        "Microsoft.Network/virtualNetworks/subnets/join/action",
      ]
    }
  }
}

resource "azurerm_subnet" "private_endpoints" {
  name                 = "private-endpoints"
  resource_group_name  = local.rg_name
  virtual_network_name = azurerm_virtual_network.this.name
  address_prefixes     = [cidrsubnet(var.vnet_cidr, 8, 11)]
}

resource "azurerm_private_dns_zone" "postgres" {
  name                = "${var.name_prefix}.postgres.database.azure.com"
  resource_group_name = local.rg_name
}

resource "azurerm_private_dns_zone_virtual_network_link" "postgres" {
  name                  = "${var.name_prefix}-pg-dns"
  private_dns_zone_name = azurerm_private_dns_zone.postgres.name
  virtual_network_id    = azurerm_virtual_network.this.id
  resource_group_name   = local.rg_name
}

resource "azurerm_private_dns_zone" "keyvault" {
  name                = "privatelink.vaultcore.azure.net"
  resource_group_name = local.rg_name
}

resource "azurerm_private_dns_zone_virtual_network_link" "keyvault" {
  name                  = "${var.name_prefix}-kv-dns"
  private_dns_zone_name = azurerm_private_dns_zone.keyvault.name
  virtual_network_id    = azurerm_virtual_network.this.id
  resource_group_name   = local.rg_name
}

resource "azurerm_private_dns_zone" "blob" {
  name                = "privatelink.blob.core.windows.net"
  resource_group_name = local.rg_name
}

resource "azurerm_private_dns_zone_virtual_network_link" "blob" {
  name                  = "${var.name_prefix}-blob-dns"
  private_dns_zone_name = azurerm_private_dns_zone.blob.name
  virtual_network_id    = azurerm_virtual_network.this.id
  resource_group_name   = local.rg_name
}

resource "azurerm_user_assigned_identity" "server" {
  name                = "${var.name_prefix}-server-id"
  location            = var.location
  resource_group_name = local.rg_name
}

resource "azurerm_user_assigned_identity" "cmk" {
  name                = "${var.name_prefix}-cmk-id"
  location            = var.location
  resource_group_name = local.rg_name
}

resource "azurerm_federated_identity_credential" "server" {
  name                = "${var.name_prefix}-aks-wif"
  resource_group_name = local.rg_name
  parent_id           = azurerm_user_assigned_identity.server.id
  audience            = ["api://AzureADTokenExchange"]
  issuer              = var.aks_oidc_issuer_url
  subject             = "system:serviceaccount:${var.kubernetes_namespace}:${var.service_account_name}"
}

resource "azurerm_key_vault" "this" {
  name                          = "${var.name_prefix}kv${substr(sha256(local.rg_name), 0, 8)}"
  location                      = var.location
  resource_group_name           = local.rg_name
  tenant_id                     = data.azurerm_client_config.current.tenant_id
  sku_name                      = "standard"
  rbac_authorization_enabled    = true
  purge_protection_enabled      = true
  soft_delete_retention_days    = 30
  public_network_access_enabled = false
}

resource "azurerm_role_assignment" "cmk_crypto" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto Service Encryption User"
  principal_id         = azurerm_user_assigned_identity.cmk.principal_id
}

resource "azurerm_key_vault_key" "cmk" {
  name         = "${var.name_prefix}-cmk"
  key_vault_id = azurerm_key_vault.this.id
  key_type     = "RSA"
  key_size     = 4096
  key_opts     = ["decrypt", "encrypt", "sign", "unwrapKey", "verify", "wrapKey"]

  rotation_policy {
    automatic {
      time_before_expiry = "P30D"
    }
    expire_after         = "P365D"
    notify_before_expiry = "P45D"
  }
}

resource "azurerm_private_endpoint" "keyvault" {
  name                = "${var.name_prefix}-kv-pe"
  location            = var.location
  resource_group_name = local.rg_name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${var.name_prefix}-kv-psc"
    private_connection_resource_id = azurerm_key_vault.this.id
    subresource_names              = ["vault"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "kv-dns"
    private_dns_zone_ids = [azurerm_private_dns_zone.keyvault.id]
  }
}

resource "azurerm_postgresql_flexible_server" "this" {
  name                          = "${var.name_prefix}-postgres"
  resource_group_name           = local.rg_name
  location                      = var.location
  version                       = var.postgresql_version
  sku_name                      = var.postgres_sku_name
  delegated_subnet_id           = azurerm_subnet.postgres.id
  private_dns_zone_id           = azurerm_private_dns_zone.postgres.id
  public_network_access_enabled = false
  backup_retention_days         = var.backup_retention_days
  geo_redundant_backup_enabled  = true

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.cmk.id]
  }

  customer_managed_key {
    key_vault_key_id          = azurerm_key_vault_key.cmk.id
    primary_user_assigned_identity_id = azurerm_user_assigned_identity.cmk.id
  }

  authentication {
    active_directory_auth_enabled = true
    password_auth_enabled         = false
    tenant_id                     = data.azurerm_client_config.current.tenant_id
  }

  high_availability {
    mode = "ZoneRedundant"
  }

  depends_on = [
    azurerm_private_dns_zone_virtual_network_link.postgres,
    azurerm_role_assignment.cmk_crypto,
  ]
}

resource "azurerm_postgresql_flexible_server_active_directory_administrator" "this" {
  server_name         = azurerm_postgresql_flexible_server.this.name
  resource_group_name = local.rg_name
  tenant_id           = data.azurerm_client_config.current.tenant_id
  object_id           = var.postgres_administrator_object_id
  principal_name      = "${var.name_prefix}-pg-admin"
  principal_type      = "ServicePrincipal"
}

resource "azurerm_postgresql_flexible_server_configuration" "require_tls" {
  name      = "require_secure_transport"
  server_id = azurerm_postgresql_flexible_server.this.id
  value     = "ON"
}

resource "azurerm_postgresql_flexible_server_database" "grdr" {
  name      = "grdr"
  server_id = azurerm_postgresql_flexible_server.this.id
  charset   = "UTF8"
  collation = "en_US.utf8"
}

resource "azurerm_storage_account" "this" {
  name                            = "${var.name_prefix}st${substr(sha256(local.rg_name), 0, 10)}"
  resource_group_name             = local.rg_name
  location                        = var.location
  account_tier                    = "Standard"
  account_replication_type        = "ZRS"
  min_tls_version                 = "TLS1_2"
  allow_nested_items_to_be_public = false
  public_network_access_enabled   = false
  shared_access_key_enabled       = false

  identity {
    type         = "UserAssigned"
    identity_ids = [azurerm_user_assigned_identity.cmk.id]
  }

  network_rules {
    default_action = "Deny"
    bypass         = ["AzureServices"]
  }

  blob_properties {
    versioning_enabled = true
    delete_retention_policy {
      days = var.backup_retention_days
    }
    container_delete_retention_policy {
      days = var.backup_retention_days
    }
  }
}

resource "azurerm_storage_account_customer_managed_key" "this" {
  storage_account_id        = azurerm_storage_account.this.id
  key_vault_id              = azurerm_key_vault.this.id
  key_name                  = azurerm_key_vault_key.cmk.name
  user_assigned_identity_id = azurerm_user_assigned_identity.cmk.id

  depends_on = [azurerm_role_assignment.cmk_crypto]
}

resource "azurerm_private_endpoint" "blob" {
  name                = "${var.name_prefix}-blob-pe"
  location            = var.location
  resource_group_name = local.rg_name
  subnet_id           = azurerm_subnet.private_endpoints.id

  private_service_connection {
    name                           = "${var.name_prefix}-blob-psc"
    private_connection_resource_id = azurerm_storage_account.this.id
    subresource_names              = ["blob"]
    is_manual_connection           = false
  }

  private_dns_zone_group {
    name                 = "blob-dns"
    private_dns_zone_ids = [azurerm_private_dns_zone.blob.id]
  }
}

resource "azurerm_storage_container" "data" {
  name                  = "grdr-lake-data"
  storage_account_id    = azurerm_storage_account.this.id
  container_access_type = "private"
}

resource "azurerm_storage_container" "backup" {
  name                  = "grdr-backups"
  storage_account_id    = azurerm_storage_account.this.id
  container_access_type = "private"
}

resource "azurerm_storage_container_immutability_policy" "backup" {
  storage_container_resource_manager_id = azurerm_storage_container.backup.id
  immutability_period_in_days           = var.backup_retention_days
  locked                                = true
}

resource "azurerm_role_assignment" "data_blob_contributor" {
  scope                = azurerm_storage_container.data.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.server.principal_id
}

resource "azurerm_role_assignment" "backup_blob_contributor" {
  scope                = azurerm_storage_container.backup.id
  role_definition_name = "Storage Blob Data Contributor"
  principal_id         = azurerm_user_assigned_identity.server.principal_id
}

resource "azurerm_role_assignment" "kv_crypto" {
  scope                = azurerm_key_vault.this.id
  role_definition_name = "Key Vault Crypto User"
  principal_id         = azurerm_user_assigned_identity.server.principal_id
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
          "azure.workload.identity/client-id" = azurerm_user_assigned_identity.server.client_id
        }
      }
      storage = {
        database = {
          existingSecret = var.database_existing_secret
          sslMode        = "verify-full"
        }
        objectStore = {
          provider       = "azure"
          dir            = "/var/lib/grdr-objects"
          endpoint       = azurerm_storage_account.this.primary_blob_endpoint
          bucket         = azurerm_storage_container.data.name
          backupBucket   = azurerm_storage_container.backup.name
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
    azurerm_postgresql_flexible_server.this,
    azurerm_federated_identity_credential.server,
  ]
}
