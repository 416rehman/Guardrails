output "resource_group_name" {
  value       = local.rg_name
  description = "Resource group holding Guardrails ADR resources."
}

output "postgres_fqdn" {
  value       = azurerm_postgresql_flexible_server.this.fqdn
  description = "Private FQDN for PostgreSQL 18 Flexible Server."
}

output "storage_account_name" {
  value       = azurerm_storage_account.this.name
  description = "Versioned private Azure Blob Storage account."
}

output "key_vault_uri" {
  value       = azurerm_key_vault.this.vault_uri
  description = "Azure Key Vault URI."
}

output "workload_identity_client_id" {
  value       = azurerm_user_assigned_identity.server.client_id
  description = "User-assigned managed identity client id for AKS Workload Identity."
}

output "operator_host" {
  value       = var.operator_host
  description = "Isolated D-70 operator hostname."
}

output "helm_release_name" {
  value       = helm_release.grdr_server.name
  description = "Deployed grdr-server Helm release name."
}
