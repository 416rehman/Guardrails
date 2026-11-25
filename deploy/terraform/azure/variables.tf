variable "name_prefix" {
  type        = string
  description = "Prefix applied to Azure resources for this Guardrails ADR deployment."
  default     = "grdr"

  validation {
    condition     = can(regex("^[a-z][a-z0-9]{1,12}$", var.name_prefix))
    error_message = "name_prefix must match ^[a-z][a-z0-9]{1,12}$ for Azure storage account compatibility."
  }
}

variable "location" {
  type        = string
  description = "Azure region."
  default     = "eastus2"
}

variable "resource_group_name" {
  type        = string
  description = "Optional BYO resource group name. Creates a dedicated group when null."
  default     = null
}

variable "aks_oidc_issuer_url" {
  type        = string
  description = "AKS cluster OIDC issuer URL for Microsoft Entra Workload Identity."
}

variable "kubernetes_namespace" {
  type        = string
  description = "Kubernetes namespace for grdr-server."
  default     = "grdr-system"
}

variable "service_account_name" {
  type        = string
  description = "Kubernetes ServiceAccount federated with Entra Workload Identity."
  default     = "grdr-server"
}

variable "postgresql_version" {
  type        = string
  description = "Azure Database for PostgreSQL Flexible Server major version."
  default     = "18"

  validation {
    condition     = tonumber(var.postgresql_version) >= 18
    error_message = "postgresql_version must be 18 or newer per contracts/support.toml."
  }
}

variable "postgres_sku_name" {
  type        = string
  description = "PostgreSQL Flexible Server SKU."
  default     = "GP_Standard_D2ds_v5"
}

variable "backup_retention_days" {
  type        = number
  description = "Backup retention and blob version retention days."
  default     = 35

  validation {
    condition     = var.backup_retention_days >= 35
    error_message = "backup_retention_days must be at least 35 days."
  }
}

variable "vnet_cidr" {
  type        = string
  description = "Virtual network address space."
  default     = "10.46.0.0/16"
}

variable "ingress_host" {
  type        = string
  description = "Hostname for tenant API and Web Console ingress."
}

variable "ingress_tls_secret_name" {
  type        = string
  description = "TLS secret name for tenant API ingress."
  default     = "grdr-api-tls"

  validation {
    condition     = length(var.ingress_tls_secret_name) > 0
    error_message = "ingress_tls_secret_name must not be empty."
  }
}

variable "operator_host" {
  type        = string
  description = "Distinct hostname for D-70 operator plane ingress."
}

variable "operator_tls_secret_name" {
  type        = string
  description = "TLS secret name for D-70 operator plane ingress."
  default     = "grdr-operator-tls"

  validation {
    condition     = length(var.operator_tls_secret_name) > 0
    error_message = "operator_tls_secret_name must not be empty."
  }
}

variable "operator_allow_cidrs" {
  type        = list(string)
  description = "Source CIDRs permitted to reach the operator plane."
  default     = ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]

  validation {
    condition     = !contains(var.operator_allow_cidrs, "0.0.0.0/0")
    error_message = "operator_allow_cidrs must never allow 0.0.0.0/0."
  }
}

variable "postgres_administrator_object_id" {
  type        = string
  description = "Entra principal object id assigned PostgreSQL Active Directory admin role (passwordless auth)."
}

variable "bootstrap_existing_secret" {
  type        = string
  description = "Existing Kubernetes Secret name holding api-token and enroll-token."
  default     = "grdr-bootstrap"
}

variable "database_existing_secret" {
  type        = string
  description = "Existing Kubernetes Secret name carrying the PostgreSQL connection URI."
  default     = "grdr-db-credentials"
}

variable "helm_chart_path" {
  type        = string
  description = "Path or OCI ref for grdr-server chart."
  default     = "../../helm/grdr-server"
}

variable "server_image_digest" {
  type        = string
  description = "Immutable sha256 digest of the grdr-server container image from release-manifest.json."

  validation {
    condition     = can(regex("^sha256:[0-9a-f]{64}$", var.server_image_digest)) && !startswith(var.server_image_digest, "sha256:0000000000000000")
    error_message = "server_image_digest must be a non-zero immutable sha256:<64-hex> digest."
  }
}
