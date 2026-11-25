variable "project_id" {
  type        = string
  description = "GCP project id hosting the Guardrails ADR deployment."
}

variable "region" {
  type        = string
  description = "GCP region."
  default     = "us-central1"
}

variable "name_prefix" {
  type        = string
  description = "Resource name prefix."
  default     = "grdr"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,28}$", var.name_prefix))
    error_message = "name_prefix must match ^[a-z][a-z0-9-]{1,28}$."
  }
}

variable "network_self_link" {
  type        = string
  description = "Optional BYO VPC network self_link."
  default     = null
}

variable "kubernetes_namespace" {
  type        = string
  description = "GKE namespace for grdr-server."
  default     = "grdr-system"
}

variable "service_account_name" {
  type        = string
  description = "Kubernetes ServiceAccount bound via Workload Identity Federation."
  default     = "grdr-server"
}

variable "postgresql_version" {
  type        = string
  description = "Cloud SQL PostgreSQL major version."
  default     = "POSTGRES_18"

  validation {
    condition     = can(regex("^POSTGRES_(1[89]|[2-9][0-9])$", var.postgresql_version))
    error_message = "postgresql_version must be POSTGRES_18 or newer per contracts/support.toml."
  }
}

variable "db_tier" {
  type        = string
  description = "Cloud SQL machine tier."
  default     = "db-custom-2-8192"
}

variable "enable_deletion_protection" {
  type        = bool
  description = "Enable Cloud SQL deletion protection."
  default     = true
}

variable "backup_retention_days" {
  type        = number
  description = "Retention window in days for backups and noncurrent GCS object versions."
  default     = 35

  validation {
    condition     = var.backup_retention_days >= 35
    error_message = "backup_retention_days must be at least 35 days."
  }
}

variable "ingress_host" {
  type        = string
  description = "Hostname for tenant API and console ingress."
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
