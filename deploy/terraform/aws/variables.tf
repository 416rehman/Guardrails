variable "name_prefix" {
  type        = string
  description = "Prefix applied to AWS resources for this Guardrails ADR deployment."
  default     = "grdr"

  validation {
    condition     = can(regex("^[a-z][a-z0-9-]{1,28}$", var.name_prefix))
    error_message = "name_prefix must match ^[a-z][a-z0-9-]{1,28}$."
  }
}

variable "region" {
  type        = string
  description = "AWS region for the Guardrails ADR cell."
  default     = "us-east-1"
}

variable "vpc_id" {
  type        = string
  description = "Optional BYO VPC id. When null, creates an isolated VPC with private subnets."
  default     = null
}

variable "private_subnet_ids" {
  type        = list(string)
  description = "Private subnet ids when vpc_id is supplied."
  default     = []
}

variable "vpc_cidr" {
  type        = string
  description = "CIDR block when creating a dedicated VPC."
  default     = "10.42.0.0/16"
}

variable "eks_node_security_group_ids" {
  type        = list(string)
  description = "EKS node or pod security group ids permitted to reach PostgreSQL 5432."
  default     = []
}

variable "db_allowed_cidr_blocks" {
  type        = list(string)
  description = "Optional explicit narrow CIDRs permitted to reach PostgreSQL 5432 when eks_node_security_group_ids is empty."
  default     = []

  validation {
    condition     = !contains(var.db_allowed_cidr_blocks, "0.0.0.0/0")
    error_message = "db_allowed_cidr_blocks must never allow 0.0.0.0/0."
  }
}

variable "kubernetes_namespace" {
  type        = string
  description = "Namespace for the grdr-server Helm release."
  default     = "grdr-system"
}

variable "service_account_name" {
  type        = string
  description = "Kubernetes ServiceAccount bound to EKS Pod Identity."
  default     = "grdr-server"
}

variable "eks_cluster_name" {
  type        = string
  description = "Target EKS cluster name for Pod Identity and Helm release."
  default     = "grdr-cluster"
}

variable "postgresql_version" {
  type        = string
  description = "PostgreSQL major version (supported line starts at 18)."
  default     = "18"

  validation {
    condition     = tonumber(split(".", var.postgresql_version)[0]) >= 18
    error_message = "postgresql_version must be 18 or newer per support.toml."
  }
}

variable "db_instance_class" {
  type        = string
  description = "RDS instance class."
  default     = "db.m7g.large"
}

variable "enable_deletion_protection" {
  type        = bool
  description = "Protect RDS and KMS keys against accidental deletion."
  default     = true
}

variable "backup_retention_days" {
  type        = number
  description = "PITR and noncurrent object retention days (limits.toml pitr_window_days)."
  default     = 35

  validation {
    condition     = var.backup_retention_days >= 35
    error_message = "backup_retention_days must be at least 35 days."
  }
}

variable "kms_key_arn" {
  type        = string
  description = "Optional existing KMS key ARN. Creates a dedicated rotating CMK when null."
  default     = null
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

  validation {
    condition     = length(var.operator_host) > 0
    error_message = "operator_host must be configured separately from ingress_host (D-70)."
  }
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
  description = "Existing Kubernetes Secret name carrying the RDS connection URI."
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
