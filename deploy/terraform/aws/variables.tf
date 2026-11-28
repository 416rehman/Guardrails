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
    condition = alltrue([
      for c in var.db_allowed_cidr_blocks : (
        can(cidrsubnet(c, 0, 0)) &&
        !can(regex("^(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[01]$|0\\.|127\\.|(?:[0-9]|[1-9][0-9]|1[0-8][0-9]|19[01])\\.[^/]+/[0-7]$|169\\.(?:254\\.|[^/]+/[0-8]$|(?:1[2-9][0-9]|2[0-4][0-9]|25[0-5])\\.[^/]+/(?:9|1[0-5])$)|[0-9A-Fa-f:]+/[0-7]$|(?:0+:)+:(?:0+:)*0*/|::(?:0+:)*0*/|(?:0+:){1,7}0+/|(?:::(?:0+:)*|(?:0+:){1,7}:?(?:0+:)*)0*1/|(?:(?:0+:)+:(?:0+:)*|::(?:0+:)*|(?:0+:){5})(?:[^/]*/(?:[0-7]?[0-9]|80)$|[89a-fA-F][0-9a-fA-F]{3}:[^/]+/81$|[c-fC-F][0-9a-fA-F]{3}:[^/]+/82$|[eEfF][0-9a-fA-F]{3}:[^/]+/83$|[fF][0-9a-fA-F]{3}:[^/]+/84$|[fF][89a-fA-F][0-9a-fA-F]{2}:[^/]+/85$|[fF][c-fC-F][0-9a-fA-F]{2}:[^/]+/86$|[fF][eEfF][0-9a-fA-F]{2}:[^/]+/87$|[fF]{2}[0-9a-fA-F]{2}:[^/]+/88$|[fF]{2}[89a-fA-F][0-9a-fA-F]:[^/]+/89$|[fF]{2}[c-fC-F][0-9a-fA-F]:[^/]+/90$|[fF]{2}[eEfF][0-9a-fA-F]:[^/]+/91$|[fF]{3}[0-9a-fA-F]:[^/]+/92$|[fF]{3}[89a-fA-F]:[^/]+/93$|[fF]{3}[c-fC-F]:[^/]+/94$|[fF]{3}[eEfF]:[^/]+/95$|[fF]{4}:)|[fF][dD][0-9a-fA-F]{2}:[^/]+/8$|[fF][dD][0-7][0-9a-fA-F]:[^/]+/(?:9|1[0-5])$|[fF][dD]00:[^/]+/16$|[fF][dD]00:(?:[0-7][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/17$|[fF][dD]00:(?:[0-3][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/18$|[fF][dD]00:(?:[01][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/19$|[fF][dD]00:(?:0[0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/20$|[fF][dD]00:0*[89a-fA-F][0-9a-fA-F]{2}:[^/]+/21$|[fF][dD]00:0*[c-fC-F][0-9a-fA-F]{2}:[^/]+/22$|[fF][dD]00:0*[eEfF][0-9a-fA-F]{2}:[^/]+/23$|[fF][dD]00:0*[eE][0-9a-fA-F]{2}:[^/]+/24$|[fF][dD]00:0*[eE][89a-fA-F][0-9a-fA-F]:[^/]+/25$|[fF][dD]00:0*[eE][c-fC-F][0-9a-fA-F]:[^/]+/26$|[fF][dD]00:0*[eE][cCdD][0-9a-fA-F]:[^/]+/27$|[fF][dD]00:0*[eE][cC][0-9a-fA-F]:[^/]+/28$|[fF][dD]00:0*[eE][cC][0-7]:[^/]+/29$|[fF][dD]00:0*[eE][cC][0-3]:[^/]+/30$|[fF][dD]00:0*[eE][cC][23]:[^/]+/31$|[fF][dD]00:0*[eE][cC]2[:/]|[fF][eE][0-9a-fA-F]{2}:[^/]+/8$|[fF][eE][89aAbB][0-9a-fA-F]:)", c))
      )
    ])
    error_message = "db_allowed_cidr_blocks must contain valid narrow CIDRs and never allow 0.0.0.0/0, loopback, or IMDS/link-local ranges."
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
    error_message = "postgresql_version must be 18 or newer per contracts/support.toml."
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
  description = "PITR and noncurrent object retention days (contracts/limits.toml pitr_window_days)."
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
    condition = (
      length(var.operator_allow_cidrs) > 0 &&
      alltrue([
        for c in var.operator_allow_cidrs : (
          can(cidrsubnet(c, 0, 0)) &&
          !can(regex("^(?:(?:[0-9]{1,3}\\.){3}[0-9]{1,3}/[01]$|0\\.|127\\.|(?:[0-9]|[1-9][0-9]|1[0-8][0-9]|19[01])\\.[^/]+/[0-7]$|169\\.(?:254\\.|[^/]+/[0-8]$|(?:1[2-9][0-9]|2[0-4][0-9]|25[0-5])\\.[^/]+/(?:9|1[0-5])$)|[0-9A-Fa-f:]+/[0-7]$|(?:0+:)+:(?:0+:)*0*/|::(?:0+:)*0*/|(?:0+:){1,7}0+/|(?:::(?:0+:)*|(?:0+:){1,7}:?(?:0+:)*)0*1/|(?:(?:0+:)+:(?:0+:)*|::(?:0+:)*|(?:0+:){5})(?:[^/]*/(?:[0-7]?[0-9]|80)$|[89a-fA-F][0-9a-fA-F]{3}:[^/]+/81$|[c-fC-F][0-9a-fA-F]{3}:[^/]+/82$|[eEfF][0-9a-fA-F]{3}:[^/]+/83$|[fF][0-9a-fA-F]{3}:[^/]+/84$|[fF][89a-fA-F][0-9a-fA-F]{2}:[^/]+/85$|[fF][c-fC-F][0-9a-fA-F]{2}:[^/]+/86$|[fF][eEfF][0-9a-fA-F]{2}:[^/]+/87$|[fF]{2}[0-9a-fA-F]{2}:[^/]+/88$|[fF]{2}[89a-fA-F][0-9a-fA-F]:[^/]+/89$|[fF]{2}[c-fC-F][0-9a-fA-F]:[^/]+/90$|[fF]{2}[eEfF][0-9a-fA-F]:[^/]+/91$|[fF]{3}[0-9a-fA-F]:[^/]+/92$|[fF]{3}[89a-fA-F]:[^/]+/93$|[fF]{3}[c-fC-F]:[^/]+/94$|[fF]{3}[eEfF]:[^/]+/95$|[fF]{4}:)|[fF][dD][0-9a-fA-F]{2}:[^/]+/8$|[fF][dD][0-7][0-9a-fA-F]:[^/]+/(?:9|1[0-5])$|[fF][dD]00:[^/]+/16$|[fF][dD]00:(?:[0-7][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/17$|[fF][dD]00:(?:[0-3][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/18$|[fF][dD]00:(?:[01][0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/19$|[fF][dD]00:(?:0[0-9a-fA-F]{3}|[0-9a-fA-F]{1,3}|):[^/]*/20$|[fF][dD]00:0*[89a-fA-F][0-9a-fA-F]{2}:[^/]+/21$|[fF][dD]00:0*[c-fC-F][0-9a-fA-F]{2}:[^/]+/22$|[fF][dD]00:0*[eEfF][0-9a-fA-F]{2}:[^/]+/23$|[fF][dD]00:0*[eE][0-9a-fA-F]{2}:[^/]+/24$|[fF][dD]00:0*[eE][89a-fA-F][0-9a-fA-F]:[^/]+/25$|[fF][dD]00:0*[eE][c-fC-F][0-9a-fA-F]:[^/]+/26$|[fF][dD]00:0*[eE][cCdD][0-9a-fA-F]:[^/]+/27$|[fF][dD]00:0*[eE][cC][0-9a-fA-F]:[^/]+/28$|[fF][dD]00:0*[eE][cC][0-7]:[^/]+/29$|[fF][dD]00:0*[eE][cC][0-3]:[^/]+/30$|[fF][dD]00:0*[eE][cC][23]:[^/]+/31$|[fF][dD]00:0*[eE][cC]2[:/]|[fF][eE][0-9a-fA-F]{2}:[^/]+/8$|[fF][eE][89aAbB][0-9a-fA-F]:)", c))
        )
      ])
    )
    error_message = "operator_allow_cidrs must be non-empty valid CIDRs and must never allow wildcard, loopback, or IMDS/link-local ranges."
  }
}

variable "api_ingress_namespaces" {
  type        = list(string)
  description = "Kubernetes namespaces permitted to reach the public API port via NetworkPolicy."
  default     = ["ingress-nginx"]
}

variable "bootstrap_existing_secret" {
  type        = string
  description = "Existing Kubernetes Secret name holding api-token and enroll-token."
  default     = "grdr-bootstrap"
}

variable "operator_existing_secret" {
  type        = string
  description = "Existing Kubernetes Secret name holding operator-token and optional step-up-token (D-70)."
  default     = "grdr-operator"

  validation {
    condition     = length(trimspace(var.operator_existing_secret)) > 0
    error_message = "operator_existing_secret must not be empty when operator plane is non-loopback."
  }
}

variable "operator_client_ca_existing_secret" {
  type        = string
  description = "Optional existing Kubernetes Secret name carrying client mTLS CA for the operator plane."
  default     = ""
}

variable "object_store_existing_secret" {
  type        = string
  description = "Optional existing Kubernetes Secret name carrying S3 static credentials when Pod Identity is not used."
  default     = ""
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
