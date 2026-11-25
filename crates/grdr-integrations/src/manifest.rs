// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::IntegrationError;
use crate::egress::{is_valid_dns_suffix, validate_egress_url};

const DEFAULT_DENY_SCOPES: &[&str] = &[
    "script_execution",
    "remote_shell",
    "rtr",
    "file_put",
    "run_command",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorKind {
    Sink,
    Source,
    Ticket,
    Notify,
    Action,
    Reconciler,
    Callout,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorDirection {
    Out,
    In,
    Both,
    Act,
    Deploy,
    Restrict,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SupportTier {
    Tier1,
    Tier2,
    Tier3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StabilityClass {
    Experimental,
    Beta,
    Stable,
    Deprecated,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CaptureCeiling {
    Metadata,
    RedactedArguments,
    Content,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectorHealth {
    Healthy,
    Degraded,
    Lagging,
    Failing,
    Paused,
    Misconfigured,
    AtRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuthScheme {
    None,
    HeaderToken,
    Basic,
    MutualTls,
    HmacStandardWebhooks,
    AwsSigV4,
    OAuth2ClientCredentials,
    WorkloadIdentity,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CodecKind {
    Json,
    Ndjson,
    HecEvent,
    SyslogRfc5424,
    OtlpJson,
    Parquet,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigFieldType {
    HttpsUrl,
    SecretRef,
    String,
    Integer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SecretRef {
    pub key: String,
    pub store: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigFieldSpec {
    pub key: String,
    pub field_type: ConfigFieldType,
    pub required: bool,
    pub host_constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VendorApiCompat {
    pub name: String,
    pub tested: String,
    pub verified: bool,
    pub sunset: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConnectorManifest {
    pub integration: String,
    pub publisher: String,
    pub version: String,
    pub kind: ConnectorKind,
    pub family: String,
    pub direction: ConnectorDirection,
    pub support_tier: SupportTier,
    pub stability: StabilityClass,
    pub vendor_api: VendorApiCompat,
    pub config: Vec<ConfigFieldSpec>,
    pub auth_scheme: AuthScheme,
    pub codec: CodecKind,
    pub request_path: String,
    pub data_classes_read: Vec<String>,
    pub capture_max: CaptureCeiling,
    pub required_scopes: Vec<String>,
    #[serde(default)]
    pub prohibited_commands: Vec<String>,
    #[serde(default)]
    pub prohibited_env_sets: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct IntegrationInstance {
    pub instance_id: String,
    pub org_id: String,
    pub manifest_key: String,
    pub base_url: String,
    pub secret_refs: BTreeMap<String, SecretRef>,
    pub allow_private_ranges: bool,
    pub health: ConnectorHealth,
}

#[derive(Debug, Default, Clone)]
pub struct IntegrationHost {
    manifests: BTreeMap<String, ConnectorManifest>,
    instances: BTreeMap<String, IntegrationInstance>,
    deny_scopes: Vec<String>,
}

impl IntegrationHost {
    #[must_use]
    pub fn new() -> Self {
        Self {
            manifests: BTreeMap::new(),
            instances: BTreeMap::new(),
            deny_scopes: DEFAULT_DENY_SCOPES
                .iter()
                .map(|s| (*s).to_owned())
                .collect(),
        }
    }

    #[must_use]
    pub fn with_deny_scopes(mut self, deny_scopes: Vec<String>) -> Self {
        self.deny_scopes = deny_scopes;
        self
    }

    pub fn register_manifest(
        &mut self,
        manifest: ConnectorManifest,
    ) -> Result<String, IntegrationError> {
        validate_manifest(&manifest, &self.deny_scopes)?;
        let key = manifest_key(
            &manifest.publisher,
            &manifest.integration,
            &manifest.version,
        );
        self.manifests.insert(key.clone(), manifest);
        Ok(key)
    }

    pub fn create_instance(
        &mut self,
        instance: IntegrationInstance,
    ) -> Result<(), IntegrationError> {
        if instance.instance_id.trim().is_empty() || instance.org_id.trim().is_empty() {
            return Err(IntegrationError::InvalidManifest(
                "instance_id and org_id must be non-empty".into(),
            ));
        }
        if self.instances.contains_key(&instance.instance_id) {
            return Err(IntegrationError::InvalidManifest(format!(
                "duplicate instance_id `{}`",
                instance.instance_id
            )));
        }

        let Some(manifest) = self.manifests.get(&instance.manifest_key) else {
            return Err(IntegrationError::UnknownConnector(
                instance.manifest_key.clone(),
            ));
        };

        let host_constraints: Vec<String> = manifest
            .config
            .iter()
            .filter(|c| c.field_type == ConfigFieldType::HttpsUrl)
            .flat_map(|c| c.host_constraints.iter().cloned())
            .collect();
        validate_egress_url(
            &instance.base_url,
            &host_constraints,
            instance.allow_private_ranges,
        )?;

        for secret in instance.secret_refs.values() {
            if secret.key.trim().is_empty() || secret.store.trim().is_empty() {
                return Err(IntegrationError::InvalidManifest(
                    "secret_ref key and store must be non-empty".into(),
                ));
            }
        }
        for spec in &manifest.config {
            if spec.required
                && spec.field_type == ConfigFieldType::SecretRef
                && !instance.secret_refs.contains_key(&spec.key)
            {
                return Err(IntegrationError::InvalidManifest(format!(
                    "missing required secret_ref `{}`",
                    spec.key
                )));
            }
        }

        self.instances
            .insert(instance.instance_id.clone(), instance);
        Ok(())
    }

    #[must_use]
    pub fn manifest(&self, key: &str) -> Option<&ConnectorManifest> {
        self.manifests.get(key)
    }

    #[must_use]
    pub fn instance(&self, instance_id: &str) -> Option<&IntegrationInstance> {
        self.instances.get(instance_id)
    }
}

pub fn validate_manifest(
    manifest: &ConnectorManifest,
    deny_scopes: &[String],
) -> Result<(), IntegrationError> {
    if manifest.integration.trim().is_empty()
        || manifest.publisher.trim().is_empty()
        || manifest.version.trim().is_empty()
    {
        return Err(IntegrationError::InvalidManifest(
            "integration, publisher, and version must be non-empty".into(),
        ));
    }
    if !manifest.prohibited_commands.is_empty() || !manifest.prohibited_env_sets.is_empty() {
        return Err(IntegrationError::InvalidManifest(
            "declarative manifest must not execute commands or set environment variables".into(),
        ));
    }
    validate_request_path(&manifest.request_path)?;
    for field in &manifest.config {
        for constraint in &field.host_constraints {
            if !is_valid_dns_suffix(constraint) {
                return Err(IntegrationError::InvalidManifest(format!(
                    "host_constraint `{constraint}` must be a valid DNS suffix only"
                )));
            }
        }
    }
    if manifest.capture_max > CaptureCeiling::Metadata
        && !manifest.data_classes_read.iter().any(|c| c == "content")
    {
        return Err(IntegrationError::InvalidManifest(
            "capture_max above metadata requires `content` in data_classes_read".into(),
        ));
    }
    if manifest.support_tier < SupportTier::Tier3 && !manifest.vendor_api.verified {
        return Err(IntegrationError::InvalidManifest(
            "Tier 1 and Tier 2 manifests require vendor_api.verified = true".into(),
        ));
    }
    if manifest.kind == ConnectorKind::Action || manifest.direction == ConnectorDirection::Act {
        let normalized_denies: Vec<String> = deny_scopes
            .iter()
            .map(|d| normalize_scope_token(d))
            .filter(|d| !d.is_empty())
            .collect();
        for scope in &manifest.required_scopes {
            let norm = normalize_scope_token(scope);
            if normalized_denies.iter().any(|d| norm.contains(d.as_str())) {
                return Err(IntegrationError::ForbiddenScope(scope.clone()));
            }
        }
    }
    Ok(())
}

fn validate_request_path(path: &str) -> Result<(), IntegrationError> {
    if !path.starts_with('/') || path.starts_with("//") || path.contains("://") {
        return Err(IntegrationError::InvalidManifest(
            "request_path must be relative without scheme, host, or protocol-relative prefix"
                .into(),
        ));
    }
    if path
        .chars()
        .any(|c| c.is_ascii_control() || c.is_ascii_whitespace() || matches!(c, '\\' | '?' | '#'))
    {
        return Err(IntegrationError::InvalidManifest(
            "request_path contains forbidden control, whitespace, query, fragment, or backslash characters".into(),
        ));
    }
    let lower = path.to_ascii_lowercase();
    if path.split('/').any(|seg| seg == "." || seg == "..")
        || lower.contains("%2e")
        || lower.contains("%2f")
        || lower.contains("%5c")
        || lower.contains("%00")
    {
        return Err(IntegrationError::InvalidManifest(
            "request_path must not contain dot segments or percent-encoded path delimiters".into(),
        ));
    }
    Ok(())
}

fn normalize_scope_token(scope: &str) -> String {
    scope
        .chars()
        .map(|c| {
            if matches!(c, '-' | '.' | ' ' | '\t') {
                '_'
            } else {
                c.to_ascii_lowercase()
            }
        })
        .collect()
}

fn manifest_key(publisher: &str, integration: &str, version: &str) -> String {
    format!("{publisher}/{integration}@{version}")
}
