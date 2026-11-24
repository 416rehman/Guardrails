// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::net::IpAddr;

use serde::{Deserialize, Serialize};

use crate::IntegrationError;

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
pub struct SecretRef {
    pub key: String,
    pub store: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConfigFieldSpec {
    pub key: String,
    pub field_type: ConfigFieldType,
    pub required: bool,
    pub host_constraints: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VendorApiCompat {
    pub name: String,
    pub tested: String,
    pub verified: bool,
    pub sunset: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
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
    if manifest.integration.trim().is_empty() || manifest.publisher.trim().is_empty() {
        return Err(IntegrationError::InvalidManifest(
            "integration and publisher must be non-empty".into(),
        ));
    }
    if !manifest.prohibited_commands.is_empty() || !manifest.prohibited_env_sets.is_empty() {
        return Err(IntegrationError::InvalidManifest(
            "declarative manifest must not execute commands or set environment variables".into(),
        ));
    }
    if !manifest.request_path.starts_with('/') || manifest.request_path.contains("://") {
        return Err(IntegrationError::InvalidManifest(
            "request_path must be relative without scheme or host".into(),
        ));
    }
    for field in &manifest.config {
        for constraint in &field.host_constraints {
            if constraint.contains("://")
                || constraint.contains('/')
                || constraint.contains(':')
                || constraint.trim().is_empty()
            {
                return Err(IntegrationError::InvalidManifest(format!(
                    "host_constraint `{constraint}` must be a DNS suffix only"
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
    if manifest.kind == ConnectorKind::Action {
        for scope in &manifest.required_scopes {
            let lower = scope.to_ascii_lowercase();
            if deny_scopes
                .iter()
                .any(|d| lower.contains(&d.to_ascii_lowercase()))
            {
                return Err(IntegrationError::ForbiddenScope(scope.clone()));
            }
        }
    }
    Ok(())
}

pub fn validate_egress_url(
    base_url: &str,
    host_constraints: &[String],
    allow_private_ranges: bool,
) -> Result<(), IntegrationError> {
    let rest = if let Some(https) = base_url.strip_prefix("https://") {
        https
    } else if allow_private_ranges {
        base_url
            .strip_prefix("http://")
            .ok_or_else(|| IntegrationError::EgressDenied("URL must use https://".into()))?
    } else {
        return Err(IntegrationError::EgressDenied(
            "egress URL must use https://".into(),
        ));
    };

    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(IntegrationError::EgressDenied(
            "egress URL has invalid authority".into(),
        ));
    }
    let host = strip_port(authority);
    if host.is_empty() {
        return Err(IntegrationError::EgressDenied(
            "egress URL missing host".into(),
        ));
    }

    if !allow_private_ranges && is_disallowed_host(host) {
        return Err(IntegrationError::EgressDenied(format!(
            "private, loopback, or metadata address `{host}` is forbidden"
        )));
    }

    if !host_constraints.is_empty()
        && !host_constraints
            .iter()
            .any(|suffix| matches_dns_suffix(host, suffix))
    {
        return Err(IntegrationError::EgressDenied(format!(
            "host `{host}` does not satisfy manifest host_constraints"
        )));
    }
    Ok(())
}

fn manifest_key(publisher: &str, integration: &str, version: &str) -> String {
    format!("{publisher}/{integration}@{version}")
}

fn strip_port(authority: &str) -> &str {
    if authority.starts_with('[') {
        authority
            .split(']')
            .next()
            .map(|v| v.trim_start_matches('['))
            .unwrap_or("")
    } else {
        authority.split(':').next().unwrap_or("")
    }
}

fn is_disallowed_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if lower == "localhost" || lower.ends_with(".local") || lower.ends_with(".internal") {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return match ip {
            IpAddr::V4(v4) => {
                v4.is_loopback() || v4.is_private() || v4.is_link_local() || v4.is_unspecified()
            }
            IpAddr::V6(v6) => v6.is_loopback() || v6.is_unspecified() || v6.is_unique_local(),
        };
    }
    false
}

fn matches_dns_suffix(host: &str, suffix: &str) -> bool {
    let h = host.to_ascii_lowercase();
    let s = suffix.to_ascii_lowercase();
    let trimmed = s.trim_start_matches('.');
    h == trimmed || h.ends_with(&format!(".{trimmed}"))
}
