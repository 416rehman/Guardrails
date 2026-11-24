// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

pub const CREDENTIAL_EXPIRY_WARNING_DAYS: u32 = 14;
pub const OTLP_DEFAULT_GRPC_PORT: u16 = 4317;
pub const OTLP_DEFAULT_HTTP_PORT: u16 = 4318;
pub const OTLP_DEFAULT_BIND_ADDRESS: &str = "127.0.0.1";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeploymentKeyStatus {
    Active,
    Exhausted,
    Expired,
    Revoked,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeploymentKey {
    pub id: String,
    pub label: String,
    pub token_preview: String,
    pub install_profile: String,
    pub wave: String,
    pub max_uses: u32,
    pub used_count: u32,
    pub status: DeploymentKeyStatus,
    pub created_at: String,
    pub expires_at: String,
    pub created_by: String,
}

impl DeploymentKey {
    pub fn effective_status(&self, now_rfc3339: &str) -> DeploymentKeyStatus {
        if self.status == DeploymentKeyStatus::Revoked {
            return DeploymentKeyStatus::Revoked;
        }
        if !self.expires_at.is_empty() && now_rfc3339 >= self.expires_at.as_str() {
            return DeploymentKeyStatus::Expired;
        }
        if self.used_count >= self.max_uses {
            return DeploymentKeyStatus::Exhausted;
        }
        DeploymentKeyStatus::Active
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDeploymentKeyRequest {
    pub label: String,
    pub wave: String,
    pub install_profile: String,
    pub max_uses: u32,
    pub ttl_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateDeploymentKeyResponse {
    pub key: DeploymentKey,
    pub plaintext_token: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MdmFormat {
    IntuneWin32,
    JamfMobileconfig,
    Hexnode,
    Tanium,
    ChromeEnterprise,
    FirefoxGpo,
    LinuxRepo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InstallerSpec {
    pub platform: String,
    pub label: String,
    pub version: String,
    pub command: String,
    pub sha256: String,
    pub doctor_command: String,
    pub notes: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdmRenderRequest {
    pub format: MdmFormat,
    pub deployment_key_id: Option<String>,
    pub include_browser_extension: bool,
    pub update_authority: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MdmRenderResponse {
    pub format: MdmFormat,
    pub filename: String,
    pub content_type: String,
    pub payload: String,
    pub deployment_notes: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationCategory {
    DirectorySync,
    SaasConnector,
    ExportSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IntegrationHealthState {
    Connected,
    AtRisk,
    Degraded,
    NotConfigured,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReadinessCheck {
    pub name: String,
    pub passed: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IntegrationEntry {
    pub id: String,
    pub name: String,
    pub provider: String,
    pub category: IntegrationCategory,
    pub state: IntegrationHealthState,
    pub synced_users: u32,
    pub last_sync_at: Option<String>,
    pub credential_expires_in_days: Option<u32>,
    pub detail: String,
    pub readiness_checks: Vec<ReadinessCheck>,
}

impl IntegrationEntry {
    pub fn evaluate_health(&self) -> IntegrationHealthState {
        if self.state == IntegrationHealthState::NotConfigured {
            return IntegrationHealthState::NotConfigured;
        }
        let has_failure = self.readiness_checks.iter().any(|c| !c.passed);
        if has_failure {
            return IntegrationHealthState::Degraded;
        }
        if let Some(days) = self.credential_expires_in_days
            && days <= CREDENTIAL_EXPIRY_WARNING_DAYS
        {
            return IntegrationHealthState::AtRisk;
        }
        IntegrationHealthState::Connected
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OtlpFanoutConfig {
    pub enabled: bool,
    pub grpc_port: u16,
    pub http_port: u16,
    pub bind_address: String,
    pub downstream_targets: Vec<String>,
    pub loopback_only: bool,
    pub accepted_spans_24h: u64,
}

impl Default for OtlpFanoutConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            grpc_port: OTLP_DEFAULT_GRPC_PORT,
            http_port: OTLP_DEFAULT_HTTP_PORT,
            bind_address: OTLP_DEFAULT_BIND_ADDRESS.into(),
            downstream_targets: Vec::new(),
            loopback_only: true,
            accepted_spans_24h: 0,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectConfigResponse {
    pub server_origin: String,
    pub installers: Vec<InstallerSpec>,
    pub deployment_keys: Vec<DeploymentKey>,
    pub otlp: OtlpFanoutConfig,
    pub integrations: Vec<IntegrationEntry>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_key(used_count: u32, status: DeploymentKeyStatus, expires_at: &str) -> DeploymentKey {
        DeploymentKey {
            id: "key-wave-1".into(),
            label: "Pilot Wave 1".into(),
            token_preview: "grdr_wk_pilot_9f1a".into(),
            install_profile: "standard".into(),
            wave: "wave-1".into(),
            max_uses: 50,
            used_count,
            status,
            created_at: "2026-11-01T00:00:00Z".into(),
            expires_at: expires_at.into(),
            created_by: "secops@acme.dev".into(),
        }
    }

    #[test]
    fn effective_status_transitions() {
        let now = "2026-11-24T10:00:00Z";
        let active = sample_key(14, DeploymentKeyStatus::Active, "2026-12-24T00:00:00Z");
        assert_eq!(active.effective_status(now), DeploymentKeyStatus::Active);

        let exhausted = sample_key(50, DeploymentKeyStatus::Active, "2026-12-24T00:00:00Z");
        assert_eq!(
            exhausted.effective_status(now),
            DeploymentKeyStatus::Exhausted
        );

        let expired = sample_key(10, DeploymentKeyStatus::Active, "2026-11-20T00:00:00Z");
        assert_eq!(expired.effective_status(now), DeploymentKeyStatus::Expired);

        let revoked = sample_key(10, DeploymentKeyStatus::Revoked, "2026-12-24T00:00:00Z");
        assert_eq!(revoked.effective_status(now), DeploymentKeyStatus::Revoked);
    }

    #[test]
    fn integration_at_risk_within_fourteen_days() {
        let entry = IntegrationEntry {
            id: "idp-entra".into(),
            name: "Microsoft Entra ID".into(),
            provider: "Entra".into(),
            category: IntegrationCategory::DirectorySync,
            state: IntegrationHealthState::Connected,
            synced_users: 42,
            last_sync_at: Some("2026-11-24T09:00:00Z".into()),
            credential_expires_in_days: Some(9),
            detail: "SCIM 2.0 pull active".into(),
            readiness_checks: vec![ReadinessCheck {
                name: "Credential validity".into(),
                passed: true,
                detail: "Expires in 9 days".into(),
            }],
        };
        assert_eq!(entry.evaluate_health(), IntegrationHealthState::AtRisk);

        let healthy = IntegrationEntry {
            credential_expires_in_days: Some(30),
            ..entry.clone()
        };
        assert_eq!(healthy.evaluate_health(), IntegrationHealthState::Connected);
    }

    #[test]
    fn mdm_format_serde_roundtrip() {
        let raw = serde_json::to_string(&MdmFormat::JamfMobileconfig).expect("serialize");
        assert_eq!(raw, "\"jamf_mobileconfig\"");
        let parsed: MdmFormat = serde_json::from_str(&raw).expect("deserialize");
        assert_eq!(parsed, MdmFormat::JamfMobileconfig);
    }
}
