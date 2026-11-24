// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use uuid::Uuid;

use grdr_model::{
    AuditEntry, CREDENTIAL_EXPIRY_WARNING_DAYS, CodedError, ConnectConfigResponse,
    CreateDeploymentKeyRequest, CreateDeploymentKeyResponse, DeploymentKey, DeploymentKeyStatus,
    IntegrationEntry, IntegrationHealthState, MdmRenderRequest, MdmRenderResponse, slugify_id,
};

use super::AppState;
use super::connect_mdm::{
    CODE_CONNECT_INVALID, DEMO_ORIGIN, default_installers, render_mdm_artifact,
};

const CODE_CONNECT_NOT_FOUND: &str = "GRDR-CONNECT-0002";
const MAX_KEY_USES: u32 = 50_000;
const MAX_KEY_TTL_DAYS: u32 = 365;
const SECONDS_PER_DAY: i64 = 86_400;

impl AppState {
    pub async fn connect_config(&self) -> ConnectConfigResponse {
        let now_str = Timestamp::now().to_string();
        let guard = self.inner.read().await;
        let deployment_keys = guard
            .deployment_keys
            .iter()
            .cloned()
            .map(|mut key| {
                key.status = key.effective_status(&now_str);
                key
            })
            .collect();
        let integrations = guard
            .integrations
            .iter()
            .cloned()
            .map(|mut item| {
                item.state = item.evaluate_health();
                item
            })
            .collect();

        ConnectConfigResponse {
            server_origin: DEMO_ORIGIN.into(),
            installers: default_installers(DEMO_ORIGIN),
            deployment_keys,
            otlp: guard.otlp_config.clone(),
            integrations,
        }
    }

    pub async fn create_deployment_key(
        &self,
        req: CreateDeploymentKeyRequest,
    ) -> Result<CreateDeploymentKeyResponse, CodedError> {
        let label = req.label.trim();
        if label.is_empty() {
            return Err(CodedError::new(
                CODE_CONNECT_INVALID,
                "Deployment key label cannot be empty.",
                "Provide a descriptive wave label such as `Finance Pilot`.",
            ));
        }
        if req.max_uses == 0 || req.max_uses > MAX_KEY_USES {
            return Err(CodedError::new(
                CODE_CONNECT_INVALID,
                "Deployment key max_uses must be between 1 and 50000.",
                "Choose a wave quota within the allowed range.",
            ));
        }
        if req.ttl_days == 0 || req.ttl_days > MAX_KEY_TTL_DAYS {
            return Err(CodedError::new(
                CODE_CONNECT_INVALID,
                "Deployment key ttl_days must be between 1 and 365.",
                "Specify an expiration window between 1 and 365 days.",
            ));
        }

        let now = Timestamp::now();
        let ttl_secs = i64::from(req.ttl_days).saturating_mul(SECONDS_PER_DAY);
        let expires_at = Timestamp::from_second(now.as_second().saturating_add(ttl_secs))
            .unwrap_or(now)
            .to_string();
        let raw_uuid = Uuid::now_v7().simple().to_string();
        let suffix: String = raw_uuid.chars().take(16).collect();
        let preview_part: String = suffix.chars().take(8).collect();
        let plaintext_token = format!("grdr_wk_{suffix}");
        let key_id = format!("key-{}", slugify_id(label, 40, "wave"));

        let key = DeploymentKey {
            id: key_id,
            label: label.to_string(),
            token_preview: format!("grdr_wk_{preview_part}"),
            install_profile: if req.install_profile.trim().is_empty() {
                "standard".into()
            } else {
                req.install_profile.trim().to_string()
            },
            wave: if req.wave.trim().is_empty() {
                "wave-custom".into()
            } else {
                req.wave.trim().to_string()
            },
            max_uses: req.max_uses,
            used_count: 0,
            status: DeploymentKeyStatus::Active,
            created_at: now.to_string(),
            expires_at,
            created_by: "console-operator".into(),
        };

        let mut guard = self.inner.write().await;
        guard.deployment_keys.insert(0, key.clone());
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud-{}", Uuid::now_v7().simple()),
                kind: "connect.key.created".into(),
                actor: "console-operator".into(),
                summary: format!(
                    "Issued deployment key `{}` (quota {})",
                    key.label, key.max_uses
                ),
                target: key.id.clone(),
                timestamp: now,
            },
        );
        self.persist_store(&guard)?;

        Ok(CreateDeploymentKeyResponse {
            key,
            plaintext_token,
        })
    }

    pub async fn revoke_deployment_key(&self, id: &str) -> Result<DeploymentKey, CodedError> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        let idx = guard
            .deployment_keys
            .iter()
            .position(|k| k.id == id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_CONNECT_NOT_FOUND,
                    format!("Deployment key `{id}` was not found."),
                    "Refresh Connect keys and retry.",
                )
            })?;

        let updated = {
            let key = guard
                .deployment_keys
                .get_mut(idx)
                .ok_or_else(|| CodedError::new(CODE_CONNECT_NOT_FOUND, "Missing key", "Retry"))?;
            key.status = DeploymentKeyStatus::Revoked;
            key.clone()
        };

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud-{}", Uuid::now_v7().simple()),
                kind: "connect.key.revoked".into(),
                actor: "console-operator".into(),
                summary: format!("Revoked deployment key `{}`", updated.label),
                target: updated.id.clone(),
                timestamp: now,
            },
        );
        self.persist_store(&guard)?;
        Ok(updated)
    }

    pub async fn render_mdm_config(
        &self,
        req: MdmRenderRequest,
    ) -> Result<MdmRenderResponse, CodedError> {
        let guard = self.inner.read().await;
        let selected_key = match req.deployment_key_id.as_deref() {
            Some(kid) if !kid.trim().is_empty() => Some(
                guard
                    .deployment_keys
                    .iter()
                    .find(|k| k.id == kid)
                    .ok_or_else(|| {
                        CodedError::new(
                            CODE_CONNECT_NOT_FOUND,
                            format!("Deployment key `{kid}` was not found."),
                            "Select an active wave deployment key.",
                        )
                    })?,
            ),
            _ => None,
        };
        render_mdm_artifact(&req, DEMO_ORIGIN, selected_key)
    }

    pub async fn list_integrations(&self) -> Vec<IntegrationEntry> {
        let guard = self.inner.read().await;
        guard
            .integrations
            .iter()
            .cloned()
            .map(|mut item| {
                item.state = item.evaluate_health();
                item
            })
            .collect()
    }

    pub async fn check_integration_readiness(
        &self,
        id: &str,
    ) -> Result<IntegrationEntry, CodedError> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        let idx = guard
            .integrations
            .iter()
            .position(|item| item.id == id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_CONNECT_NOT_FOUND,
                    format!("Integration `{id}` was not found."),
                    "Return to Connect & Integrations to pick a configured provider.",
                )
            })?;

        let updated = {
            let entry = guard
                .integrations
                .get_mut(idx)
                .ok_or_else(|| CodedError::new(CODE_CONNECT_NOT_FOUND, "Missing entry", "Retry"))?;
            if entry.state != IntegrationHealthState::NotConfigured {
                entry.last_sync_at = Some(now.to_string());
                if let Some(days) = entry.credential_expires_in_days
                    && days <= CREDENTIAL_EXPIRY_WARNING_DAYS
                    && let Some(check) = entry.readiness_checks.first_mut()
                {
                    check.passed = true;
                    check.detail = format!(
                        "Secret expires in {days} days (below {CREDENTIAL_EXPIRY_WARNING_DAYS}d threshold)"
                    );
                }
            }
            entry.state = entry.evaluate_health();
            entry.clone()
        };

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud-{}", Uuid::now_v7().simple()),
                kind: "integration.readiness.checked".into(),
                actor: "console-operator".into(),
                summary: format!("Checked readiness for `{}`", updated.name),
                target: updated.id.clone(),
                timestamp: now,
            },
        );
        self.persist_store(&guard)?;
        Ok(updated)
    }
}
