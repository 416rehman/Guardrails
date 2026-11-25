// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{PrivacyCeilingProfile, RetentionProposal, resolve_retention_policy};
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND};
use grdr_model::{AuditEntry, CodedError, IdentityMode};
use grdr_proto::api::operator::{
    ConfigRevisionEntry, GetOperatorStateResponse, OperatorRuntimeConfig,
    StageConfigRevisionRequest,
};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::AppState;
use super::surfaces_operator_helpers::{
    compute_config_diff, config_to_proto, parse_op_preset, profile_str, revision_to_proto,
};
use super::surfaces_operator_ops::{
    compute_compat_matrix, drill_to_proto, ensure_operator_seeded, target_to_proto,
};
use super::surfaces_types::{ConfigRevLifecycle, OperatorConfigSnapshot, OperatorRevisionRecord};

impl AppState {
    pub async fn get_operator_state(&self) -> Result<GetOperatorStateResponse, CodedError> {
        let now = Timestamp::now();
        {
            let mut guard = self.inner.write().await;
            ensure_operator_seeded(&mut guard, now);
        }
        let guard = self.inner.read().await;
        let op = guard.surfaces.operator.as_ref();
        let target_ver = op
            .map(|o| o.target_upgrade_version.clone())
            .unwrap_or_else(|| "0.2.0".to_owned());
        let (preflight_matrix, overall_compatible) = compute_compat_matrix(&guard, &target_ver)?;

        Ok(GetOperatorStateResponse {
            runtime_config: op.map(|o| config_to_proto(&o.current)),
            revisions: op
                .map(|o| o.revisions.iter().map(revision_to_proto).collect())
                .unwrap_or_default(),
            preflight_matrix,
            target_version: target_ver,
            overall_compatible,
            targets: op
                .map(|o| o.targets.iter().map(target_to_proto).collect())
                .unwrap_or_default(),
            drills: op
                .map(|o| o.drills.iter().map(drill_to_proto).collect())
                .unwrap_or_default(),
            revision: None,
        })
    }

    pub async fn stage_config_revision(
        &self,
        req: StageConfigRevisionRequest,
        auth: &AuthContext,
    ) -> Result<ConfigRevisionEntry, CodedError> {
        let now = Timestamp::now();
        let capture = match req.capture_level.trim().to_ascii_lowercase().as_str() {
            "metadata-only" => "metadata-only".to_owned(),
            "metadata-and-signals" => "metadata-and-signals".to_owned(),
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Invalid capture level `{}`.", req.capture_level),
                    "Use `metadata-only` or `metadata-and-signals`.",
                ));
            }
        };
        let profile = match req.privacy_profile.trim().to_ascii_lowercase().as_str() {
            "standard" => PrivacyCeilingProfile::Standard,
            "works-council" | "works_council" => PrivacyCeilingProfile::WorksCouncil,
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Invalid privacy profile `{}`.", req.privacy_profile),
                    "Use `standard` or `works-council`.",
                ));
            }
        };
        let preset = parse_op_preset(&req.retention_preset)?;
        let channel = match req.release_channel.trim().to_ascii_lowercase().as_str() {
            "stable" => "stable".to_owned(),
            "canary" => "canary".to_owned(),
            "airgap" => "airgap".to_owned(),
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Unsupported release channel `{}`.", req.release_channel),
                    "Use stable, canary, or airgap.",
                ));
            }
        };

        let mut basis = BTreeMap::new();
        basis.insert(preset, grdr_comply::preset_spec(preset).legal_basis);
        let policy = resolve_retention_policy(&RetentionProposal {
            organisation: "org-default".to_owned(),
            presets: vec![preset],
            ceiling_profile: profile,
            legal_basis: basis,
            override_legal_basis: None,
            content_days: None,
            activity_days: None,
            decision_days: None,
            audit_days: None,
            hot_days: None,
        })
        .map_err(|e| {
            CodedError::new(
                CODE_INVALID_INPUT,
                e.to_string(),
                "Adjust privacy profile or preset.",
            )
        })?;

        let mut guard = self.inner.write().await;
        ensure_operator_seeded(&mut guard, now);

        let op = guard.surfaces.operator.as_mut().ok_or_else(|| {
            CodedError::new(
                CODE_NOT_FOUND,
                "Operator state uninitialized.",
                "Reload operator plane.",
            )
        })?;
        let next_ver = op
            .revisions
            .iter()
            .map(|r| r.version)
            .max()
            .unwrap_or(op.current.version)
            .saturating_add(1);
        let rev_id = format!("cfg-rev-{next_ver}");
        let summary_clean = sanitize_inert_text(
            Some(req.summary.trim())
                .filter(|s| !s.is_empty())
                .unwrap_or("Staged runtime configuration update"),
        );

        let next_cfg = OperatorConfigSnapshot {
            revision_id: rev_id.clone(),
            version: next_ver,
            capture_level: capture,
            privacy_profile: profile_str(profile).to_owned(),
            retention_preset: req.retention_preset.trim().to_ascii_lowercase(),
            hot_days: policy.hot_days,
            activity_days: policy.activity_days,
            decision_days: policy.decision_days,
            audit_days: policy.audit_days,
            otlp_enabled: req.otlp_enabled,
            release_channel: channel,
            summary: summary_clean.clone(),
        };
        let diff_lines = compute_config_diff(&op.current, &next_cfg);

        for rev in &mut op.revisions {
            if matches!(
                rev.state,
                ConfigRevLifecycle::Draft | ConfigRevLifecycle::Validated
            ) {
                rev.state = ConfigRevLifecycle::Discarded;
            }
        }

        let actor = auth.principal_id.clone();
        let entry = OperatorRevisionRecord {
            revision_id: rev_id.clone(),
            version: next_ver,
            state: ConfigRevLifecycle::Validated,
            author: actor.clone(),
            summary: summary_clean,
            created_at: now.to_string(),
            applied_at: None,
            diff_lines,
            config: next_cfg,
        };
        op.revisions.insert(0, entry.clone());

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "operator.config.staged".to_owned(),
                actor,
                summary: format!("Staged validated config revision {rev_id}"),
                target: rev_id,
            },
        );
        self.persist_store(&guard)?;
        Ok(revision_to_proto(&entry))
    }

    pub async fn apply_config_revision(
        &self,
        revision_id: &str,
        auth: &AuthContext,
    ) -> Result<(OperatorRuntimeConfig, ConfigRevisionEntry), CodedError> {
        let now = Timestamp::now();
        let target_id = revision_id.trim();
        if target_id.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Revision identifier is required.",
                "Select a validated staged revision.",
            ));
        }

        let mut guard = self.inner.write().await;
        ensure_operator_seeded(&mut guard, now);

        let candidate_profile = guard
            .surfaces
            .operator
            .as_ref()
            .and_then(|op| {
                op.revisions
                    .iter()
                    .find(|r| r.revision_id == target_id)
                    .map(|r| r.config.privacy_profile.clone())
            })
            .unwrap_or_default();

        if guard.privacy.identity_mode == IdentityMode::Pseudonymous
            && candidate_profile != "works-council"
            && !auth.confirmation.is_step_up()
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Cannot weaken active works-council privacy profile to standard without passkey step-up confirmation (D-70).",
                "Supply a valid X-Grdr-Step-Up credential or StepUpVerified principal, or preserve works-council profile.",
            ));
        }

        let op = guard.surfaces.operator.as_mut().ok_or_else(|| {
            CodedError::new(CODE_NOT_FOUND, "Operator state uninitialized.", "Reload.")
        })?;

        let idx = op
            .revisions
            .iter()
            .position(|r| r.revision_id == target_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Config revision `{target_id}` was not found."),
                    "Stage a new revision first.",
                )
            })?;

        let target_state = op.revisions.get(idx).map(|r| r.state);
        if !matches!(
            target_state,
            Some(ConfigRevLifecycle::Validated | ConfigRevLifecycle::Draft)
        ) {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                format!("Revision `{target_id}` is not awaiting staged apply."),
                "Stage a new draft or select a validated revision.",
            ));
        }

        for rev in &mut op.revisions {
            if rev.state == ConfigRevLifecycle::Applied {
                rev.state = ConfigRevLifecycle::Superseded;
            }
        }
        let applied_record = {
            let Some(slot) = op.revisions.get_mut(idx) else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    "Revision missing.",
                    "Reload.",
                ));
            };
            slot.state = ConfigRevLifecycle::Applied;
            slot.applied_at = Some(now.to_string());
            op.current = slot.config.clone();
            slot.clone()
        };

        let next_current = op.current.clone();
        if next_current.privacy_profile == "works-council" {
            guard.privacy.identity_mode = IdentityMode::Pseudonymous;
            guard.privacy.user_risk_scoring = false;
        } else if guard.privacy.identity_mode == IdentityMode::Pseudonymous
            && auth.confirmation.is_step_up()
        {
            guard.privacy.identity_mode = IdentityMode::Named;
        }
        guard.otlp_config.enabled = next_current.otlp_enabled;

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "operator.config.applied".to_owned(),
                actor: auth.principal_id.clone(),
                summary: format!("Applied operator config revision {target_id}"),
                target: target_id.to_owned(),
            },
        );
        self.persist_store(&guard)?;
        drop(guard);
        self.emit_live(
            "privacy.updated",
            "Applied operator runtime configuration revision".to_owned(),
            None,
        );
        Ok((
            config_to_proto(&next_current),
            revision_to_proto(&applied_record),
        ))
    }

    pub async fn rollback_config_revision(
        &self,
        target_revision_id: Option<&str>,
        reason: &str,
        auth: &AuthContext,
    ) -> Result<(OperatorRuntimeConfig, ConfigRevisionEntry), CodedError> {
        let now = Timestamp::now();
        let reason_clean = sanitize_inert_text(reason.trim());
        if reason_clean.is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Rollback reason is required for operator audit trail.",
                "Provide a concise reason before rolling back.",
            ));
        }

        let mut guard = self.inner.write().await;
        ensure_operator_seeded(&mut guard, now);

        let restore_idx = {
            let op = guard.surfaces.operator.as_ref().ok_or_else(|| {
                CodedError::new(CODE_NOT_FOUND, "Operator state uninitialized.", "Reload.")
            })?;
            if let Some(tid) = target_revision_id.map(str::trim).filter(|s| !s.is_empty()) {
                op.revisions.iter().position(|r| r.revision_id == tid)
            } else {
                op.revisions
                    .iter()
                    .position(|r| r.state == ConfigRevLifecycle::Superseded)
            }
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    "No superseded prior configuration revision available to restore.",
                    "Apply a second revision before testing rollback.",
                )
            })?
        };

        let restored_profile = guard
            .surfaces
            .operator
            .as_ref()
            .and_then(|op| op.revisions.get(restore_idx))
            .map(|r| r.config.privacy_profile.clone())
            .unwrap_or_default();

        if guard.privacy.identity_mode == IdentityMode::Pseudonymous
            && restored_profile != "works-council"
            && !auth.confirmation.is_step_up()
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Rollback cannot downgrade active works-council privacy profile to standard without passkey step-up confirmation (D-70).",
                "Supply a valid X-Grdr-Step-Up credential or StepUpVerified principal before rolling back off works-council.",
            ));
        }

        let op = guard.surfaces.operator.as_mut().ok_or_else(|| {
            CodedError::new(CODE_NOT_FOUND, "Operator state uninitialized.", "Reload.")
        })?;
        for rev in &mut op.revisions {
            if rev.state == ConfigRevLifecycle::Applied {
                rev.state = ConfigRevLifecycle::RolledBack;
            }
        }
        let restored_record = {
            let Some(slot) = op.revisions.get_mut(restore_idx) else {
                return Err(CodedError::new(
                    CODE_NOT_FOUND,
                    "Target revision missing.",
                    "Reload.",
                ));
            };
            slot.state = ConfigRevLifecycle::Applied;
            slot.applied_at = Some(now.to_string());
            op.current = slot.config.clone();
            slot.clone()
        };

        let restored_cfg = op.current.clone();
        if restored_cfg.privacy_profile == "works-council" {
            guard.privacy.identity_mode = IdentityMode::Pseudonymous;
            guard.privacy.user_risk_scoring = false;
        } else if guard.privacy.identity_mode == IdentityMode::Pseudonymous
            && auth.confirmation.is_step_up()
        {
            guard.privacy.identity_mode = IdentityMode::Named;
        }
        guard.otlp_config.enabled = restored_cfg.otlp_enabled;

        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "operator.config.rolled_back".to_owned(),
                actor: auth.principal_id.clone(),
                summary: format!(
                    "Rolled back to {} ({reason_clean})",
                    restored_record.revision_id
                ),
                target: restored_record.revision_id.clone(),
            },
        );
        self.persist_store(&guard)?;
        drop(guard);
        self.emit_live(
            "privacy.updated",
            "Rolled back operator runtime configuration".to_owned(),
            None,
        );
        Ok((
            config_to_proto(&restored_cfg),
            revision_to_proto(&restored_record),
        ))
    }
}
