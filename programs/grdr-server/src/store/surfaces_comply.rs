// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    DrillDownAuditRecord, NoticeLocale, OversightQualityReport, PrivacyCeilingProfile,
    RecordOfProcessing, RetentionPreset, RetentionProposal, format_utc_quarter,
    resolve_retention_policy, validate_purpose_bound_drill_down,
};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{AuditEntry, CodedError, IdentityMode, InstallProfile};
use grdr_proto::api::surfaces::{
    CompleteFirstRunRequest, FirstRunState, GetComplianceWorkspaceResponse, RetentionStateSummary,
    UpdateCompliancePolicyRequest,
};
use grdr_strings::sanitize_untrusted_text as sanitize_inert_text;

use crate::auth::AuthContext;

use super::AppState;
use super::surfaces_comply_helpers::{
    build_first_run_state, clean_customer_basis, comply_to_coded, parse_privacy_profile,
    parse_retention_preset, retention_summary_from_policy,
};
use super::surfaces_comply_seed::ensure_compliance_seeded;
use super::surfaces_types::DisclosureRecord;

#[path = "surfaces_comply_dsar.rs"]
mod dsar;

#[path = "surfaces_comply_ops.rs"]
#[allow(dead_code)]
pub(crate) mod ops;

#[path = "surfaces_comply_policy.rs"]
mod policy;

#[path = "surfaces_comply_workspace.rs"]
mod workspace;

#[cfg(test)]
#[path = "surfaces_comply_tests.rs"]
mod tests;

impl AppState {
    pub async fn get_compliance_workspace(
        &self,
        tenant_id: &str,
    ) -> GetComplianceWorkspaceResponse {
        let now = Timestamp::now();
        let mut persist_error: Option<String> = None;
        {
            let mut guard = self.inner.write().await;
            ensure_compliance_seeded(&mut guard, now);
            let prev_snapshot = guard
                .surfaces
                .compliance
                .as_ref()
                .map(|c| (c.capture_level.clone(), c.pending_capture_change.clone()));
            let audit_len_before = guard.audit.len();
            if ops::activate_due_capture_and_audit(&mut guard, now)
                && let Err(err) = self.persist_store(&guard)
            {
                if let (Some((prev_cap, prev_pending)), Some(comp)) =
                    (prev_snapshot, guard.surfaces.compliance.as_mut())
                {
                    comp.capture_level = prev_cap;
                    comp.pending_capture_change = prev_pending;
                }
                if guard.audit.len() > audit_len_before && !guard.audit.is_empty() {
                    guard.audit.remove(0);
                }
                persist_error = Some(err.message);
            }
        }
        let lake_result = match &self.storage {
            Some(s) => match s.lake_manifest() {
                Ok(manifest) => Ok(manifest),
                Err(_) => Err(()),
            },
            None => Ok(None),
        };
        let guard = self.inner.read().await;
        workspace::assemble_workspace_response(
            &guard,
            &self.signing_key,
            tenant_id,
            lake_result.as_ref().map(Option::as_ref).map_err(|_| ()),
            persist_error.as_deref(),
            now,
        )
    }

    pub async fn update_compliance_policy(
        &self,
        req: UpdateCompliancePolicyRequest,
        auth: &AuthContext,
    ) -> Result<RetentionStateSummary, CodedError> {
        let now = Timestamp::now();
        let profile = parse_privacy_profile(&req.privacy_profile)?;
        let presets = if req.presets.is_empty() {
            vec![RetentionPreset::Default]
        } else {
            req.presets
                .iter()
                .map(|p| parse_retention_preset(p))
                .collect::<Result<Vec<_>, _>>()?
        };

        let caller_basis = req
            .override_legal_basis
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(sanitize_inert_text);

        let mut basis_map = BTreeMap::new();
        let mut recorded_updates = BTreeMap::new();
        for p in &presets {
            let spec = grdr_comply::preset_spec(*p).map_err(comply_to_coded)?;
            if spec.requires_recorded_basis {
                let basis = caller_basis.clone().ok_or_else(|| {
                    CodedError::new(
                        CODE_INVALID_INPUT,
                        format!(
                            "Preset `{:?}` ({}) requires an explicit recorded legal basis.",
                            spec.preset, spec.clause_id
                        ),
                        "Provide override_legal_basis before enabling this regulated preset.",
                    )
                })?;
                recorded_updates.insert(*p, basis.clone());
                basis_map.insert(*p, basis);
            } else {
                let basis = caller_basis
                    .clone()
                    .unwrap_or_else(|| clean_customer_basis(&spec.legal_basis));
                basis_map.insert(*p, basis);
            }
        }

        let resolved = resolve_retention_policy(&RetentionProposal {
            organisation: auth.tenant_id.clone(),
            presets: presets.clone(),
            ceiling_profile: profile,
            legal_basis: basis_map,
            override_legal_basis: caller_basis.clone(),
            content_days: None,
            activity_days: None,
            decision_days: None,
            audit_days: None,
            hot_days: None,
        })
        .map_err(comply_to_coded)?;

        let requested_capture = req
            .capture_level
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty())
            .map(ops::parse_capture_level)
            .transpose()?;

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        if let Some(ref mut comp) = guard.surfaces.compliance
            && let Some(pending) = ops::activate_due_capture_change(comp, now)
        {
            guard.audit.insert(
                0,
                AuditEntry {
                    id: format!("aud_{}", Uuid::now_v7().simple()),
                    timestamp: now,
                    kind: "compliance.capture.activated".to_owned(),
                    actor: pending.actor,
                    summary: format!(
                        "Activated scheduled capture increase to `{}` after advance notice",
                        pending.target_capture_level
                    ),
                    target: "compliance-capture".to_owned(),
                },
            );
        }

        let current_profile = guard
            .surfaces
            .compliance
            .as_ref()
            .map(|c| c.privacy_profile)
            .unwrap_or(PrivacyCeilingProfile::Standard);
        let next_mode = match profile {
            PrivacyCeilingProfile::Standard => IdentityMode::Named,
            PrivacyCeilingProfile::WorksCouncil => IdentityMode::Pseudonymous,
        };
        let is_downgrade = (guard.privacy.identity_mode == IdentityMode::Pseudonymous
            || current_profile == PrivacyCeilingProfile::WorksCouncil)
            && next_mode == IdentityMode::Named;
        if is_downgrade && (!auth.confirmation.is_step_up() || caller_basis.is_none()) {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Downgrading privacy ceiling from works-council to standard requires step-up verification and a recorded legal basis.",
                "Provide override_legal_basis and step-up approval before switching off works-council pseudonymous mode.",
            ));
        }

        let requested_capture_str = requested_capture.map(|c| ops::capture_level_str(c).to_owned());
        let actor = auth.principal_id.clone();
        if is_downgrade {
            let staged_summary = policy::stage_or_complete_downgrade(
                &mut guard,
                policy::DowngradeProposal {
                    tenant_id: &auth.tenant_id,
                    actor: &actor,
                    presets: &presets,
                    caller_basis: &caller_basis,
                    requested_capture_str: &requested_capture_str,
                    now,
                },
            )?;
            if let Some(summary) = staged_summary {
                self.persist_store(&guard)?;
                drop(guard);
                self.emit_live(
                    "privacy.updated",
                    "Proposed works-council downgrade awaiting co-approver quorum".to_owned(),
                    None,
                );
                return Ok(summary);
            }
        } else if let Some(ref mut comp) = guard.surfaces.compliance {
            comp.pending_profile_downgrade = None;
        }

        guard.privacy.identity_mode = next_mode;
        if profile == PrivacyCeilingProfile::WorksCouncil {
            guard.privacy.user_risk_scoring = false;
        }

        let mut notice_note = String::new();
        if let Some(ref mut comp) = guard.surfaces.compliance {
            notice_note = policy::apply_capture_schedule_update(
                comp,
                profile,
                requested_capture,
                &actor,
                now,
            )?;
            comp.privacy_profile = profile;
            comp.presets = presets;
            comp.override_legal_basis = caller_basis;
            comp.recorded_legal_bases.extend(recorded_updates);
            comp.disclosures.insert(
                0,
                DisclosureRecord {
                    id: format!("disc_{}", Uuid::now_v7().simple()),
                    organisation: auth.tenant_id.clone(),
                    kind: "retention_policy".to_owned(),
                    actor: actor.clone(),
                    target_ref: format!("{profile:?}"),
                    legal_basis: clean_customer_basis(&resolved.legal_basis.join("; ")),
                    timestamp: now.to_string(),
                    quarter: format_utc_quarter(now),
                    summary: format!(
                        "Updated retention ({}d activity / {}d audit){notice_note}",
                        resolved.activity_days, resolved.audit_days
                    ),
                },
            );
        }

        let summary = retention_summary_from_policy(&resolved);
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "compliance.retention.updated".to_owned(),
                actor,
                summary: format!(
                    "Privacy profile `{}` applied ({}d activity ceiling){notice_note}",
                    summary.privacy_profile, summary.activity_days
                ),
                target: "compliance-retention".to_owned(),
            },
        );
        self.persist_store(&guard)?;
        drop(guard);
        self.emit_live(
            "privacy.updated",
            "Updated compliance privacy profile and retention windows".to_owned(),
            None,
        );
        Ok(summary)
    }

    pub async fn complete_first_run(
        &self,
        req: CompleteFirstRunRequest,
        auth: &AuthContext,
    ) -> Result<FirstRunState, CodedError> {
        let now = Timestamp::now();
        let prof_norm = req.profile.trim().to_ascii_lowercase();
        let profile = match prof_norm.as_str() {
            "protected" | "user" => prof_norm,
            _ => {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Unsupported onboarding profile `{}`.", req.profile),
                    "Select `protected` or `user`.",
                ));
            }
        };

        let mut guard = self.inner.write().await;
        guard.surfaces.first_run.selected_profile = profile.clone();
        guard.surfaces.first_run.confirmed = req.confirm_protection;
        guard.surfaces.first_run.step_up_enabled = req.step_up_enabled;
        for dev in &mut guard.devices {
            dev.install_profile = if profile == "protected" {
                InstallProfile::Protected
            } else {
                InstallProfile::User
            };
        }
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: "onboarding.profile.updated".to_owned(),
                actor: auth.principal_id.clone(),
                summary: format!(
                    "First-run profile set to {profile} (confirmed={}, step_up={})",
                    req.confirm_protection, req.step_up_enabled
                ),
                target: "first-run".to_owned(),
            },
        );
        self.persist_store(&guard)?;
        let out = build_first_run_state(&guard);
        drop(guard);
        self.emit_live(
            "inventory.device",
            "Updated local endpoint protection profile".to_owned(),
            None,
        );
        Ok(out)
    }

    #[allow(dead_code)]
    pub async fn build_server_ropa(
        &self,
        tenant_id: &str,
        controller: &str,
        dpo: &str,
    ) -> Result<RecordOfProcessing, CodedError> {
        let now = Timestamp::now();
        {
            let mut g = self.inner.write().await;
            ensure_compliance_seeded(&mut g, now);
            if ops::activate_due_capture_and_audit(&mut g, now) {
                self.persist_store(&g)?;
            }
        }
        let guard = self.inner.read().await;
        let comp = guard.surfaces.compliance.as_ref().ok_or_else(|| {
            CodedError::new(
                CODE_INVALID_INPUT,
                "Missing compliance state.",
                "Initialize workspace.",
            )
        })?;
        ops::build_server_ropa_doc(&guard, comp, tenant_id, controller, dpo, now)
    }

    #[allow(dead_code)]
    pub(crate) async fn build_server_privacy_docs(
        &self,
        tenant_id: &str,
        locale: NoticeLocale,
    ) -> Result<ops::ServerPrivacyDocsBundle, CodedError> {
        let now = Timestamp::now();
        {
            let mut g = self.inner.write().await;
            ensure_compliance_seeded(&mut g, now);
            if ops::activate_due_capture_and_audit(&mut g, now) {
                self.persist_store(&g)?;
            }
        }
        let guard = self.inner.read().await;
        let comp = guard.surfaces.compliance.as_ref().ok_or_else(|| {
            CodedError::new(
                CODE_INVALID_INPUT,
                "Missing compliance state.",
                "Initialize workspace.",
            )
        })?;
        ops::build_server_privacy_docs(&guard, comp, tenant_id, locale, now)
    }

    #[allow(dead_code)]
    pub async fn build_server_oversight_report(
        &self,
        tenant_id: &str,
    ) -> Result<OversightQualityReport, CodedError> {
        let now = Timestamp::now();
        let guard = self.inner.read().await;
        ops::build_server_oversight_doc(&guard, tenant_id, now)
    }

    #[allow(dead_code)]
    pub async fn validate_and_log_drill_down(
        &self,
        target_ref: &str,
        incident_ref: Option<&str>,
        assigned_finding_id: Option<&str>,
        purpose: &str,
        auth: &AuthContext,
    ) -> Result<DrillDownAuditRecord, CodedError> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);
        let profile = guard
            .surfaces
            .compliance
            .as_ref()
            .map(|c| c.privacy_profile)
            .unwrap_or(PrivacyCeilingProfile::Standard);
        let rec = validate_purpose_bound_drill_down(
            profile,
            &auth.principal_id,
            target_ref,
            incident_ref,
            assigned_finding_id,
            purpose,
            now,
        )
        .map_err(comply_to_coded)?;
        ops::validate_live_incident_and_finding_refs(&guard, &rec)?;
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud_{}", Uuid::now_v7().simple()),
                timestamp: now,
                kind: rec.audit_kind.clone(),
                actor: auth.principal_id.clone(),
                summary: format!(
                    "Purpose-bound drill-down: {}",
                    sanitize_inert_text(&rec.purpose)
                ),
                target: sanitize_inert_text(&rec.target_ref),
            },
        );
        self.persist_store(&guard)?;
        Ok(rec)
    }
}
