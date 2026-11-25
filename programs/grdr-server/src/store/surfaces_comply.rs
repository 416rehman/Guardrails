// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    PrivacyCeilingProfile, RetentionPreset, RetentionProposal, default_registry,
    resolve_retention_policy,
};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{AuditEntry, CodedError, IdentityMode, InstallProfile};
use grdr_proto::api::surfaces::{
    CompleteFirstRunRequest, ComplianceConnectorEntry, ComplianceEvidenceEntry,
    DisclosureLedgerEntry, FirstRunState, FrameworkCoverageSummary, GetComplianceWorkspaceResponse,
    LegalHoldEntry, RetentionStateSummary, SubjectRequestEntry, UpdateCompliancePolicyRequest,
};
use grdr_proto::common::SubjectRequestStatus;

use crate::auth::AuthContext;

use super::AppState;
use super::surfaces_comply_helpers::{
    build_first_run_state, build_retention_summary, clean_customer_basis, comply_to_coded,
    compute_disclosure_metrics, evaluate_live_evidence, evidence_result_str, hold_lifecycle_str,
    hold_notice_str, parse_privacy_profile, parse_retention_preset, reid_to_proto,
    responsibility_str, retention_summary_from_policy,
};
use super::surfaces_comply_seed::ensure_compliance_seeded;
use super::surfaces_types::{DisclosureRecord, SubjectRequestLifecycle};

fn format_framework_title(framework_id: &str, raw_title: &str) -> String {
    let lower = framework_id.to_ascii_lowercase();
    if lower.contains("nist") || lower.contains("omb") || lower.contains("fedramp") {
        grdr_comply::eo14434_display_label(raw_title)
    } else {
        raw_title.to_owned()
    }
}

impl AppState {
    pub async fn get_compliance_workspace(
        &self,
        tenant_id: &str,
    ) -> GetComplianceWorkspaceResponse {
        let now = Timestamp::now();
        {
            let mut guard = self.inner.write().await;
            ensure_compliance_seeded(&mut guard, now);
        }
        let guard = self.inner.read().await;
        let state = guard.surfaces.compliance.clone();
        let registry = default_registry();

        let frameworks: Vec<FrameworkCoverageSummary> = registry
            .frameworks
            .keys()
            .filter_map(|id| {
                let report = registry.framework_coverage(id).ok()?;
                let display_title = registry
                    .frameworks
                    .get(id)
                    .map(|f| format_framework_title(id, &f.title))
                    .unwrap_or_else(|| format_framework_title(id, &report.display_title));
                Some((display_title, report))
            })
            .map(|(display_title, report)| {
                let total = u32::try_from(report.total_controls).unwrap_or(u32::MAX);
                let addressed = u32::try_from(report.addressed_controls).unwrap_or(u32::MAX);
                let pct = addressed
                    .saturating_mul(100)
                    .checked_div(total)
                    .unwrap_or(0);
                FrameworkCoverageSummary {
                    framework_id: report.framework_id,
                    display_title,
                    total_controls: total,
                    addressed_controls: addressed,
                    coverage_percent: pct,
                }
            })
            .collect();

        let evidence_items = evaluate_live_evidence(&guard, &self.signing_key, tenant_id, now)
            .into_iter()
            .map(|item| {
                let cap_rec = registry.capabilities.get(&item.capability);
                ComplianceEvidenceEntry {
                    id: item.id,
                    capability: item.capability.clone(),
                    statement: cap_rec
                        .map(|c| c.statement.clone())
                        .unwrap_or_else(|| item.capability.clone()),
                    result: evidence_result_str(item.result).to_owned(),
                    responsibility: cap_rec
                        .map(|c| responsibility_str(c.responsibility).to_owned())
                        .unwrap_or_else(|| "product".to_owned()),
                    control_refs: item.control_refs,
                    sample_ids: item.sample_ids,
                    period_end: item.period_end.to_string(),
                    signature_status: if item.signature.is_some() {
                        "verified".to_owned()
                    } else {
                        "unsigned".to_owned()
                    },
                }
            })
            .collect();

        let comp = state.as_ref();
        let retention = comp.map(|c| build_retention_summary(c, tenant_id));
        let mut legal_holds: Vec<LegalHoldEntry> = comp
            .map(|c| {
                c.pending_holds
                    .iter()
                    .filter(|h| h.organisation == tenant_id)
                    .map(|h| LegalHoldEntry {
                        hold_id: h.hold_id.clone(),
                        matter_ref: h.matter_ref.clone(),
                        reason: h.reason.clone(),
                        lifecycle: "pending_quorum".to_owned(),
                        created_by: h.created_by.clone(),
                        approvers: h.approvers.clone(),
                        created_at: h.created_at.clone(),
                        review_by: h.review_by.clone(),
                        notice_mode: "immediate".to_owned(),
                        scope_summary: h.target_ref.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();
        if let Some(c) = comp {
            legal_holds.extend(
                c.legal_holds
                    .iter()
                    .filter(|h| h.organisation == tenant_id)
                    .map(|h| LegalHoldEntry {
                        hold_id: h.hold_id.clone(),
                        matter_ref: h.matter_ref.clone(),
                        reason: h.reason.clone(),
                        lifecycle: hold_lifecycle_str(h.lifecycle).to_owned(),
                        created_by: h.created_by.clone(),
                        approvers: h.approvers.clone(),
                        created_at: h.created_at.to_string(),
                        review_by: h.review_by.to_string(),
                        notice_mode: hold_notice_str(h.notice).to_owned(),
                        scope_summary: if h.scope.pseudonyms.is_empty() {
                            h.scope.session_ids.join(", ")
                        } else {
                            h.scope.pseudonyms.join(", ")
                        },
                    }),
            );
        }

        let subject_requests = comp
            .map(|c| {
                c.subject_requests
                    .iter()
                    .filter(|r| r.organisation == tenant_id)
                    .map(|r| SubjectRequestEntry {
                        request_id: r.request_id.clone(),
                        kind: r.kind.clone(),
                        subject_ref: r.subject_ref.clone(),
                        status: match r.status {
                            SubjectRequestLifecycle::Executed => {
                                SubjectRequestStatus::Executed as i32
                            }
                            SubjectRequestLifecycle::PendingHeld => {
                                SubjectRequestStatus::PendingHeld as i32
                            }
                        },
                        hold_ids: r.hold_ids.clone(),
                        requested_at: r.requested_at.clone(),
                        detail: r.detail.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let connectors = comp
            .map(|c| {
                c.connectors
                    .iter()
                    .map(|cn| ComplianceConnectorEntry {
                        id: cn.id.clone(),
                        name: cn.name.clone(),
                        kind: cn.kind.clone(),
                        stability: cn.stability.clone(),
                        circuit_state: cn.circuit_state.clone(),
                        queued_items: cn.queued_items,
                        delivered_items: cn.delivered_items,
                        capture_ceiling: cn.capture_ceiling.clone(),
                        assurance_label: cn.assurance_label.clone(),
                        last_delivery_at: cn.last_delivery_at.clone(),
                        summary: cn.summary.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let reid_requests = comp
            .map(|c| {
                c.reid_requests
                    .iter()
                    .filter(|r| r.organisation == tenant_id)
                    .map(reid_to_proto)
                    .collect()
            })
            .unwrap_or_default();

        let disclosures: Vec<DisclosureLedgerEntry> = comp
            .map(|c| {
                c.disclosures
                    .iter()
                    .filter(|d| d.organisation == tenant_id)
                    .map(|d| DisclosureLedgerEntry {
                        id: d.id.clone(),
                        kind: d.kind.clone(),
                        actor: d.actor.clone(),
                        target_ref: d.target_ref.clone(),
                        legal_basis: clean_customer_basis(&d.legal_basis),
                        timestamp: d.timestamp.clone(),
                        quarter: d.quarter.clone(),
                        summary: d.summary.clone(),
                    })
                    .collect()
            })
            .unwrap_or_default();

        let disclosure_metrics = Some(compute_disclosure_metrics(&disclosures));
        let first_run = Some(build_first_run_state(&guard));

        GetComplianceWorkspaceResponse {
            frameworks,
            evidence_items,
            retention,
            legal_holds,
            subject_requests,
            connectors,
            reid_requests,
            disclosures,
            disclosure_metrics,
            first_run,
            revision: None,
        }
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

        let mut basis_map = BTreeMap::new();
        for p in &presets {
            basis_map.insert(
                *p,
                clean_customer_basis(&grdr_comply::preset_spec(*p).legal_basis),
            );
        }

        let resolved = resolve_retention_policy(&RetentionProposal {
            organisation: auth.tenant_id.clone(),
            presets: presets.clone(),
            ceiling_profile: profile,
            legal_basis: basis_map,
            override_legal_basis: req
                .override_legal_basis
                .clone()
                .filter(|s| !s.trim().is_empty()),
            content_days: None,
            activity_days: None,
            decision_days: None,
            audit_days: None,
            hot_days: None,
        })
        .map_err(comply_to_coded)?;

        let mut guard = self.inner.write().await;
        ensure_compliance_seeded(&mut guard, now);

        let next_mode = match profile {
            PrivacyCeilingProfile::Standard => IdentityMode::Named,
            PrivacyCeilingProfile::WorksCouncil => IdentityMode::Pseudonymous,
        };
        if guard.privacy.identity_mode == IdentityMode::Pseudonymous
            && next_mode == IdentityMode::Named
            && (!auth.confirmation.is_step_up()
                || req
                    .override_legal_basis
                    .as_deref()
                    .map(str::trim)
                    .is_none_or(str::is_empty))
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Downgrading privacy ceiling from works-council to standard requires step-up verification and a recorded legal basis.",
                "Provide override_legal_basis and step-up approval before switching off works-council pseudonymous mode.",
            ));
        }

        let actor = auth.principal_id.clone();
        guard.privacy.identity_mode = next_mode;
        if profile == PrivacyCeilingProfile::WorksCouncil {
            guard.privacy.user_risk_scoring = false;
        }

        if let Some(ref mut comp) = guard.surfaces.compliance {
            comp.privacy_profile = profile;
            comp.presets = presets;
            comp.override_legal_basis = req
                .override_legal_basis
                .clone()
                .filter(|s| !s.trim().is_empty());
            if let Some(cap) = req
                .capture_level
                .as_deref()
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                comp.capture_level = cap.to_owned();
            }
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
                    quarter: "2026-Q4".to_owned(),
                    summary: format!(
                        "Updated retention ({}d activity / {}d audit)",
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
                    "Privacy profile `{}` applied ({}d activity ceiling)",
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
}
