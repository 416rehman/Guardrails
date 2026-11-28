// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use uuid::Uuid;

use grdr_comply::{
    CaptureLevel, DrillDownAuditRecord, ErasureLegalBasis, EvidenceDataClass,
    ImpactAssessmentPackDoc, MonitoringCatalogueDoc, NoticeChangeState, NoticeLocale,
    OversightAssignment, OversightDecisionOutcome, OversightEventInput, OversightQualityReport,
    PackFieldReadSpec, PrivacyDocConfig, RecordOfProcessing, RetentionPolicy, RetentionPreset,
    RetentionProposal, RopaInput, RuleCatalogSummary, WorkerNoticeDoc, WorksAgreementAnnexDoc,
    compute_oversight_quality_report, exports::DEFAULT_PRIVACY_CONTACT,
    generate_impact_assessment_pack, generate_monitoring_catalogue, generate_ropa,
    generate_worker_notice, generate_works_agreement_annex, resolve_retention_policy,
    schedule_capture_change, try_default_registry,
};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{ApprovalState, AuditEntry, CodedError, FindingLifecycle, IntegrationHealthState};

use crate::store::StoreData;
use crate::store::surfaces_comply_helpers::{clean_customer_basis, comply_to_coded};
use crate::store::surfaces_types::{ComplianceGovernanceState, PendingCaptureChange};

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ServerPrivacyDocsBundle {
    pub(crate) monitoring_catalogue: MonitoringCatalogueDoc,
    pub(crate) worker_notice: WorkerNoticeDoc,
    pub(crate) dpia: ImpactAssessmentPackDoc,
    pub(crate) works_annex: WorksAgreementAnnexDoc,
}

fn resolve_policy_for_comp(
    comp: &ComplianceGovernanceState,
    tenant_id: &str,
) -> Result<RetentionPolicy, CodedError> {
    let mut basis_map = BTreeMap::new();
    let presets = if comp.presets.is_empty() {
        vec![RetentionPreset::Default]
    } else {
        comp.presets.clone()
    };
    for p in &presets {
        let spec = grdr_comply::preset_spec(*p).map_err(comply_to_coded)?;
        if spec.requires_recorded_basis {
            if let Some(basis) = comp
                .recorded_legal_bases
                .get(p)
                .cloned()
                .or_else(|| comp.override_legal_basis.clone())
            {
                basis_map.insert(*p, clean_customer_basis(&basis));
            }
        } else {
            let basis = comp
                .recorded_legal_bases
                .get(p)
                .cloned()
                .unwrap_or_else(|| clean_customer_basis(&spec.legal_basis));
            basis_map.insert(*p, basis);
        }
    }
    resolve_retention_policy(&RetentionProposal {
        organisation: tenant_id.to_owned(),
        presets,
        ceiling_profile: comp.privacy_profile,
        legal_basis: basis_map,
        override_legal_basis: comp.override_legal_basis.clone(),
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    })
    .map_err(comply_to_coded)
}

pub(crate) fn build_server_ropa_doc(
    data: &StoreData,
    comp: &ComplianceGovernanceState,
    tenant_id: &str,
    controller: &str,
    dpo: &str,
    now: Timestamp,
) -> Result<RecordOfProcessing, CodedError> {
    let registry = try_default_registry().map_err(comply_to_coded)?;
    let retention = resolve_policy_for_comp(comp, tenant_id)?;
    let subprocessors = data
        .integrations
        .iter()
        .filter(|i| i.state != IntegrationHealthState::NotConfigured)
        .map(|i| i.name.clone())
        .collect();
    generate_ropa(
        &RopaInput {
            organisation: tenant_id.to_owned(),
            controller_name: controller.to_owned(),
            dpo_contact: dpo.to_owned(),
            org_region: "local-deployment".to_owned(),
            judge_region: "local-only".to_owned(),
            capture_level: comp.capture_level.clone(),
            data_categories: vec![
                "pseudonymous-action-metadata".to_owned(),
                "signed-decision-receipts".to_owned(),
            ],
            recipients: vec!["authorised-security-reviewers".to_owned()],
            subprocessors,
            residual_erasure_basis: ErasureLegalBasis::Art17_3bLegalObligation,
            generated_at: now,
        },
        &retention,
        &registry,
    )
    .map_err(comply_to_coded)
}

pub(crate) fn build_server_privacy_docs(
    data: &StoreData,
    comp: &ComplianceGovernanceState,
    tenant_id: &str,
    locale: NoticeLocale,
    now: Timestamp,
) -> Result<ServerPrivacyDocsBundle, CodedError> {
    let rules: Vec<RuleCatalogSummary> = data
        .packs
        .iter()
        .flat_map(|pack| {
            pack.rules.iter().map(move |rule| {
                let mut reads = Vec::new();
                if !rule.matcher.action_classes.is_empty() {
                    reads.push(PackFieldReadSpec {
                        field_path: "action.class".to_owned(),
                        data_class: EvidenceDataClass::Structural,
                    });
                }
                if !rule.matcher.target_prefixes.is_empty()
                    || !rule.matcher.target_contains.is_empty()
                {
                    reads.push(PackFieldReadSpec {
                        field_path: "action.target_pattern".to_owned(),
                        data_class: EvidenceDataClass::Derived,
                    });
                }
                if !rule.matcher.agents.is_empty() {
                    reads.push(PackFieldReadSpec {
                        field_path: "session.agent".to_owned(),
                        data_class: EvidenceDataClass::Structural,
                    });
                }
                if rule.cedar.is_some() || reads.is_empty() {
                    reads.push(PackFieldReadSpec {
                        field_path: "receipt.verdict".to_owned(),
                        data_class: EvidenceDataClass::Derived,
                    });
                }
                let mut outputs = vec![
                    format!("mode:{}", rule.mode.label().to_ascii_lowercase()),
                    format!("grade:{}", rule.min_grade.label().to_ascii_lowercase()),
                ];
                if rule.locked {
                    outputs.push("locked".to_owned());
                }
                RuleCatalogSummary {
                    pack_id: pack.id.clone(),
                    rule_id: rule.id.clone(),
                    rule_sentence: rule.description.clone(),
                    reads,
                    outputs,
                    reader_roles: vec!["security-reviewer".to_owned()],
                }
            })
        })
        .collect();
    let policy = resolve_policy_for_comp(comp, tenant_id)?;
    let sched = schedule_capture_change(
        comp.privacy_profile,
        CaptureLevel::MetadataOnly,
        CaptureLevel::MetadataAndSignals,
        now,
    )
    .map_err(comply_to_coded)?;
    let effective_change_notice = match sched.schedule {
        NoticeChangeState::Scheduled { notice_days, .. } => {
            format!(
                "{notice_days}d prior notice for {:?} profile",
                comp.privacy_profile
            )
        }
        NoticeChangeState::Immediate => "immediate".to_owned(),
    };
    let exclusions = comp
        .exclusions
        .iter()
        .filter(|e| e.organisation == tenant_id)
        .map(|e| e.entry.clone())
        .collect();
    let co_approver_group = comp
        .co_approver_group
        .iter()
        .map(|m| m.trim().to_ascii_lowercase())
        .filter(|m| !m.is_empty())
        .collect();
    let cfg = PrivacyDocConfig {
        organisation: tenant_id.to_owned(),
        profile: comp.privacy_profile,
        capture_level: comp.capture_level.clone(),
        retention_summary: format!(
            "capture={} | profile={:?} | {}d activity / {}d audit / {}d max backup age-out",
            comp.capture_level,
            comp.privacy_profile,
            policy.activity_days,
            policy.audit_days,
            policy.backup_days_max
        ),
        exclusions,
        reader_roles: vec![(
            "privacy-officer".to_owned(),
            1,
            "dual-quorum + audit.access".to_owned(),
        )],
        privacy_contact: DEFAULT_PRIVACY_CONTACT.to_owned(),
        co_approver_group,
        effective_change_notice,
        is_annex_iii_deployer: true,
        recipients: vec!["security-reviewers".to_owned()],
        generated_at: now,
    };
    let monitoring_catalogue =
        generate_monitoring_catalogue(&cfg, rules, Vec::new()).map_err(comply_to_coded)?;
    let worker_notice = generate_worker_notice(&cfg, locale).map_err(comply_to_coded)?;
    let dpia = generate_impact_assessment_pack(&cfg).map_err(comply_to_coded)?;
    let works_annex = generate_works_agreement_annex(&cfg).map_err(comply_to_coded)?;
    Ok(ServerPrivacyDocsBundle {
        monitoring_catalogue,
        worker_notice,
        dpia,
        works_annex,
    })
}

pub(crate) fn build_server_oversight_doc(
    data: &StoreData,
    tenant_id: &str,
    now: Timestamp,
) -> Result<OversightQualityReport, CodedError> {
    let mut events = Vec::with_capacity(data.approvals.len());
    let mut expected_classes = BTreeSet::new();
    for apr in &data.approvals {
        let rc = format!("{:?}", apr.action_class).to_ascii_lowercase();
        expected_classes.insert(rc.clone());
        let outcome = match apr.state {
            ApprovalState::Pending { .. } => OversightDecisionOutcome::Pending,
            ApprovalState::Approved { .. } => OversightDecisionOutcome::Approved,
            ApprovalState::Denied { .. } => OversightDecisionOutcome::Denied,
            ApprovalState::Expired { .. } => OversightDecisionOutcome::TimedOut,
        };
        let latency_ms = match apr.state {
            ApprovalState::Approved { decided_at, .. }
            | ApprovalState::Denied { decided_at, .. } => u64::try_from(
                decided_at
                    .as_second()
                    .saturating_sub(apr.requested_at.as_second())
                    .max(0),
            )
            .unwrap_or(0)
            .saturating_mul(1_000),
            _ => 0,
        };
        let pending_age = match apr.state {
            ApprovalState::Pending { .. } => u64::try_from(
                now.as_second()
                    .saturating_sub(apr.requested_at.as_second())
                    .max(0),
            )
            .unwrap_or(0),
            _ => 0,
        };
        let cohort_size = count_oversight_reviewers(data);
        events.push(OversightEventInput {
            rule_id: apr.rule_id.clone(),
            rule_class: rc,
            queue: "default".to_owned(),
            group_name: Some("oversight-reviewers".to_owned()),
            group_member_count: Some(cohort_size),
            min_grade: apr.required_grade,
            effective_grade: apr.required_grade,
            outcome,
            latency_ms,
            pending_age_seconds: pending_age,
            has_written_justification: !apr.reason.trim().is_empty(),
        });
    }
    let expected: Vec<String> = expected_classes.into_iter().collect();
    let assignments: Vec<OversightAssignment> = Vec::new();
    compute_oversight_quality_report(tenant_id, &events, &assignments, &expected, now)
        .map_err(comply_to_coded)
}

fn count_oversight_reviewers(data: &StoreData) -> usize {
    let mut reviewers = BTreeSet::new();
    if let Some(ref comp) = data.surfaces.compliance {
        for member in &comp.co_approver_group {
            let norm = member.trim().to_ascii_lowercase();
            if !norm.is_empty() {
                reviewers.insert(norm);
            }
        }
        for hold in &comp.legal_holds {
            for a in &hold.approvers {
                let norm = a.trim().to_ascii_lowercase();
                if !norm.is_empty() {
                    reviewers.insert(norm);
                }
            }
        }
        for reid in &comp.reid_requests {
            for a in &reid.approvers {
                let norm = a.trim().to_ascii_lowercase();
                if !norm.is_empty() {
                    reviewers.insert(norm);
                }
            }
        }
    }
    for entry in &data.audit {
        if entry.kind.starts_with("approval.")
            || entry.kind.starts_with("review.")
            || entry.kind.starts_with("compliance.hold")
            || entry.kind.starts_with("privacy.reidentification")
        {
            let norm = entry.actor.trim().to_ascii_lowercase();
            if !norm.is_empty() {
                reviewers.insert(norm);
            }
        }
    }
    reviewers.len()
}

pub(crate) fn capture_level_str(level: CaptureLevel) -> &'static str {
    match level {
        CaptureLevel::MetadataOnly => "metadata-only",
        CaptureLevel::MetadataAndSignals => "metadata-and-signals",
        CaptureLevel::ContentGrantOnly => "content-grant-only",
    }
}

pub(crate) fn activate_due_capture_change(
    comp: &mut ComplianceGovernanceState,
    now: Timestamp,
) -> Option<PendingCaptureChange> {
    let pending = comp.pending_capture_change.as_ref()?;
    let effective_ts = pending.effective_at.parse::<Timestamp>().ok()?;
    if now < effective_ts {
        return None;
    }
    let activated = comp.pending_capture_change.take()?;
    comp.capture_level = activated.target_capture_level.clone();
    Some(activated)
}

pub(crate) fn activate_due_capture_and_audit(guard: &mut StoreData, now: Timestamp) -> bool {
    let activated = guard
        .surfaces
        .compliance
        .as_mut()
        .and_then(|c| activate_due_capture_change(c, now));
    let Some(pending) = activated else {
        return false;
    };
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
    true
}

pub(crate) fn extend_pending_capture_for_works_council(
    comp: &mut ComplianceGovernanceState,
    now: Timestamp,
) -> Result<Option<String>, CodedError> {
    let prev_cap = parse_capture_level(&comp.capture_level).unwrap_or(CaptureLevel::MetadataOnly);
    let Some(ref mut pending) = comp.pending_capture_change else {
        return Ok(None);
    };
    let target_cap = parse_capture_level(&pending.target_capture_level)?;
    let orig_req = pending.requested_at.parse::<Timestamp>().unwrap_or(now);
    let sched = schedule_capture_change(
        grdr_comply::PrivacyCeilingProfile::WorksCouncil,
        prev_cap,
        target_cap,
        orig_req,
    )
    .map_err(comply_to_coded)?;
    let note = match sched.schedule {
        NoticeChangeState::Scheduled {
            notice_days,
            announced_at,
            effective_at,
        } => {
            pending.effective_at = effective_at.to_string();
            pending.notice_rule =
                format!("{notice_days}d advance notice (announced {announced_at})");
            Some(format!(
                "; extended pending capture increase to {notice_days}d works-council notice until {effective_at}"
            ))
        }
        NoticeChangeState::Immediate => None,
    };
    Ok(note)
}

pub(crate) fn validate_live_incident_and_finding_refs(
    data: &StoreData,
    rec: &DrillDownAuditRecord,
) -> Result<(), CodedError> {
    if let Some(ref inc_id) = rec.incident_ref {
        let states = grdr_core::session::replay_session_states(&data.attempts, &data.receipts);
        let incidents = grdr_core::detect::correlate_incidents(&data.findings, &states);
        let valid_open = incidents
            .iter()
            .any(|inc| inc.id == *inc_id && inc.lifecycle != FindingLifecycle::Resolved);
        if !valid_open {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                format!("Incident `{inc_id}` was not found or is already resolved."),
                "Provide an active, unresolved incident ID.",
            ));
        }
    }
    if let Some(ref fnd_id) = rec.assigned_finding_id {
        let valid_open = data
            .findings
            .iter()
            .any(|f| f.id == *fnd_id && f.lifecycle != FindingLifecycle::Resolved);
        if !valid_open {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                format!("Finding `{fnd_id}` was not found or is already resolved."),
                "Provide an active, unresolved finding ID.",
            ));
        }
    }
    Ok(())
}

pub(crate) fn parse_capture_level(raw: &str) -> Result<CaptureLevel, CodedError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "metadata-only" | "metadata_only" => Ok(CaptureLevel::MetadataOnly),
        "metadata-and-signals" | "metadata_and_signals" => Ok(CaptureLevel::MetadataAndSignals),
        "content-grant-only" | "content_grant_only" => Ok(CaptureLevel::ContentGrantOnly),
        _ => Err(CodedError::new(
            CODE_INVALID_INPUT,
            format!("Unsupported capture level `{raw}`."),
            "Use `metadata-only`, `metadata-and-signals`, or `content-grant-only`.",
        )),
    }
}
