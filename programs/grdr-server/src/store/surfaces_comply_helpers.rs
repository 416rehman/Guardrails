// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;

use grdr_comply::{
    ComplyError, EvidenceDataClass, EvidenceItem, EvidencePipelineInput, EvidenceQuery,
    EvidenceResult, FieldRead, HoldLifecycle, HoldNotice, PrivacyCeilingProfile, Responsibility,
    RetentionPolicy, RetentionPreset, RetentionProposal, default_registry, evaluate_evidence_item,
    resolve_retention_policy,
};
use grdr_crypto::{SigningKeypair, sha256_hex};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{ApprovalGrade, CodedError};
use grdr_proto::api::overview::SetupStep;
use grdr_proto::api::surfaces::{
    DisclosureLedgerEntry, DisclosureMetrics, FirstRunState, ReidentificationRequestEntry,
    RetentionStateSummary,
};
use grdr_proto::common::ReidRequestStatus;

use super::StoreData;
use super::surfaces_types::{ComplianceGovernanceState, ReidLifecycle, ReidentificationRecord};

const SECONDS_PER_DAY: i64 = 86_400;

pub(crate) fn evaluate_live_evidence(
    data: &StoreData,
    keypair: &SigningKeypair,
    organisation: &str,
    now: Timestamp,
) -> Vec<EvidenceItem> {
    let registry = default_registry();
    let total_agents =
        u64::try_from(data.devices.iter().map(|d| d.agents.len()).sum::<usize>()).unwrap_or(0);
    let covered_agents = u64::try_from(
        data.devices
            .iter()
            .flat_map(|d| d.agents.iter())
            .filter(|a| a.hook_installed)
            .count(),
    )
    .unwrap_or(0);
    let total_receipts = u64::try_from(data.receipts.len()).unwrap_or(0);
    let signed_receipts = u64::try_from(
        data.receipts
            .iter()
            .filter(|r| r.signature.is_some() && r.signature_verified != Some(false))
            .count(),
    )
    .unwrap_or(0);
    let total_approvals =
        u64::try_from(data.approvals.len().saturating_add(data.grants.len())).unwrap_or(0);
    let graded_approvals = u64::try_from(
        data.grants.len().saturating_add(
            data.approvals
                .iter()
                .filter(|a| !matches!(a.required_grade, ApprovalGrade::G0))
                .count(),
        ),
    )
    .unwrap_or(0);
    let start =
        Timestamp::from_second(now.as_second().saturating_sub(SECONDS_PER_DAY)).unwrap_or(now);

    let specs = [
        ("cap.inventory.agents", total_agents, total_agents),
        ("cap.preexec.enforce", covered_agents, total_agents),
        ("cap.approval.graded", graded_approvals, total_approvals),
        ("cap.receipts.signed", signed_receipts, total_receipts),
    ];

    let mut out = Vec::new();
    for (cap, covered, total) in specs {
        let query = EvidenceQuery {
            id: format!("q.{cap}"),
            version: "1.0.0".to_owned(),
            capability: cap.to_owned(),
            reads: vec![FieldRead {
                field_path: "decision.verdict".to_owned(),
                data_class: EvidenceDataClass::Derived,
            }],
            max_class: EvidenceDataClass::Derived,
            group_by: vec!["capability".to_owned(), "verdict".to_owned()],
        };
        let input = EvidencePipelineInput {
            organisation: organisation.to_owned(),
            period_start: start,
            period_end: now,
            pipeline_lag_seconds: 12,
            max_lag_seconds: 300,
            total_observations: total,
            covered_observations: covered.min(total),
            sample_ids: data
                .receipts
                .iter()
                .take(4)
                .map(|r| r.receipt_id.clone())
                .collect(),
            query_digest: sha256_hex(cap.as_bytes()),
            pack_digest: sha256_hex(b"pack-essentials-slice0"),
            schema_rev: "v1alpha1".to_owned(),
        };
        if let Ok(item) = evaluate_evidence_item(&query, &input, &registry, keypair) {
            out.push(item);
        }
    }
    out
}

pub(crate) fn clean_customer_basis(raw: &str) -> String {
    raw.replace(" (D-51 baseline)", "")
        .replace(" (D-51)", "")
        .replace("(D-51)", "")
        .trim()
        .to_owned()
}

pub(crate) fn build_retention_summary(
    comp: &ComplianceGovernanceState,
    organisation: &str,
) -> RetentionStateSummary {
    let mut basis_map = BTreeMap::new();
    for p in &comp.presets {
        basis_map.insert(
            *p,
            clean_customer_basis(&grdr_comply::preset_spec(*p).legal_basis),
        );
    }
    match resolve_retention_policy(&RetentionProposal {
        organisation: organisation.to_owned(),
        presets: comp.presets.clone(),
        ceiling_profile: comp.privacy_profile,
        legal_basis: basis_map,
        override_legal_basis: comp.override_legal_basis.clone(),
        content_days: None,
        activity_days: None,
        decision_days: None,
        audit_days: None,
        hot_days: None,
    }) {
        Ok(policy) => retention_summary_from_policy(&policy),
        Err(err) => RetentionStateSummary {
            organisation: organisation.to_owned(),
            privacy_profile: profile_str(comp.privacy_profile).to_owned(),
            presets: comp
                .presets
                .iter()
                .map(|p| preset_str(*p).to_owned())
                .collect(),
            content_days: 30,
            activity_days: 90,
            decision_days: 396,
            audit_days: 396,
            hot_days: 30,
            backup_days_max: 35,
            legal_basis: Vec::new(),
            conflict_note: err.to_string(),
        },
    }
}

pub(crate) fn retention_summary_from_policy(policy: &RetentionPolicy) -> RetentionStateSummary {
    RetentionStateSummary {
        organisation: policy.organisation.clone(),
        privacy_profile: profile_str(policy.ceilings_from).to_owned(),
        presets: policy
            .presets
            .iter()
            .map(|p| preset_str(*p).to_owned())
            .collect(),
        content_days: policy.content_days,
        activity_days: policy.activity_days,
        decision_days: policy.decision_days,
        audit_days: policy.audit_days,
        hot_days: policy.hot_days,
        backup_days_max: policy.backup_days_max,
        legal_basis: policy
            .legal_basis
            .iter()
            .map(|b| clean_customer_basis(b))
            .collect(),
        conflict_note: String::new(),
    }
}

pub(crate) fn compute_disclosure_metrics(entries: &[DisclosureLedgerEntry]) -> DisclosureMetrics {
    let mut reids: u32 = 0;
    let mut holds: u32 = 0;
    let mut erasures: u32 = 0;
    let mut exports: u32 = 0;
    for entry in entries {
        match entry.kind.as_str() {
            "reidentification" => reids = reids.saturating_add(1),
            "legal_hold" => holds = holds.saturating_add(1),
            "erasure" => erasures = erasures.saturating_add(1),
            "export" => exports = exports.saturating_add(1),
            _ => {}
        }
    }
    DisclosureMetrics {
        quarter: "2026-Q4".to_owned(),
        total_reidentifications: reids,
        total_holds: holds,
        total_erasures: erasures,
        total_exports: exports,
    }
}

pub(crate) fn build_first_run_state(data: &StoreData) -> FirstRunState {
    let fr = &data.surfaces.first_run;
    let agent_count = data.devices.iter().map(|d| d.agents.len()).sum::<usize>();
    let hook_count = data
        .devices
        .iter()
        .flat_map(|d| d.agents.iter())
        .filter(|a| a.hook_installed)
        .count();
    let rule_count = data.packs.iter().map(|p| p.rules.len()).sum::<usize>();

    let steps = vec![
        SetupStep {
            id: "scan-agents".to_owned(),
            label: "Read-only agent scan completed".to_owned(),
            done: true,
            detail: format!("{agent_count} local AI harnesses discovered"),
        },
        SetupStep {
            id: "stage-baseline".to_owned(),
            label: "Essentials protection rules staged".to_owned(),
            done: true,
            detail: format!("{rule_count} rules loaded with tamper locks"),
        },
        SetupStep {
            id: "signing-ready".to_owned(),
            label: "Local Ed25519 receipt signing ready".to_owned(),
            done: true,
            detail: "Every action writes a signed decision receipt".to_owned(),
        },
        SetupStep {
            id: "confirm-profile".to_owned(),
            label: "Confirm endpoint protection profile".to_owned(),
            done: fr.confirmed,
            detail: format!(
                "Selected {} profile for enrolled hosts",
                if fr.selected_profile == "protected" {
                    "Protected"
                } else {
                    "User mode"
                }
            ),
        },
        SetupStep {
            id: "verify-hooks".to_owned(),
            label: "Prove pre-execution hooks in active session".to_owned(),
            done: fr.confirmed && hook_count > 0,
            detail: format!("{hook_count} of {agent_count} agents guarded by hooks"),
        },
        SetupStep {
            id: "step-up-biometric".to_owned(),
            label: "Enable OS step-up approval prompt".to_owned(),
            done: fr.step_up_enabled,
            detail: "Touch ID / Windows Hello / polkit verification".to_owned(),
        },
    ];

    FirstRunState {
        selected_profile: fr.selected_profile.clone(),
        confirmed: fr.confirmed,
        step_up_enabled: fr.step_up_enabled,
        steps,
    }
}

pub(crate) fn reid_to_proto(r: &ReidentificationRecord) -> ReidentificationRequestEntry {
    ReidentificationRequestEntry {
        request_id: r.request_id.clone(),
        pseudonym_id: r.pseudonym_id.clone(),
        requester: r.requester.clone(),
        reason: r.reason.clone(),
        legal_basis: r.legal_basis.clone(),
        status: match r.status {
            ReidLifecycle::PendingQuorum => ReidRequestStatus::PendingQuorum as i32,
            ReidLifecycle::Approved => ReidRequestStatus::Approved as i32,
            ReidLifecycle::Denied => ReidRequestStatus::Denied as i32,
        },
        approvers: r.approvers.clone(),
        required_approvals: 2,
        resolved_identity: r.resolved_identity.clone(),
        created_at: r.created_at.clone(),
        resolved_at: r.resolved_at.clone(),
    }
}

pub(crate) fn parse_privacy_profile(raw: &str) -> Result<PrivacyCeilingProfile, CodedError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "standard" => Ok(PrivacyCeilingProfile::Standard),
        "works-council" | "works_council" => Ok(PrivacyCeilingProfile::WorksCouncil),
        _ => Err(CodedError::new(
            CODE_INVALID_INPUT,
            format!("Unsupported privacy profile `{raw}`."),
            "Select `standard` or `works-council`.",
        )),
    }
}

pub(crate) fn parse_retention_preset(raw: &str) -> Result<RetentionPreset, CodedError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "default" => Ok(RetentionPreset::Default),
        "eu-ai-act-deployer" => Ok(RetentionPreset::EuAiActDeployer),
        "pci-dss-4" => Ok(RetentionPreset::PciDss4),
        "hipaa" => Ok(RetentionPreset::Hipaa),
        "nydfs-500" => Ok(RetentionPreset::Nydfs500),
        "colorado-adm" => Ok(RetentionPreset::ColoradoAdm),
        "sox-itgc" => Ok(RetentionPreset::SoxItgc),
        _ => Err(CodedError::new(
            CODE_INVALID_INPUT,
            format!("Unsupported retention preset `{raw}`."),
            "Pick default, eu-ai-act-deployer, pci-dss-4, hipaa, nydfs-500, colorado-adm, or sox-itgc.",
        )),
    }
}

pub(crate) fn hold_lifecycle_str(h: HoldLifecycle) -> &'static str {
    match h {
        HoldLifecycle::Active => "active",
        HoldLifecycle::ReviewOverdue => "review_overdue",
        HoldLifecycle::Released => "released",
    }
}

pub(crate) fn hold_notice_str(n: HoldNotice) -> &'static str {
    match n {
        HoldNotice::Immediate => "immediate",
        HoldNotice::Deferred { .. } => "deferred",
    }
}

pub(crate) fn evidence_result_str(r: EvidenceResult) -> &'static str {
    match r {
        EvidenceResult::Met => "met",
        EvidenceResult::Partial => "partial",
        EvidenceResult::NotMet => "not-met",
        EvidenceResult::NotEvaluable => "not-evaluable",
    }
}

pub(crate) fn responsibility_str(r: Responsibility) -> &'static str {
    match r {
        Responsibility::Product => "product",
        Responsibility::Operator => "operator",
        Responsibility::Customer => "customer",
    }
}

pub(crate) fn comply_to_coded(err: ComplyError) -> CodedError {
    CodedError::new(
        CODE_INVALID_INPUT,
        err.to_string(),
        "Check privacy ceiling, legal basis, or dual-approver requirements.",
    )
}

fn profile_str(profile: PrivacyCeilingProfile) -> &'static str {
    match profile {
        PrivacyCeilingProfile::Standard => "standard",
        PrivacyCeilingProfile::WorksCouncil => "works-council",
    }
}

fn preset_str(preset: RetentionPreset) -> &'static str {
    match preset {
        RetentionPreset::Default => "default",
        RetentionPreset::EuAiActDeployer => "eu-ai-act-deployer",
        RetentionPreset::PciDss4 => "pci-dss-4",
        RetentionPreset::Hipaa => "hipaa",
        RetentionPreset::Nydfs500 => "nydfs-500",
        RetentionPreset::ColoradoAdm => "colorado-adm",
        RetentionPreset::SoxItgc => "sox-itgc",
    }
}
