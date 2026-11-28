// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;

use grdr_comply::{
    ComplyError, EvidenceItem, EvidencePipelineInput, EvidenceResult, HoldLifecycle, HoldNotice,
    PrivacyCeilingProfile, Responsibility, RetentionPolicy, RetentionPreset, RetentionProposal,
    default_compliance_pack_digest, default_evidence_queries, evaluate_evidence_item,
    format_utc_quarter, resolve_retention_policy, try_default_registry,
};
use grdr_crypto::{SigningKeypair, sha256_hex};
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{ApprovalGrade, CodedError};
use grdr_ports::LakeManifest;
use grdr_proto::api::overview::SetupStep;
use grdr_proto::api::surfaces::{
    DisclosureLedgerEntry, DisclosureMetrics, FirstRunState, ReidentificationRequestEntry,
    RetentionStateSummary,
};
use grdr_proto::common::ReidRequestStatus;

use super::StoreData;
use super::surfaces_types::{ComplianceGovernanceState, ReidLifecycle, ReidentificationRecord};

const SECONDS_PER_DAY: i64 = 86_400;
const MAX_COMPLIANCE_LAG_SECONDS: u64 = 300;

pub(crate) fn evaluate_live_evidence_with_lake(
    data: &StoreData,
    keypair: &SigningKeypair,
    organisation: &str,
    lake_result: Result<Option<&LakeManifest>, ()>,
    now: Timestamp,
) -> Result<Vec<EvidenceItem>, CodedError> {
    let registry = try_default_registry().map_err(comply_to_coded)?;
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
    let pipeline_lag_seconds = match lake_result {
        Ok(manifest) => compute_pipeline_lag_seconds(data, manifest, now),
        Err(()) => MAX_COMPLIANCE_LAG_SECONDS.saturating_add(1),
    };
    let pack_digest = compute_live_pack_digest(data).map_err(comply_to_coded)?;
    let pack_queries = default_evidence_queries().map_err(comply_to_coded)?;

    let specs = [
        ("cap.inventory.agents", total_agents, total_agents),
        ("cap.preexec.enforce", covered_agents, total_agents),
        ("cap.approval.graded", graded_approvals, total_approvals),
        ("cap.receipts.signed", signed_receipts, total_receipts),
    ];

    let mut out = Vec::new();
    for (cap, covered, total) in specs {
        let query = pack_queries
            .iter()
            .find(|q| q.capability == cap)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("Missing evidence query for capability `{cap}` in compliance pack."),
                    "Verify the signed compliance pack manifest contains all required evidence queries.",
                )
            })?;
        let query_bytes = serde_json::to_vec(query).map_err(|e| {
            CodedError::new(
                CODE_INVALID_INPUT,
                format!("Failed canonicalizing query `{cap}`: {e}"),
                "Inspect compliance evidence query definition.",
            )
        })?;
        let query_digest = sha256_hex(&query_bytes);
        let input = EvidencePipelineInput {
            organisation: organisation.to_owned(),
            period_start: start,
            period_end: now,
            pipeline_lag_seconds,
            max_lag_seconds: MAX_COMPLIANCE_LAG_SECONDS,
            total_observations: total,
            covered_observations: covered.min(total),
            sample_ids: data
                .receipts
                .iter()
                .take(4)
                .map(|r| r.receipt_id.clone())
                .collect(),
            query_digest,
            pack_digest: pack_digest.clone(),
            schema_rev: "v1alpha1".to_owned(),
        };
        let item =
            evaluate_evidence_item(query, &input, &registry, keypair).map_err(comply_to_coded)?;
        out.push(item);
    }
    Ok(out)
}

pub(crate) fn compute_pipeline_lag_seconds(
    data: &StoreData,
    lake_manifest: Option<&LakeManifest>,
    now: Timestamp,
) -> u64 {
    let receipted: BTreeSet<&str> = data
        .receipts
        .iter()
        .map(|r| r.attempt_id.as_str())
        .collect();
    let oldest_unreceipted = data
        .attempts
        .iter()
        .filter(|a| !receipted.contains(a.id.as_str()))
        .map(|a| a.timestamp.as_second())
        .min();
    let mut lag = oldest_unreceipted
        .map(|sec| u64::try_from(now.as_second().saturating_sub(sec).max(0)).unwrap_or(u64::MAX))
        .unwrap_or(0);

    if let Some(manifest) = lake_manifest
        && let Some(newest_receipt) = data.receipts.iter().map(|r| r.decided_at.as_second()).max()
    {
        let manifest_sec = manifest.created_at_ms / 1_000;
        if newest_receipt > manifest_sec {
            let lake_lag = u64::try_from(now.as_second().saturating_sub(manifest_sec).max(0))
                .unwrap_or(u64::MAX);
            lag = lag.max(lake_lag);
        }
    }
    lag
}

fn compute_live_pack_digest(data: &StoreData) -> Result<String, ComplyError> {
    let mut material = default_compliance_pack_digest()?;
    for pack in &data.packs {
        material.push(':');
        material.push_str(&pack.id);
        material.push('@');
        material.push_str(&pack.version);
    }
    Ok(sha256_hex(material.as_bytes()))
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
        let spec = match grdr_comply::preset_spec(*p) {
            Ok(spec) => spec,
            Err(err) => {
                return RetentionStateSummary {
                    organisation: organisation.to_owned(),
                    privacy_profile: profile_str(comp.privacy_profile).to_owned(),
                    presets: comp
                        .presets
                        .iter()
                        .map(|pr| preset_str(*pr).to_owned())
                        .collect(),
                    content_days: 0,
                    activity_days: 0,
                    decision_days: 0,
                    audit_days: 0,
                    hot_days: 0,
                    backup_days_max: 0,
                    legal_basis: Vec::new(),
                    conflict_note: err.to_string(),
                };
            }
        };
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

pub(crate) fn compute_disclosure_metrics(
    entries: &[DisclosureLedgerEntry],
    now: Timestamp,
) -> DisclosureMetrics {
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
        quarter: format_utc_quarter(now),
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
