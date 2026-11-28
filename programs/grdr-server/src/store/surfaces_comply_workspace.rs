// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_comply::try_default_registry;
use grdr_crypto::SigningKeypair;
use grdr_ports::LakeManifest;
use grdr_proto::api::surfaces::{
    ComplianceConnectorEntry, ComplianceEvidenceEntry, DisclosureLedgerEntry,
    FrameworkCoverageSummary, GetComplianceWorkspaceResponse, LegalHoldEntry, SubjectRequestEntry,
};
use grdr_proto::common::SubjectRequestStatus;

use crate::store::StoreData;
use crate::store::surfaces_comply_helpers::{
    build_first_run_state, build_retention_summary, clean_customer_basis,
    compute_disclosure_metrics, evaluate_live_evidence_with_lake, evidence_result_str,
    hold_lifecycle_str, hold_notice_str, reid_to_proto, responsibility_str,
};
use crate::store::surfaces_types::{ComplianceGovernanceState, SubjectRequestLifecycle};

pub(crate) fn format_framework_title(framework_id: &str, raw_title: &str) -> String {
    let lower = framework_id.to_ascii_lowercase();
    if lower.contains("nist") || lower.contains("omb") || lower.contains("fedramp") {
        grdr_comply::eo14434_display_label(raw_title)
    } else {
        raw_title.to_owned()
    }
}

pub(crate) fn assemble_workspace_response(
    guard: &StoreData,
    signing_key: &SigningKeypair,
    tenant_id: &str,
    lake_result: Result<Option<&LakeManifest>, ()>,
    persist_error: Option<&str>,
    now: Timestamp,
) -> GetComplianceWorkspaceResponse {
    let state = guard.surfaces.compliance.clone();
    let registry_res = try_default_registry();

    let mut error_note = persist_error.map(str::to_owned);
    let frameworks: Vec<FrameworkCoverageSummary> = match &registry_res {
        Ok(registry) => {
            let mut list = Vec::with_capacity(registry.frameworks.len());
            for id in registry.frameworks.keys() {
                match registry.framework_coverage(id) {
                    Ok(report) => {
                        let display_title = registry
                            .frameworks
                            .get(id)
                            .map(|f| format_framework_title(id, &f.title))
                            .unwrap_or_else(|| format_framework_title(id, &report.display_title));
                        let total = u32::try_from(report.total_controls).unwrap_or(u32::MAX);
                        let addressed =
                            u32::try_from(report.addressed_controls).unwrap_or(u32::MAX);
                        let pct = addressed
                            .saturating_mul(100)
                            .checked_div(total)
                            .unwrap_or(0);
                        list.push(FrameworkCoverageSummary {
                            framework_id: report.framework_id,
                            display_title,
                            total_controls: total,
                            addressed_controls: addressed,
                            coverage_percent: pct,
                        });
                    }
                    Err(err) => {
                        if error_note.is_none() {
                            error_note = Some(err.to_string());
                        }
                    }
                }
            }
            list
        }
        Err(err) => {
            if error_note.is_none() {
                error_note = Some(err.to_string());
            }
            Vec::new()
        }
    };

    let evidence_items = match (
        &registry_res,
        evaluate_live_evidence_with_lake(guard, signing_key, tenant_id, lake_result, now),
    ) {
        (Ok(registry), Ok(items)) => items
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
            .collect(),
        (Err(err), _) => {
            let msg = err.to_string();
            if error_note.is_none() {
                error_note = Some(msg.clone());
            }
            vec![ComplianceEvidenceEntry {
                id: "ev-compliance-pack-error".to_owned(),
                capability: "cap.compliance.pack".to_owned(),
                statement: format!("Compliance evidence unavailable: {msg}"),
                result: "not-evaluable".to_owned(),
                responsibility: "operator".to_owned(),
                control_refs: Vec::new(),
                sample_ids: Vec::new(),
                period_end: now.to_string(),
                signature_status: "unverified".to_owned(),
            }]
        }
        (Ok(_), Err(err)) => {
            if error_note.is_none() {
                error_note = Some(err.message.clone());
            }
            vec![ComplianceEvidenceEntry {
                id: "ev-live-evidence-error".to_owned(),
                capability: "cap.compliance.evidence".to_owned(),
                statement: format!("Live compliance evidence unavailable: {}", err.message),
                result: "not-evaluable".to_owned(),
                responsibility: "operator".to_owned(),
                control_refs: Vec::new(),
                sample_ids: Vec::new(),
                period_end: now.to_string(),
                signature_status: "unverified".to_owned(),
            }]
        }
    };

    let comp = state.as_ref();
    let retention = comp.map(|c| {
        let mut r = build_retention_summary(c, tenant_id);
        if let Some(ref note) = error_note {
            if r.conflict_note.is_empty() {
                r.conflict_note = note.clone();
            } else {
                r.conflict_note = format!("{}; {note}", r.conflict_note);
            }
        }
        r
    });
    let legal_holds = comp
        .map(|c| collect_legal_holds(c, tenant_id))
        .unwrap_or_default();
    let subject_requests = comp
        .map(|c| collect_subject_requests(c, tenant_id))
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

    let disclosure_metrics = Some(compute_disclosure_metrics(&disclosures, now));
    let first_run = Some(build_first_run_state(guard));

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

fn collect_legal_holds(c: &ComplianceGovernanceState, tenant_id: &str) -> Vec<LegalHoldEntry> {
    let mut legal_holds: Vec<LegalHoldEntry> = c
        .pending_holds
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
        .collect();
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
    legal_holds
}

fn collect_subject_requests(
    c: &ComplianceGovernanceState,
    tenant_id: &str,
) -> Vec<SubjectRequestEntry> {
    c.subject_requests
        .iter()
        .filter(|r| r.organisation == tenant_id)
        .map(|r| SubjectRequestEntry {
            request_id: r.request_id.clone(),
            kind: r.kind.clone(),
            subject_ref: if r.status == SubjectRequestLifecycle::Executed && r.kind == "erasure" {
                "[erased]".to_owned()
            } else {
                r.subject_ref.clone()
            },
            status: match r.status {
                SubjectRequestLifecycle::Executed => SubjectRequestStatus::Executed as i32,
                SubjectRequestLifecycle::PendingHeld => SubjectRequestStatus::PendingHeld as i32,
            },
            hold_ids: r.hold_ids.clone(),
            requested_at: r.requested_at.clone(),
            detail: r.detail.clone(),
        })
        .collect()
}
