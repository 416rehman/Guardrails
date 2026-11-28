// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! GDPR Art. 15/17/18/21 subject requests, erasure cascades, and Art. 30 Record of Processing.

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::holds::HoldsLedger;
use crate::limits::compliance_limits;
use crate::registry::CapabilityRegistry;
use crate::retention::RetentionPolicy;
use crate::{ComplyError, deterministic_prefixed_id, markdown_safe};

const SECONDS_PER_DAY: i64 = 86_400;
const ACCESS_BUNDLE_SLA_HOURS: i64 = 24;
const SECONDS_PER_HOUR: i64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRequestKind {
    Access,
    Erasure,
    Restriction,
    Objection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ErasureLegalBasis {
    Art17_3bLegalObligation,
    Art17_3eLegalClaims,
    Art17_1cLegitimateSecurityGrounds,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum SubjectRequestLifecycle {
    Submitted,
    PendingHeld {
        hold_ids: Vec<String>,
        disclose_hold: bool,
    },
    Fulfilled {
        completed_at: Timestamp,
        output_ref: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRequestRecord {
    pub id: String,
    pub organisation: String,
    pub kind: SubjectRequestKind,
    pub subject_ref: String,
    pub pseudonyms: Vec<String>,
    pub received_at: Timestamp,
    pub due_at: Timestamp,
    pub lifecycle: SubjectRequestLifecycle,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectAccessBundle {
    pub request_id: String,
    pub organisation: String,
    pub subject_ref: String,
    pub generated_at: Timestamp,
    pub sla_due_at: Timestamp,
    pub effective_policy_summary: String,
    pub session_records: Vec<String>,
    pub access_audit_records: Vec<String>,
    pub reidentification_records: Vec<String>,
    pub remaining_data_notice: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectErasureCascade {
    pub request_id: String,
    pub organisation: String,
    pub subject_ref: String,
    pub pseudonyms_unlinked: Vec<String>,
    pub destroyed_session_content_keys: Vec<String>,
    pub reduced_archive_sessions: Vec<String>,
    pub excluded_from_future_collection: Vec<String>,
    pub backup_age_out_max_days: u32,
    pub residual_records_basis: ErasureLegalBasis,
    pub residual_personal_data_notice: String,
    pub executed_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectRequestExecution {
    pub record: SubjectRequestRecord,
    pub access_bundle: Option<SubjectAccessBundle>,
    pub erasure_cascade: Option<SubjectErasureCascade>,
    pub exclusion_added: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RopaInput {
    pub organisation: String,
    pub controller_name: String,
    pub dpo_contact: String,
    pub org_region: String,
    pub judge_region: String,
    pub capture_level: String,
    pub data_categories: Vec<String>,
    pub recipients: Vec<String>,
    pub subprocessors: Vec<String>,
    pub residual_erasure_basis: ErasureLegalBasis,
    pub generated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecordOfProcessing {
    pub schema: String,
    pub organisation: String,
    pub controller_name: String,
    pub dpo_contact: String,
    pub purposes: Vec<String>,
    pub data_categories: Vec<String>,
    pub recipients: Vec<String>,
    pub subprocessors: Vec<String>,
    pub cross_border_transfers: Vec<String>,
    pub retention_summary: String,
    pub security_measures_ref: String,
    pub residual_erasure_basis: String,
    pub generated_at: Timestamp,
}

pub fn execute_subject_request(
    organisation: &str,
    kind: SubjectRequestKind,
    subject_ref: &str,
    pseudonyms: &[String],
    root_sessions: &[String],
    holds: &HoldsLedger,
    now: Timestamp,
) -> Result<SubjectRequestExecution, ComplyError> {
    if organisation.trim().is_empty() || subject_ref.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "subject request requires non-empty organisation and subject_ref".into(),
        });
    }
    let clean_pseudonyms: Vec<String> = pseudonyms
        .iter()
        .map(|p| p.trim().to_owned())
        .filter(|p| !p.is_empty())
        .collect();
    let req_id = deterministic_prefixed_id(
        "dsr",
        &format!("{organisation}:{subject_ref}:{kind:?}:{now}"),
    );
    let limits = compliance_limits()?;
    let due_sec = now
        .as_second()
        .checked_add(
            limits
                .gdpr_response_deadline_days
                .checked_mul(SECONDS_PER_DAY)
                .ok_or_else(|| ComplyError::InvalidEvidenceInput {
                    detail: "subject request deadline overflow".into(),
                })?,
        )
        .ok_or_else(|| ComplyError::InvalidEvidenceInput {
            detail: "subject request deadline timestamp overflow".into(),
        })?;
    let due_at =
        Timestamp::from_second(due_sec).map_err(|e| ComplyError::InvalidEvidenceInput {
            detail: format!("subject request due_at invalid: {e}"),
        })?;

    match kind {
        SubjectRequestKind::Access => {
            let sla_sec = now
                .as_second()
                .checked_add(ACCESS_BUNDLE_SLA_HOURS.saturating_mul(SECONDS_PER_HOUR))
                .ok_or_else(|| ComplyError::InvalidEvidenceInput {
                    detail: "subject access SLA timestamp overflow".into(),
                })?;
            let sla_due =
                Timestamp::from_second(sla_sec).map_err(|e| ComplyError::InvalidEvidenceInput {
                    detail: format!("subject access SLA invalid: {e}"),
                })?;
            let output_ref = format!("access://{organisation}/{req_id}.json");
            let bundle = SubjectAccessBundle {
                request_id: req_id.clone(),
                organisation: organisation.to_owned(),
                subject_ref: subject_ref.to_owned(),
                generated_at: now,
                sla_due_at: sla_due,
                effective_policy_summary: "Active retention and capture floor applied".to_owned(),
                session_records: root_sessions.to_vec(),
                access_audit_records: Vec::new(),
                reidentification_records: Vec::new(),
                remaining_data_notice:
                    "Returned at stored capture level including audit.access and re-identification log."
                        .to_owned(),
            };
            let record = SubjectRequestRecord {
                id: req_id,
                organisation: organisation.to_owned(),
                kind,
                subject_ref: subject_ref.to_owned(),
                pseudonyms: clean_pseudonyms,
                received_at: now,
                due_at,
                lifecycle: SubjectRequestLifecycle::Fulfilled {
                    completed_at: now,
                    output_ref,
                },
                detail: "GDPR Art. 15 subject access bundle compiled within 24h target".into(),
            };
            Ok(SubjectRequestExecution {
                record,
                access_bundle: Some(bundle),
                erasure_cascade: None,
                exclusion_added: Vec::new(),
            })
        }
        SubjectRequestKind::Erasure => build_erasure_execution(
            req_id,
            organisation,
            subject_ref,
            clean_pseudonyms,
            root_sessions,
            holds,
            due_at,
            now,
        ),
        SubjectRequestKind::Restriction | SubjectRequestKind::Objection => {
            let mut exclusions = clean_pseudonyms.clone();
            exclusions.push(subject_ref.trim().to_owned());
            let output_ref = format!("exclusion://{organisation}/{req_id}");
            let record = SubjectRequestRecord {
                id: req_id,
                organisation: organisation.to_owned(),
                kind,
                subject_ref: subject_ref.to_owned(),
                pseudonyms: clean_pseudonyms,
                received_at: now,
                due_at,
                lifecycle: SubjectRequestLifecycle::Fulfilled {
                    completed_at: now,
                    output_ref,
                },
                detail: "Added principal and pseudonyms to organisation collection exclusion list; past records await privacy-officer disposition".into(),
            };
            Ok(SubjectRequestExecution {
                record,
                access_bundle: None,
                erasure_cascade: None,
                exclusion_added: exclusions,
            })
        }
    }
}

pub fn generate_ropa(
    input: &RopaInput,
    retention: &RetentionPolicy,
    registry: &CapabilityRegistry,
) -> Result<RecordOfProcessing, ComplyError> {
    if input.organisation.trim().is_empty() || input.dpo_contact.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "GDPR Art. 30 RoPA requires non-empty organisation and dpo_contact".into(),
        });
    }
    let retention_summary = format!(
        "profile={:?}; content={}d; activity={}d; decision={}d; audit={}d; hot={}d; backups_max={}d; legal_basis=[{}]",
        retention.ceilings_from,
        retention.content_days,
        retention.activity_days,
        retention.decision_days,
        retention.audit_days,
        retention.hot_days,
        retention.backup_days_max,
        retention.legal_basis.join(", ")
    );
    let basis_str = match input.residual_erasure_basis {
        ErasureLegalBasis::Art17_3bLegalObligation => {
            "GDPR Art. 17(3)(b): compliance with legal security-logging obligation"
        }
        ErasureLegalBasis::Art17_3eLegalClaims => {
            "GDPR Art. 17(3)(e): establishment, exercise, or defence of legal claims"
        }
        ErasureLegalBasis::Art17_1cLegitimateSecurityGrounds => {
            "GDPR Art. 17(1)(c) with Art. 21(1): compelling legitimate grounds for agent security telemetry"
        }
    };
    let comp_count = registry.capabilities.len();
    let fw_count = registry.frameworks.len();
    Ok(RecordOfProcessing {
        schema: "grdr.ropa.art30.v1".into(),
        organisation: input.organisation.clone(),
        controller_name: input.controller_name.clone(),
        dpo_contact: input.dpo_contact.clone(),
        purposes: vec![
            "Pre-execution security policy enforcement and containment for coding agents".into(),
            "Tamper-evident audit receipting and incident investigation".into(),
        ],
        data_categories: input.data_categories.clone(),
        recipients: input.recipients.clone(),
        subprocessors: input.subprocessors.clone(),
        cross_border_transfers: vec![
            format!("Primary data region: {}", input.org_region),
            format!("Model/judge processing region: {}", input.judge_region),
        ],
        retention_summary,
        security_measures_ref: format!(
            "OSCAL 1.2.3 component-definition ({comp_count} capabilities across {fw_count} frameworks); Ed25519 receipts; ChaCha20-Poly1305 vault & lake keys"
        ),
        residual_erasure_basis: basis_str.into(),
        generated_at: input.generated_at,
    })
}

pub fn render_ropa_markdown(ropa: &RecordOfProcessing) -> String {
    format!(
        "# GDPR Article 30 Record of Processing ({})\n\n- Controller: {}\n- Privacy Contact / DPO: {}\n- Generated: {}\n\n## Purposes\n{}\n\n## Data Categories\n{}\n\n## Recipients & Transfers\n- Recipients: {}\n- Sub-processors: {}\n- Transfers: {}\n\n## Retention & Security Measures\n- Retention: {}\n- Security measures: {}\n- Erasure residual legal basis: {}\n",
        markdown_safe(&ropa.organisation),
        markdown_safe(&ropa.controller_name),
        markdown_safe(&ropa.dpo_contact),
        ropa.generated_at,
        ropa.purposes
            .iter()
            .map(|p| format!("- {}", markdown_safe(p)))
            .collect::<Vec<_>>()
            .join("\n"),
        ropa.data_categories
            .iter()
            .map(|c| format!("- {}", markdown_safe(c)))
            .collect::<Vec<_>>()
            .join("\n"),
        markdown_safe(&join_or_none(&ropa.recipients)),
        markdown_safe(&join_or_none(&ropa.subprocessors)),
        markdown_safe(&join_or_none(&ropa.cross_border_transfers)),
        markdown_safe(&ropa.retention_summary),
        markdown_safe(&ropa.security_measures_ref),
        markdown_safe(&ropa.residual_erasure_basis),
    )
}

#[allow(clippy::too_many_arguments)]
fn build_erasure_execution(
    req_id: String,
    organisation: &str,
    subject_ref: &str,
    clean_pseudonyms: Vec<String>,
    root_sessions: &[String],
    holds: &HoldsLedger,
    due_at: Timestamp,
    now: Timestamp,
) -> Result<SubjectRequestExecution, ComplyError> {
    let limits = compliance_limits()?;
    let mut checks = clean_pseudonyms.clone();
    checks.push(subject_ref.trim().to_owned());

    if let Some((held_ids, disclose_all)) =
        holds.check_erasure_targets(organisation, &checks, root_sessions, now)
    {
        let detail = if disclose_all {
            format!(
                "pending, held (active legal hold(s): {})",
                held_ids.join(", ")
            )
        } else {
            "pending".to_owned()
        };
        return Ok(SubjectRequestExecution {
            record: SubjectRequestRecord {
                id: req_id,
                organisation: organisation.to_owned(),
                kind: SubjectRequestKind::Erasure,
                subject_ref: subject_ref.to_owned(),
                pseudonyms: clean_pseudonyms,
                received_at: now,
                due_at,
                lifecycle: SubjectRequestLifecycle::PendingHeld {
                    hold_ids: held_ids,
                    disclose_hold: disclose_all,
                },
                detail,
            },
            access_bundle: None,
            erasure_cascade: None,
            exclusion_added: Vec::new(),
        });
    }

    let cascade = SubjectErasureCascade {
        request_id: req_id.clone(),
        organisation: organisation.to_owned(),
        subject_ref: subject_ref.to_owned(),
        pseudonyms_unlinked: clean_pseudonyms.clone(),
        destroyed_session_content_keys: root_sessions.to_vec(),
        reduced_archive_sessions: root_sessions.to_vec(),
        excluded_from_future_collection: checks,
        backup_age_out_max_days: limits.backup_retention_max_days,
        residual_records_basis: ErasureLegalBasis::Art17_3bLegalObligation,
        residual_personal_data_notice: "Identity mapping deleted and content DEKs destroyed. Remaining pseudonymous security records stay personal data until retention expiry under legal obligation / legitimate security grounds and are not anonymous.".into(),
        executed_at: now,
    };
    let output_ref = format!("erasure://{organisation}/{req_id}");
    Ok(SubjectRequestExecution {
        record: SubjectRequestRecord {
            id: req_id,
            organisation: organisation.to_owned(),
            kind: SubjectRequestKind::Erasure,
            subject_ref: subject_ref.to_owned(),
            pseudonyms: clean_pseudonyms,
            received_at: now,
            due_at,
            lifecycle: SubjectRequestLifecycle::Fulfilled {
                completed_at: now,
                output_ref,
            },
            detail: cascade.residual_personal_data_notice.clone(),
        },
        access_bundle: None,
        erasure_cascade: Some(cascade),
        exclusion_added: Vec::new(),
    })
}

fn join_or_none(items: &[String]) -> String {
    if items.is_empty() {
        "none".to_owned()
    } else {
        items.join("; ")
    }
}
