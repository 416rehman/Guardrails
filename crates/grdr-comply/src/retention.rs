// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Retention presets, privacy ceilings, conflict resolution, and legal holds (`D-57`).

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ComplyError;

const ABS_MAX_CONTENT_DAYS: u32 = 365;
const ABS_MAX_OTHER_DAYS: u32 = 2555;
const ABS_MAX_BACKUP_DAYS: u32 = 35;
const WORKS_COUNCIL_MAX_ACTIVITY_DAYS: u32 = 90;
const WORKS_COUNCIL_MAX_CONTENT_DAYS: u32 = 30;
const WORKS_COUNCIL_MAX_DECISION_DAYS: u32 = 396;
const WORKS_COUNCIL_MAX_AUDIT_DAYS: u32 = 396;
const MAX_HOLD_REVIEW_SECONDS: i64 = 365 * 86_400;
const MAX_DEFERRED_NOTICE_SECONDS: i64 = 90 * 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum RetentionPreset {
    Default,
    EuAiActDeployer,
    PciDss4,
    Hipaa,
    Nydfs500,
    ColoradoAdm,
    SoxItgc,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyCeilingProfile {
    Standard,
    WorksCouncil,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PresetSpec {
    pub preset: RetentionPreset,
    pub clause_id: String,
    pub content_days: u32,
    pub activity_days: u32,
    pub decision_days: u32,
    pub audit_days: u32,
    pub hot_days: u32,
    pub legal_basis: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionProposal {
    pub organisation: String,
    pub presets: Vec<RetentionPreset>,
    pub ceiling_profile: PrivacyCeilingProfile,
    pub legal_basis: BTreeMap<RetentionPreset, String>,
    pub content_days: Option<u32>,
    pub activity_days: Option<u32>,
    pub decision_days: Option<u32>,
    pub audit_days: Option<u32>,
    pub hot_days: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub organisation: String,
    pub content_days: u32,
    pub activity_days: u32,
    pub decision_days: u32,
    pub audit_days: u32,
    pub hot_days: u32,
    pub backup_days_max: u32,
    pub presets: Vec<RetentionPreset>,
    pub legal_basis: Vec<String>,
    pub ceilings_from: PrivacyCeilingProfile,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldLifecycle {
    Active,
    ReviewOverdue,
    Released,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HoldNotice {
    Immediate,
    Deferred { until: Timestamp, renewals: u32 },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldScope {
    pub pseudonyms: Vec<String>,
    pub session_ids: Vec<String>,
    pub incident_id: Option<String>,
    pub classes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hold {
    pub hold_id: String,
    pub organisation: String,
    pub scope: HoldScope,
    pub matter_ref: String,
    pub reason: String,
    pub created_by: String,
    pub approvers: Vec<String>,
    pub created_at: Timestamp,
    pub review_by: Timestamp,
    pub notice: HoldNotice,
    pub lifecycle: HoldLifecycle,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum HoldCheckResult {
    Clear,
    Held { hold_ids: Vec<String> },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoldReviewFinding {
    pub hold_id: String,
    pub matter_ref: String,
    pub review_by: Timestamp,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ErasureOutcome {
    Executed {
        subject_ref: String,
    },
    PendingHeld {
        subject_ref: String,
        hold_ids: Vec<String>,
        disclose_hold: bool,
    },
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct HoldsLedger {
    pub holds: Vec<Hold>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlaceHoldInput {
    pub organisation: String,
    pub scope: HoldScope,
    pub matter_ref: String,
    pub reason: String,
    pub created_by: String,
    pub approvers: Vec<String>,
    pub created_at: Timestamp,
    pub review_by: Timestamp,
    pub notice: HoldNotice,
}

pub fn preset_spec(preset: RetentionPreset) -> PresetSpec {
    match preset {
        RetentionPreset::Default => PresetSpec {
            preset,
            clause_id: "default (D-51 baseline)".into(),
            content_days: 30,
            activity_days: 184,
            decision_days: 396,
            audit_days: 396,
            hot_days: 30,
            legal_basis: "Security monitoring baseline (D-51)".into(),
        },
        RetentionPreset::EuAiActDeployer => PresetSpec {
            preset,
            clause_id: "eu-ai-act-deployer (Art. 26(6))".into(),
            content_days: 30,
            activity_days: 184,
            decision_days: 396,
            audit_days: 396,
            hot_days: 30,
            legal_basis: "EU AI Act Art. 26(6) six-month log retention".into(),
        },
        RetentionPreset::PciDss4 => PresetSpec {
            preset,
            clause_id: "pci-dss-4 (Req. 10.5.1: 12 months activity, 3 months hot)".into(),
            content_days: 30,
            activity_days: 365,
            decision_days: 396,
            audit_days: 396,
            hot_days: 90,
            legal_basis: "PCI DSS v4.0.1 Req. 10.5.1".into(),
        },
        RetentionPreset::Hipaa => PresetSpec {
            preset,
            clause_id: "hipaa (45 CFR 164.316(b)(2): 6 years)".into(),
            content_days: 30,
            activity_days: 365,
            decision_days: 2190,
            audit_days: 2190,
            hot_days: 30,
            legal_basis: "HIPAA 45 CFR 164.316(b)(2)".into(),
        },
        RetentionPreset::Nydfs500 => PresetSpec {
            preset,
            clause_id: "nydfs-500 (23 NYCRR 500.06: 3y/5y)".into(),
            content_days: 30,
            activity_days: 1095,
            decision_days: 1825,
            audit_days: 1825,
            hot_days: 30,
            legal_basis: "23 NYCRR 500.06".into(),
        },
        RetentionPreset::ColoradoAdm => PresetSpec {
            preset,
            clause_id: "colorado-adm (SB26-189: 3 years decisions)".into(),
            content_days: 30,
            activity_days: 184,
            decision_days: 1095,
            audit_days: 1095,
            hot_days: 30,
            legal_basis: "Colorado SB26-189 decision record retention".into(),
        },
        RetentionPreset::SoxItgc => PresetSpec {
            preset,
            clause_id: "sox-itgc (7 years audit)".into(),
            content_days: 30,
            activity_days: 184,
            decision_days: 2555,
            audit_days: 2555,
            hot_days: 30,
            legal_basis: "SOX ITGC seven-year audit retention".into(),
        },
    }
}

pub fn resolve_retention_policy(
    proposal: &RetentionProposal,
) -> Result<RetentionPolicy, ComplyError> {
    let presets = if proposal.presets.is_empty() {
        vec![RetentionPreset::Default]
    } else {
        proposal.presets.clone()
    };

    let mut floor_content: (u32, String) = (0, String::new());
    let mut floor_activity: (u32, String) = (0, String::new());
    let mut floor_decision: (u32, String) = (0, String::new());
    let mut floor_audit: (u32, String) = (0, String::new());
    let mut floor_hot: (u32, String) = (0, String::new());
    let mut basis_list = Vec::new();

    for preset in &presets {
        let spec = preset_spec(*preset);
        if *preset != RetentionPreset::Default {
            let recorded = proposal
                .legal_basis
                .get(preset)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let Some(basis_text) = recorded else {
                return Err(ComplyError::MissingLegalBasis(spec.clause_id));
            };
            basis_list.push(format!("{}: {}", spec.clause_id, basis_text));
        } else {
            basis_list.push(spec.legal_basis.clone());
        }

        let effective_activity_floor = if *preset == RetentionPreset::Default
            && proposal.ceiling_profile == PrivacyCeilingProfile::WorksCouncil
        {
            WORKS_COUNCIL_MAX_ACTIVITY_DAYS
        } else {
            spec.activity_days
        };

        update_floor(&mut floor_content, spec.content_days, &spec.clause_id);
        update_floor(
            &mut floor_activity,
            effective_activity_floor,
            &spec.clause_id,
        );
        update_floor(&mut floor_decision, spec.decision_days, &spec.clause_id);
        update_floor(&mut floor_audit, spec.audit_days, &spec.clause_id);
        update_floor(&mut floor_hot, spec.hot_days, &spec.clause_id);
    }

    let (ceil_content, ceil_activity, ceil_decision, ceil_audit, ceil_clause) = match proposal
        .ceiling_profile
    {
        PrivacyCeilingProfile::Standard => (
            ABS_MAX_CONTENT_DAYS,
            ABS_MAX_OTHER_DAYS,
            ABS_MAX_OTHER_DAYS,
            ABS_MAX_OTHER_DAYS,
            "standard-absolute-ceiling (1y content / 7y logs)",
        ),
        PrivacyCeilingProfile::WorksCouncil => (
            WORKS_COUNCIL_MAX_CONTENT_DAYS,
            WORKS_COUNCIL_MAX_ACTIVITY_DAYS,
            WORKS_COUNCIL_MAX_DECISION_DAYS,
            WORKS_COUNCIL_MAX_AUDIT_DAYS,
            "works-council (BetrVG s.87(1) no.6: max 90d activity / 30d content / 13mo decision)",
        ),
    };

    check_floor_ceiling("content_days", &floor_content, ceil_content, ceil_clause)?;
    check_floor_ceiling("activity_days", &floor_activity, ceil_activity, ceil_clause)?;
    check_floor_ceiling("decision_days", &floor_decision, ceil_decision, ceil_clause)?;
    check_floor_ceiling("audit_days", &floor_audit, ceil_audit, ceil_clause)?;

    let content_days = apply_override(
        "content_days",
        proposal.content_days,
        &floor_content,
        ceil_content,
        ceil_clause,
    )?;
    let activity_days = apply_override(
        "activity_days",
        proposal.activity_days,
        &floor_activity,
        ceil_activity,
        ceil_clause,
    )?;
    let decision_days = apply_override(
        "decision_days",
        proposal.decision_days,
        &floor_decision,
        ceil_decision,
        ceil_clause,
    )?;
    let audit_days = apply_override(
        "audit_days",
        proposal.audit_days,
        &floor_audit,
        ceil_audit,
        ceil_clause,
    )?;
    let hot_days = proposal.hot_days.unwrap_or(floor_hot.0).max(floor_hot.0);

    Ok(RetentionPolicy {
        organisation: proposal.organisation.clone(),
        content_days,
        activity_days,
        decision_days,
        audit_days,
        hot_days,
        backup_days_max: ABS_MAX_BACKUP_DAYS,
        presets,
        legal_basis: basis_list,
        ceilings_from: proposal.ceiling_profile,
    })
}

fn update_floor(current: &mut (u32, String), candidate_days: u32, clause: &str) {
    if candidate_days > current.0 {
        *current = (candidate_days, clause.to_owned());
    }
}

fn check_floor_ceiling(
    field: &str,
    floor: &(u32, String),
    ceiling_days: u32,
    ceiling_clause: &str,
) -> Result<(), ComplyError> {
    if floor.0 > ceiling_days {
        return Err(ComplyError::RetentionConflict {
            floor_clause: floor.1.clone(),
            ceiling_clause: ceiling_clause.to_owned(),
            detail: format!(
                "{field} floor {}d exceeds ceiling {}d",
                floor.0, ceiling_days
            ),
        });
    }
    Ok(())
}

fn apply_override(
    field: &str,
    requested: Option<u32>,
    floor: &(u32, String),
    ceiling_days: u32,
    ceiling_clause: &str,
) -> Result<u32, ComplyError> {
    let Some(val) = requested else {
        return Ok(floor.0);
    };
    if val < floor.0 {
        return Err(ComplyError::RetentionConflict {
            floor_clause: floor.1.clone(),
            ceiling_clause: format!("requested-{field} ({val}d)"),
            detail: format!(
                "requested {field} {val}d is below active preset floor {}d",
                floor.0
            ),
        });
    }
    if val > ceiling_days {
        return Err(ComplyError::RetentionConflict {
            floor_clause: format!("requested-{field} ({val}d)"),
            ceiling_clause: ceiling_clause.to_owned(),
            detail: format!("requested {field} {val}d exceeds ceiling {ceiling_days}d"),
        });
    }
    Ok(val)
}

impl HoldsLedger {
    pub fn place_hold(&mut self, input: PlaceHoldInput) -> Result<Hold, ComplyError> {
        let hold_id = format!("hld_{}", Uuid::now_v7().simple());
        if input.approvers.len() < 2 {
            return Err(ComplyError::InvalidHold {
                hold_id,
                detail:
                    "legal hold requires at least two approvers (privacy officer and org owner)"
                        .into(),
            });
        }
        let review_delta = input
            .review_by
            .as_second()
            .saturating_sub(input.created_at.as_second());
        if review_delta <= 0 || review_delta > MAX_HOLD_REVIEW_SECONDS {
            return Err(ComplyError::InvalidHold {
                hold_id,
                detail: "hold review_by must be within 12 months of creation".into(),
            });
        }
        if let HoldNotice::Deferred { until, .. } = input.notice {
            let defer_delta = until
                .as_second()
                .saturating_sub(input.created_at.as_second());
            if defer_delta <= 0 || defer_delta > MAX_DEFERRED_NOTICE_SECONDS {
                return Err(ComplyError::InvalidHold {
                    hold_id,
                    detail: "deferred subject notice cannot exceed 90 days".into(),
                });
            }
        }

        let hold = Hold {
            hold_id,
            organisation: input.organisation,
            scope: input.scope,
            matter_ref: input.matter_ref,
            reason: input.reason,
            created_by: input.created_by,
            approvers: input.approvers,
            created_at: input.created_at,
            review_by: input.review_by,
            notice: input.notice,
            lifecycle: HoldLifecycle::Active,
        };
        self.holds.push(hold.clone());
        Ok(hold)
    }

    pub fn check(
        &self,
        pseudonym: &str,
        session_id: Option<&str>,
        data_class: Option<&str>,
    ) -> HoldCheckResult {
        let matching: Vec<String> = self
            .holds
            .iter()
            .filter(|h| h.lifecycle != HoldLifecycle::Released)
            .filter(|h| {
                let ps_hit = h.scope.pseudonyms.iter().any(|p| p == pseudonym);
                let sess_hit =
                    session_id.is_some_and(|sid| h.scope.session_ids.iter().any(|s| s == sid));
                let class_hit = h.scope.classes.is_empty()
                    || data_class.is_some_and(|c| h.scope.classes.iter().any(|hc| hc == c));
                (ps_hit || sess_hit) && class_hit
            })
            .map(|h| h.hold_id.clone())
            .collect();

        if matching.is_empty() {
            HoldCheckResult::Clear
        } else {
            HoldCheckResult::Held { hold_ids: matching }
        }
    }

    pub fn flag_expired_reviews(&mut self, now: Timestamp) -> Vec<HoldReviewFinding> {
        let mut findings = Vec::new();
        for hold in &mut self.holds {
            if hold.lifecycle == HoldLifecycle::Active && now >= hold.review_by {
                hold.lifecycle = HoldLifecycle::ReviewOverdue;
                findings.push(HoldReviewFinding {
                    hold_id: hold.hold_id.clone(),
                    matter_ref: hold.matter_ref.clone(),
                    review_by: hold.review_by,
                    detail:
                        "Legal hold review_by expired; hold stays pinned until renewed or released."
                            .into(),
                });
            }
        }
        findings
    }

    pub fn release_hold(&mut self, hold_id: &str) -> Result<(), ComplyError> {
        let hold = self
            .holds
            .iter_mut()
            .find(|h| h.hold_id == hold_id)
            .ok_or_else(|| ComplyError::UnknownHold(hold_id.to_owned()))?;
        hold.lifecycle = HoldLifecycle::Released;
        Ok(())
    }

    pub fn process_erasure(&self, subject_pseudonym: &str, now: Timestamp) -> ErasureOutcome {
        match self.check(subject_pseudonym, None, None) {
            HoldCheckResult::Clear => ErasureOutcome::Executed {
                subject_ref: subject_pseudonym.to_owned(),
            },
            HoldCheckResult::Held { hold_ids } => {
                let disclose_hold = self
                    .holds
                    .iter()
                    .filter(|h| hold_ids.contains(&h.hold_id))
                    .all(|h| match h.notice {
                        HoldNotice::Immediate => true,
                        HoldNotice::Deferred { until, .. } => now >= until,
                    });
                ErasureOutcome::PendingHeld {
                    subject_ref: subject_pseudonym.to_owned(),
                    hold_ids,
                    disclose_hold,
                }
            }
        }
    }
}
