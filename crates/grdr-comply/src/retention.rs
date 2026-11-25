// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Retention presets, privacy ceilings, and conflict resolution (`D-57`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ComplyError;

const ABS_MAX_CONTENT_DAYS: u32 = 365;
const ABS_MAX_OTHER_DAYS: u32 = 2555;
const ABS_MAX_BACKUP_DAYS: u32 = 35;
const WORKS_COUNCIL_MAX_ACTIVITY_DAYS: u32 = 90;
const WORKS_COUNCIL_MAX_CONTENT_DAYS: u32 = 30;
const WORKS_COUNCIL_MAX_DECISION_DAYS: u32 = 396;
const WORKS_COUNCIL_MAX_AUDIT_DAYS: u32 = 396;

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
    #[serde(default)]
    pub override_legal_basis: Option<String>,
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
    let hot_days = apply_override(
        "hot_days",
        proposal.hot_days,
        &floor_hot,
        activity_days,
        "activity_days ceiling (hot_days cannot exceed activity_days)",
    )?;

    let widens_beyond_floor = content_days > floor_content.0
        || activity_days > floor_activity.0
        || decision_days > floor_decision.0
        || audit_days > floor_audit.0
        || hot_days > floor_hot.0;
    if widens_beyond_floor {
        let basis = proposal
            .override_legal_basis
            .as_deref()
            .map(str::trim)
            .filter(|s| !s.is_empty());
        let Some(basis_text) = basis else {
            return Err(ComplyError::MissingLegalBasis(
                "explicit retention override above baseline floor".into(),
            ));
        };
        basis_list.push(format!("explicit-override: {basis_text}"));
    }

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
