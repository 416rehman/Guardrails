// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Data-driven retention presets, privacy ceilings, and conflict resolution (`D-57`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::ComplyError;
use crate::pack_loader::{
    load_yaml_checked, yaml_req_bool, yaml_req_seq, yaml_req_str, yaml_req_u32,
};

const EMBEDDED_RETENTION_YAML: &str = include_str!("../data/retention-presets.yaml");

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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
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
    pub requires_recorded_basis: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CeilingSpec {
    pub profile: PrivacyCeilingProfile,
    pub clause: String,
    pub content_days: u32,
    pub activity_days: u32,
    pub decision_days: u32,
    pub audit_days: u32,
    pub backup_days_max: u32,
    pub notice_days: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionCatalogue {
    pub presets: BTreeMap<RetentionPreset, PresetSpec>,
    pub ceilings: BTreeMap<PrivacyCeilingProfile, CeilingSpec>,
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

pub fn load_retention_catalogue_yaml(raw: &str) -> Result<RetentionCatalogue, ComplyError> {
    let doc = load_yaml_checked(raw, "retention-presets.yaml")?;
    let mut presets = BTreeMap::new();
    for node in yaml_req_seq(&doc, "presets", "retention-presets.yaml")? {
        let name = yaml_req_str(node, "preset", "retention preset")?;
        let preset = parse_preset_id(name)?;
        let spec = PresetSpec {
            preset,
            clause_id: yaml_req_str(node, "clause_id", name)?.to_owned(),
            content_days: yaml_req_u32(node, "content_days", name)?,
            activity_days: yaml_req_u32(node, "activity_days", name)?,
            decision_days: yaml_req_u32(node, "decision_days", name)?,
            audit_days: yaml_req_u32(node, "audit_days", name)?,
            hot_days: yaml_req_u32(node, "hot_days", name)?,
            legal_basis: yaml_req_str(node, "legal_basis", name)?.to_owned(),
            requires_recorded_basis: yaml_req_bool(node, "requires_recorded_basis", name)?,
        };
        if presets.insert(preset, spec).is_some() {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate retention preset `{name}`"),
            });
        }
    }

    let mut ceilings = BTreeMap::new();
    for node in yaml_req_seq(&doc, "ceilings", "retention-presets.yaml")? {
        let name = yaml_req_str(node, "profile", "retention ceiling")?;
        let profile = parse_profile_id(name)?;
        let spec = CeilingSpec {
            profile,
            clause: yaml_req_str(node, "clause", name)?.to_owned(),
            content_days: yaml_req_u32(node, "content_days", name)?,
            activity_days: yaml_req_u32(node, "activity_days", name)?,
            decision_days: yaml_req_u32(node, "decision_days", name)?,
            audit_days: yaml_req_u32(node, "audit_days", name)?,
            backup_days_max: yaml_req_u32(node, "backup_days_max", name)?,
            notice_days: yaml_req_u32(node, "notice_days", name)?,
        };
        if ceilings.insert(profile, spec).is_some() {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate ceiling profile `{name}`"),
            });
        }
    }

    Ok(RetentionCatalogue { presets, ceilings })
}

pub fn default_retention_catalogue() -> Result<RetentionCatalogue, ComplyError> {
    load_retention_catalogue_yaml(EMBEDDED_RETENTION_YAML)
}

pub fn preset_spec(preset: RetentionPreset) -> Result<PresetSpec, ComplyError> {
    let cat = default_retention_catalogue()?;
    cat.presets
        .get(&preset)
        .cloned()
        .ok_or_else(|| ComplyError::MissingLegalBasis(format!("{preset:?}")))
}

pub fn ceiling_spec(profile: PrivacyCeilingProfile) -> Result<CeilingSpec, ComplyError> {
    let cat = default_retention_catalogue()?;
    cat.ceilings
        .get(&profile)
        .cloned()
        .ok_or_else(|| ComplyError::RetentionConflict {
            floor_clause: "catalogue".into(),
            ceiling_clause: format!("{profile:?}"),
            detail: "missing privacy ceiling specification in retention catalogue".into(),
        })
}

pub fn resolve_retention_policy(
    proposal: &RetentionProposal,
) -> Result<RetentionPolicy, ComplyError> {
    let cat = default_retention_catalogue()?;
    resolve_retention_policy_with_catalogue(proposal, &cat)
}

pub fn resolve_retention_policy_with_catalogue(
    proposal: &RetentionProposal,
    catalogue: &RetentionCatalogue,
) -> Result<RetentionPolicy, ComplyError> {
    if proposal.organisation.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "retention proposal requires non-empty organisation".into(),
        });
    }
    let presets = if proposal.presets.is_empty() {
        vec![RetentionPreset::Default]
    } else {
        proposal.presets.clone()
    };

    let ceiling = catalogue
        .ceilings
        .get(&proposal.ceiling_profile)
        .ok_or_else(|| ComplyError::RetentionConflict {
            floor_clause: "catalogue".into(),
            ceiling_clause: format!("{:?}", proposal.ceiling_profile),
            detail: "ceiling profile missing from retention YAML catalogue".into(),
        })?;

    let mut floor_content: (u32, String) = (0, String::new());
    let mut floor_activity: (u32, String) = (0, String::new());
    let mut floor_decision: (u32, String) = (0, String::new());
    let mut floor_audit: (u32, String) = (0, String::new());
    let mut floor_hot: (u32, String) = (0, String::new());
    let mut basis_list = Vec::new();

    for preset in &presets {
        let spec = catalogue
            .presets
            .get(preset)
            .ok_or_else(|| ComplyError::MissingLegalBasis(format!("{preset:?}")))?;
        if spec.requires_recorded_basis {
            let recorded = proposal
                .legal_basis
                .get(preset)
                .map(|s| s.trim())
                .filter(|s| !s.is_empty());
            let Some(basis_text) = recorded else {
                return Err(ComplyError::MissingLegalBasis(spec.clause_id.clone()));
            };
            basis_list.push(format!("{}: {basis_text}", spec.clause_id));
        } else {
            basis_list.push(spec.legal_basis.clone());
        }

        let effective_activity_floor = if *preset == RetentionPreset::Default
            && proposal.ceiling_profile == PrivacyCeilingProfile::WorksCouncil
        {
            ceiling.activity_days
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

    check_floor_ceiling(
        "content_days",
        &floor_content,
        ceiling.content_days,
        &ceiling.clause,
    )?;
    check_floor_ceiling(
        "activity_days",
        &floor_activity,
        ceiling.activity_days,
        &ceiling.clause,
    )?;
    check_floor_ceiling(
        "decision_days",
        &floor_decision,
        ceiling.decision_days,
        &ceiling.clause,
    )?;
    check_floor_ceiling(
        "audit_days",
        &floor_audit,
        ceiling.audit_days,
        &ceiling.clause,
    )?;

    let content_days = apply_override(
        "content_days",
        proposal.content_days,
        &floor_content,
        ceiling.content_days,
        &ceiling.clause,
    )?;
    let activity_days = apply_override(
        "activity_days",
        proposal.activity_days,
        &floor_activity,
        ceiling.activity_days,
        &ceiling.clause,
    )?;
    let decision_days = apply_override(
        "decision_days",
        proposal.decision_days,
        &floor_decision,
        ceiling.decision_days,
        &ceiling.clause,
    )?;
    let audit_days = apply_override(
        "audit_days",
        proposal.audit_days,
        &floor_audit,
        ceiling.audit_days,
        &ceiling.clause,
    )?;
    check_floor_ceiling(
        "hot_days",
        &floor_hot,
        activity_days,
        "activity_days ceiling (hot_days cannot exceed activity_days)",
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
        backup_days_max: ceiling.backup_days_max,
        presets,
        legal_basis: basis_list,
        ceilings_from: proposal.ceiling_profile,
    })
}

fn parse_preset_id(raw: &str) -> Result<RetentionPreset, ComplyError> {
    match raw {
        "default" => Ok(RetentionPreset::Default),
        "eu-ai-act-deployer" => Ok(RetentionPreset::EuAiActDeployer),
        "pci-dss-4" => Ok(RetentionPreset::PciDss4),
        "hipaa" => Ok(RetentionPreset::Hipaa),
        "nydfs-500" => Ok(RetentionPreset::Nydfs500),
        "colorado-adm" => Ok(RetentionPreset::ColoradoAdm),
        "sox-itgc" => Ok(RetentionPreset::SoxItgc),
        other => Err(ComplyError::Serialization {
            detail: format!("unknown retention preset `{other}`"),
        }),
    }
}

fn parse_profile_id(raw: &str) -> Result<PrivacyCeilingProfile, ComplyError> {
    match raw {
        "standard" => Ok(PrivacyCeilingProfile::Standard),
        "works-council" => Ok(PrivacyCeilingProfile::WorksCouncil),
        other => Err(ComplyError::Serialization {
            detail: format!("unknown privacy profile `{other}`"),
        }),
    }
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
            detail: format!("{field} floor {}d exceeds ceiling {ceiling_days}d", floor.0),
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
