// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Regulatory incident timeline calculator loaded from YAML (`CRA`, `NIS2`, `DORA`, `SEC`, `NYDFS`, `GDPR`).

use jiff::{Timestamp, civil::Weekday, tz::TimeZone};
use serde::{Deserialize, Serialize};

use crate::pack_loader::{load_yaml_checked, yaml_req_seq, yaml_req_str, yaml_req_u32};
use crate::{ComplyError, markdown_safe};

const EMBEDDED_INCIDENT_REGIMES_YAML: &str = include_str!("../data/incident-regimes.yaml");
const SECONDS_PER_HOUR: i64 = 3_600;
const SECONDS_PER_DAY: i64 = 86_400;
const MAX_INCIDENT_BUSINESS_DAYS: u32 = 3_650;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClockAnchorKind {
    Detected,
    FixedOrDetected,
    NotifiedOr72h,
    MaterialityOrDetected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RegimeStageSpec {
    pub stage_id: String,
    pub citation: String,
    pub anchor: ClockAnchorKind,
    pub offset_hours: u32,
    pub offset_days: u32,
    pub offset_business_days: u32,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentRegimeSpec {
    pub id: String,
    pub title: String,
    pub authority: String,
    pub source_note: String,
    pub stages: Vec<RegimeStageSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentFixtureInput {
    pub incident_id: String,
    pub regime_id: String,
    pub summary: String,
    pub detected_at: Timestamp,
    #[serde(default)]
    pub fixed_at: Option<Timestamp>,
    #[serde(default)]
    pub notified_at: Option<Timestamp>,
    #[serde(default)]
    pub materiality_determined_at: Option<Timestamp>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentDeadline {
    pub milestone_id: String,
    pub citation: String,
    pub due_at: Timestamp,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncidentTimelineReport {
    pub incident_id: String,
    pub regime_id: String,
    pub regime_title: String,
    pub authority: String,
    pub source_note: String,
    pub deadlines: Vec<IncidentDeadline>,
}

pub fn load_incident_regimes_yaml(raw: &str) -> Result<Vec<IncidentRegimeSpec>, ComplyError> {
    let doc = load_yaml_checked(raw, "incident-regimes.yaml")?;
    let seq = yaml_req_seq(&doc, "regimes", "incident-regimes.yaml")?;
    let mut regimes = Vec::with_capacity(seq.len());
    for node in seq {
        let id = yaml_req_str(node, "id", "regime")?.to_owned();
        let stage_nodes = yaml_req_seq(node, "stages", &id)?;
        let mut stages = Vec::with_capacity(stage_nodes.len());
        for snode in stage_nodes {
            let sid = yaml_req_str(snode, "stage", &id)?.to_owned();
            let anchor_str = yaml_req_str(snode, "anchor", &sid)?;
            let anchor = match anchor_str {
                "detected" => ClockAnchorKind::Detected,
                "fixed_or_detected" => ClockAnchorKind::FixedOrDetected,
                "notified_or_72h" => ClockAnchorKind::NotifiedOr72h,
                "materiality_or_detected" => ClockAnchorKind::MaterialityOrDetected,
                other => {
                    return Err(ComplyError::Serialization {
                        detail: format!("unknown incident anchor `{other}` in `{id}`"),
                    });
                }
            };
            stages.push(RegimeStageSpec {
                stage_id: sid.clone(),
                citation: yaml_req_str(snode, "citation", &sid)?.to_owned(),
                anchor,
                offset_hours: yaml_req_u32(snode, "offset_hours", &sid)?,
                offset_days: yaml_req_u32(snode, "offset_days", &sid)?,
                offset_business_days: yaml_req_u32(snode, "offset_business_days", &sid)?,
                summary: yaml_req_str(snode, "summary", &sid)?.to_owned(),
            });
        }
        regimes.push(IncidentRegimeSpec {
            id: id.clone(),
            title: yaml_req_str(node, "title", &id)?.to_owned(),
            authority: yaml_req_str(node, "authority", &id)?.to_owned(),
            source_note: yaml_req_str(node, "source_note", &id)?.to_owned(),
            stages,
        });
    }
    Ok(regimes)
}

pub fn export_incident_timeline(
    input: &IncidentFixtureInput,
) -> Result<IncidentTimelineReport, ComplyError> {
    let regimes = load_incident_regimes_yaml(EMBEDDED_INCIDENT_REGIMES_YAML)?;
    export_incident_timeline_from_specs(input, &regimes)
}

pub fn export_incident_timeline_from_specs(
    input: &IncidentFixtureInput,
    regimes: &[IncidentRegimeSpec],
) -> Result<IncidentTimelineReport, ComplyError> {
    if input.incident_id.trim().is_empty() || input.summary.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "incident_id and summary must be non-empty".into(),
        });
    }
    let spec = regimes
        .iter()
        .find(|r| r.id == input.regime_id)
        .ok_or_else(|| ComplyError::UnknownFramework(input.regime_id.clone()))?;

    let mut deadlines = Vec::with_capacity(spec.stages.len());
    for stage in &spec.stages {
        let anchor_ts = match stage.anchor {
            ClockAnchorKind::Detected => input.detected_at,
            ClockAnchorKind::FixedOrDetected => input.fixed_at.unwrap_or(input.detected_at),
            ClockAnchorKind::NotifiedOr72h => match input.notified_at {
                Some(ts) => ts,
                None => {
                    add_seconds_checked(input.detected_at, 72_i64.saturating_mul(SECONDS_PER_HOUR))?
                }
            },
            ClockAnchorKind::MaterialityOrDetected => {
                input.materiality_determined_at.unwrap_or(input.detected_at)
            }
        };
        let due_at = if stage.offset_business_days > 0 {
            add_business_days(anchor_ts, stage.offset_business_days)?
        } else {
            let hours_secs = i64::from(stage.offset_hours)
                .checked_mul(SECONDS_PER_HOUR)
                .ok_or_else(|| ComplyError::InvalidEvidenceInput {
                    detail: "incident offset_hours overflow".into(),
                })?;
            let day_secs = i64::from(stage.offset_days)
                .checked_mul(SECONDS_PER_DAY)
                .ok_or_else(|| ComplyError::InvalidEvidenceInput {
                    detail: "incident offset_days overflow".into(),
                })?;
            let secs = hours_secs.checked_add(day_secs).ok_or_else(|| {
                ComplyError::InvalidEvidenceInput {
                    detail: "incident timeline offset overflow".into(),
                }
            })?;
            add_seconds_checked(anchor_ts, secs)?
        };
        deadlines.push(IncidentDeadline {
            milestone_id: stage.stage_id.clone(),
            citation: stage.citation.clone(),
            due_at,
            summary: stage.summary.clone(),
        });
    }

    Ok(IncidentTimelineReport {
        incident_id: input.incident_id.clone(),
        regime_id: spec.id.clone(),
        regime_title: spec.title.clone(),
        authority: spec.authority.clone(),
        source_note: spec.source_note.clone(),
        deadlines,
    })
}

pub fn render_incident_timeline_markdown(report: &IncidentTimelineReport) -> String {
    let mut out = format!(
        "# Regulatory Incident Timeline: {} ({})\n\n- Regime: {}\n- Authority: {}\n- Note: {}\n\n| Milestone | Citation | Due (UTC) | Summary |\n|---|---|---|---|\n",
        markdown_safe(&report.incident_id),
        markdown_safe(&report.regime_id),
        markdown_safe(&report.regime_title),
        markdown_safe(&report.authority),
        markdown_safe(&report.source_note),
    );
    for d in &report.deadlines {
        out.push_str(&format!(
            "| `{}` | {} | `{}` | {} |\n",
            markdown_safe(&d.milestone_id),
            markdown_safe(&d.citation),
            d.due_at,
            markdown_safe(&d.summary)
        ));
    }
    out
}

fn add_seconds_checked(anchor: Timestamp, secs: i64) -> Result<Timestamp, ComplyError> {
    let target =
        anchor
            .as_second()
            .checked_add(secs)
            .ok_or_else(|| ComplyError::InvalidEvidenceInput {
                detail: "incident timestamp arithmetic overflow".into(),
            })?;
    Timestamp::from_second(target).map_err(|e| ComplyError::InvalidEvidenceInput {
        detail: format!("incident timestamp out of range: {e}"),
    })
}

fn add_business_days(anchor: Timestamp, days: u32) -> Result<Timestamp, ComplyError> {
    if days > MAX_INCIDENT_BUSINESS_DAYS {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: format!(
                "offset_business_days ({days}) exceeds maximum {MAX_INCIDENT_BUSINESS_DAYS}"
            ),
        });
    }
    let mut cur = anchor;
    let mut remaining = days;
    while remaining > 0 {
        cur = add_seconds_checked(cur, SECONDS_PER_DAY)?;
        let wd = TimeZone::UTC.to_datetime(cur).weekday();
        if !matches!(wd, Weekday::Saturday | Weekday::Sunday) {
            remaining = remaining.saturating_sub(1);
        }
    }
    Ok(cur)
}
