// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Structural validation against NIST OSCAL 1.2.3 Component Definition and Assessment Results rules.

use std::collections::BTreeSet;

use jiff::Timestamp;
use serde_json::Value;
use uuid::Uuid;

use crate::ComplyError;
use crate::limits::compliance_limits;
use crate::oscal::OSCAL_VERSION;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OscalArtifactKind {
    ComponentDefinition,
    AssessmentResults,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OscalValidationReport {
    pub kind: OscalArtifactKind,
    pub oscal_version: String,
    pub root_uuid: String,
    pub record_count: usize,
}

pub fn validate_oscal_component_json(raw_json: &str) -> Result<OscalValidationReport, ComplyError> {
    let limits = compliance_limits()?;
    if raw_json.len() > limits.max_oscal_json_bytes {
        return Err(ComplyError::VerificationFailed {
            detail: "OSCAL JSON payload exceeds max_oscal_json_bytes limit".into(),
        });
    }
    let doc: Value = serde_json::from_str(raw_json).map_err(|e| ComplyError::Serialization {
        detail: format!("invalid OSCAL JSON: {e}"),
    })?;
    let body = doc
        .get("component-definition")
        .and_then(Value::as_object)
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: "OSCAL component-definition missing top-level `component-definition` object"
                .into(),
        })?;
    let mut seen_uuids = BTreeSet::new();
    let root_uuid = require_unique_uuid(
        body.get("uuid"),
        "component-definition.uuid",
        &mut seen_uuids,
    )?;
    let oscal_version = validate_oscal_metadata(body.get("metadata"), "component-definition")?;
    let components = body
        .get("components")
        .and_then(Value::as_array)
        .filter(|c| !c.is_empty())
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: "OSCAL component-definition must list >= 1 component".into(),
        })?;

    let mut req_count = 0usize;
    for comp in components {
        let obj = comp
            .as_object()
            .ok_or_else(|| ComplyError::VerificationFailed {
                detail: "OSCAL component entry must be an object".into(),
            })?;
        require_unique_uuid(obj.get("uuid"), "component.uuid", &mut seen_uuids)?;
        require_non_empty_str(obj.get("type"), "component.type")?;
        require_non_empty_str(obj.get("title"), "component.title")?;
        require_non_empty_str(obj.get("description"), "component.description")?;
        let impls = obj
            .get("control-implementations")
            .and_then(Value::as_array)
            .filter(|i| !i.is_empty())
            .ok_or_else(|| ComplyError::VerificationFailed {
                detail: "OSCAL component missing `control-implementations`".into(),
            })?;
        for ci in impls {
            let ci_obj = ci
                .as_object()
                .ok_or_else(|| ComplyError::VerificationFailed {
                    detail: "control-implementation entry must be an object".into(),
                })?;
            require_unique_uuid(
                ci_obj.get("uuid"),
                "control-implementation.uuid",
                &mut seen_uuids,
            )?;
            require_non_empty_str(ci_obj.get("source"), "control-implementation.source")?;
            require_non_empty_str(
                ci_obj.get("description"),
                "control-implementation.description",
            )?;
            let reqs = ci_obj
                .get("implemented-requirements")
                .and_then(Value::as_array)
                .filter(|r| !r.is_empty())
                .ok_or_else(|| ComplyError::VerificationFailed {
                    detail: "control-implementation missing non-empty `implemented-requirements`"
                        .into(),
                })?;
            for req in reqs {
                let r_obj = req
                    .as_object()
                    .ok_or_else(|| ComplyError::VerificationFailed {
                        detail: "implemented-requirement entry must be an object".into(),
                    })?;
                require_unique_uuid(
                    r_obj.get("uuid"),
                    "implemented-requirement.uuid",
                    &mut seen_uuids,
                )?;
                require_non_empty_str(
                    r_obj.get("control-id"),
                    "implemented-requirement.control-id",
                )?;
                require_non_empty_str(
                    r_obj.get("description"),
                    "implemented-requirement.description",
                )?;
                req_count = req_count.saturating_add(1);
            }
        }
    }

    Ok(OscalValidationReport {
        kind: OscalArtifactKind::ComponentDefinition,
        oscal_version,
        root_uuid,
        record_count: req_count,
    })
}

pub fn validate_oscal_assessment_json(
    raw_json: &str,
) -> Result<OscalValidationReport, ComplyError> {
    let limits = compliance_limits()?;
    if raw_json.len() > limits.max_oscal_json_bytes {
        return Err(ComplyError::VerificationFailed {
            detail: "OSCAL assessment JSON payload exceeds max_oscal_json_bytes limit".into(),
        });
    }
    let doc: Value = serde_json::from_str(raw_json).map_err(|e| ComplyError::Serialization {
        detail: format!("invalid OSCAL JSON: {e}"),
    })?;
    let body = doc
        .get("assessment-results")
        .and_then(Value::as_object)
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: "OSCAL assessment-results missing top-level `assessment-results` object".into(),
        })?;
    let mut seen_uuids = BTreeSet::new();
    let root_uuid =
        require_unique_uuid(body.get("uuid"), "assessment-results.uuid", &mut seen_uuids)?;
    let oscal_version = validate_oscal_metadata(body.get("metadata"), "assessment-results")?;
    let results = body
        .get("results")
        .and_then(Value::as_array)
        .filter(|r| !r.is_empty())
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: "OSCAL assessment-results must contain >= 1 result".into(),
        })?;

    let mut obs_count = 0usize;
    for res in results {
        let obj = res
            .as_object()
            .ok_or_else(|| ComplyError::VerificationFailed {
                detail: "OSCAL result entry must be an object".into(),
            })?;
        require_unique_uuid(obj.get("uuid"), "result.uuid", &mut seen_uuids)?;
        require_non_empty_str(obj.get("title"), "result.title")?;
        require_non_empty_str(obj.get("description"), "result.description")?;
        let start = require_timestamp(obj.get("start"), "result.start")?;
        let end = require_timestamp(obj.get("end"), "result.end")?;
        if end < start {
            return Err(ComplyError::VerificationFailed {
                detail: "OSCAL result `end` precedes `start`".into(),
            });
        }
        let observations = obj
            .get("observations")
            .and_then(Value::as_array)
            .filter(|o| !o.is_empty())
            .ok_or_else(|| ComplyError::VerificationFailed {
                detail: "OSCAL result missing non-empty `observations` array".into(),
            })?;
        for obs in observations {
            let o_obj = obs
                .as_object()
                .ok_or_else(|| ComplyError::VerificationFailed {
                    detail: "OSCAL observation entry must be an object".into(),
                })?;
            require_unique_uuid(o_obj.get("uuid"), "observation.uuid", &mut seen_uuids)?;
            require_non_empty_str(o_obj.get("description"), "observation.description")?;
            require_timestamp(o_obj.get("collected"), "observation.collected")?;
            validate_observation_methods(o_obj.get("methods"))?;
            validate_subject_references(o_obj.get("subject-references"))?;
            obs_count = obs_count.saturating_add(1);
        }
    }

    Ok(OscalValidationReport {
        kind: OscalArtifactKind::AssessmentResults,
        oscal_version,
        root_uuid,
        record_count: obs_count,
    })
}

fn validate_observation_methods(val: Option<&Value>) -> Result<(), ComplyError> {
    let methods = val
        .and_then(Value::as_array)
        .filter(|m| !m.is_empty())
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: "OSCAL observation requires non-empty `methods` array".into(),
        })?;
    for m in methods {
        require_non_empty_str(Some(m), "observation.methods[]")?;
    }
    Ok(())
}

fn validate_subject_references(val: Option<&Value>) -> Result<(), ComplyError> {
    let Some(v) = val else {
        return Ok(());
    };
    let refs = v
        .as_array()
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: "OSCAL observation `subject-references` must be an array".into(),
        })?;
    for entry in refs {
        let obj = entry
            .as_object()
            .ok_or_else(|| ComplyError::VerificationFailed {
                detail: "OSCAL `subject-references` entries must be objects".into(),
            })?;
        let sref_uuid =
            require_non_empty_str(obj.get("subject-uuid"), "subject-references.subject-uuid")?;
        Uuid::parse_str(sref_uuid).map_err(|e| ComplyError::VerificationFailed {
            detail: format!("invalid UUID in `subject-references.subject-uuid`: {e}"),
        })?;
        require_non_empty_str(obj.get("type"), "subject-references.type")?;
    }
    Ok(())
}

fn validate_oscal_metadata(meta: Option<&Value>, label: &str) -> Result<String, ComplyError> {
    let obj = meta
        .and_then(Value::as_object)
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("OSCAL `{label}` missing `metadata` object"),
        })?;
    require_non_empty_str(obj.get("title"), "metadata.title")?;
    require_non_empty_str(obj.get("version"), "metadata.version")?;
    require_timestamp(obj.get("last-modified"), "metadata.last-modified")?;
    let ver = require_non_empty_str(obj.get("oscal-version"), "metadata.oscal-version")?;
    if ver != OSCAL_VERSION {
        return Err(ComplyError::VerificationFailed {
            detail: format!("OSCAL version `{ver}` != required `{OSCAL_VERSION}`"),
        });
    }
    Ok(ver.to_owned())
}

fn require_unique_uuid(
    val: Option<&Value>,
    field: &str,
    seen: &mut BTreeSet<String>,
) -> Result<String, ComplyError> {
    let s = require_non_empty_str(val, field)?;
    let parsed = Uuid::parse_str(s).map_err(|e| ComplyError::VerificationFailed {
        detail: format!("invalid UUID in `{field}`: {e}"),
    })?;
    let canonical = parsed.hyphenated().to_string();
    if !seen.insert(canonical.clone()) {
        return Err(ComplyError::VerificationFailed {
            detail: format!("duplicate OSCAL UUID `{canonical}` in `{field}`"),
        });
    }
    Ok(canonical)
}

fn require_timestamp(val: Option<&Value>, field: &str) -> Result<Timestamp, ComplyError> {
    let s = require_non_empty_str(val, field)?;
    s.parse::<Timestamp>()
        .map_err(|e| ComplyError::VerificationFailed {
            detail: format!("invalid RFC-3339 timestamp in `{field}`: {e}"),
        })
}

fn require_non_empty_str<'a>(val: Option<&'a Value>, field: &str) -> Result<&'a str, ComplyError> {
    val.and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("missing non-empty string field `{field}`"),
        })
}
