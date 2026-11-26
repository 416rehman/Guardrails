// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Reclassification TOML parser (`reclassifications.toml`) for `SL12` and R17b holds.

use std::collections::{BTreeMap, BTreeSet};

use crate::capture_toml::{
    CANONICAL_CLASSES, parse_openness, parse_tomlish_key, strip_toml_comment, unquote_toml_str,
};
use crate::{LintDomain, LintError, LintFinding, LintSeverity};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReclassKind {
    Field,
    Level,
    WireName,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ReclassificationEntry {
    pub kind: ReclassKind,
    pub target: String,
    pub from: String,
    pub to: String,
    pub rfc: String,
    pub seat: String,
    pub successor: Option<String>,
    pub from_sealable: Option<bool>,
    pub to_sealable: Option<bool>,
    pub from_policy_readable: Option<bool>,
    pub to_policy_readable: Option<bool>,
    pub justification: String,
}

pub fn parse_reclassifications_toml(raw: &str) -> Result<Vec<ReclassificationEntry>, LintError> {
    let mut out = Vec::new();
    let mut current: Option<(ReclassKind, BTreeMap<String, String>)> = None;
    let mut schema = String::new();
    let allowed_keys = [
        "target",
        "from",
        "to",
        "rfc",
        "seat",
        "successor",
        "from_sealable",
        "to_sealable",
        "from_policy_readable",
        "to_policy_readable",
        "justification",
    ];
    let bool_keys = [
        "from_sealable",
        "to_sealable",
        "from_policy_readable",
        "to_policy_readable",
    ];

    for raw_line in raw.lines() {
        let trimmed = strip_toml_comment(raw_line).trim().to_owned();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed == "[[field]]" || trimmed == "[[level]]" || trimmed == "[[wire_name]]" {
            if let Some((k, map)) = current.take() {
                out.push(build_reclass_entry(k, &map)?);
            }
            let kind = match trimmed.as_str() {
                "[[field]]" => ReclassKind::Field,
                "[[level]]" => ReclassKind::Level,
                _ => ReclassKind::WireName,
            };
            current = Some((kind, BTreeMap::new()));
            continue;
        }
        if trimmed.starts_with('[') {
            return Err(LintError::CompareViolation {
                target: "reclassifications.toml".into(),
                detail: format!("unexpected TOML header `{trimmed}`"),
            });
        }
        let Some((k_raw, v_raw)) = trimmed.split_once('=') else {
            return Err(LintError::CompareViolation {
                target: "reclassifications.toml".into(),
                detail: format!("malformed line `{trimmed}`"),
            });
        };
        let key = parse_tomlish_key(k_raw.trim(), "reclassifications.toml")?;
        let val_raw = v_raw.trim();
        let val = if current.is_some() && bool_keys.contains(&key.as_str()) {
            match val_raw {
                "true" => "true".to_owned(),
                "false" => "false".to_owned(),
                _ => {
                    return Err(LintError::CompareViolation {
                        target: "reclassifications.toml".into(),
                        detail: format!("boolean key `{key}` must be `true` or `false`"),
                    });
                }
            }
        } else {
            unquote_toml_str(val_raw, "reclassifications.toml")?
        };
        if let Some((_, ref mut map)) = current {
            if !allowed_keys.contains(&key.as_str()) {
                return Err(LintError::CompareViolation {
                    target: "reclassifications.toml".into(),
                    detail: format!("unknown reclassification key `{key}`"),
                });
            }
            if map.insert(key.clone(), val).is_some() {
                return Err(LintError::CompareViolation {
                    target: "reclassifications.toml".into(),
                    detail: format!("duplicate key `{key}` in reclassification entry"),
                });
            }
        } else if key == "schema" {
            if !schema.is_empty() {
                return Err(LintError::CompareViolation {
                    target: "reclassifications.toml".into(),
                    detail: "duplicate `schema` key".into(),
                });
            }
            schema = val;
        } else {
            return Err(LintError::CompareViolation {
                target: "reclassifications.toml".into(),
                detail: format!("unexpected top-level key `{key}`"),
            });
        }
    }
    if schema != "grdr.reclassifications.v1alpha1" {
        return Err(LintError::CompareViolation {
            target: "reclassifications.toml".into(),
            detail: format!(
                "reclassifications schema must be `grdr.reclassifications.v1alpha1`, found `{schema}`"
            ),
        });
    }
    if let Some((k, map)) = current {
        out.push(build_reclass_entry(k, &map)?);
    }
    Ok(out)
}

fn parse_opt_bool(map: &BTreeMap<String, String>, key: &str) -> Result<Option<bool>, LintError> {
    match map.get(key).map(String::as_str) {
        None => Ok(None),
        Some("true") => Ok(Some(true)),
        Some("false") => Ok(Some(false)),
        Some(other) => Err(LintError::CompareViolation {
            target: "reclassifications.toml".into(),
            detail: format!("invalid boolean `{other}` for `{key}`"),
        }),
    }
}

fn build_reclass_entry(
    kind: ReclassKind,
    map: &BTreeMap<String, String>,
) -> Result<ReclassificationEntry, LintError> {
    let req = |k: &str| {
        map.get(k)
            .map(|s| s.trim().to_owned())
            .filter(|s| !s.is_empty())
            .ok_or_else(|| LintError::CompareViolation {
                target: "reclassifications.toml".into(),
                detail: format!("missing or empty required key `{k}`"),
            })
    };
    Ok(ReclassificationEntry {
        kind,
        target: req("target")?,
        from: req("from")?,
        to: req("to")?,
        rfc: req("rfc")?,
        seat: req("seat")?,
        successor: map.get("successor").map(|s| s.trim().to_owned()),
        from_sealable: parse_opt_bool(map, "from_sealable")?,
        to_sealable: parse_opt_bool(map, "to_sealable")?,
        from_policy_readable: parse_opt_bool(map, "from_policy_readable")?,
        to_policy_readable: parse_opt_bool(map, "to_policy_readable")?,
        justification: req("justification")?,
    })
}

fn is_valid_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
}

fn is_valid_wire_name_tok(s: &str) -> bool {
    !s.is_empty()
        && s.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'_' | b'-' | b'.')
        })
}

pub fn validate_reclassifications_entries(
    entries: &[ReclassificationEntry],
    findings: &mut Vec<LintFinding>,
) {
    let mut seen = BTreeSet::new();
    let mut successors: BTreeMap<&str, &str> = BTreeMap::new();
    for entry in entries {
        if entry.rfc.trim().is_empty()
            || entry.seat.trim().is_empty()
            || entry.justification.trim().is_empty()
        {
            findings.push(compare_err(
                &entry.target,
                "SL12: reclassification entry requires non-empty `rfc`, `seat`, and `justification`",
            ));
        }
        let kind_tag = match entry.kind {
            ReclassKind::Field => "field",
            ReclassKind::Level => "level",
            ReclassKind::WireName => "wire_name",
        };
        if !seen.insert((
            kind_tag,
            entry.target.clone(),
            entry.from.clone(),
            entry.to.clone(),
        )) {
            findings.push(compare_err(
                &entry.target,
                "SL12: duplicate reclassification entry for identical `(kind, target, from, to)`",
            ));
        }
        validate_entry_by_kind(entry, findings);
        if entry.kind == ReclassKind::Field
            && let Some(ref succ) = entry.successor
            && !succ.is_empty()
            && let Some(prev) = successors.insert(entry.target.as_str(), succ.as_str())
            && prev != succ
        {
            findings.push(compare_err(
                &entry.target,
                "SL12: conflicting `successor` targets for the same field",
            ));
        }
    }
    for start in successors.keys() {
        let mut cur = *start;
        let mut path = BTreeSet::new();
        while let Some(&next) = successors.get(cur) {
            if !path.insert(cur) {
                break;
            }
            if next == *start || path.contains(next) {
                findings.push(compare_err(
                    start,
                    &format!("SL12: cyclic field `successor` chain detected at `{start}`"),
                ));
                break;
            }
            cur = next;
        }
    }
}

fn validate_entry_by_kind(entry: &ReclassificationEntry, findings: &mut Vec<LintFinding>) {
    match entry.kind {
        ReclassKind::Field => {
            if entry.target.split('.').count() < 4 || !is_valid_token(&entry.target) {
                findings.push(compare_err(
                    &entry.target,
                    "SL12: field target must be a fully-qualified `pkg.Message.field` path",
                ));
            }
            if !CANONICAL_CLASSES.contains(&entry.from.as_str()) {
                findings.push(compare_err(
                    &entry.target,
                    &format!("SL12: invalid `from` class `{}` on `[[field]]`", entry.from),
                ));
            }
            let valid_to = entry.to == "removed" || CANONICAL_CLASSES.contains(&entry.to.as_str());
            if !valid_to {
                findings.push(compare_err(
                    &entry.target,
                    &format!(
                        "SL12: `to` class `{}` on `[[field]]` must be canonical or `removed`",
                        entry.to
                    ),
                ));
            }
            if entry.to == "removed" && entry.successor.as_deref().is_none_or(str::is_empty) {
                findings.push(compare_err(
                    &entry.target,
                    "SL12: `[[field]]` with `to = \"removed\"` requires non-empty `successor`",
                ));
            }
            if entry.seat != "persona-privacy-officer" {
                findings.push(compare_err(
                    &entry.target,
                    &format!(
                        "SL12: `[[field]]` reclassification requires seat `persona-privacy-officer`, found `{}`",
                        entry.seat
                    ),
                ));
            }
            if let Some(ref succ) = entry.successor
                && (succ.split('.').count() < 4 || !is_valid_token(succ))
            {
                findings.push(compare_err(
                    &entry.target,
                    "SL12: `successor` must be a valid `pkg.Message.field` path",
                ));
            }
        }
        ReclassKind::Level => {
            forbid_field_only_attrs(entry, "[[level]]", findings);
            let Some((level_name, class_name)) = entry.target.split_once(':') else {
                findings.push(compare_err(
                    &entry.target,
                    "SL12: `[[level]]` target must be `<level_name>:<class>`",
                ));
                return;
            };
            if !is_valid_token(level_name) || !CANONICAL_CLASSES.contains(&class_name) {
                findings.push(compare_err(
                    &entry.target,
                    "SL12: `[[level]]` target must name a valid level and canonical commitment class",
                ));
            }
            if entry.from != "absent" && parse_openness(&entry.from).is_none() {
                findings.push(compare_err(
                    &entry.target,
                    &format!(
                        "SL12: invalid `from` disposition `{}` on `[[level]]`",
                        entry.from
                    ),
                ));
            }
            if parse_openness(&entry.to).is_none() {
                findings.push(compare_err(
                    &entry.target,
                    &format!(
                        "SL12: invalid `to` disposition `{}` on `[[level]]`",
                        entry.to
                    ),
                ));
            }
            if entry.seat != "persona-privacy-officer" {
                findings.push(compare_err(
                    &entry.target,
                    &format!(
                        "SL12: `[[level]]` tightening/reclassification requires seat `persona-privacy-officer`, found `{}`",
                        entry.seat
                    ),
                ));
            }
        }
        ReclassKind::WireName => {
            forbid_field_only_attrs(entry, "[[wire_name]]", findings);
            if entry.target.split('.').count() < 4 || !is_valid_token(&entry.target) {
                findings.push(compare_err(
                    &entry.target,
                    "SL12: `[[wire_name]]` target must be `pkg.Enum.ENUM_VALUE`",
                ));
            }
            if !is_valid_wire_name_tok(&entry.from) || !is_valid_wire_name_tok(&entry.to) {
                findings.push(compare_err(
                    &entry.target,
                    "SL12: `[[wire_name]]` from/to must be valid lowercase wire tokens",
                ));
            }
            if entry.seat != "persona-soc-analyst" {
                findings.push(compare_err(
                    &entry.target,
                    &format!(
                        "SL12: `[[wire_name]]` rename requires seat `persona-soc-analyst`, found `{}`",
                        entry.seat
                    ),
                ));
            }
        }
    }
}

fn forbid_field_only_attrs(
    entry: &ReclassificationEntry,
    kind_label: &str,
    findings: &mut Vec<LintFinding>,
) {
    if entry.successor.is_some()
        || entry.from_sealable.is_some()
        || entry.to_sealable.is_some()
        || entry.from_policy_readable.is_some()
        || entry.to_policy_readable.is_some()
    {
        findings.push(compare_err(
            &entry.target,
            &format!(
                "SL12: `{kind_label}` entry cannot declare field-only `successor` or sealable/policy_readable attributes"
            ),
        ));
    }
}

fn compare_err(target: &str, msg: &str) -> LintFinding {
    LintFinding {
        code: "GRDR-LINT-0008".into(),
        domain: LintDomain::Proto,
        severity: LintSeverity::Error,
        target: target.into(),
        message: msg.into(),
    }
}
