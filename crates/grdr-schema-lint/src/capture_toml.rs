// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Capture matrix validator (`SL13`) and strict TOML scalar parser (`crates/grdr-schema/capture.toml`).

use std::collections::{BTreeMap, BTreeSet};

pub use crate::reclass_toml::{ReclassKind, ReclassificationEntry, parse_reclassifications_toml};
use crate::{LintDomain, LintError, LintFinding, LintSeverity};

pub const CANONICAL_CLASSES: &[&str] = &[
    "structural",
    "derived",
    "identifier",
    "content.argument",
    "content.body",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Openness {
    Withheld = 0,
    Redacted = 1,
    DigestOnly = 2,
    Pseudonymous = 3,
    Full = 4,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureLevelRow {
    pub name: String,
    pub rank: u8,
    pub dispositions: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CaptureConfig {
    pub schema: String,
    pub default_level: String,
    pub classes: Vec<String>,
    pub levels: Vec<CaptureLevelRow>,
}

pub fn parse_capture_toml(raw: &str) -> Result<CaptureConfig, LintError> {
    let mut schema = String::new();
    let mut default_level = String::new();
    let mut classes: Vec<String> = Vec::new();
    let mut levels: Vec<CaptureLevelRow> = Vec::new();
    let mut current: Option<(CaptureLevelRow, BTreeSet<String>)> = None;
    let mut top_seen: BTreeSet<String> = BTreeSet::new();
    let mut reading_classes = false;

    for raw_line in raw.lines() {
        let trimmed = strip_toml_comment(raw_line).trim().to_owned();
        if trimmed.is_empty() {
            continue;
        }
        if reading_classes {
            if trimmed == "]" {
                reading_classes = false;
                continue;
            }
            for item in trimmed.trim_end_matches(',').split(',') {
                let piece = item.trim();
                if piece.is_empty() {
                    continue;
                }
                classes.push(unquote_toml_str(piece, "capture.toml")?);
            }
            continue;
        }
        if trimmed == "[[levels]]" {
            if let Some((done, _)) = current.take() {
                levels.push(done);
            }
            current = Some((
                CaptureLevelRow {
                    name: String::new(),
                    rank: 0,
                    dispositions: BTreeMap::new(),
                },
                BTreeSet::new(),
            ));
            continue;
        }
        if trimmed.starts_with('[') {
            return Err(LintError::CaptureOrCodegenViolation {
                target: "capture.toml".into(),
                detail: format!("unexpected TOML section `{trimmed}`"),
            });
        }
        let Some((k_raw, v_raw)) = trimmed.split_once('=') else {
            return Err(LintError::CaptureOrCodegenViolation {
                target: "capture.toml".into(),
                detail: format!("malformed key-value line `{trimmed}`"),
            });
        };
        let key = parse_tomlish_key(k_raw.trim(), "capture.toml")?;
        let val = v_raw.trim();
        if let Some((ref mut lvl, ref mut seen_keys)) = current {
            if !seen_keys.insert(key.clone()) {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: "capture.toml".into(),
                    detail: format!("duplicate key `{key}` inside [[levels]]"),
                });
            }
            if key == "name" {
                lvl.name = unquote_toml_str(val, "capture.toml")?;
            } else if key == "rank" {
                lvl.rank = val
                    .parse::<u8>()
                    .map_err(|_| LintError::CaptureOrCodegenViolation {
                        target: "capture.toml".into(),
                        detail: format!("invalid rank `{val}`"),
                    })?;
            } else if key == "description" {
                let _ = unquote_toml_str(val, "capture.toml")?;
            } else if CANONICAL_CLASSES.contains(&key.as_str()) {
                lvl.dispositions
                    .insert(key, unquote_toml_str(val, "capture.toml")?);
            } else {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: "capture.toml".into(),
                    detail: format!("unknown key `{key}` inside [[levels]]"),
                });
            }
        } else {
            if !top_seen.insert(key.clone()) {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: "capture.toml".into(),
                    detail: format!("duplicate top-level key `{key}` in capture.toml"),
                });
            }
            if key == "schema" {
                schema = unquote_toml_str(val, "capture.toml")?;
            } else if key == "default" {
                default_level = unquote_toml_str(val, "capture.toml")?;
            } else if key == "classes" {
                if val.starts_with('[') && val.ends_with(']') {
                    let inner = val.trim_start_matches('[').trim_end_matches(']');
                    for item in inner.split(',') {
                        let piece = item.trim();
                        if piece.is_empty() {
                            continue;
                        }
                        classes.push(unquote_toml_str(piece, "capture.toml")?);
                    }
                } else if val == "[" {
                    reading_classes = true;
                } else {
                    return Err(LintError::CaptureOrCodegenViolation {
                        target: "capture.toml".into(),
                        detail: "malformed `classes` array in capture.toml".into(),
                    });
                }
            } else {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: "capture.toml".into(),
                    detail: format!("unknown top-level key `{key}` in capture.toml"),
                });
            }
        }
    }
    if reading_classes {
        return Err(LintError::CaptureOrCodegenViolation {
            target: "capture.toml".into(),
            detail: "unterminated `classes = [` array in capture.toml".into(),
        });
    }
    if let Some((done, _)) = current {
        levels.push(done);
    }
    if schema.is_empty() {
        return Err(LintError::CaptureOrCodegenViolation {
            target: "capture.toml".into(),
            detail: "missing required `schema` in capture.toml".into(),
        });
    }
    Ok(CaptureConfig {
        schema,
        default_level,
        classes,
        levels,
    })
}

pub fn validate_capture_sl13(
    cfg: &CaptureConfig,
    options_class_wire_names: &BTreeSet<String>,
    findings: &mut Vec<LintFinding>,
) {
    if cfg.schema != "grdr.capture.v1alpha1" {
        findings.push(capture_err(
            "SL13: `capture.toml` schema must be `grdr.capture.v1alpha1`",
        ));
    }
    if cfg.default_level != "metadata" {
        findings.push(capture_err(
            "SL13: `capture.toml` default level must be `metadata`",
        ));
    }
    let expected: Vec<String> = CANONICAL_CLASSES.iter().map(|s| (*s).to_owned()).collect();
    if cfg.classes != expected {
        findings.push(capture_err(
            "SL13: `capture.toml` classes must exactly match [structural, derived, identifier, content.argument, content.body]",
        ));
    }
    for cls in CANONICAL_CLASSES {
        if !options_class_wire_names.contains(*cls) {
            findings.push(capture_err(&format!(
                "SL13: commitment class `{cls}` missing lower-case wire_name binding in options.proto"
            )));
        }
    }
    if cfg.levels.is_empty() {
        findings.push(capture_err(
            "SL13: `capture.toml` must define at least one level",
        ));
        return;
    }

    let mut prev_rank: u8 = 0;
    let mut prev_openness: Option<Vec<Openness>> = None;
    let mut found_default = false;
    let mut seen_names = BTreeSet::new();

    for lvl in &cfg.levels {
        if lvl.name.is_empty()
            || !lvl
                .name
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
            || !seen_names.insert(lvl.name.clone())
        {
            findings.push(capture_err(&format!(
                "SL13: invalid or duplicate capture level name `{}`",
                lvl.name
            )));
        }
        if lvl.rank <= prev_rank {
            findings.push(capture_err(&format!(
                "SL13: level `{}` rank {} must strictly increase",
                lvl.name, lvl.rank
            )));
        }
        prev_rank = lvl.rank;
        if lvl.name == cfg.default_level {
            found_default = true;
            let arg = lvl.dispositions.get("content.argument").map(String::as_str);
            let body = lvl.dispositions.get("content.body").map(String::as_str);
            let ident = lvl.dispositions.get("identifier").map(String::as_str);
            if arg != Some("withheld") || body != Some("withheld") {
                findings.push(capture_err(
                    "SL13: default capture level must withhold both content.argument and content.body",
                ));
            }
            if ident == Some("full") {
                findings.push(capture_err(
                    "SL13: default capture level cannot expose identifier as `full`",
                ));
            }
        }
        let mut row_openness = Vec::new();
        let mut prev_class_open: Option<Openness> = None;
        for cls in CANONICAL_CLASSES {
            let Some(disp) = lvl.dispositions.get(*cls) else {
                findings.push(capture_err(&format!(
                    "SL13: level `{}` missing class `{cls}`",
                    lvl.name
                )));
                continue;
            };
            let Some(open) = parse_openness(disp) else {
                findings.push(capture_err(&format!(
                    "SL13: level `{}` class `{cls}` invalid disposition `{disp}`",
                    lvl.name
                )));
                continue;
            };
            if let Some(prev_c) = prev_class_open
                && open > prev_c
            {
                findings.push(capture_err(&format!(
                    "SL13: openness rises with sensitivity at level `{}` class `{cls}`",
                    lvl.name
                )));
            }
            prev_class_open = Some(open);
            row_openness.push(open);
        }
        if let Some(ref prev_lvl) = prev_openness {
            for (idx, (prev_o, cur_o)) in prev_lvl.iter().zip(row_openness.iter()).enumerate() {
                if cur_o < prev_o {
                    let cls = CANONICAL_CLASSES.get(idx).copied().unwrap_or("unknown");
                    findings.push(capture_err(&format!(
                        "SL13: openness fell at level `{}` class `{cls}`",
                        lvl.name
                    )));
                }
            }
        }
        prev_openness = Some(row_openness);
    }

    if !found_default {
        findings.push(capture_err(&format!(
            "SL13: `capture.toml` default level `{}` not defined",
            cfg.default_level
        )));
    }
}

pub(crate) fn parse_openness(raw: &str) -> Option<Openness> {
    match raw {
        "withheld" => Some(Openness::Withheld),
        "redacted" => Some(Openness::Redacted),
        "digest_only" => Some(Openness::DigestOnly),
        "pseudonymous" => Some(Openness::Pseudonymous),
        "full" => Some(Openness::Full),
        _ => None,
    }
}

pub(crate) fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_double {
            escaped = true;
            continue;
        }
        if ch == '"' && !in_single {
            in_double = !in_double;
            continue;
        }
        if ch == '\'' && !in_double {
            in_single = !in_single;
            continue;
        }
        if ch == '#' && !in_double && !in_single {
            return line.get(..idx).unwrap_or(line);
        }
    }
    line
}

pub(crate) fn parse_tomlish_key(raw: &str, file: &str) -> Result<String, LintError> {
    let s = raw.trim();
    if s.starts_with('"') || s.starts_with('\'') {
        return unquote_toml_str(s, file);
    }
    if !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.'))
    {
        return Ok(s.to_owned());
    }
    Err(LintError::CaptureOrCodegenViolation {
        target: file.into(),
        detail: format!("invalid TOML key `{s}`"),
    })
}

pub(crate) fn unquote_toml_str(raw: &str, file: &str) -> Result<String, LintError> {
    let s = raw.trim();
    if let Some(inner) = s.strip_prefix('"').and_then(|v| v.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    _ => {
                        return Err(LintError::CaptureOrCodegenViolation {
                            target: file.into(),
                            detail: format!("unsupported TOML escape in `{s}`"),
                        });
                    }
                }
            } else if ch == '"' {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: file.into(),
                    detail: format!("unescaped quote inside TOML string `{s}`"),
                });
            } else {
                out.push(ch);
            }
        }
        return Ok(out);
    }
    if let Some(inner) = s.strip_prefix('\'').and_then(|v| v.strip_suffix('\''))
        && !inner.contains('\'')
    {
        return Ok(inner.to_owned());
    }
    Err(LintError::CaptureOrCodegenViolation {
        target: file.into(),
        detail: format!("expected quoted TOML string, got `{s}`"),
    })
}

fn capture_err(msg: &str) -> LintFinding {
    LintFinding {
        code: "GRDR-LINT-0009".into(),
        domain: LintDomain::Proto,
        severity: LintSeverity::Error,
        target: "crates/grdr-schema/capture.toml".into(),
        message: msg.into(),
    }
}
