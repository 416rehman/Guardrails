// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Execution of Sigma detection rule fixtures and CRA workspace member cross-checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use crate::ConformanceError;
use crate::pack_manifest::{conf_err, read_regular_text, unquote};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SigmaRuleSpec {
    pub row: u32,
    pub rule_id: String,
    pub selection: BTreeMap<String, Vec<String>>,
    pub positive_fixture: String,
    pub negative_fixture: String,
    pub response_verbs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionFixtureSpec {
    pub id: String,
    pub rule_id: String,
    pub expect_match: bool,
    pub payload: BTreeMap<String, String>,
}

pub fn execute_detection_fixtures(
    rule_files: &[PathBuf],
    fixtures_path: &Path,
    known_actions: &BTreeSet<String>,
) -> Result<usize, ConformanceError> {
    let mut rules = Vec::with_capacity(rule_files.len());
    for path in rule_files {
        let raw = read_regular_text(path)?;
        let spec = parse_sigma_rule_yaml(&raw, path)?;
        for verb in &spec.response_verbs {
            if !known_actions.contains(verb) {
                return Err(conf_err(
                    "det-fixtures",
                    &format!(
                        "rule `{}` cites unknown response verb `{verb}`",
                        spec.rule_id
                    ),
                ));
            }
        }
        rules.push(spec);
    }

    let fixtures_raw = read_regular_text(fixtures_path)?;
    let fixtures = parse_detection_fixtures_yaml(&fixtures_raw)?;
    let mut by_id: BTreeMap<&str, &DetectionFixtureSpec> = BTreeMap::new();
    for fix in &fixtures {
        if by_id.insert(fix.id.as_str(), fix).is_some() {
            return Err(conf_err(
                "det-fixtures",
                &format!("duplicate fixture id `{}`", fix.id),
            ));
        }
    }

    let mut used_ids = BTreeSet::new();
    for rule in &rules {
        let pos = by_id.get(rule.positive_fixture.as_str()).ok_or_else(|| {
            conf_err(
                "det-fixtures",
                &format!(
                    "missing positive fixture `{}` for rule `{}`",
                    rule.positive_fixture, rule.rule_id
                ),
            )
        })?;
        let neg = by_id.get(rule.negative_fixture.as_str()).ok_or_else(|| {
            conf_err(
                "det-fixtures",
                &format!(
                    "missing negative fixture `{}` for rule `{}`",
                    rule.negative_fixture, rule.rule_id
                ),
            )
        })?;
        used_ids.insert(pos.id.as_str());
        used_ids.insert(neg.id.as_str());

        if pos.rule_id != rule.rule_id || !pos.expect_match {
            return Err(conf_err(
                "det-fixtures",
                &format!("positive fixture `{}` metadata mismatch", pos.id),
            ));
        }
        if neg.rule_id != rule.rule_id || neg.expect_match {
            return Err(conf_err(
                "det-fixtures",
                &format!("negative fixture `{}` metadata mismatch", neg.id),
            ));
        }

        for field in rule.selection.keys() {
            let Some(val) = pos.payload.get(field) else {
                return Err(conf_err(
                    "det-fixtures",
                    &format!(
                        "positive fixture `{}` missing constrained field `{field}`",
                        pos.id
                    ),
                ));
            };
            if val.trim().is_empty() || val.contains('*') || val.contains('?') {
                return Err(conf_err(
                    "det-fixtures",
                    &format!(
                        "positive fixture `{}` field `{field}` uses empty or wildcard value",
                        pos.id
                    ),
                ));
            }
        }

        if !selection_matches(&rule.selection, &pos.payload) {
            return Err(conf_err(
                "det-fixtures",
                &format!(
                    "positive fixture `{}` did not match rule `{}` selection",
                    pos.id, rule.rule_id
                ),
            ));
        }
        if selection_matches(&rule.selection, &neg.payload) {
            return Err(conf_err(
                "det-fixtures",
                &format!(
                    "negative fixture `{}` unexpectedly matched rule `{}`",
                    neg.id, rule.rule_id
                ),
            ));
        }
    }

    if used_ids.len() != fixtures.len() {
        return Err(conf_err(
            "det-fixtures",
            "orphan detection fixture(s) unreferenced by any rule",
        ));
    }
    Ok(fixtures.len())
}

pub fn validate_cra_workspace_refs(repo_root: &Path) -> Result<(), ConformanceError> {
    let cra_path = repo_root.join("docs/compliance/cra-technical-file.md");
    let raw = read_regular_text(&cra_path)?;
    let crates_dir = repo_root.join("crates");
    let programs_dir = repo_root.join("programs");
    let mut checked = 0_usize;

    for token in raw.split('`') {
        if !token.starts_with("grdr-") || token.contains(' ') || token.contains('/') {
            continue;
        }
        if matches!(
            token,
            "grdr-sensor-linux-bpf" | "grdr-desktop" | "grdr-airgap-bundle"
        ) {
            continue;
        }
        let in_crates = crates_dir.join(token).is_dir();
        let in_programs = programs_dir.join(token).is_dir();
        if !in_crates && !in_programs {
            return Err(conf_err(
                "cra-doc",
                &format!("cra-technical-file.md cites non-existent crate or program `{token}`"),
            ));
        }
        checked = checked.saturating_add(1);
    }
    if checked < 10 {
        return Err(conf_err(
            "cra-doc",
            "expected >= 10 workspace crate/program references in cra-technical-file.md",
        ));
    }
    Ok(())
}

pub fn collect_response_action_ids(actions_raw: &str) -> BTreeSet<String> {
    let mut ids = BTreeSet::new();
    for line in actions_raw.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix("- id:") {
            let id = unquote(rest);
            if !id.is_empty() {
                ids.insert(id);
            }
        }
    }
    ids
}

fn selection_matches(
    selection: &BTreeMap<String, Vec<String>>,
    payload: &BTreeMap<String, String>,
) -> bool {
    !selection.is_empty()
        && selection.iter().all(|(field, allowed)| {
            payload
                .get(field)
                .is_some_and(|actual| allowed.iter().any(|cand| cand == actual))
        })
}

fn parse_sigma_rule_yaml(raw: &str, path: &Path) -> Result<SigmaRuleSpec, ConformanceError> {
    let mut row: Option<u32> = None;
    let mut rule_id = String::new();
    let mut positive_fixture = String::new();
    let mut negative_fixture = String::new();
    let mut response_verbs = Vec::new();
    let mut selection: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut in_selection = false;
    let mut current_sel_key: Option<String> = None;

    for raw_line in raw.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if raw_line.starts_with("  selection:") {
            in_selection = true;
            current_sel_key = None;
            continue;
        }
        if in_selection && !raw_line.starts_with("    ") {
            in_selection = false;
            current_sel_key = None;
        }
        if in_selection {
            if raw_line.starts_with("      - ") {
                if let Some(key) = current_sel_key.as_deref()
                    && let Some(item) = trimmed.strip_prefix("- ")
                {
                    selection
                        .entry(key.to_owned())
                        .or_default()
                        .push(unquote(item));
                }
            } else if raw_line.starts_with("    ")
                && let Some((k, v)) = trimmed.split_once(':')
            {
                let key = unquote(k);
                let val = v.trim();
                if val.is_empty() {
                    current_sel_key = Some(key);
                } else {
                    selection.entry(key).or_default().push(unquote(val));
                    current_sel_key = None;
                }
            }
            continue;
        }

        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim();
            let val = v.trim();
            match key {
                "row" => row = val.parse::<u32>().ok(),
                "rule_id" => rule_id = unquote(val),
                "positive" => positive_fixture = unquote(val),
                "negative" => negative_fixture = unquote(val),
                "verbs" => {
                    response_verbs = val
                        .trim_start_matches('[')
                        .trim_end_matches(']')
                        .split(',')
                        .map(unquote)
                        .filter(|s| !s.is_empty())
                        .collect();
                }
                _ => {}
            }
        }
    }

    let resolved_row = row.ok_or_else(|| {
        conf_err(
            "det-pack",
            &format!("missing x_grdr.row in {}", path.display()),
        )
    })?;
    if rule_id.is_empty()
        || selection.is_empty()
        || positive_fixture.is_empty()
        || negative_fixture.is_empty()
    {
        return Err(conf_err(
            "det-pack",
            &format!(
                "incomplete rule metadata or selection in {}",
                path.display()
            ),
        ));
    }
    Ok(SigmaRuleSpec {
        row: resolved_row,
        rule_id,
        selection,
        positive_fixture,
        negative_fixture,
        response_verbs,
    })
}

fn parse_detection_fixtures_yaml(raw: &str) -> Result<Vec<DetectionFixtureSpec>, ConformanceError> {
    let mut out = Vec::new();
    for line in raw.lines() {
        let trimmed = line.trim();
        let Some(inner) = trimmed.strip_prefix("- {") else {
            continue;
        };
        let body = inner.trim_end_matches('}');
        let (head, payload_part) = body
            .split_once("payload:")
            .ok_or_else(|| conf_err("det-fixtures", &format!("missing payload in `{trimmed}`")))?;
        let (mut id, mut rule_id, mut expect_match) = (String::new(), String::new(), None);
        for pair in head.split(',') {
            if let Some((k, v)) = pair.split_once(':') {
                match k.trim() {
                    "id" => id = unquote(v),
                    "rule_id" => rule_id = unquote(v),
                    "expect_match" => expect_match = Some(v.trim() == "true"),
                    _ => {}
                }
            }
        }
        let payload_inner = payload_part
            .trim()
            .trim_start_matches('{')
            .trim_end_matches('}');
        let mut payload = BTreeMap::new();
        for pair in payload_inner.split(',') {
            if let Some((k, v)) = pair.split_once(':') {
                let fk = unquote(k);
                let fv = unquote(v);
                if !fk.is_empty() {
                    payload.insert(fk, fv);
                }
            }
        }
        out.push(DetectionFixtureSpec {
            id,
            rule_id,
            expect_match: expect_match.ok_or_else(|| {
                conf_err(
                    "det-fixtures",
                    &format!("missing expect_match in `{trimmed}`"),
                )
            })?,
            payload,
        });
    }
    Ok(out)
}
