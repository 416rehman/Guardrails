// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Execution of Sigma detection rule fixtures and CRA workspace member cross-checks.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use grdr_core::detect::engine::SigmaDetectionEngine;
use grdr_core::detect::response::DEFAULT_MAX_SHARE_BP;
use grdr_core::detect::types::{
    DeploymentScope, DetectionEngine, HostProfile, ResponseExecutionMode, SigmaRule,
    VerifiedDetectionContent,
};
use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_model::Mode;

use crate::ConformanceError;
use crate::pack_fixture_eval::{
    DetectionFixtureSpec, eval_condition_for_fixture, parse_detection_fixtures_yaml,
    validate_positive_payload_concrete,
};
use crate::pack_manifest::{conf_err, read_regular_text, unquote};

#[derive(Debug, Clone)]
struct ParsedFixtureRule {
    rule: SigmaRule,
    positive_fixture: String,
    negative_fixture: String,
}

pub fn execute_detection_fixtures(
    rule_files: &[PathBuf],
    fixture_paths: &[PathBuf],
    known_actions: &BTreeSet<String>,
) -> Result<usize, ConformanceError> {
    if rule_files.is_empty() || fixture_paths.is_empty() {
        return Err(conf_err(
            "det-fixtures",
            "expected non-empty detection rules and fixture files",
        ));
    }

    let mut raw_rules_yaml = Vec::with_capacity(rule_files.len());
    let mut fixture_refs: BTreeMap<String, (String, String)> = BTreeMap::new();
    for path in rule_files {
        let raw = read_regular_text(path)?;
        let (rule_id, pos_id, neg_id) = parse_rule_fixture_refs(&raw, path)?;
        if fixture_refs
            .insert(rule_id.clone(), (pos_id, neg_id))
            .is_some()
        {
            return Err(conf_err(
                "det-fixtures",
                &format!("duplicate detection rule_id `{rule_id}`"),
            ));
        }
        raw_rules_yaml.push(raw);
    }

    let host = default_fixture_host();
    let content = VerifiedDetectionContent {
        pack_id: "grdr.det.core".into(),
        version: "1.0.0".into(),
        raw_rules_yaml,
        pack_mode: Mode::Watch,
    };
    let (engine, load_report) = SigmaDetectionEngine::load(&content, &host)
        .map_err(|e| conf_err("det-fixtures", &e.to_string()))?;
    if load_report.loaded_rules.len() != rule_files.len() || !load_report.skipped_rules.is_empty() {
        return Err(conf_err(
            "det-fixtures",
            &format!(
                "expected all {} rules to load cleanly (loaded={}, skipped={})",
                rule_files.len(),
                load_report.loaded_rules.len(),
                load_report.skipped_rules.len()
            ),
        ));
    }

    let mut rules = Vec::with_capacity(rule_files.len());
    for loaded in engine.loaded_rules() {
        validate_rule_response(loaded, known_actions)?;
        let (positive_fixture, negative_fixture) =
            fixture_refs.get(&loaded.rule_id).cloned().ok_or_else(|| {
                conf_err(
                    "det-fixtures",
                    &format!("missing test refs for rule `{}`", loaded.rule_id),
                )
            })?;
        rules.push(ParsedFixtureRule {
            rule: loaded.clone(),
            positive_fixture,
            negative_fixture,
        });
    }

    let mut all_fixtures = Vec::new();
    let mut seen_fixture_ids = BTreeSet::new();
    for fix_path in fixture_paths {
        let raw = read_regular_text(fix_path)?;
        let parsed = parse_detection_fixtures_yaml(&raw, fix_path)?;
        for fix in parsed {
            if !seen_fixture_ids.insert(fix.id.clone()) {
                return Err(conf_err(
                    "det-fixtures",
                    &format!("duplicate fixture id `{}`", fix.id),
                ));
            }
            all_fixtures.push(fix);
        }
    }

    let by_id: BTreeMap<&str, &DetectionFixtureSpec> =
        all_fixtures.iter().map(|f| (f.id.as_str(), f)).collect();
    let mut used_ids = BTreeSet::new();

    for entry in &rules {
        let pos = by_id
            .get(entry.positive_fixture.as_str())
            .copied()
            .ok_or_else(|| {
                conf_err(
                    "det-fixtures",
                    &format!(
                        "missing positive fixture `{}` for rule `{}`",
                        entry.positive_fixture, entry.rule.rule_id
                    ),
                )
            })?;
        let neg = by_id
            .get(entry.negative_fixture.as_str())
            .copied()
            .ok_or_else(|| {
                conf_err(
                    "det-fixtures",
                    &format!(
                        "missing negative fixture `{}` for rule `{}`",
                        entry.negative_fixture, entry.rule.rule_id
                    ),
                )
            })?;
        used_ids.insert(pos.id.as_str());
        used_ids.insert(neg.id.as_str());

        if pos.rule_id != entry.rule.rule_id || !pos.expect_match {
            return Err(conf_err(
                "det-fixtures",
                &format!("positive fixture `{}` metadata mismatch", pos.id),
            ));
        }
        if neg.rule_id != entry.rule.rule_id || neg.expect_match {
            return Err(conf_err(
                "det-fixtures",
                &format!("negative fixture `{}` metadata mismatch", neg.id),
            ));
        }

        validate_positive_payload_concrete(&entry.rule, pos, &host.expand_vars)?;

        if !eval_condition_for_fixture(
            &entry.rule.condition_ast,
            &entry.rule.selections,
            &pos.payload,
            &host.expand_vars,
            0,
        )? {
            return Err(conf_err(
                "det-fixtures",
                &format!(
                    "positive fixture `{}` did not match rule `{}`",
                    pos.id, entry.rule.rule_id
                ),
            ));
        }
        if eval_condition_for_fixture(
            &entry.rule.condition_ast,
            &entry.rule.selections,
            &neg.payload,
            &host.expand_vars,
            0,
        )? {
            return Err(conf_err(
                "det-fixtures",
                &format!(
                    "negative fixture `{}` unexpectedly matched rule `{}`",
                    neg.id, entry.rule.rule_id
                ),
            ));
        }
    }

    if used_ids.len() != all_fixtures.len() {
        return Err(conf_err(
            "det-fixtures",
            "orphan detection fixture(s) unreferenced by any rule",
        ));
    }
    Ok(all_fixtures.len())
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

fn default_fixture_host() -> HostProfile {
    let mut expand_vars = BTreeMap::new();
    expand_vars.insert(
        "grdr_agent_images".into(),
        vec!["claude".into(), "codex".into()],
    );
    HostProfile {
        device_id: "conformance-dev".into(),
        device_name: "conformance-host".into(),
        organisation_id: "default".into(),
        scope: DeploymentScope::Any,
        provenance_grade: 2,
        expand_vars,
        model_audit_passed: true,
        remediate_approvers: BTreeMap::new(),
    }
}

fn parse_rule_fixture_refs(
    raw: &str,
    path: &Path,
) -> Result<(String, String, String), ConformanceError> {
    let doc = parse_yaml(raw).map_err(|e| conf_err("det-pack", &e.to_string()))?;
    let x_grdr = doc
        .get("x_grdr")
        .ok_or_else(|| conf_err("det-pack", &format!("missing x_grdr in {}", path.display())))?;
    let rule_id = x_grdr
        .get("rule_id")
        .and_then(YamlValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            conf_err(
                "det-pack",
                &format!("missing x_grdr.rule_id in {}", path.display()),
            )
        })?
        .to_owned();
    let tests = x_grdr.get("tests").ok_or_else(|| {
        conf_err(
            "det-pack",
            &format!("missing x_grdr.tests in {}", path.display()),
        )
    })?;
    let pos = tests
        .get("positive")
        .and_then(YamlValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            conf_err(
                "det-pack",
                &format!("missing x_grdr.tests.positive in {}", path.display()),
            )
        })?
        .to_owned();
    let neg = tests
        .get("negative")
        .and_then(YamlValue::as_str)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| {
            conf_err(
                "det-pack",
                &format!("missing x_grdr.tests.negative in {}", path.display()),
            )
        })?
        .to_owned();
    Ok((rule_id, pos, neg))
}

fn validate_rule_response(
    rule: &SigmaRule,
    known_actions: &BTreeSet<String>,
) -> Result<(), ConformanceError> {
    let Some(binding) = &rule.response else {
        return Err(conf_err(
            "det-pack",
            &format!("rule `{}` missing x_grdr.response block", rule.rule_id),
        ));
    };
    if binding.mode != ResponseExecutionMode::Simulate {
        return Err(conf_err(
            "det-pack",
            &format!("rule `{}` response mode must be `simulate`", rule.rule_id),
        ));
    }
    if binding.max_scope != "session" && binding.max_scope != "organisation" {
        return Err(conf_err(
            "det-pack",
            &format!(
                "rule `{}` invalid response max_scope `{}`",
                rule.rule_id, binding.max_scope
            ),
        ));
    }
    if binding.max_share_bp > DEFAULT_MAX_SHARE_BP {
        return Err(conf_err(
            "det-pack",
            &format!(
                "rule `{}` response max_share_bp {} exceeds {DEFAULT_MAX_SHARE_BP}",
                rule.rule_id, binding.max_share_bp
            ),
        ));
    }
    for verb in &binding.verbs {
        if !known_actions.contains(verb) {
            return Err(conf_err(
                "det-fixtures",
                &format!(
                    "rule `{}` cites unknown response verb `{verb}`",
                    rule.rule_id
                ),
            ));
        }
    }
    Ok(())
}
