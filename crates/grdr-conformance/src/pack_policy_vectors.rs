// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Execution of Essentials Cedar policy vectors through the `grdr_core::policy::evaluate` Cedar 4.x engine.

use std::path::Path;

use grdr_core::policy::evaluate;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ControlPoint, KillSwitchState, Mode, PolicyPack,
    PolicyRule, RuleMatch, Verdict,
};
use jiff::Timestamp;

use crate::ConformanceError;
use crate::pack_manifest::{conf_err, read_regular_text, unquote};

#[derive(Debug, Clone, PartialEq, Eq)]
struct EssentialsVectorSpec {
    id: String,
    expect_verdict: Verdict,
    expect_rule: Option<String>,
    action: ActionClass,
    target: String,
}

pub fn execute_essentials_vectors(
    cedar_source: &str,
    vectors_path: &Path,
) -> Result<usize, ConformanceError> {
    let pack = compile_essentials_pack_from_cedar(cedar_source)?;
    let vectors_raw = read_regular_text(vectors_path)?;
    let vectors = parse_essentials_vectors_yaml(&vectors_raw)?;
    if vectors.is_empty() {
        return Err(conf_err(
            "ess-vectors",
            "essentials-vectors.yaml contains zero test vectors",
        ));
    }

    let now = Timestamp::from_second(1_750_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    let packs = [pack];
    for vec_item in &vectors {
        let attempt = ActionAttempt {
            id: vec_item.id.clone(),
            session_id: "sess-pack-conformance".into(),
            device_id: "dev-pack-conformance".into(),
            device_name: "pack-runner".into(),
            agent_name: "claude-code".into(),
            action_class: vec_item.action,
            control_point: ControlPoint::Hook,
            target: vec_item.target.clone(),
            summary: vec_item.id.clone(),
            timestamp: now,
            ..Default::default()
        };
        let receipt = evaluate(&attempt, &packs, &[], &KillSwitchState::Inactive, now);
        if receipt.verdict != vec_item.expect_verdict {
            return Err(conf_err(
                "ess-vectors",
                &format!(
                    "vector `{}` expected {:?}, got {:?} (rule={:?}, reason={})",
                    vec_item.id,
                    vec_item.expect_verdict,
                    receipt.verdict,
                    receipt.rule_id,
                    receipt.reason
                ),
            ));
        }
        if let Some(expected_rule) = vec_item.expect_rule.as_deref()
            && receipt.rule_id.as_deref() != Some(expected_rule)
        {
            return Err(conf_err(
                "ess-vectors",
                &format!(
                    "vector `{}` expected rule `{expected_rule}`, got `{:?}` (reason={})",
                    vec_item.id, receipt.rule_id, receipt.reason
                ),
            ));
        }
    }
    Ok(vectors.len())
}

fn compile_essentials_pack_from_cedar(source: &str) -> Result<PolicyPack, ConformanceError> {
    let stripped: String = source
        .lines()
        .filter(|line| !line.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    let mut rules = Vec::new();
    for raw_stmt in stripped.split(';') {
        let stmt = raw_stmt.trim();
        if !stmt.contains("forbid") {
            continue;
        }
        let cedar_stmt = format!("{stmt};");
        let id = extract_attr(stmt, "@id(\"")
            .ok_or_else(|| conf_err("ess-vectors", "Cedar statement missing @id"))?;
        let locked = stmt.contains("@final(\"true\")");
        let mode = if locked {
            Mode::Block
        } else if stmt.contains("@max_mode(\"Ask\")") {
            Mode::Ask
        } else {
            Mode::Block
        };
        let min_grade = if stmt.contains("@min_grade(\"G3\")") {
            ApprovalGrade::G3
        } else if stmt.contains("@min_grade(\"G2\")") {
            ApprovalGrade::G2
        } else {
            ApprovalGrade::G1
        };
        rules.push(PolicyRule {
            id: id.clone(),
            title: id.clone(),
            description: String::new(),
            mode,
            min_grade,
            enabled: true,
            locked,
            matcher: RuleMatch {
                action_classes: Vec::new(),
                target_prefixes: Vec::new(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: format!("Matched Essentials policy rule {id}."),
            cedar: Some(cedar_stmt),
        });
    }
    Ok(PolicyPack {
        id: "grdr.essentials".into(),
        name: "Essentials".into(),
        description: "Compiled live Essentials Cedar policy pack".into(),
        version: "1.0.0".into(),
        channel: "schema-policy".into(),
        rules,
        key_id: None,
        signature: None,
    })
}

fn parse_essentials_vectors_yaml(raw: &str) -> Result<Vec<EssentialsVectorSpec>, ConformanceError> {
    let mut items = Vec::new();
    let mut cur_id = String::new();
    let mut cur_verdict: Option<Verdict> = None;
    let mut cur_rule: Option<String> = None;
    let mut cur_action: Option<ActionClass> = None;
    let mut cur_target = String::new();

    for raw_line in raw.lines() {
        let trimmed = raw_line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- id:") {
            if !cur_id.is_empty() {
                items.push(finish_vector(
                    &mut cur_id,
                    &mut cur_verdict,
                    &mut cur_rule,
                    &mut cur_action,
                    &mut cur_target,
                )?);
            }
            cur_id = unquote(rest);
            continue;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            match k.trim() {
                "expect_verdict" => {
                    cur_verdict = Some(match unquote(v).as_str() {
                        "Allow" => Verdict::Allow,
                        "Deny" => Verdict::Deny,
                        "StepUp" => Verdict::StepUp,
                        other => {
                            return Err(conf_err("ess-vectors", &format!("bad verdict `{other}`")));
                        }
                    });
                }
                "expect_rule" => cur_rule = Some(unquote(v)),
                "action" => cur_action = Some(ActionClass::from_name(&unquote(v))),
                "target" => cur_target = unquote(v),
                _ => {}
            }
        }
    }
    if !cur_id.is_empty() {
        items.push(finish_vector(
            &mut cur_id,
            &mut cur_verdict,
            &mut cur_rule,
            &mut cur_action,
            &mut cur_target,
        )?);
    }
    Ok(items)
}

fn finish_vector(
    id: &mut String,
    verdict: &mut Option<Verdict>,
    rule: &mut Option<String>,
    action: &mut Option<ActionClass>,
    target: &mut String,
) -> Result<EssentialsVectorSpec, ConformanceError> {
    Ok(EssentialsVectorSpec {
        id: std::mem::take(id),
        expect_verdict: verdict
            .take()
            .ok_or_else(|| conf_err("ess-vectors", "vector missing expect_verdict"))?,
        expect_rule: rule.take(),
        action: action
            .take()
            .ok_or_else(|| conf_err("ess-vectors", "vector missing action"))?,
        target: std::mem::take(target),
    })
}

fn extract_attr(src: &str, prefix: &str) -> Option<String> {
    let start = src.find(prefix)?;
    let rest = src.get(start.saturating_add(prefix.len())..)?;
    let end = rest.find('"')?;
    rest.get(..end).map(str::to_owned)
}
