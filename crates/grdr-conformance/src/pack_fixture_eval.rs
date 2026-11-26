// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Sigma fixture payload parsing and AST selection matching for conformance checks.

use std::collections::BTreeMap;
use std::path::Path;

use grdr_core::detect::condition::{sel_name_matches_pattern, wildcard_match_ci};
use grdr_core::detect::types::{
    ConditionExpr, FieldPredicate, MAX_CONDITION_DEPTH, SelectionBlock, SigmaModifier, SigmaRule,
};
use grdr_core::detect::yaml::{YamlValue, parse_yaml};

use crate::ConformanceError;
use crate::pack_manifest::conf_err;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DetectionFixtureSpec {
    pub id: String,
    pub rule_id: String,
    pub expect_match: bool,
    pub payload: BTreeMap<String, String>,
}

pub(crate) fn parse_detection_fixtures_yaml(
    raw: &str,
    path: &Path,
) -> Result<Vec<DetectionFixtureSpec>, ConformanceError> {
    let doc = parse_yaml(raw).map_err(|e| conf_err("det-fixtures", &e.to_string()))?;
    let pack_id = doc
        .get("pack_id")
        .and_then(YamlValue::as_str)
        .ok_or_else(|| {
            conf_err(
                "det-fixtures",
                &format!("missing pack_id in {}", path.display()),
            )
        })?;
    if pack_id != "grdr.det.core" {
        return Err(conf_err(
            "det-fixtures",
            &format!(
                "expected fixture pack_id `grdr.det.core`, got `{pack_id}` in {}",
                path.display()
            ),
        ));
    }
    let items = doc
        .get("fixtures")
        .and_then(YamlValue::as_seq)
        .ok_or_else(|| {
            conf_err(
                "det-fixtures",
                &format!("missing fixtures sequence in {}", path.display()),
            )
        })?;

    let mut out = Vec::with_capacity(items.len());
    for item in items {
        let map = item.as_map().ok_or_else(|| {
            conf_err(
                "det-fixtures",
                &format!("fixture entry must be map in {}", path.display()),
            )
        })?;
        let id = map
            .get("id")
            .and_then(YamlValue::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| conf_err("det-fixtures", &format!("missing id in {}", path.display())))?
            .to_owned();
        let rule_id = map
            .get("rule_id")
            .and_then(YamlValue::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| {
                conf_err(
                    "det-fixtures",
                    &format!("missing rule_id in fixture `{id}`"),
                )
            })?
            .to_owned();
        let expect_match = map
            .get("expect_match")
            .and_then(YamlValue::as_bool)
            .ok_or_else(|| {
                conf_err(
                    "det-fixtures",
                    &format!("missing expect_match in fixture `{id}`"),
                )
            })?;

        let mut payload = BTreeMap::new();
        if let Some(nested) = map.get("payload").and_then(YamlValue::as_map) {
            for (k, v) in nested {
                if let Some(s) = yaml_scalar_to_string(v) {
                    payload.insert(k.clone(), s);
                }
            }
        } else {
            for (k, v) in map {
                if k != "id"
                    && k != "rule_id"
                    && k != "expect_match"
                    && let Some(s) = yaml_scalar_to_string(v)
                {
                    payload.insert(k.clone(), s);
                }
            }
        }
        out.push(DetectionFixtureSpec {
            id,
            rule_id,
            expect_match,
            payload,
        });
    }
    Ok(out)
}

fn yaml_scalar_to_string(v: &YamlValue) -> Option<String> {
    match v {
        YamlValue::Str(s) => Some(s.clone()),
        YamlValue::Bool(b) => Some(if *b { "true" } else { "false" }.to_owned()),
        YamlValue::Int(i) => Some(i.to_string()),
        YamlValue::Null | YamlValue::Seq(_) | YamlValue::Map(_) => None,
    }
}

pub(crate) fn validate_positive_payload_concrete(
    rule: &SigmaRule,
    pos: &DetectionFixtureSpec,
    expand_vars: &BTreeMap<String, Vec<String>>,
) -> Result<(), ConformanceError> {
    let mut any_matched_selection = false;
    for sel in rule.selections.values() {
        if !eval_selection_for_fixture(sel, &pos.payload, expand_vars)? {
            continue;
        }
        any_matched_selection = true;
        for pred in &sel.predicates {
            if pred.modifiers.contains(&SigmaModifier::Exists) {
                continue;
            }
            let Some(val) = pos.payload.get(&pred.field) else {
                return Err(conf_err(
                    "det-fixtures",
                    &format!(
                        "positive fixture `{}` missing constrained field `{}`",
                        pos.id, pred.field
                    ),
                ));
            };
            if val.trim().is_empty() || val.contains('*') || val.contains('?') {
                return Err(conf_err(
                    "det-fixtures",
                    &format!(
                        "positive fixture `{}` field `{}` uses empty or wildcard value",
                        pos.id, pred.field
                    ),
                ));
            }
        }
    }
    if !any_matched_selection {
        return Err(conf_err(
            "det-fixtures",
            &format!(
                "positive fixture `{}` satisfied no selection block in `{}`",
                pos.id, rule.rule_id
            ),
        ));
    }
    Ok(())
}

pub(crate) fn eval_condition_for_fixture(
    expr: &ConditionExpr,
    selections: &BTreeMap<String, SelectionBlock>,
    payload: &BTreeMap<String, String>,
    expand_vars: &BTreeMap<String, Vec<String>>,
    depth: usize,
) -> Result<bool, ConformanceError> {
    if depth >= MAX_CONDITION_DEPTH {
        return Err(conf_err("det-fixtures", "Sigma condition depth exceeded"));
    }
    let next = depth.saturating_add(1);
    match expr {
        ConditionExpr::Sel(name) => {
            let Some(sel) = selections.get(name) else {
                return Ok(false);
            };
            eval_selection_for_fixture(sel, payload, expand_vars)
        }
        ConditionExpr::Not(inner) => Ok(!eval_condition_for_fixture(
            inner,
            selections,
            payload,
            expand_vars,
            next,
        )?),
        ConditionExpr::And(lhs, rhs) => {
            Ok(
                eval_condition_for_fixture(lhs, selections, payload, expand_vars, next)?
                    && eval_condition_for_fixture(rhs, selections, payload, expand_vars, next)?,
            )
        }
        ConditionExpr::Or(lhs, rhs) => {
            Ok(
                eval_condition_for_fixture(lhs, selections, payload, expand_vars, next)?
                    || eval_condition_for_fixture(rhs, selections, payload, expand_vars, next)?,
            )
        }
        ConditionExpr::Of { all, pattern } => {
            let mut matched_any = false;
            for (name, sel) in selections {
                if !sel_name_matches_pattern(name, pattern) {
                    continue;
                }
                matched_any = true;
                let ok = eval_selection_for_fixture(sel, payload, expand_vars)?;
                if *all && !ok {
                    return Ok(false);
                }
                if !*all && ok {
                    return Ok(true);
                }
            }
            Ok(*all && matched_any)
        }
    }
}

fn eval_selection_for_fixture(
    sel: &SelectionBlock,
    payload: &BTreeMap<String, String>,
    expand_vars: &BTreeMap<String, Vec<String>>,
) -> Result<bool, ConformanceError> {
    if sel.predicates.is_empty() {
        return Ok(false);
    }
    for pred in &sel.predicates {
        if !eval_predicate_for_fixture(pred, payload, expand_vars)? {
            return Ok(false);
        }
    }
    Ok(true)
}

fn eval_predicate_for_fixture(
    pred: &FieldPredicate,
    payload: &BTreeMap<String, String>,
    expand_vars: &BTreeMap<String, Vec<String>>,
) -> Result<bool, ConformanceError> {
    let expanded = if pred.modifiers.contains(&SigmaModifier::Expand) {
        let mut out = Vec::new();
        for val in &pred.values {
            if let Some(var_name) = val.strip_prefix('%').and_then(|s| s.strip_suffix('%')) {
                let vars = expand_vars.get(var_name).ok_or_else(|| {
                    conf_err(
                        "det-fixtures",
                        &format!("unresolved expand variable `%{var_name}%`"),
                    )
                })?;
                out.extend(vars.iter().cloned());
            } else {
                out.push(val.clone());
            }
        }
        out
    } else {
        pred.values.clone()
    };

    if pred.modifiers.contains(&SigmaModifier::Exists) {
        let want = expanded
            .first()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
        return Ok(payload.contains_key(&pred.field) == want);
    }

    if pred.modifiers.contains(&SigmaModifier::Re) || pred.modifiers.contains(&SigmaModifier::Cidr)
    {
        return Err(conf_err(
            "det-fixtures",
            &format!(
                "unsupported regex/cidr fixture predicate on field `{}`",
                pred.field
            ),
        ));
    }

    let Some(actual) = payload.get(&pred.field) else {
        return Ok(false);
    };
    let actual_lower = actual.to_ascii_lowercase();
    let require_all = pred.modifiers.contains(&SigmaModifier::All);

    let mut matched = expanded.iter().map(|pat| {
        if pred.modifiers.contains(&SigmaModifier::Contains) {
            actual_lower.contains(&pat.to_ascii_lowercase())
        } else if pred.modifiers.contains(&SigmaModifier::StartsWith) {
            actual_lower.starts_with(&pat.to_ascii_lowercase())
        } else if pred.modifiers.contains(&SigmaModifier::EndsWith) {
            actual_lower.ends_with(&pat.to_ascii_lowercase())
        } else {
            wildcard_match_ci(pat, actual)
        }
    });

    Ok(if require_all {
        !expanded.is_empty() && matched.all(|b| b)
    } else {
        matched.any(|b| b)
    })
}
