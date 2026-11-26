// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Sigma rule load-time compiler and predicate evaluator (`D-09`).

use std::collections::BTreeMap;
use std::net::IpAddr;

use ipnet::IpNet;
use regex::{Regex, RegexBuilder};

pub use crate::detect::condition::parse_condition_ast;
use crate::detect::condition::{eval_condition_ast, wildcard_match_ci};
use crate::detect::types::{
    DeploymentScope, DetectError, EventView, FieldPredicate, HostProfile, SigmaModifier, SigmaRule,
};

const MAX_REGEX_SIZE_BYTES: usize = 256 * 1024;
const STRUCTURAL_FIELDS: &[&str] = &[
    "action_class",
    "target",
    "agent_name",
    "session_id",
    "root_session_id",
    "session.root",
    "device_id",
    "organisation_id",
];

#[derive(Debug, Clone)]
pub struct CompiledPredicate {
    pub field: String,
    pub modifiers: Vec<SigmaModifier>,
    pub expanded_values: Vec<String>,
    pub compiled_regexes: Vec<Regex>,
    pub compiled_cidrs: Vec<IpNet>,
}

#[derive(Debug, Clone)]
pub struct CompiledSelection {
    pub predicates: Vec<CompiledPredicate>,
}

#[derive(Debug, Clone)]
pub struct CompiledSigmaRule {
    pub rule: SigmaRule,
    pub selections: BTreeMap<String, CompiledSelection>,
}

/// Compiles regexes, CIDRs, and `%expand%` variables once at load time (`#230 B2`, `#226 H1/H5`).
pub fn compile_sigma_rule(
    rule: &SigmaRule,
    host: &HostProfile,
) -> Result<CompiledSigmaRule, DetectError> {
    let mut selections = BTreeMap::new();
    for (sel_name, block) in &rule.selections {
        let mut predicates = Vec::with_capacity(block.predicates.len());
        for pred in &block.predicates {
            predicates.push(compile_predicate(pred, host)?);
        }
        selections.insert(sel_name.clone(), CompiledSelection { predicates });
    }
    Ok(CompiledSigmaRule {
        rule: rule.clone(),
        selections,
    })
}

/// Evaluates a precompiled Sigma rule against `ev` without per-event regex/CIDR compilation.
#[must_use]
pub fn evaluate_compiled_rule(compiled: &CompiledSigmaRule, ev: &EventView<'_>) -> bool {
    let rule = &compiled.rule;
    if ev.provenance_grade < rule.min_provenance {
        return false;
    }
    let prod = rule.logsource.product.as_str();
    if !prod.eq_ignore_ascii_case("grdr")
        && !prod.eq_ignore_ascii_case("any")
        && !prod.eq_ignore_ascii_case("sigma")
    {
        return false;
    }
    if let Some(cat) = &rule.logsource.category
        && !cat.eq_ignore_ascii_case(ev.category)
        && !cat.eq_ignore_ascii_case("any")
    {
        return false;
    }
    if let Some(svc) = &rule.logsource.service
        && !svc.eq_ignore_ascii_case(ev.service)
        && !svc.eq_ignore_ascii_case("any")
    {
        return false;
    }
    if compiled.selections.is_empty() {
        return false;
    }
    eval_condition_ast(&rule.condition_ast, &compiled.selections, ev, 0)
}

/// Evaluates `rule` against `ev` and `host` (compiles once for standalone/test callers).
#[must_use]
pub fn evaluate_sigma_rule(rule: &SigmaRule, ev: &EventView<'_>, host: &HostProfile) -> bool {
    match compile_sigma_rule(rule, host) {
        Ok(compiled) => evaluate_compiled_rule(&compiled, ev),
        Err(_) => false,
    }
}

/// Extracts event field candidates while keeping structural event attributes isolated from `ev.fields`.
#[must_use]
pub fn collect_event_field_values<'a>(field: &str, ev: &'a EventView<'a>) -> Vec<String> {
    match field {
        "action_class" => vec![ev.action_class.as_str().to_owned()],
        "target" => vec![ev.target.to_owned()],
        "agent_name" => vec![ev.agent_name.to_owned()],
        "session_id" => vec![ev.session_id.to_owned()],
        "root_session_id" | "session.root" => vec![ev.root_session_id.to_owned()],
        "device_id" => vec![ev.device_id.to_owned()],
        "organisation_id" => vec![ev.organisation_id.to_owned()],
        other => {
            let mut out = Vec::new();
            if let Some(v) = ev.fields.get(other) {
                out.push((*v).to_owned());
            }
            if let Some(list) = ev.list_fields.get(other) {
                for item in list {
                    out.push((*item).to_owned());
                }
            }
            out
        }
    }
}

/// Checks whether a host scope may execute a rule's deployment placement (`docs/design/13` s.2).
#[must_use]
pub const fn scope_permits_rule(host_scope: DeploymentScope, rule_scope: DeploymentScope) -> bool {
    matches!(
        (host_scope, rule_scope),
        (_, DeploymentScope::Any)
            | (DeploymentScope::Any, _)
            | (DeploymentScope::Device, DeploymentScope::Device)
            | (DeploymentScope::Server, DeploymentScope::Server)
    )
}

pub(crate) fn eval_compiled_selection(sel: &CompiledSelection, ev: &EventView<'_>) -> bool {
    sel.predicates
        .iter()
        .all(|pred| eval_compiled_predicate(pred, ev))
}

fn compile_predicate(
    pred: &FieldPredicate,
    host: &HostProfile,
) -> Result<CompiledPredicate, DetectError> {
    let expanded_values = if pred.modifiers.contains(&SigmaModifier::Expand) {
        let mut out = Vec::new();
        for val in &pred.values {
            let Some(var_name) = val.strip_prefix('%').and_then(|s| s.strip_suffix('%')) else {
                out.push(val.clone());
                continue;
            };
            let vals = host.expand_vars.get(var_name).ok_or_else(|| {
                DetectError::InvalidRule(format!(
                    "unresolved Sigma expand variable `%{var_name}%` for field `{}`",
                    pred.field
                ))
            })?;
            out.extend(vals.iter().cloned());
        }
        out
    } else {
        pred.values.clone()
    };

    let mut compiled_regexes = Vec::new();
    if pred.modifiers.contains(&SigmaModifier::Re) {
        for pat in &expanded_values {
            let re = RegexBuilder::new(pat)
                .size_limit(MAX_REGEX_SIZE_BYTES)
                .dfa_size_limit(256 * 1024)
                .build()
                .map_err(|e| {
                    DetectError::InvalidRule(format!("invalid Sigma regex `{pat}`: {e}"))
                })?;
            compiled_regexes.push(re);
        }
    }

    let mut compiled_cidrs = Vec::new();
    if pred.modifiers.contains(&SigmaModifier::Cidr) {
        for pat in &expanded_values {
            let net = pat.parse::<IpNet>().map_err(|e| {
                DetectError::InvalidRule(format!("invalid Sigma CIDR `{pat}`: {e}"))
            })?;
            compiled_cidrs.push(net);
        }
    }

    Ok(CompiledPredicate {
        field: pred.field.clone(),
        modifiers: pred.modifiers.clone(),
        expanded_values,
        compiled_regexes,
        compiled_cidrs,
    })
}

fn eval_compiled_predicate(pred: &CompiledPredicate, ev: &EventView<'_>) -> bool {
    if pred.modifiers.contains(&SigmaModifier::Exists) {
        let want = pred
            .expanded_values
            .first()
            .is_some_and(|v| v.trim().eq_ignore_ascii_case("true"));
        let present = STRUCTURAL_FIELDS.contains(&pred.field.as_str())
            || ev.fields.contains_key(pred.field.as_str())
            || ev
                .list_fields
                .get(pred.field.as_str())
                .is_some_and(|v| !v.is_empty());
        return present == want;
    }

    let candidates = collect_event_field_values(pred.field.as_str(), ev);
    if candidates.is_empty() {
        return false;
    }
    let require_all = pred.modifiers.contains(&SigmaModifier::All);

    if pred.modifiers.contains(&SigmaModifier::Cidr) {
        let mut iter = pred.compiled_cidrs.iter().map(|net| {
            candidates.iter().any(|c| {
                c.trim()
                    .parse::<IpAddr>()
                    .is_ok_and(|ip| net.contains(&ip.to_canonical()))
            })
        });
        return if require_all {
            !pred.compiled_cidrs.is_empty() && iter.all(|b| b)
        } else {
            iter.any(|b| b)
        };
    }

    if pred.modifiers.contains(&SigmaModifier::Re) {
        let mut iter = pred
            .compiled_regexes
            .iter()
            .map(|re| candidates.iter().any(|c| re.is_match(c)));
        return if require_all {
            !pred.compiled_regexes.is_empty() && iter.all(|b| b)
        } else {
            iter.any(|b| b)
        };
    }

    let matches_pat = |pat: &str| {
        candidates
            .iter()
            .any(|cand| match_text_value(cand, pat, &pred.modifiers))
    };
    if require_all {
        !pred.expanded_values.is_empty() && pred.expanded_values.iter().all(|p| matches_pat(p))
    } else {
        pred.expanded_values.iter().any(|p| matches_pat(p))
    }
}

fn match_text_value(candidate: &str, pattern: &str, modifiers: &[SigmaModifier]) -> bool {
    let cand_low = candidate.to_ascii_lowercase();
    let pat_low = pattern.to_ascii_lowercase();
    if modifiers.contains(&SigmaModifier::Contains) {
        cand_low.contains(&pat_low)
    } else if modifiers.contains(&SigmaModifier::StartsWith) {
        cand_low.starts_with(&pat_low)
    } else if modifiers.contains(&SigmaModifier::EndsWith) {
        cand_low.ends_with(&pat_low)
    } else {
        wildcard_match_ci(&cand_low, &pat_low)
    }
}
