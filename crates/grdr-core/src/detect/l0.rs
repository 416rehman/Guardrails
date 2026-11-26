// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Embedding option L0 portability analyser and AST query compilers (`KQL`, `LogScale`, `EQL`, `XQL`, `SPL`, `GenericSigma`).

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::detect::condition::sel_name_matches_pattern;
use crate::detect::l0_format::{
    expand_l0_values, format_single_term, format_spl_where_term, valid_field_ident,
};
use crate::detect::types::{
    ConditionExpr, DetectError, FieldPredicate, HostProfile, MAX_CONDITION_DEPTH, SigmaModifier,
    SigmaRule,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum L0LowerMode {
    Standard(L0Target),
    SplWhere,
}

const PORTABLE_L0_FIELDS: &[&str] = &[
    "action_class",
    "target",
    "agent_name",
    "device_id",
    "Image",
    "ParentImage",
    "CommandLine",
    "TargetFilename",
    "DestinationIp",
    "DestinationHostname",
    "DestinationPort",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L0Target {
    Kql,
    LogScale,
    Eql,
    Xql,
    Spl,
    GenericSigma,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum L0Portability {
    Portable,
    PartialWithNote,
    GuardrailsOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentSupport {
    DefenderDeviceIdJoin,
    DetectOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledL0Rule {
    pub rule_id: String,
    pub target: L0Target,
    pub portability: L0Portability,
    pub containment: ContainmentSupport,
    pub query: String,
    pub lineage_gap_note: String,
}

/// Evaluates whether `rule` references only validated L0-portable endpoint fields.
#[must_use]
pub fn classify_l0_portability(rule: &SigmaRule) -> L0Portability {
    let mut uses_non_portable = rule.correlation.is_some();
    for sel in rule.selections.values() {
        for pred in &sel.predicates {
            if !valid_field_ident(&pred.field)
                || pred.field.starts_with("session.")
                || pred.field.starts_with("label.")
                || pred.field.starts_with("verdict")
                || pred.field.starts_with("effect.")
                || pred.field.starts_with("judge.")
                || !PORTABLE_L0_FIELDS.contains(&pred.field.as_str())
            {
                uses_non_portable = true;
            }
        }
    }
    if uses_non_portable && rule.derived_from.is_none() {
        L0Portability::GuardrailsOnly
    } else if uses_non_portable {
        L0Portability::PartialWithNote
    } else {
        L0Portability::Portable
    }
}

/// Compiles `rule` to an L0 target using default Tier-A agent binary expansion (`%grdr_agent_images%`).
pub fn compile_l0_target(
    rule: &SigmaRule,
    target: L0Target,
) -> Result<CompiledL0Rule, DetectError> {
    let mut expand_vars = BTreeMap::new();
    expand_vars.insert(
        "grdr_agent_images".to_owned(),
        vec![
            "claude".into(),
            "codex".into(),
            "cursor".into(),
            "gemini".into(),
            "opencode".into(),
            "aider".into(),
        ],
    );
    let host = HostProfile {
        device_id: "l0-export".into(),
        device_name: "l0-export".into(),
        organisation_id: "default".into(),
        scope: crate::detect::types::DeploymentScope::Any,
        provenance_grade: 0,
        expand_vars,
        model_audit_passed: false,
        remediate_approvers: BTreeMap::new(),
    };
    compile_l0_target_with_host(rule, target, &host)
}

/// Compiles `rule` to `KQL`, `LogScale`, `EQL`, `XQL`, `SPL`, or `GenericSigma` preserving boolean `condition_ast`.
pub fn compile_l0_target_with_host(
    rule: &SigmaRule,
    target: L0Target,
    host: &HostProfile,
) -> Result<CompiledL0Rule, DetectError> {
    let portability = classify_l0_portability(rule);
    if portability == L0Portability::GuardrailsOnly || rule.correlation.is_some() {
        return Err(DetectError::L0Unsupported(format!(
            "rule `{}` uses Guardrails correlation or session/verdict fields with no L0 rewrite",
            rule.rule_id
        )));
    }
    if portability == L0Portability::PartialWithNote
        && !rule.selections.values().all(|s| {
            s.predicates.iter().all(|p| {
                valid_field_ident(&p.field) && PORTABLE_L0_FIELDS.contains(&p.field.as_str())
            })
        })
    {
        return Err(DetectError::L0Unsupported(format!(
            "rule `{}` contains non-portable/unallowlisted L0 fields",
            rule.rule_id
        )));
    }
    if rule.selections.is_empty() {
        return Err(DetectError::L0Unsupported(format!(
            "rule `{}` has zero selections for L0 target",
            rule.rule_id
        )));
    }

    let (query, containment) = match target {
        L0Target::Kql => (
            compile_kql(rule, host)?,
            ContainmentSupport::DefenderDeviceIdJoin,
        ),
        L0Target::LogScale => (
            compile_expr_query(rule, target, host)?,
            ContainmentSupport::DetectOnly,
        ),
        L0Target::Eql => (compile_eql(rule, host)?, ContainmentSupport::DetectOnly),
        L0Target::Xql => (compile_xql(rule, host)?, ContainmentSupport::DetectOnly),
        L0Target::Spl => (compile_spl(rule, host)?, ContainmentSupport::DetectOnly),
        L0Target::GenericSigma => (
            compile_generic_sigma(rule, host)?,
            ContainmentSupport::DetectOnly,
        ),
    };

    Ok(CompiledL0Rule {
        rule_id: rule.rule_id.clone(),
        target,
        portability,
        containment,
        query,
        lineage_gap_note: "L0 ParentImage filter observes direct children of catalogued agent binaries only; deep grandchild trees require the Guardrails sensor.".into(),
    })
}

fn compile_kql(rule: &SigmaRule, host: &HostProfile) -> Result<String, DetectError> {
    let table = match rule.logsource.category.as_deref() {
        Some("file" | "file_event") => "DeviceFileEvents",
        Some("network" | "network_connection" | "dataflow") => "DeviceNetworkEvents",
        _ => "DeviceProcessEvents",
    };
    let expr = lower_ast(
        &rule.condition_ast,
        rule,
        L0LowerMode::Standard(L0Target::Kql),
        host,
        0,
    )?;
    Ok(format!(
        "{table} | where {expr} | project Timestamp, DeviceId, DeviceName, ActionType"
    ))
}

fn compile_eql(rule: &SigmaRule, host: &HostProfile) -> Result<String, DetectError> {
    let ev_type = match rule.logsource.category.as_deref() {
        Some("file" | "file_event") => "file",
        Some("network" | "network_connection" | "dataflow") => "network",
        _ => "process",
    };
    let expr = lower_ast(
        &rule.condition_ast,
        rule,
        L0LowerMode::Standard(L0Target::Eql),
        host,
        0,
    )?;
    Ok(format!("{ev_type} where {expr}"))
}

fn compile_xql(rule: &SigmaRule, host: &HostProfile) -> Result<String, DetectError> {
    let expr = lower_ast(
        &rule.condition_ast,
        rule,
        L0LowerMode::Standard(L0Target::Xql),
        host,
        0,
    )?;
    Ok(format!("dataset = xdr_data | filter {expr}"))
}

fn compile_spl(rule: &SigmaRule, host: &HostProfile) -> Result<String, DetectError> {
    let needs_where = rule.selections.values().any(|s| {
        s.predicates.iter().any(|p| {
            p.modifiers
                .iter()
                .any(|m| matches!(m, SigmaModifier::Re | SigmaModifier::Cidr))
        })
    });
    if needs_where {
        let expr = lower_ast(&rule.condition_ast, rule, L0LowerMode::SplWhere, host, 0)?;
        Ok(format!("index=* | where {expr}"))
    } else {
        let expr = lower_ast(
            &rule.condition_ast,
            rule,
            L0LowerMode::Standard(L0Target::Spl),
            host,
            0,
        )?;
        Ok(format!("index=* | search {expr}"))
    }
}

fn compile_expr_query(
    rule: &SigmaRule,
    target: L0Target,
    host: &HostProfile,
) -> Result<String, DetectError> {
    if target == L0Target::LogScale
        && rule.selections.values().any(|s| {
            s.predicates.iter().any(|p| {
                p.modifiers.contains(&SigmaModifier::Re) && p.values.iter().any(|v| v.is_empty())
            })
        })
    {
        return Err(DetectError::L0Unsupported(
            "LogScale L0 target cannot lower empty `|re` pattern (`//` comment hazard)".into(),
        ));
    }
    lower_ast(
        &rule.condition_ast,
        rule,
        L0LowerMode::Standard(target),
        host,
        0,
    )
}

fn safe_yaml_token(raw: &str, allow_condition_chars: bool) -> bool {
    !raw.is_empty()
        && (allow_condition_chars
            || raw
                .bytes()
                .next()
                .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_'))
        && raw.chars().all(|c| {
            if allow_condition_chars {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.' | '*' | '(' | ')' | ' ')
            } else {
                c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.')
            }
        })
}

fn compile_generic_sigma(rule: &SigmaRule, host: &HostProfile) -> Result<String, DetectError> {
    let cat = rule
        .logsource
        .category
        .as_deref()
        .unwrap_or("process_creation");
    if !safe_yaml_token(&rule.uuid, false)
        || !safe_yaml_token(cat, false)
        || !safe_yaml_token(&rule.condition, true)
    {
        return Err(DetectError::L0Unsupported(
            "GenericSigma metadata/condition contains unsafe YAML control characters".into(),
        ));
    }
    let title_json = serde_json::to_string(&rule.title)
        .map_err(|e| DetectError::L0Unsupported(format!("invalid title JSON: {e}")))?;
    let mut out = format!(
        "title: {title_json}\nid: {}\nstatus: test\nlogsource:\n  category: {cat}\ndetection:\n",
        rule.uuid
    );
    for (name, sel) in &rule.selections {
        if !safe_yaml_token(name, false) {
            return Err(DetectError::L0Unsupported(format!(
                "GenericSigma invalid selection name `{name}`"
            )));
        }
        out.push_str(&format!("  {name}:\n"));
        for pred in &sel.predicates {
            if !valid_field_ident(&pred.field) {
                return Err(DetectError::L0Unsupported(format!(
                    "GenericSigma invalid field `{}`",
                    pred.field
                )));
            }
            let expanded = expand_l0_values(pred, host)?;
            let mods: Vec<&str> = pred
                .modifiers
                .iter()
                .filter(|m| !matches!(m, SigmaModifier::Exact | SigmaModifier::Expand))
                .map(|m| match m {
                    SigmaModifier::Contains => "contains",
                    SigmaModifier::StartsWith => "startswith",
                    SigmaModifier::EndsWith => "endswith",
                    SigmaModifier::Re => "re",
                    SigmaModifier::Cidr => "cidr",
                    SigmaModifier::Exists => "exists",
                    SigmaModifier::All => "all",
                    SigmaModifier::Exact | SigmaModifier::Expand => "",
                })
                .collect();
            let field_key = if mods.is_empty() {
                pred.field.clone()
            } else {
                format!("{}|{}", pred.field, mods.join("|"))
            };
            out.push_str(&format!("    {field_key}:\n"));
            for v in expanded {
                let q = serde_json::to_string(&v)
                    .map_err(|e| DetectError::L0Unsupported(format!("invalid scalar JSON: {e}")))?;
                out.push_str(&format!("      - {q}\n"));
            }
        }
    }
    let deriv = serde_json::to_string(rule.derived_from.as_deref().unwrap_or(&rule.rule_id))
        .map_err(|e| DetectError::L0Unsupported(format!("invalid derived_from JSON: {e}")))?;
    out.push_str(&format!(
        "  condition: {}\nx_grdr:\n  derived_from: {deriv}\n",
        rule.condition
    ));
    Ok(out)
}

fn lower_ast(
    ast: &ConditionExpr,
    rule: &SigmaRule,
    mode: L0LowerMode,
    host: &HostProfile,
    depth: usize,
) -> Result<String, DetectError> {
    if depth >= MAX_CONDITION_DEPTH {
        return Err(DetectError::L0Unsupported(
            "L0 condition AST exceeds maximum lowering depth".into(),
        ));
    }
    let (and_op, or_op, not_op) = match mode {
        L0LowerMode::Standard(L0Target::LogScale | L0Target::Spl) | L0LowerMode::SplWhere => {
            ("AND", "OR", "NOT")
        }
        _ => ("and", "or", "not"),
    };
    match ast {
        ConditionExpr::Sel(name) => {
            let sel = rule
                .selections
                .get(name)
                .ok_or_else(|| DetectError::L0Unsupported(format!("missing selection `{name}`")))?;
            let mut parts = Vec::new();
            for pred in &sel.predicates {
                parts.push(lower_predicate(pred, mode, host)?);
            }
            Ok(format!("({})", parts.join(&format!(" {and_op} "))))
        }
        ConditionExpr::Not(inner) => Ok(format!(
            "{not_op} ({})",
            lower_ast(inner, rule, mode, host, depth.saturating_add(1))?
        )),
        ConditionExpr::And(lhs, rhs) => Ok(format!(
            "({} {and_op} {})",
            lower_ast(lhs, rule, mode, host, depth.saturating_add(1))?,
            lower_ast(rhs, rule, mode, host, depth.saturating_add(1))?
        )),
        ConditionExpr::Or(lhs, rhs) => Ok(format!(
            "({} {or_op} {})",
            lower_ast(lhs, rule, mode, host, depth.saturating_add(1))?,
            lower_ast(rhs, rule, mode, host, depth.saturating_add(1))?
        )),
        ConditionExpr::Of { all, pattern } => {
            let mut items = Vec::new();
            for name in rule.selections.keys() {
                if sel_name_matches_pattern(name, pattern) {
                    items.push(lower_ast(
                        &ConditionExpr::Sel(name.clone()),
                        rule,
                        mode,
                        host,
                        depth.saturating_add(1),
                    )?);
                }
            }
            if items.is_empty() {
                return Err(DetectError::L0Unsupported(
                    "L0 quantifier matched zero selections".into(),
                ));
            }
            let joiner = if *all { and_op } else { or_op };
            Ok(format!("({})", items.join(&format!(" {joiner} "))))
        }
    }
}

fn lower_predicate(
    pred: &FieldPredicate,
    mode: L0LowerMode,
    host: &HostProfile,
) -> Result<String, DetectError> {
    if !valid_field_ident(&pred.field) || !PORTABLE_L0_FIELDS.contains(&pred.field.as_str()) {
        return Err(DetectError::L0Unsupported(format!(
            "invalid or non-portable L0 field `{}`",
            pred.field
        )));
    }
    let vals = expand_l0_values(pred, host)?;
    if vals.is_empty() {
        return Err(DetectError::L0Unsupported(format!(
            "empty values for field `{}`",
            pred.field
        )));
    }
    for v in &vals {
        if matches!(mode, L0LowerMode::Standard(L0Target::LogScale))
            && pred.modifiers.contains(&SigmaModifier::Re)
            && crate::detect::l0_format::escape_regex_slashes(v).is_empty()
        {
            return Err(DetectError::L0Unsupported(
                "LogScale L0 target cannot lower empty `|re` pattern (`//` comment hazard)".into(),
            ));
        }
        if v.chars().any(|c| c == '\0')
            || (matches!(
                mode,
                L0LowerMode::Standard(L0Target::Spl) | L0LowerMode::SplWhere
            ) && v.contains('`'))
        {
            return Err(DetectError::L0Unsupported(
                "L0 predicate value contains unsafe control/macro character".into(),
            ));
        }
    }
    let (or_op, and_op) = match mode {
        L0LowerMode::Standard(L0Target::LogScale | L0Target::Spl) | L0LowerMode::SplWhere => {
            ("OR", "AND")
        }
        _ => ("or", "and"),
    };
    let joiner = if pred.modifiers.contains(&SigmaModifier::All) {
        and_op
    } else {
        or_op
    };
    let clauses: Vec<String> = vals
        .iter()
        .map(|v| match mode {
            L0LowerMode::Standard(t) => format_single_term(pred, v, t),
            L0LowerMode::SplWhere => format_spl_where_term(pred, v),
        })
        .collect();
    Ok(format!("({})", clauses.join(&format!(" {joiner} "))))
}
