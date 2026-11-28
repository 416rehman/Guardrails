// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! YAML profile parsing and JSON/TOML/YAML serialization for CM-13 compile-down targets.

use grdr_model::{ActionClass, PolicyRule};

use super::PolicyError;
use super::compile_down::CompileDownSkipReason;
use super::compile_down_targets::{CompileTargetProfile, TargetRenderFormat, TargetRuleSpec};
use super::compiler::CompiledRuleMeta;
use super::lint_scan::{cedar_body_slice, scope_header_slice, strip_comments_and_strings};
use super::render::escape_cedar_string;
use crate::detect::yaml::{YamlValue, parse_yaml};

const COMPILE_TARGETS_FORMAT: &str = "grdr.compile-targets.v1";

/// Parses CM-13 native compile-down target profiles from YAML pack data.
pub fn parse_compile_targets_yaml(
    yaml_src: &str,
) -> Result<Vec<CompileTargetProfile>, PolicyError> {
    let doc = parse_yaml(yaml_src).map_err(|e| PolicyError::ValidationFailed {
        rule_id: "compile-targets".into(),
        detail: format!("invalid compile-targets YAML: {e}"),
    })?;
    if doc.get("format").and_then(YamlValue::as_str) != Some(COMPILE_TARGETS_FORMAT) {
        return Err(PolicyError::ValidationFailed {
            rule_id: "compile-targets".into(),
            detail: "compile-targets YAML missing expected `format` header".into(),
        });
    }
    let Some(items) = doc.get("targets").and_then(YamlValue::as_seq) else {
        return Err(PolicyError::ValidationFailed {
            rule_id: "compile-targets".into(),
            detail: "compile-targets YAML missing `targets` sequence".into(),
        });
    };
    let mut profiles = Vec::with_capacity(items.len());
    for entry in items {
        let Some(map) = entry.as_map() else {
            return Err(PolicyError::ValidationFailed {
                rule_id: "compile-targets".into(),
                detail: "target profile entry must be mapping".into(),
            });
        };
        let id = map
            .get("id")
            .and_then(YamlValue::as_str)
            .filter(|s| !s.is_empty())
            .ok_or_else(|| PolicyError::ValidationFailed {
                rule_id: "compile-targets".into(),
                detail: "target profile missing `id`".into(),
            })?
            .to_owned();
        let format = match opt_str(map, "format", &id)?.as_deref().unwrap_or("yaml") {
            "json" => TargetRenderFormat::Json,
            "toml" => TargetRenderFormat::Toml,
            "yaml" => TargetRenderFormat::Yaml,
            other => {
                return Err(PolicyError::ValidationFailed {
                    rule_id: id,
                    detail: format!("unsupported compile target format `{other}`"),
                });
            }
        };
        profiles.push(CompileTargetProfile {
            id: id.clone(),
            format,
            schema: opt_str(map, "schema", &id)?.unwrap_or_default(),
            verdict_token: opt_str(map, "verdict_token", &id)?.unwrap_or_else(|| "deny".into()),
            supports_allow_overrides: opt_bool(map, "supports_allow_overrides", &id)?
                .unwrap_or(false),
            supports_exec_rules: opt_bool(map, "supports_exec_rules", &id)?.unwrap_or(true),
            read_tool: opt_str(map, "read_tool", &id)?,
            write_tool: opt_str(map, "write_tool", &id)?,
            exec_tool: opt_str(map, "exec_tool", &id)?,
            net_tool: opt_str(map, "net_tool", &id)?,
            exec_pattern_suffix: opt_str(map, "exec_pattern_suffix", &id)?,
            approval_policy: opt_str(map, "approval_policy", &id)?,
            sandbox_mode: opt_str(map, "sandbox_mode", &id)?,
        });
    }
    Ok(profiles)
}

fn opt_str(
    map: &std::collections::BTreeMap<String, YamlValue>,
    key: &str,
    rule_id: &str,
) -> Result<Option<String>, PolicyError> {
    match map.get(key) {
        None => Ok(None),
        Some(v) => {
            v.as_str()
                .map(|s| Some(s.to_owned()))
                .ok_or_else(|| PolicyError::ValidationFailed {
                    rule_id: rule_id.to_owned(),
                    detail: format!("target profile field `{key}` must be a string"),
                })
        }
    }
}

fn opt_bool(
    map: &std::collections::BTreeMap<String, YamlValue>,
    key: &str,
    rule_id: &str,
) -> Result<Option<bool>, PolicyError> {
    match map.get(key) {
        None => Ok(None),
        Some(v) => v
            .as_bool()
            .map(Some)
            .ok_or_else(|| PolicyError::ValidationFailed {
                rule_id: rule_id.to_owned(),
                detail: format!("target profile field `{key}` must be a boolean"),
            }),
    }
}

pub(crate) fn render_generic_target(
    profile: &CompileTargetProfile,
    rules: &[TargetRuleSpec],
) -> String {
    match profile.format {
        TargetRenderFormat::Json => {
            let entries: Vec<serde_json::Value> = rules
                .iter()
                .map(|r| {
                    serde_json::json!({
                        "rule_id": r.rule_id,
                        "actions": r.actions,
                        "protect": r.protect_patterns,
                        "allow": r.allow_patterns,
                        "verdict": r.verdict,
                    })
                })
                .collect();
            serde_json::json!({
                "schema": profile.schema,
                "target": profile.id,
                "rules": entries,
            })
            .to_string()
        }
        TargetRenderFormat::Toml => {
            let mut out = format!(
                "schema = \"{}\"\ntarget = \"{}\"\n",
                escape_quoted_string(&profile.schema),
                escape_quoted_string(&profile.id)
            );
            for r in rules {
                out.push_str(&format!(
                    "\n[[rules]]\nid = \"{}\"\nverdict = \"{}\"\nactions = {}\nprotect = {}\n",
                    escape_quoted_string(&r.rule_id),
                    escape_quoted_string(&r.verdict),
                    render_toml_array(&r.actions),
                    render_toml_array(&r.protect_patterns),
                ));
                if !r.allow_patterns.is_empty() {
                    out.push_str(&format!(
                        "allow = {}\n",
                        render_toml_array(&r.allow_patterns)
                    ));
                }
            }
            out
        }
        TargetRenderFormat::Yaml => {
            let mut out = format!(
                "schema: \"{}\"\ntarget: \"{}\"\nrules:\n",
                escape_quoted_string(&profile.schema),
                escape_quoted_string(&profile.id)
            );
            for r in rules {
                out.push_str(&format!(
                    "  - id: \"{}\"\n    verdict: \"{}\"\n",
                    escape_quoted_string(&r.rule_id),
                    escape_quoted_string(&r.verdict)
                ));
                out.push_str("    actions:\n");
                for a in &r.actions {
                    out.push_str(&format!("      - \"{}\"\n", escape_quoted_string(a)));
                }
                out.push_str("    protect:\n");
                for p in &r.protect_patterns {
                    out.push_str(&format!("      - \"{}\"\n", escape_quoted_string(p)));
                }
                if !r.allow_patterns.is_empty() {
                    out.push_str("    allow:\n");
                    for a in &r.allow_patterns {
                        out.push_str(&format!("      - \"{}\"\n", escape_quoted_string(a)));
                    }
                }
            }
            out
        }
    }
}

fn render_toml_array(items: &[String]) -> String {
    let quoted: Vec<String> = items
        .iter()
        .map(|s| format!("\"{}\"", escape_quoted_string(s)))
        .collect();
    format!("[{}]", quoted.join(", "))
}

pub(crate) fn escape_quoted_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 || c == '\x7f' => {
                out.push_str(&format!("\\u{:04x}", c as u32));
            }
            c => out.push(c),
        }
    }
    out
}

pub(super) fn validate_static_cedar_clauses(
    canonical: &str,
    effective_id: &str,
    rule_id: &str,
    supports_allow_overrides: bool,
    has_allow_list: bool,
) -> Option<CompileDownSkipReason> {
    let body = cedar_body_slice(canonical);
    let body_nostr = strip_comments_and_strings(body, false);
    if body_nostr.contains("context.session") {
        return Some(CompileDownSkipReason::RequiresSessionState);
    }
    let scope = strip_comments_and_strings(scope_header_slice(&body_nostr), false);
    if !is_allowed_compile_down_scope(&scope) {
        return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
    }
    let Some((when_body, unless_body)) = parse_when_unless_bodies(body) else {
        return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
    };
    if let Some(unless_expr) = unless_body {
        if !supports_allow_overrides || !has_allow_list {
            return Some(CompileDownSkipReason::HasUnlessClause);
        }
        if !is_exact_match_predicate(&unless_expr, "allow", effective_id, rule_id) {
            return Some(CompileDownSkipReason::HasUnlessClause);
        }
    }
    if let Some(when_expr) = when_body {
        let mut has_match = false;
        for part in when_expr.split("&&") {
            if !is_exact_match_predicate(part, "match", effective_id, rule_id) {
                return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
            }
            has_match = true;
        }
        if !has_match {
            return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
        }
    }
    None
}

fn is_exact_match_predicate(expr: &str, kind: &str, effective_id: &str, rule_id: &str) -> bool {
    let compact: String = expr.chars().filter(|c| !c.is_whitespace()).collect();
    let exp1 = format!(
        "resource.classes.contains(\"{}\")",
        escape_cedar_string(&format!("{kind}:{effective_id}"))
    );
    let exp2 = format!(
        "resource.classes.contains(\"{}\")",
        escape_cedar_string(&format!("{kind}:{rule_id}"))
    );
    compact == exp1 || compact == exp2
}

fn is_allowed_compile_down_scope(scope: &str) -> bool {
    let trimmed = scope.trim();
    let Some(open) = trimmed.find('(') else {
        return false;
    };
    let Some(close) = trimmed.rfind(')') else {
        return false;
    };
    if close <= open {
        return false;
    }
    let inner = trimmed.get(open.saturating_add(1)..close).unwrap_or("");
    let parts = split_scope_clauses(inner);
    let [principal_raw, _, resource_raw] = parts.as_slice() else {
        return false;
    };
    let principal: String = principal_raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if principal != "principal" && principal != "principalisGrdr::Session" {
        return false;
    }
    let resource: String = resource_raw
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    if resource == "resource" {
        return true;
    }
    if let Some(entity_type) = resource.strip_prefix("resourceisGrdr::") {
        return !entity_type.is_empty()
            && entity_type
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_');
    }
    false
}

fn split_scope_clauses(inner: &str) -> Vec<&str> {
    let mut out = Vec::new();
    let mut bracket_depth: usize = 0;
    let mut in_str = false;
    let mut escaped = false;
    let mut start: usize = 0;
    for (idx, ch) in inner.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => in_str = true,
            '[' => bracket_depth = bracket_depth.saturating_add(1),
            ']' => bracket_depth = bracket_depth.saturating_sub(1),
            ',' if bracket_depth == 0 => {
                out.push(inner.get(start..idx).unwrap_or(""));
                start = idx.saturating_add(1);
            }
            _ => {}
        }
    }
    out.push(inner.get(start..).unwrap_or(""));
    out
}

fn parse_when_unless_bodies(body: &str) -> Option<(Option<String>, Option<String>)> {
    let close_paren = find_matching_paren(body)?;
    let mut rest = body.get(close_paren.saturating_add(1)..)?;
    let mut when_expr = None;
    let mut unless_expr = None;

    loop {
        rest = rest.trim_start();
        if rest.is_empty() || rest == ";" {
            break;
        }
        if let Some(after_kw) = rest.strip_prefix("when") {
            if when_expr.is_some() || unless_expr.is_some() {
                return None;
            }
            let (inner, rem) = extract_braced_expr(after_kw)?;
            when_expr = Some(inner);
            rest = rem;
        } else {
            let after_kw = rest.strip_prefix("unless")?;
            if unless_expr.is_some() {
                return None;
            }
            let (inner, rem) = extract_braced_expr(after_kw)?;
            unless_expr = Some(inner);
            rest = rem;
        }
    }
    Some((when_expr, unless_expr))
}

fn find_matching_paren(src: &str) -> Option<usize> {
    let start = src.find('(')?;
    let mut depth: usize = 0;
    let mut in_str = false;
    let mut escaped = false;
    for (rel, ch) in src.get(start..)?.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => in_str = true,
            '(' => depth = depth.saturating_add(1),
            ')' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Some(start.saturating_add(rel));
                }
            }
            _ => {}
        }
    }
    None
}

fn extract_braced_expr(src: &str) -> Option<(String, &str)> {
    let trimmed = src.trim_start();
    if !trimmed.starts_with('{') {
        return None;
    }
    let mut depth: usize = 0;
    let mut in_str = false;
    let mut escaped = false;
    for (idx, ch) in trimmed.char_indices() {
        if in_str {
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        match ch {
            '"' => in_str = true,
            '{' => depth = depth.saturating_add(1),
            '}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    let inner = trimmed.get(1..idx)?.to_owned();
                    let rem = trimmed.get(idx.saturating_add(1)..)?;
                    return Some((inner, rem));
                }
            }
            _ => {}
        }
    }
    None
}

pub(super) fn codex_patterns_for_rule(
    profile: &CompileTargetProfile,
    rule: &PolicyRule,
    meta: Option<&CompiledRuleMeta>,
) -> Option<(Vec<String>, Vec<String>)> {
    let all_covered = !rule.matcher.action_classes.is_empty()
        && rule.matcher.action_classes.iter().all(|a| {
            matches!(a, ActionClass::McpCall | ActionClass::McpConnect)
                || (*a == ActionClass::Exec && profile.supports_exec_rules)
        });
    if !all_covered {
        return None;
    }
    let mut cmds = Vec::new();
    let mut mcps = Vec::new();
    for action in &rule.matcher.action_classes {
        let dest = if matches!(action, ActionClass::McpCall | ActionClass::McpConnect) {
            &mut mcps
        } else {
            &mut cmds
        };
        for pat in rule
            .matcher
            .target_prefixes
            .iter()
            .chain(&rule.matcher.target_contains)
            .chain(meta.into_iter().flat_map(|m| m.protect_list.iter()))
        {
            let clean = pat.trim();
            if !clean.is_empty() {
                dest.push(clean.to_string());
            }
        }
    }
    Some((cmds, mcps))
}
