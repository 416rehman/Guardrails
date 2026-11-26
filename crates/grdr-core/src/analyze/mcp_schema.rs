// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Recursive bounded JSON Schema widening detector, JCS canonicalizer, and nested string scanner (`D-10`).

use std::collections::{BTreeMap, BTreeSet};

use serde_json::Value;

use crate::analyze::mcp_diff::is_invisible_or_bidi_char;

pub(crate) const MAX_SCHEMA_DEPTH: usize = 64;

const COSMETIC_SCHEMA_KEYS: &[&str] = &["title", "$comment", "examples"];

/// Detects schema widening or constraint weakening recursively up to `MAX_SCHEMA_DEPTH`.
#[must_use]
pub(crate) fn detect_schema_widening(base: &Value, curr: &Value) -> Option<String> {
    detect_widening_rec(base, curr, 0)
}

/// Collects all string values nested inside a JSON value with bounded iterative traversal.
/// Returns `true` if traversal hit the depth or node cap.
pub(crate) fn collect_json_strings<'a>(val: &'a Value, out: &mut Vec<&'a str>) -> bool {
    let max_depth = MAX_SCHEMA_DEPTH.saturating_mul(4);
    let max_nodes = MAX_SCHEMA_DEPTH.saturating_mul(1024);
    let mut stack: Vec<(&'a Value, usize)> = vec![(val, 0)];
    let mut visited: usize = 0;
    let mut truncated = false;
    while let Some((node, depth)) = stack.pop() {
        if depth >= max_depth || visited >= max_nodes {
            truncated = true;
            continue;
        }
        visited = visited.saturating_add(1);
        match node {
            Value::String(s) => out.push(s.as_str()),
            Value::Array(arr) => {
                for item in arr {
                    if stack.len() >= max_nodes {
                        truncated = true;
                        break;
                    }
                    stack.push((item, depth.saturating_add(1)));
                }
            }
            Value::Object(obj) => {
                for (k, v) in obj {
                    out.push(k.as_str());
                    if stack.len() >= max_nodes {
                        truncated = true;
                        break;
                    }
                    stack.push((v, depth.saturating_add(1)));
                }
            }
            Value::Null | Value::Bool(_) | Value::Number(_) => {}
        }
    }
    truncated
}

/// Produces deterministic RFC 8785-style sorted JSON text for semantic schema comparisons.
#[must_use]
pub(crate) fn canonical_json_string(val: &Value) -> String {
    canonical_json_filtered(val, false, 0)
}

fn detect_widening_rec(base: &Value, curr: &Value, depth: usize) -> Option<String> {
    if depth >= MAX_SCHEMA_DEPTH {
        return Some("schema recursion depth exceeded".into());
    }
    if base == curr {
        return None;
    }

    if let (Some(bo), Some(co)) = (base.as_object(), curr.as_object()) {
        if let Some(reason) = check_type_and_const(bo, co) {
            return Some(reason);
        }
        if let Some(reason) = check_properties_and_required(bo, co, depth) {
            return Some(reason);
        }
        if let Some(reason) = check_enum_widening(bo, co) {
            return Some(reason);
        }
        if let Some(reason) = check_numeric_and_string_bounds(bo, co) {
            return Some(reason);
        }
        if let Some(reason) = check_combinators_and_subschemas(bo, co, depth) {
            return Some(reason);
        }
        return check_remaining_semantic_drift(base, curr);
    }

    if canonical_json_string(base) != canonical_json_string(curr) {
        Some("schema node changed incompatibly".into())
    } else {
        None
    }
}

fn check_type_and_const(
    bo: &serde_json::Map<String, Value>,
    co: &serde_json::Map<String, Value>,
) -> Option<String> {
    let b_type = bo.get("type");
    let c_type = co.get("type");
    if b_type.is_some() && b_type != c_type {
        return Some("schema type constraint changed or dropped".into());
    }
    if let Some(b_const) = bo.get("const")
        && co.get("const").map(canonical_json_string) != Some(canonical_json_string(b_const))
    {
        return Some("const constraint changed or dropped".into());
    }
    for key in ["pattern", "format", "$ref"] {
        if let Some(bv) = bo.get(key)
            && co.get(key) != Some(bv)
        {
            return Some(format!("schema `{key}` constraint changed or dropped"));
        }
    }
    None
}

fn check_properties_and_required(
    bo: &serde_json::Map<String, Value>,
    co: &serde_json::Map<String, Value>,
    depth: usize,
) -> Option<String> {
    let base_props = bo.get("properties").and_then(Value::as_object);
    let curr_props = co.get("properties").and_then(Value::as_object);

    if let Some(cp) = curr_props {
        for (key, c_schema) in cp {
            match base_props.and_then(|bp| bp.get(key)) {
                None => {
                    let safe_key = sanitize_key(key);
                    return Some(format!("new property `{safe_key}` added"));
                }
                Some(b_schema) => {
                    if let Some(sub) =
                        detect_widening_rec(b_schema, c_schema, depth.saturating_add(1))
                    {
                        let safe_key = sanitize_key(key);
                        return Some(format!("property `{safe_key}`: {sub}"));
                    }
                }
            }
        }
    }

    let base_req: BTreeSet<&str> = bo
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    let curr_req: BTreeSet<&str> = co
        .get("required")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .collect();
    if let Some(missing) = base_req.difference(&curr_req).next() {
        let safe = sanitize_key(missing);
        return Some(format!("required field `{safe}` dropped"));
    }

    check_additional_props(
        bo.get("additionalProperties"),
        co.get("additionalProperties"),
        depth,
    )
}

fn check_additional_props(
    base_ap: Option<&Value>,
    curr_ap: Option<&Value>,
    depth: usize,
) -> Option<String> {
    match (base_ap, curr_ap) {
        (Some(Value::Bool(false)), Some(Value::Bool(false))) => None,
        (Some(Value::Bool(false)), _) => Some("additionalProperties widened".into()),
        (Some(b_obj), Some(c_obj)) if b_obj.is_object() && c_obj.is_object() => {
            detect_widening_rec(b_obj, c_obj, depth.saturating_add(1))
        }
        (Some(b_obj), _)
            if b_obj.is_object() && curr_ap.is_none_or(|v| v.as_bool() == Some(true)) =>
        {
            Some("additionalProperties schema dropped".into())
        }
        _ => None,
    }
}

fn check_enum_widening(
    bo: &serde_json::Map<String, Value>,
    co: &serde_json::Map<String, Value>,
) -> Option<String> {
    let base_enum = bo.get("enum").and_then(Value::as_array)?;
    let Some(curr_enum) = co.get("enum").and_then(Value::as_array) else {
        return Some("enum restriction dropped".into());
    };
    let base_set: BTreeSet<String> = base_enum.iter().map(canonical_json_string).collect();
    let curr_set: BTreeSet<String> = curr_enum.iter().map(canonical_json_string).collect();
    if !curr_set.is_subset(&base_set) {
        return Some("enum variants widened".into());
    }
    None
}

fn check_numeric_and_string_bounds(
    bo: &serde_json::Map<String, Value>,
    co: &serde_json::Map<String, Value>,
) -> Option<String> {
    for max_key in [
        "maxLength",
        "maximum",
        "exclusiveMaximum",
        "maxItems",
        "maxProperties",
    ] {
        if let Some(bv) = bo.get(max_key).and_then(Value::as_f64) {
            match co.get(max_key).and_then(Value::as_f64) {
                None => return Some(format!("upper bound `{max_key}` dropped")),
                Some(cv) if cv > bv => return Some(format!("upper bound `{max_key}` increased")),
                _ => {}
            }
        }
    }
    for min_key in [
        "minLength",
        "minimum",
        "exclusiveMinimum",
        "minItems",
        "minProperties",
    ] {
        if let Some(bv) = bo.get(min_key).and_then(Value::as_f64) {
            match co.get(min_key).and_then(Value::as_f64) {
                None => return Some(format!("lower bound `{min_key}` dropped")),
                Some(cv) if cv < bv => return Some(format!("lower bound `{min_key}` decreased")),
                _ => {}
            }
        }
    }
    None
}

fn check_combinators_and_subschemas(
    bo: &serde_json::Map<String, Value>,
    co: &serde_json::Map<String, Value>,
    depth: usize,
) -> Option<String> {
    for key in ["items", "not", "additionalItems"] {
        if let Some(bv) = bo.get(key) {
            match co.get(key) {
                None => return Some(format!("subschema `{key}` dropped")),
                Some(cv) => {
                    if let Some(sub) = detect_widening_rec(bv, cv, depth.saturating_add(1)) {
                        return Some(format!("`{key}`: {sub}"));
                    }
                }
            }
        }
    }
    for union_key in ["anyOf", "oneOf"] {
        if let Some(ba) = bo.get(union_key).and_then(Value::as_array) {
            let Some(ca) = co.get(union_key).and_then(Value::as_array) else {
                return Some(format!("`{union_key}` restriction dropped"));
            };
            if ca.len() > ba.len() {
                return Some(format!("`{union_key}` branches widened"));
            }
            let b_set: BTreeSet<String> = ba.iter().map(canonical_json_string).collect();
            let c_set: BTreeSet<String> = ca.iter().map(canonical_json_string).collect();
            if b_set == c_set {
                continue;
            }
            for (b_item, c_item) in ba.iter().zip(ca.iter()) {
                if let Some(sub) = detect_widening_rec(b_item, c_item, depth.saturating_add(1)) {
                    return Some(format!("`{union_key}`: {sub}"));
                }
            }
        }
    }
    if let Some(ba) = bo.get("allOf").and_then(Value::as_array) {
        let Some(ca) = co.get("allOf").and_then(Value::as_array) else {
            return Some("`allOf` restriction dropped".into());
        };
        if ca.len() < ba.len() {
            return Some("`allOf` branches dropped".into());
        }
        let b_set: BTreeSet<String> = ba.iter().map(canonical_json_string).collect();
        let c_set: BTreeSet<String> = ca.iter().map(canonical_json_string).collect();
        if b_set != c_set {
            for (b_item, c_item) in ba.iter().zip(ca.iter()) {
                if let Some(sub) = detect_widening_rec(b_item, c_item, depth.saturating_add(1)) {
                    return Some(format!("`allOf`: {sub}"));
                }
            }
        }
    }
    if let (Some(bp), Some(cp)) = (
        bo.get("patternProperties").and_then(Value::as_object),
        co.get("patternProperties").and_then(Value::as_object),
    ) {
        for (pat, c_schema) in cp {
            match bp.get(pat) {
                None => return Some(format!("new patternProperty `{}` added", sanitize_key(pat))),
                Some(b_schema) => {
                    if let Some(sub) =
                        detect_widening_rec(b_schema, c_schema, depth.saturating_add(1))
                    {
                        return Some(sub);
                    }
                }
            }
        }
    }
    None
}

fn check_remaining_semantic_drift(base: &Value, curr: &Value) -> Option<String> {
    let b_sem = canonical_json_filtered(base, true, 0);
    let c_sem = canonical_json_filtered(curr, true, 0);
    if b_sem != c_sem {
        Some("semantic schema structure changed".into())
    } else {
        None
    }
}

fn canonical_json_filtered(val: &Value, strip_cosmetic: bool, depth: usize) -> String {
    if depth >= MAX_SCHEMA_DEPTH {
        return "\"<max-depth>\"".into();
    }
    match val {
        Value::Object(map) => {
            let mut sorted: BTreeMap<&str, String> = BTreeMap::new();
            for (k, v) in map {
                if strip_cosmetic && COSMETIC_SCHEMA_KEYS.contains(&k.as_str()) {
                    continue;
                }
                if k == "enum"
                    && let Some(arr) = v.as_array()
                {
                    let mut items: Vec<String> = arr
                        .iter()
                        .map(|x| {
                            canonical_json_filtered(x, strip_cosmetic, depth.saturating_add(1))
                        })
                        .collect();
                    items.sort();
                    sorted.insert(k.as_str(), format!("[{}]", items.join(",")));
                    continue;
                }
                if k == "required"
                    && let Some(arr) = v.as_array()
                {
                    let mut items: Vec<String> = arr
                        .iter()
                        .map(|x| {
                            canonical_json_filtered(x, strip_cosmetic, depth.saturating_add(1))
                        })
                        .collect();
                    items.sort();
                    sorted.insert(k.as_str(), format!("[{}]", items.join(",")));
                    continue;
                }
                sorted.insert(
                    k.as_str(),
                    canonical_json_filtered(v, strip_cosmetic, depth.saturating_add(1)),
                );
            }
            let pairs: Vec<String> = sorted
                .into_iter()
                .map(|(k, v)| {
                    format!(
                        "{}:{}",
                        serde_json::to_string(k).unwrap_or_else(|_| "\"\"".into()),
                        v
                    )
                })
                .collect();
            format!("{{{}}}", pairs.join(","))
        }
        Value::Array(arr) => {
            let items: Vec<String> = arr
                .iter()
                .map(|v| canonical_json_filtered(v, strip_cosmetic, depth.saturating_add(1)))
                .collect();
            format!("[{}]", items.join(","))
        }
        other => serde_json::to_string(other).unwrap_or_else(|_| "null".into()),
    }
}

fn sanitize_key(raw: &str) -> String {
    raw.chars()
        .take(64)
        .map(|c| {
            if c.is_control() || is_invisible_or_bidi_char(c) {
                '?'
            } else {
                c
            }
        })
        .collect()
}
