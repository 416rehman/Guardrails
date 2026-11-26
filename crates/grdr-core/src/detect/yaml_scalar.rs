// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Inline flow sequence/mapping parsing and scalar unescaping for `detect::yaml`.

use std::collections::BTreeMap;

use crate::detect::types::DetectError;
use crate::detect::yaml::YamlValue;

pub(super) const MAX_YAML_NESTING_DEPTH: usize = 32;
const MAX_YAML_NODES: usize = 16_384;

pub(super) struct ParseBudget {
    nodes_left: usize,
}

impl ParseBudget {
    pub(super) fn new() -> Self {
        Self {
            nodes_left: MAX_YAML_NODES,
        }
    }

    pub(super) fn take_node(&mut self) -> Result<(), DetectError> {
        if self.nodes_left == 0 {
            return Err(DetectError::InvalidRule("YAML node budget exceeded".into()));
        }
        self.nodes_left = self.nodes_left.saturating_sub(1);
        Ok(())
    }
}

pub(super) fn insert_unique_key(
    map: &mut BTreeMap<String, YamlValue>,
    key: String,
    val: YamlValue,
) -> Result<(), DetectError> {
    if map.contains_key(&key) {
        return Err(DetectError::InvalidRule(format!(
            "duplicate YAML mapping key `{key}`"
        )));
    }
    map.insert(key, val);
    Ok(())
}

pub(super) fn parse_inline_or_scalar(
    raw: &str,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<YamlValue, DetectError> {
    if depth >= MAX_YAML_NESTING_DEPTH {
        return Err(DetectError::InvalidRule(
            "YAML flow nesting depth exceeded".into(),
        ));
    }
    budget.take_node()?;
    let trimmed = raw.trim();
    if let Some(after_open) = trimmed.strip_prefix('[') {
        let Some(inner) = after_open.strip_suffix(']') else {
            return Err(DetectError::InvalidRule(
                "unclosed inline YAML sequence `[`".into(),
            ));
        };
        let inner = inner.trim();
        if inner.is_empty() {
            return Ok(YamlValue::Seq(Vec::new()));
        }
        let mut items = Vec::new();
        for tok in split_top_level_commas(inner, depth.saturating_add(1))? {
            items.push(parse_inline_or_scalar(
                &tok,
                depth.saturating_add(1),
                budget,
            )?);
        }
        return Ok(YamlValue::Seq(items));
    }
    if let Some(after_open) = trimmed.strip_prefix('{') {
        let Some(inner) = after_open.strip_suffix('}') else {
            return Err(DetectError::InvalidRule(
                "unclosed inline YAML mapping `{`".into(),
            ));
        };
        let inner = inner.trim();
        let mut map = BTreeMap::new();
        if !inner.is_empty() {
            for pair in split_top_level_commas(inner, depth.saturating_add(1))? {
                let (k, v) = split_map_key(&pair)?.ok_or_else(|| {
                    DetectError::InvalidRule(format!("invalid inline YAML map entry `{pair}`"))
                })?;
                insert_unique_key(
                    &mut map,
                    k,
                    parse_inline_or_scalar(v, depth.saturating_add(1), budget)?,
                )?;
            }
        }
        return Ok(YamlValue::Map(map));
    }
    if trimmed.starts_with('"') {
        if trimmed.len() >= 2 && trimmed.ends_with('"') {
            let inner = trimmed
                .get(1..trimmed.len().saturating_sub(1))
                .unwrap_or("");
            return Ok(YamlValue::Str(unescape_double_quoted_scalar(inner)?));
        }
        return Err(DetectError::InvalidRule(
            "unterminated double-quoted YAML scalar".into(),
        ));
    }
    if trimmed.starts_with('\'') {
        if trimmed.len() >= 2 && trimmed.ends_with('\'') {
            let inner = trimmed
                .get(1..trimmed.len().saturating_sub(1))
                .unwrap_or("");
            return Ok(YamlValue::Str(unescape_single_quoted_scalar(inner)?));
        }
        return Err(DetectError::InvalidRule(
            "unterminated single-quoted YAML scalar".into(),
        ));
    }
    match trimmed {
        "null" | "~" => Ok(YamlValue::Null),
        "true" | "True" | "TRUE" => Ok(YamlValue::Bool(true)),
        "false" | "False" | "FALSE" => Ok(YamlValue::Bool(false)),
        _ => Ok(trimmed
            .parse::<i64>()
            .map_or_else(|_| YamlValue::Str(trimmed.to_owned()), YamlValue::Int)),
    }
}

pub(super) fn split_map_key(line: &str) -> Result<Option<(String, &str)>, DetectError> {
    let mut in_single = false;
    let mut in_double = false;
    let mut prev_esc = false;
    for (idx, ch) in line.char_indices() {
        if prev_esc {
            prev_esc = false;
            continue;
        }
        match ch {
            '\\' if in_double => prev_esc = true,
            '\'' if !in_double => in_single = !in_single,
            '"' if !in_single => in_double = !in_double,
            ':' if !in_single && !in_double => {
                let after = line.get(idx.saturating_add(1)..).unwrap_or("");
                if after.is_empty() || after.starts_with(' ') {
                    let raw_key = line.get(..idx).unwrap_or("").trim();
                    let key = unescape_map_key(raw_key)?;
                    return Ok(Some((key, after.trim())));
                }
            }
            _ => {}
        }
    }
    Ok(None)
}

fn unescape_map_key(raw_key: &str) -> Result<String, DetectError> {
    if raw_key.starts_with('"') {
        if raw_key.len() >= 2 && raw_key.ends_with('"') {
            let inner = raw_key
                .get(1..raw_key.len().saturating_sub(1))
                .unwrap_or("");
            return unescape_double_quoted_scalar(inner);
        }
        return Err(DetectError::InvalidRule(
            "unterminated or malformed double-quoted YAML key".into(),
        ));
    }
    if raw_key.starts_with('\'') {
        if raw_key.len() >= 2 && raw_key.ends_with('\'') {
            let inner = raw_key
                .get(1..raw_key.len().saturating_sub(1))
                .unwrap_or("");
            return unescape_single_quoted_scalar(inner);
        }
        return Err(DetectError::InvalidRule(
            "unterminated or malformed single-quoted YAML key".into(),
        ));
    }
    if raw_key.contains('"') || raw_key.contains('\'') {
        return Err(DetectError::InvalidRule(
            "unexpected quote inside unquoted YAML key".into(),
        ));
    }
    Ok(raw_key.to_owned())
}

fn split_top_level_commas(inner: &str, base_depth: usize) -> Result<Vec<String>, DetectError> {
    let mut out = Vec::new();
    let mut current = String::new();
    let mut expected_closers: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            current.push(ch);
            if q == '"' && ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\'' | '"' => {
                quote = Some(ch);
                current.push(ch);
            }
            '[' => {
                let next_depth = base_depth
                    .saturating_add(expected_closers.len())
                    .saturating_add(1);
                if next_depth >= MAX_YAML_NESTING_DEPTH {
                    return Err(DetectError::InvalidRule(
                        "YAML flow nesting depth exceeded".into(),
                    ));
                }
                expected_closers.push(']');
                current.push(ch);
            }
            '{' => {
                let next_depth = base_depth
                    .saturating_add(expected_closers.len())
                    .saturating_add(1);
                if next_depth >= MAX_YAML_NESTING_DEPTH {
                    return Err(DetectError::InvalidRule(
                        "YAML flow nesting depth exceeded".into(),
                    ));
                }
                expected_closers.push('}');
                current.push(ch);
            }
            ']' | '}' => {
                let Some(expected) = expected_closers.pop() else {
                    return Err(DetectError::InvalidRule(
                        "unexpected closing delimiter in flow YAML".into(),
                    ));
                };
                if ch != expected {
                    return Err(DetectError::InvalidRule(
                        "mismatched delimiter in flow YAML".into(),
                    ));
                }
                current.push(ch);
            }
            ',' if expected_closers.is_empty() => {
                out.push(std::mem::take(&mut current).trim().to_owned());
            }
            other => current.push(other),
        }
    }
    if quote.is_some() || !expected_closers.is_empty() {
        return Err(DetectError::InvalidRule(
            "unclosed quote or delimiter inside inline YAML".into(),
        ));
    }
    if !current.trim().is_empty() {
        out.push(current.trim().to_owned());
    }
    Ok(out)
}

pub(super) fn strip_unquoted_comment(line: &str) -> String {
    let mut out = String::with_capacity(line.len());
    let mut quote: Option<char> = None;
    let mut prev_ws = true;
    let mut escaped = false;
    for ch in line.chars() {
        if escaped {
            out.push(ch);
            escaped = false;
            prev_ws = false;
            continue;
        }
        if let Some(q) = quote {
            out.push(ch);
            if q == '"' && ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            prev_ws = false;
            continue;
        }
        if ch == '#' && prev_ws {
            break;
        }
        if ch == '\'' || ch == '"' {
            quote = Some(ch);
        }
        prev_ws = ch.is_ascii_whitespace();
        out.push(ch);
    }
    out
}

fn unescape_single_quoted_scalar(raw: &str) -> Result<String, DetectError> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\'' {
            out.push(ch);
            continue;
        }
        if chars.next() == Some('\'') {
            out.push('\'');
        } else {
            return Err(DetectError::InvalidRule(
                "unescaped single quote inside single-quoted YAML scalar".into(),
            ));
        }
    }
    Ok(out)
}

fn unescape_double_quoted_scalar(raw: &str) -> Result<String, DetectError> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            if ch == '"' {
                return Err(DetectError::InvalidRule(
                    "unescaped quote inside double-quoted YAML scalar".into(),
                ));
            }
            out.push(ch);
            continue;
        }
        let Some(esc) = chars.next() else {
            return Err(DetectError::InvalidRule(
                "dangling backslash in double-quoted YAML scalar".into(),
            ));
        };
        match esc {
            'a' => out.push('\u{0007}'),
            'b' => out.push('\u{0008}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'v' => out.push('\u{000B}'),
            'f' => out.push('\u{000C}'),
            'r' => out.push('\r'),
            'e' => out.push('\u{001B}'),
            ' ' => out.push(' '),
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            '/' => out.push('/'),
            '0' => out.push('\0'),
            'x' => out.push(take_yaml_hex(&mut chars, 2)?),
            'u' => out.push(take_yaml_hex(&mut chars, 4)?),
            'U' => out.push(take_yaml_hex(&mut chars, 8)?),
            other => {
                out.push('\\');
                out.push(other);
            }
        }
    }
    Ok(out)
}

fn take_yaml_hex(chars: &mut std::str::Chars<'_>, digits: usize) -> Result<char, DetectError> {
    let mut buf = String::with_capacity(digits);
    for _ in 0..digits {
        let ch = chars.next().ok_or_else(|| {
            DetectError::InvalidRule("truncated hex escape in YAML double-quoted scalar".into())
        })?;
        if !ch.is_ascii_hexdigit() {
            return Err(DetectError::InvalidRule(
                "invalid hex digit in YAML double-quoted scalar".into(),
            ));
        }
        buf.push(ch);
    }
    let code = u32::from_str_radix(&buf, 16)
        .map_err(|_| DetectError::InvalidRule("invalid hex escape in YAML scalar".into()))?;
    char::from_u32(code).ok_or_else(|| {
        DetectError::InvalidRule("invalid Unicode scalar value in YAML escape".into())
    })
}
