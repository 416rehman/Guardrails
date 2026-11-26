// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Zero-dependency pure-Rust YAML 1.2 subset parser for Sigma detection and session rules (`D-09`).

use std::collections::BTreeMap;
use std::sync::OnceLock;

use grdr_schema::limits::load_embedded_limits;

use crate::detect::types::DetectError;
use crate::detect::yaml_scalar::{
    MAX_YAML_NESTING_DEPTH, ParseBudget, insert_unique_key, parse_inline_or_scalar, split_map_key,
    strip_unquoted_comment,
};

const MAX_YAML_LINES: usize = 32_768;
const BYTES_PER_MIB: usize = 1_048_576;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum YamlValue {
    Null,
    Bool(bool),
    Int(i64),
    Str(String),
    Seq(Vec<YamlValue>),
    Map(BTreeMap<String, YamlValue>),
}

#[derive(Debug, Clone)]
struct YamlLine {
    indent: usize,
    content: String,
}

impl YamlValue {
    #[must_use]
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Self::Str(s) => Some(s.as_str()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Self::Bool(b) => Some(*b),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Self::Int(v) => Some(*v),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_seq(&self) -> Option<&[YamlValue]> {
        match self {
            Self::Seq(items) => Some(items.as_slice()),
            _ => None,
        }
    }

    #[must_use]
    pub fn as_map(&self) -> Option<&BTreeMap<String, YamlValue>> {
        match self {
            Self::Map(m) => Some(m),
            _ => None,
        }
    }

    #[must_use]
    pub fn get(&self, key: &str) -> Option<&YamlValue> {
        self.as_map()?.get(key)
    }

    #[must_use]
    pub fn to_string_list(&self) -> Vec<String> {
        match self {
            Self::Str(s) => vec![s.clone()],
            Self::Int(v) => vec![v.to_string()],
            Self::Bool(b) => vec![b.to_string()],
            Self::Seq(items) => items
                .iter()
                .filter_map(|item| match item {
                    Self::Str(s) => Some(s.clone()),
                    Self::Int(v) => Some(v.to_string()),
                    Self::Bool(b) => Some(b.to_string()),
                    _ => None,
                })
                .collect(),
            Self::Null | Self::Map(_) => Vec::new(),
        }
    }
}

fn yaml_max_bytes_cached() -> usize {
    static MAX_BYTES: OnceLock<usize> = OnceLock::new();
    *MAX_BYTES.get_or_init(|| {
        let max_mb = load_embedded_limits()
            .ok()
            .and_then(|l| usize::try_from(l.packs.detections_max_mb).ok())
            .unwrap_or(4);
        max_mb.saturating_mul(BYTES_PER_MIB)
    })
}

/// Parses bounded indentation-structured YAML documents cleanly in pure Rust.
pub fn parse_yaml(raw: &str) -> Result<YamlValue, DetectError> {
    let max_bytes = yaml_max_bytes_cached();
    if raw.len() > max_bytes {
        return Err(DetectError::InvalidRule(format!(
            "YAML input exceeds schema packs.detections_max_mb ({max_bytes} bytes)"
        )));
    }
    let lines = preprocess_lines(raw)?;
    if lines.is_empty() {
        return Ok(YamlValue::Map(BTreeMap::new()));
    }
    let mut budget = ParseBudget::new();
    let first_indent = lines.first().map_or(0, |l| l.indent);
    let (val, next_idx) = parse_block(&lines, 0, first_indent, 0, &mut budget)?;
    if next_idx < lines.len() {
        return Err(DetectError::InvalidRule(
            "unexpected trailing YAML content".into(),
        ));
    }
    Ok(val)
}

fn preprocess_lines(raw: &str) -> Result<Vec<YamlLine>, DetectError> {
    let mut lines = Vec::new();
    let mut saw_content = false;
    let mut saw_doc_end = false;
    for raw_line in raw.lines() {
        let no_cr = raw_line.trim_end_matches('\r');
        let stripped = strip_unquoted_comment(no_cr);
        let t = stripped.trim();
        if t == "---" {
            if saw_content {
                return Err(DetectError::InvalidRule(
                    "multi-document YAML `---` separator not allowed".into(),
                ));
            }
            continue;
        }
        if t == "..." {
            saw_doc_end = true;
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if saw_doc_end {
            return Err(DetectError::InvalidRule(
                "unexpected YAML content after `...` document end".into(),
            ));
        }
        saw_content = true;
        let indent = stripped.bytes().take_while(|b| *b == b' ').count();
        if stripped
            .bytes()
            .take_while(|b| *b == b' ' || *b == b'\t')
            .any(|b| b == b'\t')
        {
            return Err(DetectError::InvalidRule(
                "YAML indentation cannot use tab characters".into(),
            ));
        }
        if lines.len() >= MAX_YAML_LINES {
            return Err(DetectError::InvalidRule("YAML line limit exceeded".into()));
        }
        let content = stripped.get(indent..).unwrap_or("").trim_end().to_owned();
        lines.push(YamlLine { indent, content });
    }
    Ok(lines)
}

fn parse_block(
    lines: &[YamlLine],
    start: usize,
    base_indent: usize,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<(YamlValue, usize), DetectError> {
    if depth >= MAX_YAML_NESTING_DEPTH {
        return Err(DetectError::InvalidRule(
            "YAML nesting depth exceeded".into(),
        ));
    }
    let Some(first) = lines.get(start) else {
        return Ok((YamlValue::Null, start));
    };
    if is_seq_line(&first.content) {
        parse_sequence(lines, start, base_indent, depth.saturating_add(1), budget)
    } else {
        parse_mapping(lines, start, base_indent, depth.saturating_add(1), budget)
    }
}

fn parse_sequence(
    lines: &[YamlLine],
    mut idx: usize,
    base_indent: usize,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<(YamlValue, usize), DetectError> {
    if depth >= MAX_YAML_NESTING_DEPTH {
        return Err(DetectError::InvalidRule(
            "YAML nesting depth exceeded".into(),
        ));
    }
    let mut items = Vec::new();
    while let Some(line) = lines.get(idx) {
        if line.indent < base_indent || !is_seq_line(&line.content) {
            break;
        }
        if line.indent > base_indent {
            return Err(DetectError::InvalidRule(
                "over-indented sibling YAML sequence item".into(),
            ));
        }
        budget.take_node()?;
        let after_dash = line.content.strip_prefix('-').unwrap_or("").trim_start();
        if after_dash.is_empty() {
            idx = idx.saturating_add(1);
            if let Some(child) = lines.get(idx)
                && child.indent > line.indent
            {
                let (val, next_idx) =
                    parse_block(lines, idx, child.indent, depth.saturating_add(1), budget)?;
                items.push(val);
                idx = next_idx;
            } else {
                items.push(YamlValue::Null);
            }
            continue;
        }
        if let Some((k, rest)) = split_map_key(after_dash)? {
            let item_indent = line.indent.saturating_add(2);
            let mut map = BTreeMap::new();
            if rest.is_empty() {
                idx = idx.saturating_add(1);
                if let Some(child) = lines.get(idx)
                    && (child.indent > item_indent
                        || (child.indent == item_indent && is_seq_line(&child.content)))
                {
                    let (v, next_idx) =
                        parse_block(lines, idx, child.indent, depth.saturating_add(1), budget)?;
                    if next_idx <= idx {
                        return Err(DetectError::InvalidRule(
                            "YAML sequence child failed to advance parser".into(),
                        ));
                    }
                    insert_unique_key(&mut map, k, v)?;
                    idx = next_idx;
                } else {
                    insert_unique_key(&mut map, k, YamlValue::Null)?;
                }
            } else {
                insert_unique_key(
                    &mut map,
                    k,
                    parse_inline_or_scalar(rest, depth.saturating_add(1), budget)?,
                )?;
                idx = idx.saturating_add(1);
            }
            while let Some(next_line) = lines.get(idx) {
                if next_line.indent < item_indent
                    || (next_line.indent == line.indent && is_seq_line(&next_line.content))
                {
                    break;
                }
                if next_line.indent > item_indent || is_seq_line(&next_line.content) {
                    return Err(DetectError::InvalidRule(
                        "unexpected indented sequence or scalar inside YAML sequence mapping"
                            .into(),
                    ));
                }
                let (extra_map, next_idx) = parse_mapping_entries_until(
                    lines,
                    idx,
                    item_indent,
                    depth.saturating_add(1),
                    budget,
                )?;
                if next_idx <= idx {
                    return Err(DetectError::InvalidRule(
                        "YAML sequence mapping failed to advance parser".into(),
                    ));
                }
                for (ek, ev) in extra_map {
                    insert_unique_key(&mut map, ek, ev)?;
                }
                idx = next_idx;
            }
            items.push(YamlValue::Map(map));
        } else {
            items.push(parse_inline_or_scalar(
                after_dash,
                depth.saturating_add(1),
                budget,
            )?);
            idx = idx.saturating_add(1);
        }
    }
    Ok((YamlValue::Seq(items), idx))
}

fn parse_mapping(
    lines: &[YamlLine],
    start: usize,
    base_indent: usize,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<(YamlValue, usize), DetectError> {
    let (map, next_idx) = parse_mapping_entries_until(lines, start, base_indent, depth, budget)?;
    Ok((YamlValue::Map(map), next_idx))
}

fn parse_mapping_entries_until(
    lines: &[YamlLine],
    mut idx: usize,
    base_indent: usize,
    depth: usize,
    budget: &mut ParseBudget,
) -> Result<(BTreeMap<String, YamlValue>, usize), DetectError> {
    if depth >= MAX_YAML_NESTING_DEPTH {
        return Err(DetectError::InvalidRule(
            "YAML nesting depth exceeded".into(),
        ));
    }
    let mut map = BTreeMap::new();
    while let Some(line) = lines.get(idx) {
        if line.indent < base_indent || is_seq_line(&line.content) || line.indent > base_indent {
            break;
        }
        let Some((key, rest)) = split_map_key(&line.content)? else {
            return Err(DetectError::InvalidRule(format!(
                "expected `key: value` on YAML line `{}`",
                line.content
            )));
        };
        budget.take_node()?;
        idx = idx.saturating_add(1);
        if rest.is_empty() {
            if let Some(child) = lines.get(idx)
                && (child.indent > base_indent
                    || (child.indent == base_indent && is_seq_line(&child.content)))
            {
                let (val, next_idx) =
                    parse_block(lines, idx, child.indent, depth.saturating_add(1), budget)?;
                if next_idx <= idx {
                    return Err(DetectError::InvalidRule(
                        "YAML mapping child failed to advance parser".into(),
                    ));
                }
                insert_unique_key(&mut map, key, val)?;
                idx = next_idx;
            } else {
                insert_unique_key(&mut map, key, YamlValue::Null)?;
            }
        } else {
            insert_unique_key(
                &mut map,
                key,
                parse_inline_or_scalar(rest, depth.saturating_add(1), budget)?,
            )?;
        }
    }
    Ok((map, idx))
}

fn is_seq_line(content: &str) -> bool {
    content == "-" || content.starts_with("- ")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn yaml_rejects_flow_depth_bombs_tabs_and_duplicate_keys() {
        let depth_bomb = format!("a: {}1{}", "[".repeat(64), "]".repeat(64));
        assert!(parse_yaml(&depth_bomb).is_err());
        assert!(parse_yaml("a:\n\tb: 1\n").is_err());
        assert!(parse_yaml("a: 1\na: 2\n").is_err());
        assert!(parse_yaml("a: {x: 1, x: 2}\n").is_err());
    }

    #[test]
    fn yaml_single_quotes_preserve_backslashes_and_double_quotes_single_pass() {
        let raw = "win: '\\notepad.exe'\ndq: \"\\\\n and a\\\"b\"\n";
        let doc = parse_yaml(raw).expect("valid yaml");
        assert_eq!(
            doc.get("win").and_then(YamlValue::as_str),
            Some("\\notepad.exe")
        );
        assert_eq!(
            doc.get("dq").and_then(YamlValue::as_str),
            Some("\\n and a\"b")
        );
    }
}
