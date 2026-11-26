// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Quote-aware `.proto` option scanning and bounded identifier matching helpers.

use crate::proto_source_rpc::bounded_type_match;

pub(crate) fn find_char_outside_quotes(s: &str, target: char) -> Option<usize> {
    let (mut in_str, mut in_sgl, mut esc) = (false, false, false);
    for (idx, ch) in s.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        if ch == '\\' && (in_str || in_sgl) {
            esc = true;
            continue;
        }
        if ch == '"' && !in_sgl {
            in_str = !in_str;
            continue;
        }
        if ch == '\'' && !in_str {
            in_sgl = !in_sgl;
            continue;
        }
        if !in_str && !in_sgl && ch == target {
            return Some(idx);
        }
    }
    None
}

pub(crate) fn split_once_outside_quotes(s: &str, delim: char) -> Option<(&str, &str)> {
    let pos = find_char_outside_quotes(s, delim)?;
    let lhs = s.get(..pos)?;
    let rhs = s.get(pos.saturating_add(delim.len_utf8())..)?;
    Some((lhs, rhs))
}

pub(crate) fn strip_keyword<'a>(s: &'a str, kw: &str) -> Option<&'a str> {
    let trimmed = s.trim_start();
    let rest = trimmed.strip_prefix(kw)?;
    if rest
        .chars()
        .next()
        .is_some_and(|c| c.is_ascii_whitespace() || c == '=' || c == '"' || c == '(')
    {
        Some(rest.trim_start())
    } else {
        None
    }
}

pub(crate) fn unquote_simple(raw: &str) -> Option<String> {
    let s = raw.trim();
    s.strip_prefix('"')
        .and_then(|v| v.strip_suffix('"'))
        .or_else(|| s.strip_prefix('\'').and_then(|v| v.strip_suffix('\'')))
        .map(str::to_owned)
}

pub(crate) fn bounded_option_key_matches(
    raw_key: &str,
    key: &str,
    options_pkg: Option<&str>,
) -> bool {
    let k = remove_all_ws(raw_key);
    if let Some(inner) = k.strip_prefix('(').and_then(|s| s.strip_suffix(')')) {
        let trimmed = inner.trim_start_matches('.');
        if let Some(pkg) = options_pkg {
            bounded_type_match(&format!(".{pkg}.{key}"), trimmed)
        } else {
            trimmed == key || trimmed.strip_suffix(key).is_some_and(|p| p.ends_with('.'))
        }
    } else {
        k == key
    }
}

fn split_bracket_entries(raw: &str) -> Vec<&str> {
    let trimmed = raw.trim().trim_end_matches(';').trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    let mut parts = Vec::new();
    let (mut start, mut in_str, mut in_sgl, mut esc) = (0usize, false, false, false);
    let (mut brace, mut bracket, mut paren) = (0usize, 0usize, 0usize);
    for (idx, ch) in inner.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        if ch == '\\' && (in_str || in_sgl) {
            esc = true;
            continue;
        }
        if ch == '"' && !in_sgl {
            in_str = !in_str;
            continue;
        }
        if ch == '\'' && !in_str {
            in_sgl = !in_sgl;
            continue;
        }
        if !in_str && !in_sgl {
            match ch {
                '{' => brace = brace.saturating_add(1),
                '}' => brace = brace.saturating_sub(1),
                '[' => bracket = bracket.saturating_add(1),
                ']' => bracket = bracket.saturating_sub(1),
                '(' => paren = paren.saturating_add(1),
                ')' => paren = paren.saturating_sub(1),
                ',' if brace == 0 && bracket == 0 && paren == 0 => {
                    if let Some(slice) = inner.get(start..idx) {
                        parts.push(slice);
                    }
                    start = idx.saturating_add(1);
                }
                _ => {}
            }
        }
    }
    if let Some(tail) = inner.get(start..)
        && !tail.trim().is_empty()
    {
        parts.push(tail);
    }
    parts
}

pub(crate) fn extract_raw_option(
    raw_options: &str,
    key: &str,
    options_pkg: Option<&str>,
) -> Option<String> {
    let mut found = None;
    for entry in split_bracket_entries(raw_options) {
        let Some((lhs, rhs)) = split_once_outside_quotes(entry, '=') else {
            continue;
        };
        if bounded_option_key_matches(lhs, key, options_pkg) {
            found = Some(rhs.trim().to_owned());
        }
    }
    found
}

pub(crate) fn extract_enum_opt(
    raw_options: &str,
    key: &str,
    options_pkg: Option<&str>,
) -> Option<String> {
    let val = extract_raw_option(raw_options, key, options_pkg)?;
    let compact = remove_all_ws(&val);
    let last = compact.rsplit('.').next().unwrap_or("");
    let tok: String = last
        .chars()
        .take_while(|c| c.is_ascii_alphanumeric() || *c == '_')
        .collect();
    if tok.is_empty() { None } else { Some(tok) }
}

pub(crate) fn extract_bool_opt(raw_options: &str, key: &str, options_pkg: Option<&str>) -> bool {
    extract_raw_option(raw_options, key, options_pkg).is_some_and(|v| v.trim() == "true")
}

pub(crate) fn extract_quoted_opt(
    raw_options: &str,
    key: &str,
    options_pkg: Option<&str>,
) -> Option<String> {
    let val = extract_raw_option(raw_options, key, options_pkg)?;
    unquote_simple(&val)
}

pub(crate) fn remove_all_ws(s: &str) -> String {
    s.chars().filter(|c| !c.is_ascii_whitespace()).collect()
}
