// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bounded Cargo TOML assignment and inline-table scanner for manifest verification.

use crate::LintError;
use crate::capture_toml::strip_toml_comment;

pub(crate) fn manifest_err(target: &str, detail: &str) -> LintError {
    LintError::CaptureOrCodegenViolation {
        target: target.into(),
        detail: detail.into(),
    }
}

pub(crate) fn parse_toml_assignments(
    raw: &str,
    label: &str,
) -> Result<Vec<(String, String, String)>, LintError> {
    let mut section = String::new();
    let mut out = Vec::new();
    let mut buf = String::new();
    let (mut braces, mut brackets) = (0usize, 0usize);

    for raw_line in raw.lines() {
        let piece = strip_toml_comment(raw_line).trim();
        if piece.is_empty() {
            continue;
        }
        if buf.is_empty() && piece.starts_with('[') {
            if let Some(arr) = piece.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
                section = arr.trim().to_owned();
                continue;
            }
            if let Some(tbl) = piece.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
                section = tbl.trim().to_owned();
                continue;
            }
            return Err(manifest_err(
                label,
                &format!("malformed section header `{piece}`"),
            ));
        }
        if !buf.is_empty() {
            buf.push(' ');
        }
        buf.push_str(piece);
        update_toml_depths(piece, &mut braces, &mut brackets);
        if braces == 0 && brackets == 0 {
            let stmt = std::mem::take(&mut buf);
            let Some((k_raw, v_raw)) = stmt.split_once('=') else {
                return Err(manifest_err(
                    label,
                    &format!("malformed TOML line `{stmt}`"),
                ));
            };
            out.push((
                section.clone(),
                k_raw.trim().trim_matches('"').to_owned(),
                v_raw.trim().to_owned(),
            ));
        }
    }
    if !buf.is_empty() {
        return Err(manifest_err(label, "unterminated TOML table or array"));
    }
    Ok(out)
}

fn update_toml_depths(s: &str, braces: &mut usize, brackets: &mut usize) {
    let (mut in_str, mut in_sgl, mut esc) = (false, false, false);
    for ch in s.chars() {
        if esc {
            esc = false;
            continue;
        }
        if ch == '\\' && in_str {
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
                '{' => *braces = braces.saturating_add(1),
                '}' => *braces = braces.saturating_sub(1),
                '[' => *brackets = brackets.saturating_add(1),
                ']' => *brackets = brackets.saturating_sub(1),
                _ => {}
            }
        }
    }
}

pub(crate) fn extract_inline_string_attr(
    val: &str,
    attr: &str,
) -> Result<Option<String>, LintError> {
    let trimmed = val.trim();
    let Some(inner) = trimmed.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return Ok(None);
    };
    let mut start = 0usize;
    let (mut in_str, mut in_sgl, mut esc) = (false, false, false);
    let mut depth = 0usize;
    for (idx, ch) in inner.char_indices() {
        if esc {
            esc = false;
            continue;
        }
        if ch == '\\' && in_str {
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
                '{' | '[' => depth = depth.saturating_add(1),
                '}' | ']' => depth = depth.saturating_sub(1),
                ',' if depth == 0 => {
                    if let Some(found) = check_inline_kv(inner.get(start..idx).unwrap_or(""), attr)?
                    {
                        return Ok(Some(found));
                    }
                    start = idx.saturating_add(1);
                }
                _ => {}
            }
        }
    }
    check_inline_kv(inner.get(start..).unwrap_or(""), attr)
}

pub(crate) fn parse_string_array(val: &str, label: &str) -> Result<Vec<String>, LintError> {
    let trimmed = val.trim();
    let Some(inner) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) else {
        return Err(manifest_err(label, "expected TOML array"));
    };
    let mut out = Vec::new();
    for part in inner.split(',') {
        let piece = part.trim();
        if piece.is_empty() {
            continue;
        }
        out.push(unquote_toml_value(piece, label)?);
    }
    Ok(out)
}

fn check_inline_kv(entry: &str, attr: &str) -> Result<Option<String>, LintError> {
    let Some((k, v)) = entry.split_once('=') else {
        return Ok(None);
    };
    if k.trim() == attr {
        return Ok(Some(unquote_toml_value(v.trim(), "Cargo.toml")?));
    }
    Ok(None)
}

pub(crate) fn unquote_toml_value(raw: &str, label: &str) -> Result<String, LintError> {
    let s = raw.trim();
    if let Some(v) = s.strip_prefix('"').and_then(|t| t.strip_suffix('"')) {
        return Ok(v.to_owned());
    }
    if let Some(v) = s.strip_prefix('\'').and_then(|t| t.strip_suffix('\'')) {
        return Ok(v.to_owned());
    }
    Err(manifest_err(
        label,
        &format!("expected quoted string value, found `{s}`"),
    ))
}
