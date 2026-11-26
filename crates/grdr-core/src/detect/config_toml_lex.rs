// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Lexical statement, key-path, and value parser for Codex TOML configurations (`D-09`).

use std::collections::{BTreeMap, BTreeSet};

const MAX_TOML_INLINE_DEPTH: usize = 16;
const MAX_TOML_KEY_SEGMENTS: usize = 32;

#[derive(Debug, Clone)]
pub(super) enum TomlVal {
    Str(String),
    Other(String),
    Table(BTreeMap<String, TomlVal>),
    InlineTable(BTreeMap<String, TomlVal>),
    Array(Vec<TomlVal>),
}

pub(super) fn resolve_active_prefix(
    segs: &[String],
    array_tables: &BTreeSet<Vec<String>>,
    array_indices: &BTreeMap<Vec<String>, usize>,
) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    for (idx, seg) in segs.iter().enumerate() {
        out.push(seg.clone());
        if idx.saturating_add(1) < segs.len() && array_tables.contains(&out) {
            let cur_idx = array_indices.get(&out).copied().ok_or(())?;
            out.push(format!("#{cur_idx}"));
        }
    }
    Ok(out)
}

pub(super) fn ensure_section_table_path(
    tbl: &mut BTreeMap<String, TomlVal>,
    path: &[String],
) -> Result<(), ()> {
    let mut cur = tbl;
    for seg in path {
        let entry = cur
            .entry(seg.clone())
            .or_insert_with(|| TomlVal::Table(BTreeMap::new()));
        let TomlVal::Table(sub) = entry else {
            return Err(());
        };
        cur = sub;
    }
    Ok(())
}

pub(super) fn insert_toml_nested(
    tbl: &mut BTreeMap<String, TomlVal>,
    path: &[String],
    val: TomlVal,
) -> Result<(), ()> {
    let Some((first, rest)) = path.split_first() else {
        return Err(());
    };
    if rest.is_empty() {
        if tbl.contains_key(first) {
            return Err(());
        }
        tbl.insert(first.clone(), val);
        return Ok(());
    }
    let child = tbl
        .entry(first.clone())
        .or_insert_with(|| TomlVal::Table(BTreeMap::new()));
    let TomlVal::Table(sub) = child else {
        return Err(());
    };
    insert_toml_nested(sub, rest, val)
}

pub(super) fn join_toml_statements(text: &str) -> Result<Vec<String>, ()> {
    let mut stmts = Vec::new();
    let mut cur = String::new();
    let mut bracket_depth: usize = 0;
    let mut brace_depth: usize = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for line in text.lines() {
        let mut cleaned_line = String::new();
        for ch in line.chars() {
            if escaped {
                cleaned_line.push(ch);
                escaped = false;
                continue;
            }
            if let Some(q) = quote {
                cleaned_line.push(ch);
                if q == '"' && ch == '\\' {
                    escaped = true;
                } else if ch == q {
                    quote = None;
                }
                continue;
            }
            match ch {
                '#' => break,
                '"' | '\'' => {
                    quote = Some(ch);
                    cleaned_line.push(ch);
                }
                '[' => {
                    bracket_depth = bracket_depth.saturating_add(1);
                    cleaned_line.push(ch);
                }
                ']' => {
                    bracket_depth = bracket_depth.saturating_sub(1);
                    cleaned_line.push(ch);
                }
                '{' => {
                    brace_depth = brace_depth.saturating_add(1);
                    cleaned_line.push(ch);
                }
                '}' => {
                    brace_depth = brace_depth.saturating_sub(1);
                    cleaned_line.push(ch);
                }
                other => cleaned_line.push(other),
            }
        }
        if !cleaned_line.trim().is_empty() {
            if !cur.is_empty() {
                cur.push(' ');
            }
            cur.push_str(cleaned_line.trim());
        }
        if quote.is_some() {
            return Err(());
        }
        if bracket_depth == 0 && brace_depth == 0 && !cur.is_empty() {
            stmts.push(std::mem::take(&mut cur));
        }
    }
    if quote.is_some() || bracket_depth != 0 || brace_depth != 0 {
        return Err(());
    }
    Ok(stmts)
}

pub(super) fn parse_toml_key_path(raw: &str) -> Result<Vec<String>, ()> {
    let s = raw.trim();
    if s.is_empty() {
        return Err(());
    }
    let mut chars = s.char_indices().peekable();
    let mut segs = Vec::new();
    loop {
        while let Some(&(_, ch)) = chars.peek() {
            if ch == ' ' || ch == '\t' {
                chars.next();
            } else {
                break;
            }
        }
        if segs.len() >= MAX_TOML_KEY_SEGMENTS {
            return Err(());
        }
        let Some(&(start_idx, first_ch)) = chars.peek() else {
            return Err(());
        };
        let seg = match first_ch {
            '"' => {
                chars.next();
                let inner_start = start_idx.saturating_add(1);
                let mut esc = false;
                let mut end_idx = None;
                for (idx, ch) in chars.by_ref() {
                    if esc {
                        esc = false;
                    } else if ch == '\\' {
                        esc = true;
                    } else if ch == '"' {
                        end_idx = Some(idx);
                        break;
                    }
                }
                let end = end_idx.ok_or(())?;
                let inner = s.get(inner_start..end).ok_or(())?;
                unescape_toml_basic(inner)?
            }
            '\'' => {
                chars.next();
                let inner_start = start_idx.saturating_add(1);
                let mut end_idx = None;
                for (idx, ch) in chars.by_ref() {
                    if ch == '\'' {
                        end_idx = Some(idx);
                        break;
                    }
                }
                let end = end_idx.ok_or(())?;
                s.get(inner_start..end).ok_or(())?.to_owned()
            }
            _ => {
                let mut bare = String::new();
                while let Some(&(_, ch)) = chars.peek() {
                    if ch.is_ascii_alphanumeric() || ch == '_' || ch == '-' {
                        bare.push(ch);
                        chars.next();
                    } else {
                        break;
                    }
                }
                if bare.is_empty() {
                    return Err(());
                }
                bare
            }
        };
        segs.push(seg);
        while let Some(&(_, ch)) = chars.peek() {
            if ch == ' ' || ch == '\t' {
                chars.next();
            } else {
                break;
            }
        }
        match chars.peek().copied() {
            None => return Ok(segs),
            Some((_, '.')) => {
                chars.next();
            }
            Some(_) => return Err(()),
        }
    }
}

pub(super) fn split_unquoted_eq(raw: &str) -> Option<(&str, &str)> {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if q == '"' && ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => quote = Some(ch),
            '=' => return Some((raw.get(..idx)?, raw.get(idx.saturating_add(1)..)?)),
            _ => {}
        }
    }
    None
}

pub(super) fn parse_toml_value(raw: &str, depth: usize) -> Result<TomlVal, ()> {
    if depth >= MAX_TOML_INLINE_DEPTH {
        return Err(());
    }
    let s = raw.trim();
    if let Some(inner) = s.strip_prefix('"').and_then(|r| r.strip_suffix('"')) {
        return Ok(TomlVal::Str(unescape_toml_basic(inner)?));
    }
    if let Some(inner) = s.strip_prefix('\'').and_then(|r| r.strip_suffix('\'')) {
        if inner.contains('\'') {
            return Err(());
        }
        return Ok(TomlVal::Str(inner.to_owned()));
    }
    if let Some(inner) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']')) {
        let items = split_toml_top_commas(inner)?;
        let mut parsed = Vec::with_capacity(items.len());
        for item in items {
            parsed.push(parse_toml_value(&item, depth.saturating_add(1))?);
        }
        return Ok(TomlVal::Array(parsed));
    }
    if let Some(inner) = s.strip_prefix('{').and_then(|r| r.strip_suffix('}')) {
        let pairs = split_toml_top_commas(inner)?;
        let mut tbl = BTreeMap::new();
        for pair in pairs {
            let (k, v) = split_unquoted_eq(&pair).ok_or(())?;
            let key_segs = parse_toml_key_path(k)?;
            let val = parse_toml_value(v, depth.saturating_add(1))?;
            insert_toml_nested(&mut tbl, &key_segs, val)?;
        }
        return Ok(TomlVal::InlineTable(tbl));
    }
    if s == "true" || s == "false" || s.parse::<i64>().is_ok() || s.parse::<f64>().is_ok() {
        Ok(TomlVal::Other(s.to_owned()))
    } else {
        Err(())
    }
}

fn split_toml_top_commas(inner: &str) -> Result<Vec<String>, ()> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut depth: usize = 0;
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for ch in inner.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            cur.push(ch);
            if q == '"' && ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '"' | '\'' => {
                quote = Some(ch);
                cur.push(ch);
            }
            '[' | '{' => {
                depth = depth.saturating_add(1);
                cur.push(ch);
            }
            ']' | '}' => {
                if depth == 0 {
                    return Err(());
                }
                depth = depth.saturating_sub(1);
                cur.push(ch);
            }
            ',' if depth == 0 => {
                let tok = std::mem::take(&mut cur);
                if !tok.trim().is_empty() {
                    out.push(tok.trim().to_owned());
                }
            }
            other => cur.push(other),
        }
    }
    if quote.is_some() || depth != 0 {
        return Err(());
    }
    if !cur.trim().is_empty() {
        out.push(cur.trim().to_owned());
    }
    Ok(out)
}

fn unescape_toml_basic(raw: &str) -> Result<String, ()> {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(ch) = chars.next() {
        if ch != '\\' {
            if ch == '"' {
                return Err(());
            }
            out.push(ch);
            continue;
        }
        let esc = chars.next().ok_or(())?;
        match esc {
            'n' => out.push('\n'),
            'r' => out.push('\r'),
            't' => out.push('\t'),
            '\\' => out.push('\\'),
            '"' => out.push('"'),
            'b' => out.push('\u{0008}'),
            'f' => out.push('\u{000C}'),
            'u' => out.push(take_unicode_hex(&mut chars, 4)?),
            'U' => out.push(take_unicode_hex(&mut chars, 8)?),
            _ => return Err(()),
        }
    }
    Ok(out)
}

fn take_unicode_hex(chars: &mut std::str::Chars<'_>, digits: usize) -> Result<char, ()> {
    let mut buf = String::with_capacity(digits);
    for _ in 0..digits {
        let ch = chars.next().ok_or(())?;
        if !ch.is_ascii_hexdigit() {
            return Err(());
        }
        buf.push(ch);
    }
    let code = u32::from_str_radix(&buf, 16).map_err(|_| ())?;
    char::from_u32(code).ok_or(())
}
