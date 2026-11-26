// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pipeline, `FromBase64String`, and PowerShell `-EncodedCommand` extraction helpers.

use crate::analyze::cmd_wrappers::unwrap_prefix_command;
use crate::analyze::types::ShellDialect;

const PS_VALUE_FLAG_PREFIXES: &[(&str, usize)] = &[
    ("executionpolicy", 2),
    ("windowstyle", 1),
    ("workingdirectory", 2),
    ("inputformat", 3),
    ("outputformat", 1),
    ("configurationname", 3),
    ("configurationfile", 14),
    ("custompipename", 2),
    ("settingsfile", 2),
    ("psconsolefile", 2),
    ("version", 1),
    ("encodedarguments", 8),
];

pub(crate) fn extract_ps_encoded_arg(tokens: &[String], idx: usize) -> Option<(String, bool)> {
    let tok = tokens.get(idx)?;
    let (flag_part, attached_val) = match tok.find([':', '=']) {
        Some(sep) => (
            tok.get(..sep).unwrap_or(tok),
            tok.get(sep.saturating_add(1)..),
        ),
        None => (tok.as_str(), None),
    };
    let normalized = flag_part
        .trim_start_matches(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/'])
        .to_ascii_lowercase();
    if normalized.is_empty() {
        return None;
    }
    let has_prefix = flag_part.starts_with(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/']);
    if !has_prefix {
        return None;
    }
    let matches_switch = normalized == "ec" || "encodedcommand".starts_with(&normalized);
    if !matches_switch {
        return None;
    }
    if let Some(val) = attached_val {
        let trimmed = val.trim_matches(['"', '\'']).trim();
        return Some((trimmed.to_owned(), true));
    }
    let next = tokens
        .get(idx.saturating_add(1))
        .cloned()
        .unwrap_or_default();
    Some((next, false))
}

pub(crate) fn is_powershell_context(tokens: &[String], _dialect: Option<ShellDialect>) -> bool {
    let Some(bin) = effective_command_bin(tokens) else {
        return false;
    };
    matches!(
        bin.as_str(),
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
    )
}

pub(crate) fn is_ps_stop_flag(tok: &str) -> bool {
    if tok == "--" || tok == "--%" {
        return true;
    }
    let flag_part = tok
        .find([':', '='])
        .and_then(|sep| tok.get(..sep))
        .unwrap_or(tok);
    if !flag_part.starts_with(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/']) {
        return false;
    }
    let stripped = flag_part
        .trim_start_matches(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/'])
        .to_ascii_lowercase();
    if stripped.is_empty() {
        return false;
    }
    "command".starts_with(&stripped)
        || "commandwithargs".starts_with(&stripped)
        || "file".starts_with(&stripped)
}

pub(crate) fn is_ps_value_flag(tok: &str) -> bool {
    if tok.contains([':', '=']) || !tok.starts_with(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/'])
    {
        return false;
    }
    let stripped = tok
        .trim_start_matches(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/'])
        .to_ascii_lowercase();
    is_ps_value_flag_name(&stripped)
}

pub(crate) fn is_ps_value_flag_name(stripped_low: &str) -> bool {
    if stripped_low.is_empty() {
        return false;
    }
    if matches!(stripped_low, "ep" | "wd" | "if" | "of" | "ea") {
        return true;
    }
    PS_VALUE_FLAG_PREFIXES
        .iter()
        .any(|&(full, min_len)| stripped_low.len() >= min_len && full.starts_with(stripped_low))
}

pub(crate) fn unwrap_clause_slice(tokens: &[String]) -> &[String] {
    let mut skip = 0usize;
    while tokens
        .get(skip)
        .is_some_and(|t| t.is_empty() || is_env_assign(t))
    {
        skip = skip.saturating_add(1);
    }
    unwrap_prefix_command(tokens.get(skip..).unwrap_or(&[]))
}

fn effective_command_bin(tokens: &[String]) -> Option<String> {
    let unwrapped = unwrap_clause_slice(tokens);
    let first = unwrapped.first()?;
    Some(
        first
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(first)
            .to_ascii_lowercase(),
    )
}

fn is_env_assign(tok: &str) -> bool {
    let Some((k, _)) = tok.split_once('=') else {
        return false;
    };
    !k.is_empty() && k.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
}

pub(crate) fn extract_all_from_base64_calls_for_dialect(
    tokens: &[String],
    dialect: Option<ShellDialect>,
) -> Vec<String> {
    let mut out = extract_all_from_base64_calls(tokens);
    if dialect == Some(ShellDialect::PowerShell) && out.is_empty() {
        for (idx, tok) in tokens.iter().enumerate() {
            let low = tok.to_ascii_lowercase();
            let is_call = low == "frombase64string"
                || low.ends_with("::frombase64string")
                || low.ends_with(".frombase64string");
            if is_call && let Some(arg) = tokens.get(idx.saturating_add(1)) {
                let clean = arg
                    .trim_matches(|c| {
                        matches!(
                            c,
                            '\'' | '"' | '\u{2018}' | '\u{2019}' | '\u{201C}' | '\u{201D}'
                        )
                    })
                    .trim();
                if clean.len() >= 8
                    && clean.bytes().all(|b| {
                        b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
                    })
                {
                    out.push(clean.to_owned());
                }
            }
        }
    }
    out
}

pub(crate) fn extract_all_from_base64_calls(tokens: &[String]) -> Vec<String> {
    let joined = tokens.join(" ");
    let lower = joined.to_ascii_lowercase();
    let mut out = Vec::new();
    let mut cursor = 0usize;
    let needle = "frombase64string";
    while let Some(rel) = lower.get(cursor..).and_then(|s| s.find(needle)) {
        let after_name_idx = cursor.saturating_add(rel).saturating_add(needle.len());
        let Some(after_name) = lower.get(after_name_idx..) else {
            break;
        };
        let ws_len = after_name
            .len()
            .saturating_sub(after_name.trim_start().len());
        if !after_name.get(ws_len..).is_some_and(|s| s.starts_with('(')) {
            cursor = after_name_idx;
            continue;
        }
        let arg_start = after_name_idx.saturating_add(ws_len).saturating_add(1);
        let Some(after) = joined.get(arg_start..) else {
            break;
        };
        let Some(close_rel) = after.find(')') else {
            break;
        };
        let raw_arg = after.get(..close_rel).unwrap_or("").trim();
        let unquoted = raw_arg
            .trim_matches(|c| {
                matches!(
                    c,
                    '\'' | '"' | '\u{2018}' | '\u{2019}' | '\u{201C}' | '\u{201D}'
                )
            })
            .trim();
        out.push(unquoted.to_owned());
        cursor = arg_start.saturating_add(close_rel).saturating_add(1);
    }
    out
}

pub(crate) fn split_pipe_clauses(tokens: &[String]) -> Vec<Vec<String>> {
    let mut clauses = Vec::new();
    let mut current = Vec::new();
    for tok in tokens {
        if tok == "|" {
            if !current.is_empty() {
                clauses.push(std::mem::take(&mut current));
            }
            continue;
        }
        if tok.contains('|') && !tok.contains("||") {
            for (idx, part) in tok.split('|').enumerate() {
                if idx > 0 && !current.is_empty() {
                    clauses.push(std::mem::take(&mut current));
                }
                if !part.is_empty() {
                    current.push(part.to_owned());
                }
            }
            continue;
        }
        current.push(tok.clone());
    }
    if !current.is_empty() {
        clauses.push(current);
    }
    clauses
}

pub(crate) fn detect_base64_decode_payloads(
    clauses: &[Vec<String>],
    allow_herestring: bool,
) -> Vec<String> {
    let mut found = Vec::new();
    for (idx, clause) in clauses.iter().enumerate() {
        if !is_base64_decode_clause(clause) {
            continue;
        }
        if allow_herestring && let Some(arg) = extract_herestring_arg(clause) {
            found.push(arg);
        } else if let Some(prev) = idx.checked_sub(1).and_then(|p| clauses.get(p))
            && let Some(arg) = extract_upstream_data_arg(prev)
        {
            found.push(arg);
        }
    }
    found
}

pub(crate) fn detect_hex_decode_payloads(
    clauses: &[Vec<String>],
    allow_herestring: bool,
) -> Vec<String> {
    let mut found = Vec::new();
    for (idx, clause) in clauses.iter().enumerate() {
        if !is_xxd_reverse_clause(clause) {
            continue;
        }
        if allow_herestring && let Some(arg) = extract_herestring_arg(clause) {
            found.push(arg);
        } else if let Some(prev) = idx.checked_sub(1).and_then(|p| clauses.get(p))
            && let Some(arg) = extract_upstream_data_arg(prev)
        {
            found.push(arg);
        }
    }
    found
}

fn is_base64_decode_clause(clause: &[String]) -> bool {
    let clause = unwrap_clause_slice(clause);
    let Some(first) = clause.first() else {
        return false;
    };
    let bin = first.rsplit(['/', '\\']).next().unwrap_or(first);
    if bin.eq_ignore_ascii_case("base64") {
        return clause.iter().skip(1).any(|a| {
            a == "-d"
                || a == "--decode"
                || a == "-D"
                || (a.starts_with('-') && !a.starts_with("--") && a.contains('d'))
        });
    }
    if bin.eq_ignore_ascii_case("openssl") {
        let has_mode = clause
            .iter()
            .skip(1)
            .any(|a| a == "enc" || a == "base64" || a == "-base64" || a == "-a");
        let has_decode = clause.iter().skip(1).any(|a| a == "-d" || a == "--decode");
        return has_mode && has_decode;
    }
    false
}

fn is_xxd_reverse_clause(clause: &[String]) -> bool {
    let clause = unwrap_clause_slice(clause);
    let Some(first) = clause.first() else {
        return false;
    };
    let bin = first.rsplit(['/', '\\']).next().unwrap_or(first);
    if !bin.eq_ignore_ascii_case("xxd") {
        return false;
    }
    clause.iter().skip(1).any(|a| {
        a == "-r"
            || a == "--revert"
            || (a.starts_with('-') && !a.starts_with("--") && a.contains('r'))
    })
}

fn extract_herestring_arg(clause: &[String]) -> Option<String> {
    for (i, tok) in clause.iter().enumerate() {
        if tok == "<<<" {
            return clause
                .get(i.saturating_add(1))
                .map(|s| strip_matching_quotes(s).to_owned());
        }
        if let Some((_, rest)) = tok.split_once("<<<")
            && !rest.is_empty()
        {
            return Some(strip_matching_quotes(rest).to_owned());
        }
    }
    None
}

fn extract_upstream_data_arg(clause: &[String]) -> Option<String> {
    let clause = unwrap_clause_slice(clause);
    let bin = clause
        .first()?
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let args = clause.get(1..)?;
    match bin.as_str() {
        "echo" => {
            let mut idx = 0usize;
            while let Some(a) = args.get(idx) {
                if a == "--" {
                    idx = idx.saturating_add(1);
                    break;
                }
                if a.starts_with('-')
                    && a.len() >= 2
                    && a.bytes().skip(1).all(|b| matches!(b, b'n' | b'e' | b'E'))
                {
                    idx = idx.saturating_add(1);
                    continue;
                }
                break;
            }
            let data = args.get(idx..)?;
            if data.is_empty() {
                None
            } else {
                Some(strip_matching_quotes(&data.join(" ")).to_owned())
            }
        }
        "printf" => {
            let mut idx = 0usize;
            while args.get(idx).is_some_and(|a| a == "--") {
                idx = idx.saturating_add(1);
            }
            let fmt_tok = args.get(idx)?;
            if fmt_tok.contains('%') && args.get(idx.saturating_add(1)).is_some() {
                let data = args.get(idx.saturating_add(1)..)?;
                Some(strip_matching_quotes(&data.join(" ")).to_owned())
            } else {
                Some(strip_matching_quotes(fmt_tok).to_owned())
            }
        }
        "cat" => extract_herestring_arg(clause),
        _ => None,
    }
}

fn strip_matching_quotes(s: &str) -> &str {
    let trimmed = s.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('\'') && trimmed.ends_with('\''))
            || (trimmed.starts_with('"') && trimmed.ends_with('"')))
    {
        trimmed
            .get(1..trimmed.len().saturating_sub(1))
            .unwrap_or(trimmed)
    } else {
        trimmed
    }
}
