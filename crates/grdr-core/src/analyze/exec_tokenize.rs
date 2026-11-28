// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Legacy command normalization and quote-aware decode tokenization (`D-10`).

use grdr_model::CommandParseStatus;

use crate::analyze::NormalizedCommand;
use crate::analyze::cmd::detect_shell_dialect;
use crate::analyze::decode_pipe::{
    extract_ps_encoded_arg, is_powershell_context, is_ps_stop_flag, is_ps_value_flag,
    split_pipe_clauses, unwrap_clause_slice,
};
use crate::analyze::types::ShellDialect;

pub(crate) fn normalize_command_body(raw: &str, opaque_patterns: &[String]) -> NormalizedCommand {
    let global_dialect = detect_shell_dialect(raw);
    let mut dialect = clause_dialect_from_rest(global_dialect, raw);
    let mut quote_mode: Option<char> = None;
    let mut escaped = false;
    let mut current = String::new();
    let mut segments = Vec::new();
    let mut saw_subshell = false;

    let mut chars = raw.char_indices().peekable();
    while let Some((idx, ch)) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if let Some(q) = quote_mode {
            if q == '"'
                && ((dialect == ShellDialect::Posix && ch == '\\')
                    || (dialect == ShellDialect::PowerShell && ch == '`'))
            {
                escaped = true;
                continue;
            }
            if dialect == ShellDialect::PowerShell {
                if q == '\'' && is_ps_single_quote(ch) {
                    if chars.peek().is_some_and(|&(_, p)| is_ps_single_quote(p)) {
                        let _ = chars.next();
                        current.push('\'');
                    } else {
                        quote_mode = None;
                    }
                    continue;
                }
                if q == '"' && is_ps_double_quote(ch) {
                    if chars.peek().is_some_and(|&(_, p)| is_ps_double_quote(p)) {
                        let _ = chars.next();
                        current.push('"');
                    } else {
                        quote_mode = None;
                    }
                    continue;
                }
            } else if ch == q {
                quote_mode = None;
                continue;
            }
            if q == '"'
                && ((ch == '$' && chars.peek().is_some_and(|&(_, p)| p == '('))
                    || (ch == '`' && dialect == ShellDialect::Posix))
            {
                saw_subshell = true;
            }
            current.push(ch);
            continue;
        }
        match ch {
            '\\' if dialect == ShellDialect::Posix => escaped = true,
            '`' if dialect == ShellDialect::PowerShell => escaped = true,
            '^' if dialect == ShellDialect::Cmd => escaped = true,
            '\'' | '"' => quote_mode = Some(ch),
            c if dialect == ShellDialect::PowerShell && is_ps_single_quote(c) => {
                quote_mode = Some('\'');
            }
            c if dialect == ShellDialect::PowerShell && is_ps_double_quote(c) => {
                quote_mode = Some('"');
            }
            '`' => {
                saw_subshell = true;
                current.push(ch);
            }
            '$' if chars.peek().is_some_and(|&(_, p)| p == '(') => {
                saw_subshell = true;
                current.push(ch);
            }
            ';' | '\n' | '\r' => {
                push_segment(&mut current, &mut segments);
                let next_off = idx.saturating_add(ch.len_utf8());
                dialect =
                    clause_dialect_from_rest(global_dialect, raw.get(next_off..).unwrap_or(""));
            }
            '&' => {
                let mut next_off = idx.saturating_add(1);
                if chars.peek().is_some_and(|&(_, p)| p == '&') {
                    let _ = chars.next();
                    next_off = next_off.saturating_add(1);
                }
                push_segment(&mut current, &mut segments);
                dialect =
                    clause_dialect_from_rest(global_dialect, raw.get(next_off..).unwrap_or(""));
            }
            '|' => {
                let mut next_off = idx.saturating_add(1);
                if chars.peek().is_some_and(|&(_, p)| p == '|') {
                    let _ = chars.next();
                    next_off = next_off.saturating_add(1);
                }
                push_segment(&mut current, &mut segments);
                dialect =
                    clause_dialect_from_rest(global_dialect, raw.get(next_off..).unwrap_or(""));
            }
            other => current.push(other),
        }
    }
    push_segment(&mut current, &mut segments);

    let canonical_text = if segments.is_empty() {
        collapse_ascii_ws(raw).to_ascii_lowercase()
    } else {
        segments.join(" ; ")
    };

    if quote_mode.is_some() || escaped {
        return NormalizedCommand {
            status: CommandParseStatus::Malformed,
            segments,
            canonical_text,
            opaque: true,
        };
    }

    let padded = format!(" {canonical_text} ");
    let decode_tokens = tokenize_shell_for_decode(raw);
    let canon_tokens = tokenize_shell_for_decode(&canonical_text);
    let has_opaque = saw_subshell
        || segments_have_ps_encoded_switch(&decode_tokens)
        || segments_have_ps_encoded_switch(&canon_tokens)
        || opaque_patterns
            .iter()
            .any(|pat| padded.contains(pat.as_str()) || canonical_text.contains(pat.as_str()));

    NormalizedCommand {
        status: if has_opaque {
            CommandParseStatus::Unresolved
        } else {
            CommandParseStatus::Resolved
        },
        segments,
        canonical_text,
        opaque: has_opaque,
    }
}

pub(crate) fn tokenize_shell_for_decode(raw: &str) -> Vec<String> {
    let global_dialect = detect_shell_dialect(raw);
    let mut dialect = clause_dialect_from_rest(global_dialect, raw);
    let mut quote_mode: Option<char> = None;
    let mut escaped = false;
    let mut cur = String::new();
    let mut active = false;
    let mut tokens = Vec::new();
    let mut chars = raw.char_indices().peekable();

    while let Some((idx, ch)) = chars.next() {
        if escaped {
            if !(dialect == ShellDialect::Posix && ch == '\n') {
                cur.push(ch);
                active = true;
            }
            escaped = false;
            continue;
        }
        if let Some(q) = quote_mode {
            if q == '"' && dialect == ShellDialect::Posix && ch == '\\' {
                if let Some(&(_, next_c)) = chars.peek()
                    && matches!(next_c, '$' | '`' | '"' | '\\' | '\n')
                {
                    escaped = true;
                } else {
                    cur.push(ch);
                    active = true;
                }
                continue;
            }
            if q == '"' && dialect == ShellDialect::PowerShell && ch == '`' {
                escaped = true;
                continue;
            }
            if dialect == ShellDialect::PowerShell {
                if q == '\'' && is_ps_single_quote(ch) {
                    if chars.peek().is_some_and(|&(_, p)| is_ps_single_quote(p)) {
                        let _ = chars.next();
                        cur.push('\'');
                        active = true;
                    } else {
                        quote_mode = None;
                    }
                    continue;
                }
                if q == '"' && is_ps_double_quote(ch) {
                    if chars.peek().is_some_and(|&(_, p)| is_ps_double_quote(p)) {
                        let _ = chars.next();
                        cur.push('"');
                        active = true;
                    } else {
                        quote_mode = None;
                    }
                    continue;
                }
            } else if ch == q {
                quote_mode = None;
                continue;
            }
            cur.push(ch);
            active = true;
            continue;
        }
        match ch {
            '\\' if dialect == ShellDialect::Posix => escaped = true,
            '`' if dialect == ShellDialect::PowerShell => escaped = true,
            '\'' | '"' => {
                quote_mode = Some(ch);
                active = true;
            }
            c if dialect == ShellDialect::PowerShell && is_ps_single_quote(c) => {
                quote_mode = Some('\'');
                active = true;
            }
            c if dialect == ShellDialect::PowerShell && is_ps_double_quote(c) => {
                quote_mode = Some('"');
                active = true;
            }
            ';' | '\n' | '\r' => {
                flush_decode_tok(&mut cur, &mut active, &mut tokens);
                tokens.push(";".into());
                let next_off = idx.saturating_add(ch.len_utf8());
                dialect =
                    clause_dialect_from_rest(global_dialect, raw.get(next_off..).unwrap_or(""));
            }
            '&' => {
                flush_decode_tok(&mut cur, &mut active, &mut tokens);
                let mut next_off = idx.saturating_add(1);
                if chars.peek().is_some_and(|&(_, p)| p == '&') {
                    let _ = chars.next();
                    tokens.push("&&".into());
                    next_off = next_off.saturating_add(1);
                } else {
                    tokens.push(";".into());
                }
                dialect =
                    clause_dialect_from_rest(global_dialect, raw.get(next_off..).unwrap_or(""));
            }
            '|' => {
                flush_decode_tok(&mut cur, &mut active, &mut tokens);
                let mut next_off = idx.saturating_add(1);
                if chars.peek().is_some_and(|&(_, p)| p == '|') {
                    let _ = chars.next();
                    tokens.push("||".into());
                    next_off = next_off.saturating_add(1);
                } else {
                    tokens.push("|".into());
                }
                dialect =
                    clause_dialect_from_rest(global_dialect, raw.get(next_off..).unwrap_or(""));
            }
            c if c.is_ascii_whitespace() => flush_decode_tok(&mut cur, &mut active, &mut tokens),
            other => {
                cur.push(other);
                active = true;
            }
        }
    }
    flush_decode_tok(&mut cur, &mut active, &mut tokens);
    tokens
}

fn clause_dialect_from_rest(global: ShellDialect, rest: &str) -> ShellDialect {
    if global == ShellDialect::PowerShell {
        return ShellDialect::PowerShell;
    }
    let seg_end = rest.find([';', '&', '|', '\n', '\r']).unwrap_or(rest.len());
    let seg = rest.get(..seg_end).unwrap_or(rest);
    let prefix_tokens: Vec<String> = seg
        .split_whitespace()
        .take(16)
        .map(|t| {
            t.trim_matches([
                '"', '\'', '\u{2018}', '\u{2019}', '\u{201A}', '\u{201B}', '\u{201C}', '\u{201D}',
                '\u{201E}',
            ])
            .to_owned()
        })
        .filter(|t| !t.is_empty())
        .collect();
    if is_powershell_context(&prefix_tokens, None) {
        return ShellDialect::PowerShell;
    }
    global
}

fn segments_have_ps_encoded_switch(tokens: &[String]) -> bool {
    let mut start = 0usize;
    for (idx, tok) in tokens.iter().enumerate() {
        if matches!(tok.as_str(), ";" | "&&" | "||" | "|") {
            if start < idx
                && segment_tokens_have_ps_encoded_switch(tokens.get(start..idx).unwrap_or(&[]))
            {
                return true;
            }
            start = idx.saturating_add(1);
        }
    }
    start < tokens.len()
        && segment_tokens_have_ps_encoded_switch(tokens.get(start..).unwrap_or(&[]))
}

fn segment_tokens_have_ps_encoded_switch(seg_tokens: &[String]) -> bool {
    for clause in split_pipe_clauses(seg_tokens) {
        if !is_powershell_context(&clause, None) {
            continue;
        }
        let unwrapped = unwrap_clause_slice(&clause);
        let mut idx = 1usize;
        while let Some(tok) = unwrapped.get(idx) {
            if is_ps_stop_flag(tok) {
                break;
            }
            if extract_ps_encoded_arg(unwrapped, idx).is_some() {
                return true;
            }
            if is_ps_value_flag(tok) {
                idx = idx.saturating_add(2);
                continue;
            }
            idx = idx.saturating_add(1);
        }
    }
    false
}

fn flush_decode_tok(cur: &mut String, active: &mut bool, tokens: &mut Vec<String>) {
    if *active {
        tokens.push(std::mem::take(cur));
        *active = false;
    }
}

fn is_ps_single_quote(ch: char) -> bool {
    matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
}

fn is_ps_double_quote(ch: char) -> bool {
    matches!(ch, '"' | '\u{201C}' | '\u{201D}' | '\u{201E}')
}

fn push_segment(current: &mut String, segments: &mut Vec<String>) {
    let collapsed = collapse_ascii_ws(current).to_ascii_lowercase();
    current.clear();
    if !collapsed.is_empty() {
        segments.push(collapsed);
    }
}

fn collapse_ascii_ws(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_ws = false;
    for ch in raw.trim().chars() {
        if ch.is_ascii_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    out
}
