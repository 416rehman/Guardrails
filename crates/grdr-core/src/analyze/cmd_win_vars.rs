// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Windows `cmd.exe` Phase-1 variable expansion, bounded replacement, and `set` mutation tracking.

use std::collections::BTreeMap;

use crate::analyze::cmd_dialects::{SegmentSep, push_checked_char, push_checked_str};
use crate::analyze::cmd_wrappers_cmd::is_cmd_pre_switch;
use crate::analyze::types::{
    LimitKind, ShellLimits, Span, UnresolvedKind, UnresolvedReason, sanitize_detail_token,
};

#[derive(Clone)]
pub(super) struct ParenFrame {
    pub(super) entry_sep: SegmentSep,
    pub(super) entry_env: BTreeMap<String, String>,
    pub(super) conditional: bool,
}

pub(super) fn is_set_cmd_token(tok: &str) -> bool {
    let t = tok.trim_start_matches(['@', '&', '|', '(']);
    t.eq_ignore_ascii_case("set") || t.get(..4).is_some_and(|p| p.eq_ignore_ascii_case("set/"))
}

pub(super) fn is_set_assignment_head(words: &[String], current: &str) -> bool {
    let sub_words = if words
        .first()
        .is_some_and(|w| w.eq_ignore_ascii_case("call"))
    {
        words
            .iter()
            .rposition(|w| matches!(w.as_str(), "&" | "&&" | "|" | "||"))
            .map_or(words, |idx| {
                words.get(idx.saturating_add(1)..).unwrap_or(&[])
            })
    } else {
        words
    };
    match sub_words.iter().find(|w| !w.eq_ignore_ascii_case("call")) {
        Some(w) => is_set_cmd_token(w),
        None => is_set_cmd_token(current),
    }
}

pub(super) fn effective_cmd_prev_sep(
    prev_sep: SegmentSep,
    conditional_outer: bool,
    paren_stack: &[ParenFrame],
    clause_conditional: bool,
) -> (SegmentSep, bool) {
    let cond = conditional_outer || paren_stack.iter().any(|f| f.conditional) || clause_conditional;
    let eff = if cond { SegmentSep::And } else { prev_sep };
    (eff, cond)
}

pub(super) fn finish_cmd_clause_scope(
    sep: SegmentSep,
    local_env: &mut BTreeMap<String, String>,
    clause_conditional: &mut bool,
    clause_pipe_entry_env: &mut Option<BTreeMap<String, String>>,
    clause_pipe_exit_env: &mut Option<BTreeMap<String, String>>,
) {
    if sep == SegmentSep::Pipe
        && let Some(saved) = clause_pipe_exit_env.take()
    {
        *local_env = saved;
    }
    *clause_pipe_exit_env = None;
    if let Some(saved) = clause_pipe_entry_env.take() {
        *local_env = saved;
    }
    *clause_conditional = false;
}

pub(super) fn expand_cmd_phase1(
    text: &str,
    env: &BTreeMap<String, String>,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<String, UnresolvedReason> {
    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut out = String::with_capacity(text.len());
    let mut i = 0usize;

    while let Some(&(pos, ch)) = chars.get(i) {
        if ch == '%' {
            if chars.get(i.saturating_add(1)).map(|c| c.1) == Some('%') {
                push_checked_char(&mut out, '%', expanded_total, limits)?;
                i = i.saturating_add(2);
                continue;
            }
            if let Some((expr, next_i)) = scan_delimited_var(&chars, i.saturating_add(1), '%')
                && !expr.contains('^')
            {
                let expanded = resolve_cmd_var_expr(&expr, pos, env, '%', expanded_total, limits)?;
                push_checked_str(&mut out, &expanded, expanded_total, limits)?;
                i = next_i;
                continue;
            }
            if let Some(&(_, next_ch)) = chars.get(i.saturating_add(1))
                && (next_ch.is_ascii_digit() || next_ch == '*' || next_ch == '~')
            {
                return Err(UnresolvedReason {
                    kind: UnresolvedKind::UnknownVariable,
                    span: Span::from_usize(pos, pos.saturating_add(2)),
                    detail: "cmd.exe batch positional parameter".into(),
                });
            }
        }
        push_checked_char(&mut out, ch, expanded_total, limits)?;
        i = i.saturating_add(1);
    }
    Ok(out)
}

pub(super) fn scan_delimited_var(
    chars: &[(usize, char)],
    start: usize,
    delim: char,
) -> Option<(String, usize)> {
    let mut idx = start;
    let mut buf = String::new();
    while let Some(&(_, c)) = chars.get(idx) {
        if c == '\n' || c == '\r' {
            return None;
        }
        if c == delim {
            if buf.is_empty() {
                return None;
            }
            return Some((buf, idx.saturating_add(1)));
        }
        buf.push(c);
        idx = idx.saturating_add(1);
    }
    None
}

pub(super) fn is_plausible_var_expr(expr: &str) -> bool {
    let name = expr.split_once(':').map_or(expr, |(n, _)| n);
    !name.is_empty()
        && !name.chars().any(char::is_whitespace)
        && name
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
}

pub(super) fn resolve_cmd_var_expr(
    expr: &str,
    pos: usize,
    env: &BTreeMap<String, String>,
    delim: char,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<String, UnresolvedReason> {
    let (var_name, modifier) = match expr.split_once(':') {
        Some((n, m)) => (n, Some(m)),
        None => (expr, None),
    };
    let safe = sanitize_detail_token(var_name, 48);
    let Some((_, raw_val)) = env.iter().find(|(k, _)| k.eq_ignore_ascii_case(var_name)) else {
        return Err(UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(pos, pos.saturating_add(expr.len())),
            detail: format!("unset cmd.exe variable `{delim}{safe}{delim}`"),
        });
    };
    let Some(mod_spec) = modifier else {
        return Ok(raw_val.clone());
    };
    if let Some((old, new)) = mod_spec.split_once('=')
        && !old.is_empty()
        && !mod_spec.starts_with('~')
        && !mod_spec.starts_with('*')
    {
        let remaining_max = usize::try_from(limits.expanded_max)
            .unwrap_or(usize::MAX)
            .saturating_sub(*expanded_total);
        return case_insensitive_replace(raw_val, old, new, remaining_max).map_err(|()| {
            UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::ExpandedBytes),
                span: Span::from_usize(pos, pos.saturating_add(expr.len())),
                detail: "expanded cmd.exe modifier exceeds budget".into(),
            }
        });
    }
    Err(UnresolvedReason {
        kind: UnresolvedKind::UnknownVariable,
        span: Span::from_usize(pos, pos.saturating_add(expr.len())),
        detail: format!("complex cmd.exe modifier on `{delim}{safe}{delim}`"),
    })
}

pub(super) fn apply_cmd_set_mutation(
    argv: &[String],
    prev_sep: SegmentSep,
    sep: SegmentSep,
    local_env: &mut BTreeMap<String, String>,
) {
    let Some(cmd0) = argv.first() else {
        return;
    };
    let (switch_opt, rest_idx): (Option<&str>, usize) = if cmd0.eq_ignore_ascii_case("set") {
        (argv.get(1).map(String::as_str), 2)
    } else if cmd0
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("set/"))
    {
        (cmd0.get(3..), 1)
    } else {
        return;
    };
    let Some(sw) = switch_opt else {
        return;
    };
    let sw_low = sw.to_ascii_lowercase();
    if let Some(after_a) = sw_low.strip_prefix("/a") {
        let attached = sw
            .get(2..)
            .unwrap_or("")
            .strip_prefix(':')
            .unwrap_or_else(|| sw.get(2..).unwrap_or(""));
        let _ = after_a;
        let mut expr = String::new();
        if !attached.is_empty() {
            expr.push_str(attached);
        }
        for extra in argv.get(rest_idx..).unwrap_or(&[]) {
            if !expr.is_empty() {
                expr.push(' ');
            }
            expr.push_str(extra);
        }
        invalidate_set_a_targets(&expr, local_env);
        return;
    }
    if sw_low.starts_with("/p") {
        let attached = sw
            .get(2..)
            .unwrap_or("")
            .strip_prefix(':')
            .unwrap_or_else(|| sw.get(2..).unwrap_or(""))
            .trim();
        let target_tok = if !attached.is_empty() {
            Some(attached)
        } else {
            argv.get(rest_idx).map(|s| s.as_str())
        };
        if let Some(rhs) = target_tok {
            let var_name = rhs.split_once('=').map_or(rhs, |(k, _)| k).trim();
            if !var_name.is_empty() {
                remove_env_case_insensitive(local_env, var_name);
            }
        }
        return;
    }
    if rest_idx != 2 {
        return;
    }
    let Some((var_name, first_val)) = sw.split_once('=') else {
        return;
    };
    if var_name.is_empty() {
        return;
    }
    let mut val = first_val.to_owned();
    for extra in argv.get(2..).unwrap_or(&[]) {
        val.push(' ');
        val.push_str(extra);
    }
    if matches!(prev_sep, SegmentSep::Pipe) || sep == SegmentSep::Pipe {
        return;
    }
    remove_env_case_insensitive(local_env, var_name);
    if !val.is_empty() && !matches!(prev_sep, SegmentSep::And | SegmentSep::Or) {
        local_env.insert(var_name.to_owned(), val);
    }
}

fn invalidate_set_a_targets(expr: &str, local_env: &mut BTreeMap<String, String>) {
    for (eq_idx, _) in expr.match_indices('=') {
        let mut lhs = expr.get(..eq_idx).unwrap_or("").trim_end();
        if lhs.ends_with("<<") || lhs.ends_with(">>") {
            lhs = lhs.get(..lhs.len().saturating_sub(2)).unwrap_or("");
        } else if lhs.ends_with(['+', '-', '*', '/', '%', '&', '|', '^']) {
            lhs = lhs.get(..lhs.len().saturating_sub(1)).unwrap_or("");
        }
        let lhs = lhs.trim_end();
        let var_start = lhs
            .rfind(|c: char| !c.is_ascii_alphanumeric() && c != '_')
            .map_or(0, |idx| idx.saturating_add(1));
        if let Some(var_name) = lhs.get(var_start..)
            && !var_name.is_empty()
        {
            remove_env_case_insensitive(local_env, var_name);
        }
    }
}

fn remove_env_case_insensitive(env: &mut BTreeMap<String, String>, var_name: &str) {
    let keys: Vec<String> = env
        .keys()
        .filter(|k| k.eq_ignore_ascii_case(var_name))
        .cloned()
        .collect();
    for k in keys {
        env.remove(&k);
    }
}

fn case_insensitive_replace(
    haystack: &str,
    needle: &str,
    replacement: &str,
    remaining_max: usize,
) -> Result<String, ()> {
    let h_low = haystack.to_ascii_lowercase();
    let n_low = needle.to_ascii_lowercase();
    if n_low.is_empty() || h_low.len() != haystack.len() {
        if haystack.len() > remaining_max {
            return Err(());
        }
        return Ok(haystack.to_owned());
    }
    let mut out = String::with_capacity(haystack.len().min(remaining_max));
    let mut cursor = 0usize;
    while let Some(rel) = h_low.get(cursor..).and_then(|s| s.find(&n_low)) {
        let start = cursor.saturating_add(rel);
        let prefix = haystack.get(cursor..start).ok_or(())?;
        let next_len = out
            .len()
            .saturating_add(prefix.len())
            .saturating_add(replacement.len());
        if next_len > remaining_max {
            return Err(());
        }
        out.push_str(prefix);
        out.push_str(replacement);
        cursor = start.saturating_add(needle.len());
    }
    let tail = haystack.get(cursor..).ok_or(())?;
    if out.len().saturating_add(tail.len()) > remaining_max {
        return Err(());
    }
    out.push_str(tail);
    Ok(out)
}

pub(super) fn is_cmd_control_flow(cmd0: &str) -> bool {
    cmd0.eq_ignore_ascii_case("if")
        || cmd0.eq_ignore_ascii_case("for")
        || cmd0.get(..3).is_some_and(|p| p.eq_ignore_ascii_case("if/"))
        || cmd0
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case("for/"))
}

pub(super) fn rejoin_cmd_call_tokens(tokens: &[String]) -> String {
    tokens
        .iter()
        .map(|tok| {
            if tok.chars().any(char::is_whitespace) && !tok.contains('^') && !tok.contains('"') {
                format!("\"{tok}\"")
            } else {
                tok.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

pub(super) fn is_cmd_exec_prefix_clause(words: &[String]) -> bool {
    let start = words
        .iter()
        .position(|w| !w.eq_ignore_ascii_case("call"))
        .unwrap_or(words.len());
    let Some(head) = words.get(start) else {
        return false;
    };
    let bin = head.rsplit(['/', '\\']).next().unwrap_or(head);
    if !bin.eq_ignore_ascii_case("cmd") && !bin.eq_ignore_ascii_case("cmd.exe") {
        return false;
    }
    words
        .get(start.saturating_add(1)..)
        .unwrap_or(&[])
        .iter()
        .all(|w| is_cmd_pre_switch(w))
}
