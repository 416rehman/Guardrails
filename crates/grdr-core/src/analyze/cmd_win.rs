// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Windows `cmd.exe` Phase-1 variable expansion and Phase-2 lexer (`D-10`).

use std::collections::BTreeMap;

use crate::analyze::cmd_dialects::{
    ParsedClause, SegmentSep, flush_word, push_checked_char, push_checked_str,
};
pub use crate::analyze::cmd_ps::{parse_powershell, parse_powershell_with_env};
use crate::analyze::cmd_win_vars::{
    ParenFrame, apply_cmd_set_mutation, effective_cmd_prev_sep, expand_cmd_phase1,
    finish_cmd_clause_scope, is_cmd_control_flow, is_cmd_exec_prefix_clause, is_plausible_var_expr,
    is_set_assignment_head, rejoin_cmd_call_tokens, resolve_cmd_var_expr, scan_delimited_var,
};
use crate::analyze::cmd_wrappers_cmd::is_cmd_exec_prefix_switch_completed;
use crate::analyze::types::{
    LimitKind, MalformedKind, MalformedReason, Resolution, ShellLimits, Span, UnresolvedKind,
    UnresolvedReason,
};

pub fn parse_cmd(
    text: &str,
    env: &BTreeMap<String, String>,
    limits: &ShellLimits,
) -> Resolution<Vec<ParsedClause>> {
    parse_cmd_with_depth(text, env, limits, 0)
}

pub fn parse_cmd_with_depth(
    text: &str,
    env: &BTreeMap<String, String>,
    limits: &ShellLimits,
    base_depth: u32,
) -> Resolution<Vec<ParsedClause>> {
    let mut local_env = env.clone();
    let mut expanded_total: usize = 0;
    let mut total_words: u32 = 0;
    let mut clauses = Vec::new();
    match parse_cmd_inner(
        text,
        &mut local_env,
        limits,
        base_depth,
        SegmentSep::End,
        SegmentSep::End,
        false,
        &mut expanded_total,
        &mut total_words,
        &mut clauses,
    ) {
        Ok(()) => Resolution::Resolved(clauses),
        Err(res) => res,
    }
}

#[allow(clippy::too_many_arguments)]
fn parse_cmd_inner(
    text: &str,
    local_env: &mut BTreeMap<String, String>,
    limits: &ShellLimits,
    base_depth: u32,
    initial_prev_sep: SegmentSep,
    final_sep: SegmentSep,
    conditional_outer: bool,
    expanded_total: &mut usize,
    total_words: &mut u32,
    clauses: &mut Vec<ParsedClause>,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    let phase1 = match expand_cmd_phase1(text, local_env, expanded_total, limits) {
        Ok(s) => s,
        Err(u) => return Err(Resolution::Unresolved(vec![u])),
    };

    let mut words: Vec<String> = Vec::new();
    let mut current = String::new();
    let mut word_active = false;
    let mut in_quotes = false;
    let mut paren_stack: Vec<ParenFrame> = Vec::new();
    let mut prev_sep = initial_prev_sep;
    let mut clause_conditional = false;
    let mut clause_pipe_entry_env: Option<BTreeMap<String, String>> = None;
    let mut clause_pipe_exit_env: Option<BTreeMap<String, String>> = None;
    let mut trailing_op_pos: Option<usize> = None;

    let chars: Vec<(usize, char)> = phase1.char_indices().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        let Some(&(pos, ch)) = chars.get(i) else {
            break;
        };

        if ch == '"' {
            if !in_quotes
                && word_active
                && is_cmd_exec_prefix_clause(&words)
                && is_cmd_exec_prefix_switch_completed(&current)
                && let Err(e) = flush_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    total_words,
                    limits,
                )
            {
                return Err(Resolution::Unresolved(vec![e]));
            }
            word_active = true;
            in_quotes = !in_quotes;
            i = i.saturating_add(1);
            continue;
        }
        if !in_quotes && ch == '^' {
            let Some(&(_, escaped_ch)) = chars.get(i.saturating_add(1)) else {
                return Err(Resolution::Malformed(MalformedReason::new(
                    MalformedKind::UnexpectedEof,
                    Span::from_usize(pos, pos.saturating_add(1)),
                    "trailing cmd.exe `^` escape",
                )));
            };
            if escaped_ch == '\n' {
                i = i.saturating_add(2);
                continue;
            }
            if escaped_ch == '\r' && chars.get(i.saturating_add(2)).map(|c| c.1) == Some('\n') {
                i = i.saturating_add(3);
                continue;
            }
            word_active = true;
            if let Err(r) = push_checked_char(&mut current, escaped_ch, expanded_total, limits) {
                return Err(Resolution::Unresolved(vec![r]));
            }
            i = i.saturating_add(2);
            continue;
        }
        if ch == '!'
            && let Some((expr, next_i)) = scan_delimited_var(&chars, i.saturating_add(1), '!')
            && is_plausible_var_expr(&expr)
        {
            let expanded =
                match resolve_cmd_var_expr(&expr, pos, local_env, '!', expanded_total, limits) {
                    Ok(s) => s,
                    Err(u) => return Err(Resolution::Unresolved(vec![u])),
                };
            word_active = true;
            if let Err(r) = push_checked_str(&mut current, &expanded, expanded_total, limits) {
                return Err(Resolution::Unresolved(vec![r]));
            }
            i = next_i;
            continue;
        }
        if !in_quotes && matches!(ch, '<' | '>') {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::UnsupportedConstruct,
                span: Span::from_usize(pos, pos.saturating_add(1)),
                detail: "cmd.exe redirection operator".into(),
            }]));
        }
        if !in_quotes && ch == '(' {
            if let Err(e) = flush_word(
                &mut word_active,
                &mut current,
                &mut words,
                total_words,
                limits,
            ) {
                return Err(Resolution::Unresolved(vec![e]));
            }
            let next_depth = u32::try_from(paren_stack.len().saturating_add(1)).unwrap_or(u32::MAX);
            if base_depth.saturating_add(next_depth) > limits.nesting_depth_max {
                return Err(Resolution::Unresolved(vec![UnresolvedReason {
                    kind: UnresolvedKind::LimitExceeded(LimitKind::NestingDepth),
                    span: Span::from_usize(pos, pos.saturating_add(1)),
                    detail: "cmd.exe paren nesting depth exceeded".into(),
                }]));
            }
            let parent_cond =
                conditional_outer || paren_stack.last().is_some_and(|f| f.conditional);
            paren_stack.push(ParenFrame {
                entry_sep: prev_sep,
                entry_env: local_env.clone(),
                conditional: parent_cond || matches!(prev_sep, SegmentSep::And | SegmentSep::Or),
            });
            prev_sep = SegmentSep::End;
            i = i.saturating_add(1);
            continue;
        }
        if !in_quotes && ch == ')' {
            let Some(frame) = paren_stack.pop() else {
                return Err(Resolution::Malformed(MalformedReason::new(
                    MalformedKind::UnmatchedDelimiter,
                    Span::from_usize(pos, pos.saturating_add(1)),
                    "unmatched closing `)` in cmd.exe",
                )));
            };
            if let Err(e) = flush_word(
                &mut word_active,
                &mut current,
                &mut words,
                total_words,
                limits,
            ) {
                return Err(Resolution::Unresolved(vec![e]));
            }
            if frame.conditional {
                clause_conditional = true;
            }
            if frame.entry_sep == SegmentSep::Pipe {
                clause_pipe_entry_env.get_or_insert_with(|| frame.entry_env.clone());
            }
            clause_pipe_exit_env = Some(frame.entry_env);
            i = i.saturating_add(1);
            continue;
        }
        if !in_quotes && matches!(ch, '&' | '|' | '\n' | '\r') {
            let is_explicit_op = matches!(ch, '&' | '|');
            let sep = match (ch, chars.get(i.saturating_add(1)).map(|c| c.1)) {
                ('&', Some('&')) => {
                    i = i.saturating_add(1);
                    SegmentSep::And
                }
                ('|', Some('|')) => {
                    i = i.saturating_add(1);
                    SegmentSep::Or
                }
                ('|', _) => SegmentSep::Pipe,
                _ => SegmentSep::Sequence,
            };
            if let Err(e) = flush_word(
                &mut word_active,
                &mut current,
                &mut words,
                total_words,
                limits,
            ) {
                return Err(Resolution::Unresolved(vec![e]));
            }
            let (eff_prev_sep, cond_scope) = effective_cmd_prev_sep(
                prev_sep,
                conditional_outer,
                &paren_stack,
                clause_conditional,
            );
            if words.is_empty() {
                if is_explicit_op {
                    return Err(Resolution::Malformed(MalformedReason::new(
                        MalformedKind::SyntaxError,
                        Span::from_usize(pos, pos.saturating_add(1)),
                        "unexpected cmd.exe operator before command",
                    )));
                }
            } else {
                push_cmd_clause(
                    &mut words,
                    eff_prev_sep,
                    sep,
                    cond_scope,
                    local_env,
                    limits,
                    base_depth,
                    expanded_total,
                    total_words,
                    clauses,
                )?;
                prev_sep = sep;
                trailing_op_pos =
                    if matches!(sep, SegmentSep::And | SegmentSep::Or | SegmentSep::Pipe) {
                        Some(pos)
                    } else {
                        None
                    };
            }
            finish_cmd_clause_scope(
                sep,
                local_env,
                &mut clause_conditional,
                &mut clause_pipe_entry_env,
                &mut clause_pipe_exit_env,
            );
            i = i.saturating_add(1);
            continue;
        }
        if !in_quotes
            && ch == '@'
            && words.iter().all(|w| w.eq_ignore_ascii_case("call"))
            && !word_active
        {
            i = i.saturating_add(1);
            continue;
        }
        if !in_quotes
            && ch == '/'
            && words.iter().all(|w| w.eq_ignore_ascii_case("call"))
            && !current.starts_with('/')
            && (current.rsplit(['/', '\\']).next().is_some_and(|b| {
                b.eq_ignore_ascii_case("cmd")
                    || b.eq_ignore_ascii_case("cmd.exe")
                    || b.eq_ignore_ascii_case("del")
                    || b.eq_ignore_ascii_case("erase")
                    || b.eq_ignore_ascii_case("rd")
                    || b.eq_ignore_ascii_case("rmdir")
            }) || (current.eq_ignore_ascii_case("set")
                && chars
                    .get(i.saturating_add(1))
                    .is_some_and(|c| matches!(c.1, 'a' | 'A' | 'p' | 'P'))))
        {
            if let Err(e) = flush_word(
                &mut word_active,
                &mut current,
                &mut words,
                total_words,
                limits,
            ) {
                return Err(Resolution::Unresolved(vec![e]));
            }
            word_active = true;
            if let Err(r) = push_checked_char(&mut current, ch, expanded_total, limits) {
                return Err(Resolution::Unresolved(vec![r]));
            }
            i = i.saturating_add(1);
            continue;
        }
        if !in_quotes && (ch.is_ascii_whitespace() || matches!(ch, ';' | ',' | '=')) {
            let keep_eq = ch == '=' && is_set_assignment_head(&words, &current);
            if !keep_eq {
                if let Err(e) = flush_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    total_words,
                    limits,
                ) {
                    return Err(Resolution::Unresolved(vec![e]));
                }
                i = i.saturating_add(1);
                continue;
            }
        }
        word_active = true;
        if let Err(r) = push_checked_char(&mut current, ch, expanded_total, limits) {
            return Err(Resolution::Unresolved(vec![r]));
        }
        i = i.saturating_add(1);
    }

    if in_quotes {
        return Err(Resolution::Malformed(MalformedReason::new(
            MalformedKind::UnterminatedQuote,
            Span::from_usize(0, text.len()),
            "unterminated quote in cmd.exe command",
        )));
    }
    if !paren_stack.is_empty() {
        return Err(Resolution::Malformed(MalformedReason::new(
            MalformedKind::UnmatchedDelimiter,
            Span::from_usize(0, text.len()),
            "unclosed `(` in cmd.exe command",
        )));
    }
    if let Err(e) = flush_word(
        &mut word_active,
        &mut current,
        &mut words,
        total_words,
        limits,
    ) {
        return Err(Resolution::Unresolved(vec![e]));
    }
    let (eff_prev_sep, cond_scope) = effective_cmd_prev_sep(
        prev_sep,
        conditional_outer,
        &paren_stack,
        clause_conditional,
    );
    if words.is_empty() {
        if let Some(op_pos) = trailing_op_pos {
            return Err(Resolution::Malformed(MalformedReason::new(
                MalformedKind::UnexpectedEof,
                Span::from_usize(op_pos, text.len()),
                "trailing cmd.exe operator with no following command",
            )));
        }
    } else {
        push_cmd_clause(
            &mut words,
            eff_prev_sep,
            final_sep,
            cond_scope,
            local_env,
            limits,
            base_depth,
            expanded_total,
            total_words,
            clauses,
        )?;
    }
    finish_cmd_clause_scope(
        final_sep,
        local_env,
        &mut clause_conditional,
        &mut clause_pipe_entry_env,
        &mut clause_pipe_exit_env,
    );
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn push_cmd_clause(
    words: &mut Vec<String>,
    prev_sep: SegmentSep,
    sep: SegmentSep,
    conditional_outer: bool,
    local_env: &mut BTreeMap<String, String>,
    limits: &ShellLimits,
    base_depth: u32,
    expanded_total: &mut usize,
    total_words: &mut u32,
    clauses: &mut Vec<ParsedClause>,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    let argv = std::mem::take(words);
    if argv.first().is_some_and(|a| is_cmd_control_flow(a)) {
        local_env.clear();
        return Err(Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(0, argv.first().map_or(0, String::len)),
            detail: "cmd.exe conditional or loop construct".into(),
        }]));
    }
    if argv.first().is_some_and(|a| a.eq_ignore_ascii_case("call")) {
        let next_depth = base_depth.saturating_add(1);
        if next_depth > limits.nesting_depth_max {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::NestingDepth),
                span: Span::from_usize(0, 4),
                detail: "cmd.exe `call` nesting depth exceeded".into(),
            }]));
        }
        let rest = argv.get(1..).unwrap_or(&[]);
        if rest.first().is_some_and(|r| r.starts_with(':')) {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::DynamicEval,
                span: Span::from_usize(0, 4),
                detail: "cmd.exe `call :label` dynamic jump".into(),
            }]));
        }
        if !rest.is_empty() {
            let rejoined = rejoin_cmd_call_tokens(rest);
            let before = clauses.len();
            let call_pipe = prev_sep == SegmentSep::Pipe || sep == SegmentSep::Pipe;
            let call_cond =
                conditional_outer || matches!(prev_sep, SegmentSep::And | SegmentSep::Or);
            let mut isolated_env;
            let child_env = if call_pipe {
                isolated_env = local_env.clone();
                &mut isolated_env
            } else {
                local_env
            };
            parse_cmd_inner(
                &rejoined,
                child_env,
                limits,
                next_depth,
                prev_sep,
                sep,
                call_cond,
                expanded_total,
                total_words,
                clauses,
            )?;
            if clauses.len() > before
                && let Some(last) = clauses.last_mut()
            {
                last.separator = sep;
            }
            return Ok(());
        }
    }
    let max_clauses = usize::try_from(limits.words_max).unwrap_or(usize::MAX);
    if clauses.len() >= max_clauses {
        return Err(Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::LimitExceeded(LimitKind::Words),
            span: Span::from_usize(0, 0),
            detail: "cmd.exe clause limit exceeded".into(),
        }]));
    }
    apply_cmd_set_mutation(&argv, prev_sep, sep, local_env);
    clauses.push(ParsedClause {
        argv,
        assignments: Vec::new(),
        redirects: Vec::new(),
        separator: sep,
    });
    Ok(())
}
