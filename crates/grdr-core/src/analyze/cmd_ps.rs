// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! PowerShell lexer, operator tokenizer, and dynamic-eval detector (`D-10`).

use std::collections::BTreeMap;

use crate::analyze::cmd_dialects::{ParsedClause, SegmentSep, flush_word, push_checked_char};
use crate::analyze::cmd_ps_helpers::{
    BacktickErr, PsQuote, decode_ps_backtick, emit_ps_paren_sub_clause, expand_ps_var,
    finalize_ps_clause_into, handle_ps_quoted, is_double_quote_char, is_ps_comment_start,
    is_single_quote_char, ps_unr, skip_ps_block_comment, skip_ws_and_ps_comments,
};
use crate::analyze::types::{
    LimitKind, MalformedKind, MalformedReason, Resolution, ShellLimits, Span, UnresolvedKind,
};

pub fn parse_powershell(text: &str, limits: &ShellLimits) -> Resolution<Vec<ParsedClause>> {
    parse_powershell_with_env(text, &BTreeMap::new(), limits, 0)
}

pub fn parse_powershell_with_env(
    text: &str,
    env: &BTreeMap<String, String>,
    limits: &ShellLimits,
    base_depth: u32,
) -> Resolution<Vec<ParsedClause>> {
    let mut clauses = Vec::new();
    let mut words: Vec<String> = Vec::new();
    let mut cmd_heads: Vec<String> = Vec::new();
    let mut expecting_cmd_head = true;
    let mut current = String::new();
    let mut word_active = false;
    let mut quote: Option<PsQuote> = None;
    let mut paren_depth: u32 = 0;
    let mut paren_starts: Vec<usize> = Vec::new();
    let mut total_words: u32 = 0;
    let mut expanded_total: usize = 0;

    let chars: Vec<(usize, char)> = text.char_indices().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        let Some(&(pos, ch)) = chars.get(i) else {
            break;
        };

        if let Some(q) = quote {
            match handle_ps_quoted(
                &chars,
                &mut i,
                pos,
                ch,
                q,
                &mut quote,
                &mut current,
                env,
                &mut expanded_total,
                limits,
            ) {
                Ok(()) => continue,
                Err(res) => return res,
            }
        }

        if ch == '<' && chars.get(i.saturating_add(1)).map(|c| c.1) == Some('#') {
            match skip_ps_block_comment(&chars, i.saturating_add(2), pos) {
                Ok(next_i) => {
                    if let Err(res) = flush_ps_word(
                        &mut word_active,
                        &mut current,
                        &mut words,
                        &mut cmd_heads,
                        &mut expecting_cmd_head,
                        &mut total_words,
                        limits,
                    ) {
                        return res;
                    }
                    i = next_i;
                    continue;
                }
                Err(mal) => return Resolution::Malformed(mal),
            }
        }

        if ch == '#' && !word_active {
            while i < chars.len() && chars.get(i).map(|c| c.1) != Some('\n') {
                i = i.saturating_add(1);
            }
            continue;
        }

        match ch {
            '`' => {
                match decode_ps_backtick(&chars, i, pos, &mut current, &mut expanded_total, limits)
                {
                    Ok((next_i, pushed)) => {
                        if pushed {
                            word_active = true;
                        }
                        i = next_i;
                    }
                    Err(BacktickErr::Malformed(m)) => return Resolution::Malformed(m),
                    Err(BacktickErr::Unresolved(u)) => return Resolution::Unresolved(vec![u]),
                }
            }
            c if is_single_quote_char(c) => {
                word_active = true;
                quote = Some(PsQuote::Single);
                i = i.saturating_add(1);
            }
            c if is_double_quote_char(c) => {
                word_active = true;
                quote = Some(PsQuote::Double);
                i = i.saturating_add(1);
            }
            '$' => {
                if chars.get(i.saturating_add(1)).map(|c| c.1) == Some('(') {
                    return ps_unr(
                        UnresolvedKind::SubstitutionInWord,
                        pos,
                        pos.saturating_add(2),
                        "PowerShell subexpression `$()`",
                    );
                }
                match expand_ps_var(
                    &chars,
                    i,
                    pos,
                    env,
                    &mut current,
                    &mut expanded_total,
                    limits,
                ) {
                    Ok(next_i) => {
                        word_active = true;
                        i = next_i;
                    }
                    Err(res) => return res,
                }
            }
            '(' => {
                if let Err(res) = flush_ps_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    &mut cmd_heads,
                    &mut expecting_cmd_head,
                    &mut total_words,
                    limits,
                ) {
                    return res;
                }
                if is_invoke_call_before_paren(&words) {
                    return ps_unr(
                        UnresolvedKind::DynamicEval,
                        pos,
                        pos.saturating_add(1),
                        "PowerShell `.Invoke` / `.InvokeScript` dynamic eval",
                    );
                }
                paren_starts.push(words.len());
                expecting_cmd_head = true;
                paren_depth = paren_depth.saturating_add(1);
                if base_depth.saturating_add(paren_depth) > limits.nesting_depth_max {
                    return ps_unr(
                        UnresolvedKind::LimitExceeded(LimitKind::NestingDepth),
                        pos,
                        pos.saturating_add(1),
                        "PowerShell paren nesting depth exceeded",
                    );
                }
                i = i.saturating_add(1);
            }
            ')' => {
                if paren_depth == 0 {
                    return Resolution::Malformed(MalformedReason::new(
                        MalformedKind::UnmatchedDelimiter,
                        Span::from_usize(pos, pos.saturating_add(1)),
                        "unmatched closing `)` in PowerShell",
                    ));
                }
                if let Err(res) = flush_ps_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    &mut cmd_heads,
                    &mut expecting_cmd_head,
                    &mut total_words,
                    limits,
                ) {
                    return res;
                }
                if let Some(start) = paren_starts.pop()
                    && let Err(res) =
                        emit_ps_paren_sub_clause(&words, start, &mut clauses, limits, text.len())
                {
                    return res;
                }
                paren_depth = paren_depth.saturating_sub(1);
                expecting_cmd_head = false;
                i = i.saturating_add(1);
            }
            '{' | '}' => {
                return ps_unr(
                    UnresolvedKind::UnsupportedConstruct,
                    pos,
                    pos.saturating_add(1),
                    "PowerShell scriptblock `{...}`",
                );
            }
            ';' | '|' | '\n' | '\r' => {
                let sep = match (ch, chars.get(i.saturating_add(1)).map(|c| c.1)) {
                    ('|', Some('|')) => {
                        i = i.saturating_add(1);
                        SegmentSep::Or
                    }
                    ('|', _) => SegmentSep::Pipe,
                    _ => SegmentSep::Sequence,
                };
                if let Err(res) = flush_ps_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    &mut cmd_heads,
                    &mut expecting_cmd_head,
                    &mut total_words,
                    limits,
                ) {
                    return res;
                }
                if let Err(res) = finalize_ps_clause_into(
                    &mut words,
                    &mut cmd_heads,
                    &mut paren_starts,
                    &mut clauses,
                    sep,
                    limits,
                    text.len(),
                ) {
                    return res;
                }
                expecting_cmd_head = true;
                i = i.saturating_add(1);
            }
            '&' => {
                if chars.get(i.saturating_add(1)).map(|c| c.1) == Some('&') {
                    if let Err(res) = flush_ps_word(
                        &mut word_active,
                        &mut current,
                        &mut words,
                        &mut cmd_heads,
                        &mut expecting_cmd_head,
                        &mut total_words,
                        limits,
                    ) {
                        return res;
                    }
                    if let Err(res) = finalize_ps_clause_into(
                        &mut words,
                        &mut cmd_heads,
                        &mut paren_starts,
                        &mut clauses,
                        SegmentSep::And,
                        limits,
                        text.len(),
                    ) {
                        return res;
                    }
                    expecting_cmd_head = true;
                    i = i.saturating_add(2);
                    continue;
                }
                if let Err(res) = flush_ps_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    &mut cmd_heads,
                    &mut expecting_cmd_head,
                    &mut total_words,
                    limits,
                ) {
                    return res;
                }
                if words.is_empty() {
                    let next_non_ws = match skip_ws_and_ps_comments(&chars, i.saturating_add(1)) {
                        Ok(next) => next,
                        Err(mal) => return Resolution::Malformed(mal),
                    };
                    if chars
                        .get(next_non_ws)
                        .is_some_and(|&(_, c)| matches!(c, '$' | '(' | '{'))
                    {
                        return ps_unr(
                            UnresolvedKind::DynamicEval,
                            pos,
                            pos.saturating_add(1),
                            "PowerShell call operator `&` on dynamic target",
                        );
                    }
                    expecting_cmd_head = true;
                    i = i.saturating_add(1);
                } else {
                    return ps_unr(
                        UnresolvedKind::UnsupportedConstruct,
                        pos,
                        pos.saturating_add(1),
                        "PowerShell `&` background operator",
                    );
                }
            }
            '.' if !word_active
                && expecting_cmd_head
                && (is_ps_comment_start(&chars, i.saturating_add(1))
                    || chars.get(i.saturating_add(1)).is_some_and(|&(_, c)| {
                        c.is_ascii_whitespace()
                            || matches!(c, '(' | '{' | '$' | '`')
                            || is_single_quote_char(c)
                            || is_double_quote_char(c)
                    })) =>
            {
                let next_non_ws = match skip_ws_and_ps_comments(&chars, i.saturating_add(1)) {
                    Ok(next) => next,
                    Err(mal) => return Resolution::Malformed(mal),
                };
                if chars
                    .get(next_non_ws)
                    .is_some_and(|&(_, c)| matches!(c, '$' | '(' | '{' | '`'))
                {
                    return ps_unr(
                        UnresolvedKind::DynamicEval,
                        pos,
                        pos.saturating_add(1),
                        "PowerShell dot-source `.` on dynamic target",
                    );
                }
                return ps_unr(
                    UnresolvedKind::DynamicSource,
                    pos,
                    pos.saturating_add(1),
                    "PowerShell dot-sourcing",
                );
            }
            ',' => {
                if let Err(res) = flush_ps_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    &mut cmd_heads,
                    &mut expecting_cmd_head,
                    &mut total_words,
                    limits,
                ) {
                    return res;
                }
                i = i.saturating_add(1);
            }
            c if c.is_ascii_whitespace() => {
                if let Err(res) = flush_ps_word(
                    &mut word_active,
                    &mut current,
                    &mut words,
                    &mut cmd_heads,
                    &mut expecting_cmd_head,
                    &mut total_words,
                    limits,
                ) {
                    return res;
                }
                i = i.saturating_add(1);
            }
            other => {
                word_active = true;
                if let Err(r) = push_checked_char(&mut current, other, &mut expanded_total, limits)
                {
                    return Resolution::Unresolved(vec![r]);
                }
                i = i.saturating_add(1);
            }
        }
    }

    if quote.is_some() {
        return Resolution::Malformed(MalformedReason::new(
            MalformedKind::UnterminatedQuote,
            Span::from_usize(0, text.len()),
            "unterminated PowerShell string quote",
        ));
    }
    if paren_depth > 0 {
        return Resolution::Malformed(MalformedReason::new(
            MalformedKind::UnmatchedDelimiter,
            Span::from_usize(0, text.len()),
            "unclosed `(` in PowerShell command",
        ));
    }
    if let Err(res) = flush_ps_word(
        &mut word_active,
        &mut current,
        &mut words,
        &mut cmd_heads,
        &mut expecting_cmd_head,
        &mut total_words,
        limits,
    ) {
        return res;
    }
    if let Err(res) = finalize_ps_clause_into(
        &mut words,
        &mut cmd_heads,
        &mut paren_starts,
        &mut clauses,
        SegmentSep::End,
        limits,
        text.len(),
    ) {
        return res;
    }
    Resolution::Resolved(clauses)
}

fn flush_ps_word(
    word_active: &mut bool,
    current: &mut String,
    words: &mut Vec<String>,
    cmd_heads: &mut Vec<String>,
    expecting_cmd_head: &mut bool,
    total_words: &mut u32,
    limits: &ShellLimits,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    let prev_len = words.len();
    flush_word(word_active, current, words, total_words, limits)
        .map_err(|e| Resolution::Unresolved(vec![e]))?;
    if words.len() > prev_len
        && *expecting_cmd_head
        && let Some(head) = words.last()
    {
        cmd_heads.push(head.clone());
        *expecting_cmd_head = false;
    }
    Ok(())
}

fn is_invoke_call_before_paren(words: &[String]) -> bool {
    let Some(last) = words.last() else {
        return false;
    };
    let last_low = last.to_ascii_lowercase();
    if last_low.ends_with(".invoke") || last_low.ends_with(".invokescript") {
        return true;
    }
    if matches!(last_low.as_str(), "invoke" | "invokescript")
        && words.len() >= 2
        && words
            .get(words.len().saturating_sub(2))
            .is_some_and(|prev| prev.ends_with('.'))
    {
        return true;
    }
    false
}
