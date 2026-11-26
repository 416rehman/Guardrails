// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! PowerShell quoting, backtick/Unicode escape decoding, and variable lookup helpers.

use std::collections::BTreeMap;

use crate::analyze::cmd_dialects::{ParsedClause, push_checked_char, push_checked_str};
use crate::analyze::types::{
    LimitKind, MalformedKind, MalformedReason, Resolution, ShellLimits, Span, UnresolvedKind,
    UnresolvedReason, sanitize_detail_token,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum PsQuote {
    Single,
    Double,
}

pub(super) enum BacktickErr {
    Malformed(MalformedReason),
    Unresolved(UnresolvedReason),
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_ps_quoted(
    chars: &[(usize, char)],
    i: &mut usize,
    pos: usize,
    ch: char,
    q: PsQuote,
    quote: &mut Option<PsQuote>,
    current: &mut String,
    env: &BTreeMap<String, String>,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    match q {
        PsQuote::Single => {
            if is_single_quote_char(ch) {
                if chars
                    .get(i.saturating_add(1))
                    .is_some_and(|&(_, n)| is_single_quote_char(n))
                {
                    push_checked_char(current, '\'', expanded_total, limits)
                        .map_err(|r| Resolution::Unresolved(vec![r]))?;
                    *i = i.saturating_add(2);
                    return Ok(());
                }
                *quote = None;
            } else {
                push_checked_char(current, ch, expanded_total, limits)
                    .map_err(|r| Resolution::Unresolved(vec![r]))?;
            }
            *i = i.saturating_add(1);
            Ok(())
        }
        PsQuote::Double => {
            if ch == '`' {
                let (next_i, _) =
                    decode_ps_backtick(chars, *i, pos, current, expanded_total, limits).map_err(
                        |err| match err {
                            BacktickErr::Malformed(m) => Resolution::Malformed(m),
                            BacktickErr::Unresolved(u) => Resolution::Unresolved(vec![u]),
                        },
                    )?;
                *i = next_i;
                return Ok(());
            }
            if is_double_quote_char(ch) {
                if chars
                    .get(i.saturating_add(1))
                    .is_some_and(|&(_, n)| is_double_quote_char(n))
                {
                    push_checked_char(current, '"', expanded_total, limits)
                        .map_err(|r| Resolution::Unresolved(vec![r]))?;
                    *i = i.saturating_add(2);
                    return Ok(());
                }
                *quote = None;
                *i = i.saturating_add(1);
                return Ok(());
            }
            if ch == '$' {
                if chars.get(i.saturating_add(1)).map(|c| c.1) == Some('(') {
                    return Err(ps_unr(
                        UnresolvedKind::SubstitutionInWord,
                        pos,
                        pos.saturating_add(2),
                        "PowerShell subexpression `$()`",
                    ));
                }
                let next_i = expand_ps_var(chars, *i, pos, env, current, expanded_total, limits)?;
                *i = next_i;
                return Ok(());
            }
            push_checked_char(current, ch, expanded_total, limits)
                .map_err(|r| Resolution::Unresolved(vec![r]))?;
            *i = i.saturating_add(1);
            Ok(())
        }
    }
}

pub(super) fn expand_ps_var(
    chars: &[(usize, char)],
    start_idx: usize,
    pos: usize,
    env: &BTreeMap<String, String>,
    out: &mut String,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<usize, Resolution<Vec<ParsedClause>>> {
    let mut cursor = start_idx.saturating_add(1);
    let mut braced = false;
    if chars.get(cursor).map(|c| c.1) == Some('{') {
        braced = true;
        cursor = cursor.saturating_add(1);
    }
    let mut name = String::new();
    let mut closed = false;
    while let Some(&(_, c)) = chars.get(cursor) {
        if braced && c == '}' {
            closed = true;
            cursor = cursor.saturating_add(1);
            break;
        }
        if c.is_ascii_alphanumeric() || c == '_' || c == ':' {
            name.push(c);
            cursor = cursor.saturating_add(1);
        } else if braced {
            return Err(Resolution::Malformed(MalformedReason::new(
                MalformedKind::SyntaxError,
                Span::from_usize(pos, cursor),
                "unexpected character inside PowerShell `${...}` variable",
            )));
        } else {
            break;
        }
    }
    if braced {
        if !closed {
            return Err(Resolution::Malformed(MalformedReason::new(
                MalformedKind::UnexpectedEof,
                Span::from_usize(pos, cursor),
                "unterminated PowerShell `${...}` variable",
            )));
        }
        if name.is_empty() {
            return Err(Resolution::Malformed(MalformedReason::new(
                MalformedKind::SyntaxError,
                Span::from_usize(pos, cursor),
                "empty PowerShell `${...}` variable",
            )));
        }
    }
    if name.is_empty() {
        if chars
            .get(cursor)
            .is_some_and(|&(_, sig)| matches!(sig, '$' | '?' | '^'))
        {
            return Err(ps_unr(
                UnresolvedKind::UnknownVariable,
                pos,
                pos.saturating_add(2),
                "dynamic PowerShell automatic variable",
            ));
        }
        push_checked_char(out, '$', expanded_total, limits)
            .map_err(|r| Resolution::Unresolved(vec![r]))?;
        return Ok(start_idx.saturating_add(1));
    }
    if name
        .get(..4)
        .is_some_and(|p| p.eq_ignore_ascii_case("env:"))
        && let Some(env_name) = name.get(4..)
        && let Some((_, val)) = env.iter().find(|(k, _)| k.eq_ignore_ascii_case(env_name))
    {
        push_checked_str(out, val, expanded_total, limits)
            .map_err(|r| Resolution::Unresolved(vec![r]))?;
        return Ok(cursor);
    }
    if let Some((_, val)) = env.iter().find(|(k, _)| k.eq_ignore_ascii_case(&name)) {
        push_checked_str(out, val, expanded_total, limits)
            .map_err(|r| Resolution::Unresolved(vec![r]))?;
        return Ok(cursor);
    }
    let safe = sanitize_detail_token(&name, 48);
    Err(ps_unr(
        UnresolvedKind::UnknownVariable,
        pos,
        pos.saturating_add(name.len()),
        &format!("unset PowerShell variable `${safe}`"),
    ))
}

pub(super) fn decode_ps_backtick(
    chars: &[(usize, char)],
    start_idx: usize,
    pos: usize,
    out: &mut String,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<(usize, bool), BacktickErr> {
    let Some(&(_, esc)) = chars.get(start_idx.saturating_add(1)) else {
        return Err(BacktickErr::Malformed(MalformedReason::new(
            MalformedKind::UnexpectedEof,
            Span::from_usize(pos, pos.saturating_add(1)),
            "trailing PowerShell backtick",
        )));
    };
    if esc == '\n' {
        return Ok((start_idx.saturating_add(2), false));
    }
    if esc == '\r' && chars.get(start_idx.saturating_add(2)).map(|c| c.1) == Some('\n') {
        return Ok((start_idx.saturating_add(3), false));
    }
    if esc == 'u' && chars.get(start_idx.saturating_add(2)).map(|c| c.1) == Some('{') {
        return decode_ps_unicode_braced(chars, start_idx, pos, out, expanded_total, limits);
    }
    let ch = match esc {
        '0' => {
            return Err(BacktickErr::Unresolved(UnresolvedReason {
                kind: UnresolvedKind::UnsupportedConstruct,
                span: Span::from_usize(pos, pos.saturating_add(2)),
                detail: "NUL byte in PowerShell escape".into(),
            }));
        }
        'a' => '\x07',
        'b' => '\x08',
        'f' => '\x0C',
        'n' => '\n',
        'r' => '\r',
        't' => '\t',
        'v' => '\x0B',
        other => other,
    };
    push_checked_char(out, ch, expanded_total, limits).map_err(BacktickErr::Unresolved)?;
    Ok((start_idx.saturating_add(2), true))
}

fn decode_ps_unicode_braced(
    chars: &[(usize, char)],
    start_idx: usize,
    pos: usize,
    out: &mut String,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<(usize, bool), BacktickErr> {
    let mut idx = start_idx.saturating_add(3);
    let mut val: u32 = 0;
    let mut count = 0usize;
    let mut closed = false;
    while let Some(&(_, c)) = chars.get(idx) {
        if c == '}' {
            closed = true;
            idx = idx.saturating_add(1);
            break;
        }
        let Some(d) = c.to_digit(16) else {
            return Err(BacktickErr::Malformed(MalformedReason::new(
                MalformedKind::SyntaxError,
                Span::from_usize(pos, idx),
                "invalid hex digit in PowerShell `` `u{...} ``",
            )));
        };
        val = val.saturating_mul(16).saturating_add(d);
        count = count.saturating_add(1);
        if count > 6 {
            return Err(BacktickErr::Malformed(MalformedReason::new(
                MalformedKind::SyntaxError,
                Span::from_usize(pos, idx),
                "overlong PowerShell `` `u{...} `` escape",
            )));
        }
        idx = idx.saturating_add(1);
    }
    if !closed || count == 0 {
        return Err(BacktickErr::Malformed(MalformedReason::new(
            MalformedKind::SyntaxError,
            Span::from_usize(pos, idx),
            "malformed PowerShell `` `u{...} `` escape",
        )));
    }
    if val == 0 {
        return Err(BacktickErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, idx),
            detail: "NUL byte in PowerShell escape".into(),
        }));
    }
    let ch = char::from_u32(val).ok_or_else(|| {
        BacktickErr::Malformed(MalformedReason::new(
            MalformedKind::SyntaxError,
            Span::from_usize(pos, idx),
            "invalid Unicode scalar in PowerShell escape",
        ))
    })?;
    push_checked_char(out, ch, expanded_total, limits).map_err(BacktickErr::Unresolved)?;
    Ok((idx, true))
}

pub(super) fn skip_ps_block_comment(
    chars: &[(usize, char)],
    mut idx: usize,
    start_pos: usize,
) -> Result<usize, MalformedReason> {
    while idx < chars.len() {
        if chars.get(idx).map(|c| c.1) == Some('#')
            && chars.get(idx.saturating_add(1)).map(|c| c.1) == Some('>')
        {
            return Ok(idx.saturating_add(2));
        }
        idx = idx.saturating_add(1);
    }
    Err(MalformedReason::new(
        MalformedKind::UnexpectedEof,
        Span::from_usize(start_pos, chars.len()),
        "unterminated PowerShell `<# ... #>` comment",
    ))
}

pub(super) fn is_ps_comment_start(chars: &[(usize, char)], idx: usize) -> bool {
    chars.get(idx).map(|c| c.1) == Some('<')
        && chars.get(idx.saturating_add(1)).map(|c| c.1) == Some('#')
}

pub(super) fn skip_ws_and_ps_comments(
    chars: &[(usize, char)],
    mut idx: usize,
) -> Result<usize, MalformedReason> {
    loop {
        while let Some(&(_, c)) = chars.get(idx) {
            if !c.is_ascii_whitespace() {
                break;
            }
            idx = idx.saturating_add(1);
        }
        if chars.get(idx).map(|c| c.1) == Some('`') {
            if chars.get(idx.saturating_add(1)).map(|c| c.1) == Some('\n') {
                idx = idx.saturating_add(2);
                continue;
            }
            if chars.get(idx.saturating_add(1)).map(|c| c.1) == Some('\r')
                && chars.get(idx.saturating_add(2)).map(|c| c.1) == Some('\n')
            {
                idx = idx.saturating_add(3);
                continue;
            }
        }
        if is_ps_comment_start(chars, idx) {
            let start_pos = chars.get(idx).map_or(0, |c| c.0);
            idx = skip_ps_block_comment(chars, idx.saturating_add(2), start_pos)?;
            continue;
        }
        return Ok(idx);
    }
}

pub(super) fn push_ps_clause_checked(
    clauses: &mut Vec<ParsedClause>,
    argv: Vec<String>,
    separator: crate::analyze::cmd_dialects::SegmentSep,
    limits: &ShellLimits,
    span_end: usize,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    let max_clauses = usize::try_from(limits.words_max).unwrap_or(usize::MAX);
    if clauses.len() >= max_clauses {
        return Err(ps_unr(
            UnresolvedKind::LimitExceeded(LimitKind::Words),
            0,
            span_end,
            "PowerShell clause limit exceeded",
        ));
    }
    clauses.push(ParsedClause {
        argv,
        assignments: Vec::new(),
        redirects: Vec::new(),
        separator,
    });
    Ok(())
}

pub(super) fn emit_ps_paren_sub_clause(
    words: &[String],
    start: usize,
    clauses: &mut Vec<ParsedClause>,
    limits: &ShellLimits,
    span_end: usize,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    if start == 0 {
        return Ok(());
    }
    let Some(sub_slice) = words.get(start..) else {
        return Ok(());
    };
    if sub_slice.is_empty() {
        return Ok(());
    }
    push_ps_clause_checked(
        clauses,
        sub_slice.to_vec(),
        crate::analyze::cmd_dialects::SegmentSep::Sequence,
        limits,
        span_end,
    )
}

#[allow(clippy::too_many_arguments)]
pub(super) fn finalize_ps_clause_into(
    words: &mut Vec<String>,
    cmd_heads: &mut Vec<String>,
    paren_starts: &mut [usize],
    clauses: &mut Vec<ParsedClause>,
    sep: crate::analyze::cmd_dialects::SegmentSep,
    limits: &ShellLimits,
    span_end: usize,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    if words.is_empty() {
        return Ok(());
    }
    validate_ps_clause(words, cmd_heads, span_end)?;
    if let Some(&start) = paren_starts.last() {
        emit_ps_paren_sub_clause(words, start, clauses, limits, span_end)?;
    }
    push_ps_clause_checked(clauses, std::mem::take(words), sep, limits, span_end)?;
    cmd_heads.clear();
    for start in paren_starts {
        *start = 0;
    }
    Ok(())
}

pub(super) fn validate_ps_clause(
    words: &[String],
    cmd_heads: &[String],
    span_end: usize,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    for head in cmd_heads {
        let bin = head
            .rsplit(['\\', '/'])
            .next()
            .unwrap_or(head)
            .to_ascii_lowercase();
        if matches!(
            bin.as_str(),
            "iex" | "invoke-expression" | "icm" | "invoke-command"
        ) {
            return Err(ps_unr(
                UnresolvedKind::DynamicEval,
                0,
                span_end,
                "PowerShell dynamic invocation",
            ));
        }
    }
    let joined_low = words.join(" ").to_ascii_lowercase();
    let joined_compact: String = joined_low
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    if joined_compact.contains("scriptblock]::create")
        || joined_low.contains("invokecommand")
        || joined_low.contains("$executioncontext")
    {
        return Err(ps_unr(
            UnresolvedKind::DynamicEval,
            0,
            span_end,
            "PowerShell scriptblock or reflection dynamic eval",
        ));
    }
    Ok(())
}

pub(super) const fn is_single_quote_char(ch: char) -> bool {
    matches!(ch, '\'' | '\u{2018}' | '\u{2019}' | '\u{201A}' | '\u{201B}')
}

pub(super) const fn is_double_quote_char(ch: char) -> bool {
    matches!(ch, '"' | '\u{201C}' | '\u{201D}' | '\u{201E}')
}

pub(super) fn ps_unr(
    kind: UnresolvedKind,
    start: usize,
    end: usize,
    detail: &str,
) -> Resolution<Vec<ParsedClause>> {
    Resolution::Unresolved(vec![UnresolvedReason {
        kind,
        span: Span::from_usize(start, end),
        detail: detail.into(),
    }])
}
