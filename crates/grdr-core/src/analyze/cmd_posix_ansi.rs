// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! POSIX line-continuation pre-pass and ANSI-C `$'...'` escape decoder (`D-10`).

use crate::analyze::cmd_dialects::push_checked_char;
use crate::analyze::types::{
    MalformedKind, MalformedReason, ShellLimits, Span, UnresolvedKind, UnresolvedReason,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ContPassState {
    Normal,
    SingleQuote,
    AnsiCQuote,
    DoubleQuote,
    Comment,
}

pub(super) enum AnsiCErr {
    Malformed(MalformedReason),
    Unresolved(UnresolvedReason),
}

pub(super) fn strip_line_continuations(
    text: &str,
    limits: &ShellLimits,
) -> Result<String, UnresolvedReason> {
    let mut out = String::with_capacity(text.len());
    let mut state = ContPassState::Normal;
    let mut prev_ws = true;
    let mut expanded: usize = 0;
    let chars: Vec<char> = text.chars().collect();
    let mut idx = 0usize;

    while idx < chars.len() {
        let Some(&ch) = chars.get(idx) else {
            break;
        };
        let next = chars.get(idx.saturating_add(1)).copied();
        let next2 = chars.get(idx.saturating_add(2)).copied();

        match state {
            ContPassState::Comment => {
                push_checked_char(&mut out, ch, &mut expanded, limits)?;
                if ch == '\n' {
                    state = ContPassState::Normal;
                    prev_ws = true;
                }
                idx = idx.saturating_add(1);
            }
            ContPassState::SingleQuote => {
                push_checked_char(&mut out, ch, &mut expanded, limits)?;
                if ch == '\'' {
                    state = ContPassState::Normal;
                    prev_ws = false;
                }
                idx = idx.saturating_add(1);
            }
            ContPassState::AnsiCQuote => {
                push_checked_char(&mut out, ch, &mut expanded, limits)?;
                if ch == '\\'
                    && let Some(n) = next
                {
                    push_checked_char(&mut out, n, &mut expanded, limits)?;
                    idx = idx.saturating_add(2);
                    continue;
                }
                if ch == '\'' {
                    state = ContPassState::Normal;
                    prev_ws = false;
                }
                idx = idx.saturating_add(1);
            }
            ContPassState::DoubleQuote => {
                if ch == '\\' && next == Some('\n') {
                    idx = idx.saturating_add(2);
                    continue;
                }
                if ch == '\\' && next == Some('\r') && next2 == Some('\n') {
                    idx = idx.saturating_add(3);
                    continue;
                }
                push_checked_char(&mut out, ch, &mut expanded, limits)?;
                if ch == '\\'
                    && let Some(n) = next
                {
                    push_checked_char(&mut out, n, &mut expanded, limits)?;
                    idx = idx.saturating_add(2);
                    continue;
                }
                if ch == '"' {
                    state = ContPassState::Normal;
                    prev_ws = false;
                }
                idx = idx.saturating_add(1);
            }
            ContPassState::Normal => {
                if ch == '\\' && next == Some('\n') {
                    idx = idx.saturating_add(2);
                    continue;
                }
                if ch == '\\' && next == Some('\r') && next2 == Some('\n') {
                    idx = idx.saturating_add(3);
                    continue;
                }
                if ch == '\\'
                    && let Some(n) = next
                {
                    push_checked_char(&mut out, ch, &mut expanded, limits)?;
                    push_checked_char(&mut out, n, &mut expanded, limits)?;
                    prev_ws = false;
                    idx = idx.saturating_add(2);
                    continue;
                }
                if ch == '#' && prev_ws {
                    push_checked_char(&mut out, ch, &mut expanded, limits)?;
                    state = ContPassState::Comment;
                    idx = idx.saturating_add(1);
                    continue;
                }
                if ch == '$' && next == Some('\'') {
                    push_checked_char(&mut out, '$', &mut expanded, limits)?;
                    push_checked_char(&mut out, '\'', &mut expanded, limits)?;
                    state = ContPassState::AnsiCQuote;
                    idx = idx.saturating_add(2);
                    continue;
                }
                push_checked_char(&mut out, ch, &mut expanded, limits)?;
                if ch == '\'' {
                    state = ContPassState::SingleQuote;
                } else if ch == '"' {
                    state = ContPassState::DoubleQuote;
                }
                prev_ws = ch.is_ascii_whitespace() || matches!(ch, ';' | '&' | '|' | '(' | ')');
                idx = idx.saturating_add(1);
            }
        }
    }
    Ok(out)
}

pub(super) fn parse_ansi_c_quote(
    chars: &[(usize, char)],
    start_idx: usize,
    out: &mut String,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<usize, AnsiCErr> {
    let mut i = start_idx;
    while let Some(&(pos, c)) = chars.get(i) {
        if c == '\'' {
            return Ok(i.saturating_add(1));
        }
        if c == '\\' {
            let Some(&(_, esc)) = chars.get(i.saturating_add(1)) else {
                return Err(AnsiCErr::Malformed(MalformedReason::new(
                    MalformedKind::UnterminatedQuote,
                    Span::from_usize(pos, pos.saturating_add(1)),
                    "unterminated `$'...'` escape",
                )));
            };
            i = i.saturating_add(2);
            match esc {
                'a' => push_c(out, '\x07', expanded_total, limits)?,
                'b' => push_c(out, '\x08', expanded_total, limits)?,
                'e' | 'E' => push_c(out, '\x1B', expanded_total, limits)?,
                'f' => push_c(out, '\x0C', expanded_total, limits)?,
                'n' => push_c(out, '\n', expanded_total, limits)?,
                'r' => push_c(out, '\r', expanded_total, limits)?,
                't' => push_c(out, '\t', expanded_total, limits)?,
                'v' => push_c(out, '\x0B', expanded_total, limits)?,
                '\\' | '\'' | '"' | '?' => push_c(out, esc, expanded_total, limits)?,
                'x' => {
                    let (ch, next_i) = decode_ansi_hex(chars, i, 2, pos, true)?;
                    push_c(out, ch, expanded_total, limits)?;
                    i = next_i;
                }
                'u' => {
                    let (ch, next_i) = decode_ansi_hex(chars, i, 4, pos, false)?;
                    push_c(out, ch, expanded_total, limits)?;
                    i = next_i;
                }
                'U' => {
                    let (ch, next_i) = decode_ansi_hex(chars, i, 8, pos, false)?;
                    push_c(out, ch, expanded_total, limits)?;
                    i = next_i;
                }
                '0'..='7' => {
                    let (ch, next_i) = decode_ansi_octal(chars, i.saturating_sub(1), pos)?;
                    push_c(out, ch, expanded_total, limits)?;
                    i = next_i;
                }
                'c' => {
                    let ch = decode_ansi_ctrl(chars, &mut i, pos)?;
                    push_c(out, ch, expanded_total, limits)?;
                }
                other => {
                    push_c(out, '\\', expanded_total, limits)?;
                    push_c(out, other, expanded_total, limits)?;
                }
            }
            continue;
        }
        push_c(out, c, expanded_total, limits)?;
        i = i.saturating_add(1);
    }
    Err(AnsiCErr::Malformed(MalformedReason::new(
        MalformedKind::UnterminatedQuote,
        Span::from_usize(start_idx, chars.len()),
        "unterminated `$'...'` literal",
    )))
}

fn push_c(
    out: &mut String,
    ch: char,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<(), AnsiCErr> {
    push_checked_char(out, ch, expanded_total, limits).map_err(AnsiCErr::Unresolved)
}

fn decode_ansi_ctrl(chars: &[(usize, char)], i: &mut usize, pos: usize) -> Result<char, AnsiCErr> {
    let Some(&(_, ctl)) = chars.get(*i) else {
        return Err(AnsiCErr::Malformed(MalformedReason::new(
            MalformedKind::UnterminatedQuote,
            Span::from_usize(pos, *i),
            "unterminated `$'\\c'` escape",
        )));
    };
    *i = i.saturating_add(1);
    let code = if ctl == '?' {
        0x7F_u8
    } else if ctl.is_ascii() {
        u8::try_from(ctl.to_ascii_uppercase()).unwrap_or(0) & 0x1F
    } else {
        return Err(AnsiCErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, *i),
            detail: "non-ASCII `$'\\c'` escape".into(),
        }));
    };
    if code == 0 {
        return Err(AnsiCErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, *i),
            detail: "NUL byte in `$'...'` escape".into(),
        }));
    }
    Ok(char::from(code))
}

fn decode_ansi_hex(
    chars: &[(usize, char)],
    start_idx: usize,
    max_digits: usize,
    pos: usize,
    byte_mode: bool,
) -> Result<(char, usize), AnsiCErr> {
    let mut val: u32 = 0;
    let mut count = 0usize;
    let mut idx = start_idx;
    while count < max_digits
        && let Some(&(_, c)) = chars.get(idx)
        && let Some(d) = c.to_digit(16)
    {
        val = val.saturating_mul(16).saturating_add(d);
        count = count.saturating_add(1);
        idx = idx.saturating_add(1);
    }
    if count == 0 {
        return Err(AnsiCErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, idx),
            detail: "empty hex escape in `$'...'`".into(),
        }));
    }
    if val == 0 {
        return Err(AnsiCErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, idx),
            detail: "NUL byte in `$'...'` escape".into(),
        }));
    }
    if byte_mode && val > 0x7F {
        return Err(AnsiCErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, idx),
            detail: "non-UTF-8 byte in `$'\\xHH'` escape".into(),
        }));
    }
    let ch = char::from_u32(val).ok_or_else(|| {
        AnsiCErr::Malformed(MalformedReason::new(
            MalformedKind::SyntaxError,
            Span::from_usize(pos, idx),
            "invalid Unicode scalar in `$'...'`",
        ))
    })?;
    Ok((ch, idx))
}

fn decode_ansi_octal(
    chars: &[(usize, char)],
    start_idx: usize,
    pos: usize,
) -> Result<(char, usize), AnsiCErr> {
    let mut val: u32 = 0;
    let mut count = 0usize;
    let mut idx = start_idx;
    while count < 3
        && let Some(&(_, c)) = chars.get(idx)
        && ('0'..='7').contains(&c)
    {
        val = val
            .saturating_mul(8)
            .saturating_add(c.to_digit(8).unwrap_or(0));
        count = count.saturating_add(1);
        idx = idx.saturating_add(1);
    }
    let byte_val = val & 0xFF;
    if byte_val == 0 {
        return Err(AnsiCErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, idx),
            detail: "NUL octal byte in `$'...'`".into(),
        }));
    }
    if byte_val > 0x7F {
        return Err(AnsiCErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(pos, idx),
            detail: "non-UTF-8 octal byte in `$'...'`".into(),
        }));
    }
    let ch = char::from_u32(byte_val).ok_or_else(|| {
        AnsiCErr::Malformed(MalformedReason::new(
            MalformedKind::SyntaxError,
            Span::from_usize(pos, idx),
            "invalid octal escape",
        ))
    })?;
    Ok((ch, idx))
}
