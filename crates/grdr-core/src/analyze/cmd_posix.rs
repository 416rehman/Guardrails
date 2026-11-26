// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! POSIX shell lexer and bounded parameter expander (`D-10`).

use std::collections::BTreeMap;

use crate::analyze::cmd_dialects::{ParsedClause, SegmentSep};
use crate::analyze::cmd_posix_ansi::{AnsiCErr, parse_ansi_c_quote, strip_line_continuations};
use crate::analyze::cmd_posix_helpers::{
    EnvOverlay, PosixWord, TildeMode, WordSyntax, finalize_posix_clause,
};
use crate::analyze::cmd_posix_word::{AssignHeadState, WordBuilder, handle_quoted_char};
use crate::analyze::types::{
    LimitKind, MalformedKind, MalformedReason, Resolution, ShellLimits, Span, UnresolvedKind,
    UnresolvedReason,
};

pub fn parse_posix(
    text: &str,
    env: &BTreeMap<String, String>,
    limits: &ShellLimits,
) -> Resolution<Vec<ParsedClause>> {
    parse_posix_with_depth(text, env, limits, 0)
}

pub fn parse_posix_with_depth(
    text: &str,
    env: &BTreeMap<String, String>,
    limits: &ShellLimits,
    base_depth: u32,
) -> Resolution<Vec<ParsedClause>> {
    let continued = match strip_line_continuations(text, limits) {
        Ok(s) => s,
        Err(r) => return Resolution::Unresolved(vec![r]),
    };

    let mut local_env = EnvOverlay::new(env);
    let mut clauses: Vec<ParsedClause> = Vec::new();
    let mut words: Vec<PosixWord> = Vec::new();
    let mut wb = WordBuilder::new();
    let mut quote: Option<char> = None;
    let mut paren_depth: u32 = 0;
    let mut just_closed_subshell = false;
    let mut total_words: u32 = 0;
    let mut expanded_total: usize = 0;
    let mut prev_sep = SegmentSep::End;
    let mut allow_assign_tilde = false;

    let chars: Vec<(usize, char)> = continued.char_indices().collect();
    let mut i: usize = 0;
    while i < chars.len() {
        let Some(&(pos, ch)) = chars.get(i) else {
            break;
        };

        if let Some(q) = quote {
            match handle_quoted_char(
                &chars,
                &mut i,
                pos,
                ch,
                q,
                &mut quote,
                &mut wb,
                &local_env,
                &words,
                &mut expanded_total,
                limits,
            ) {
                Ok(()) => continue,
                Err(res) => return res,
            }
        }

        if ch == '#' && wb.is_empty() {
            while i < chars.len() && chars.get(i).map(|c| c.1) != Some('\n') {
                i = i.saturating_add(1);
            }
            continue;
        }

        match ch {
            '\\' => {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                let Some(&(_, next_c)) = chars.get(i.saturating_add(1)) else {
                    return mal_res(
                        MalformedKind::UnexpectedEof,
                        pos,
                        pos.saturating_add(1),
                        "trailing unescaped backslash",
                    );
                };
                if let Err(r) = wb.push_escaped_char(next_c, &mut expanded_total, limits) {
                    return Resolution::Unresolved(vec![r]);
                }
                allow_assign_tilde = false;
                i = i.saturating_add(2);
            }
            '\'' | '"' => {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                wb.mark_quoted();
                allow_assign_tilde = false;
                quote = Some(ch);
                i = i.saturating_add(1);
            }
            '$' => {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                if chars.get(i.saturating_add(1)).map(|c| c.1) == Some('\'') {
                    wb.mark_quoted();
                    allow_assign_tilde = false;
                    let before_len = wb.buf.len();
                    match parse_ansi_c_quote(
                        &chars,
                        i.saturating_add(2),
                        &mut wb.buf,
                        &mut expanded_total,
                        limits,
                    ) {
                        Ok(next_i) => {
                            if wb.buf.len() > before_len {
                                wb.last_unquoted_char = None;
                            }
                            i = next_i;
                            continue;
                        }
                        Err(AnsiCErr::Malformed(mal)) => return Resolution::Malformed(mal),
                        Err(AnsiCErr::Unresolved(unr)) => return Resolution::Unresolved(vec![unr]),
                    }
                }
                let words_non_empty = !words.is_empty();
                allow_assign_tilde = false;
                match wb.expand_dollar(
                    &chars,
                    i,
                    &local_env,
                    false,
                    words_non_empty,
                    &[],
                    Some(&mut words),
                    &mut total_words,
                    &mut expanded_total,
                    limits,
                ) {
                    Ok(next_i) => i = next_i,
                    Err(res) => return res,
                }
            }
            '`' => {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                let kind = if words.is_empty() {
                    UnresolvedKind::SubstitutionInCommandPosition
                } else {
                    UnresolvedKind::SubstitutionInWord
                };
                return unr_res(
                    kind,
                    pos,
                    pos.saturating_add(1),
                    "POSIX backtick substitution",
                );
            }
            '?' | '*' | '+' | '@' | '!'
                if chars.get(i.saturating_add(1)).map(|c| c.1) == Some('(') =>
            {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                return unr_res(
                    UnresolvedKind::UnsupportedConstruct,
                    pos,
                    pos.saturating_add(2),
                    "POSIX/bash extglob pattern",
                );
            }
            '(' => {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                if wb.is_empty()
                    && words.is_empty()
                    && chars.get(i.saturating_add(1)).map(|c| c.1) == Some('(')
                {
                    return unr_res(
                        UnresolvedKind::UnsupportedConstruct,
                        pos,
                        pos.saturating_add(2),
                        "POSIX/bash arithmetic command `(( ... ))`",
                    );
                }
                if !wb.is_empty() || !words.is_empty() {
                    if chars.get(i.saturating_add(1)).map(|c| c.1) == Some(')')
                        && (words.is_empty() || (words.len() == 1 && wb.is_empty()))
                    {
                        return unr_res(
                            UnresolvedKind::UnsupportedConstruct,
                            pos,
                            pos.saturating_add(2),
                            "POSIX function definition",
                        );
                    }
                    return mal_res(
                        MalformedKind::SyntaxError,
                        pos,
                        pos.saturating_add(1),
                        "unexpected `(` in command word",
                    );
                }
                paren_depth = paren_depth.saturating_add(1);
                if base_depth.saturating_add(paren_depth) > limits.nesting_depth_max {
                    return unr_res(
                        UnresolvedKind::LimitExceeded(LimitKind::NestingDepth),
                        pos,
                        pos.saturating_add(1),
                        "POSIX subshell nesting depth exceeded",
                    );
                }
                local_env.push_subshell();
                allow_assign_tilde = false;
                i = i.saturating_add(1);
            }
            ')' => {
                if paren_depth == 0 {
                    return mal_res(
                        MalformedKind::UnmatchedDelimiter,
                        pos,
                        pos.saturating_add(1),
                        "unmatched closing `)`",
                    );
                }
                if let Err(err) = wb.flush(&mut words, &mut total_words, limits) {
                    return Resolution::Unresolved(vec![err]);
                }
                allow_assign_tilde = false;
                if words.is_empty()
                    && matches!(
                        prev_sep,
                        SegmentSep::And | SegmentSep::Or | SegmentSep::Pipe
                    )
                {
                    return mal_res(
                        MalformedKind::SyntaxError,
                        pos,
                        pos.saturating_add(1),
                        "trailing operator before closing `)` in POSIX subshell",
                    );
                }
                let had_stmt = local_env.had_stmt();
                if words.is_empty() && !had_stmt {
                    return mal_res(
                        MalformedKind::SyntaxError,
                        pos,
                        pos.saturating_add(1),
                        "empty subshell in POSIX command",
                    );
                }
                if !words.is_empty() {
                    match finalize_posix_clause(
                        &words,
                        SegmentSep::Sequence,
                        prev_sep,
                        &mut local_env,
                        &mut expanded_total,
                        limits,
                    ) {
                        Ok(clause) => clauses.push(clause),
                        Err(res) => return res,
                    }
                    words.clear();
                }
                local_env.pop_subshell();
                prev_sep = SegmentSep::Sequence;
                paren_depth = paren_depth.saturating_sub(1);
                just_closed_subshell = true;
                i = i.saturating_add(1);
            }
            '<' | '>' => {
                if chars.get(i.saturating_add(1)).map(|c| c.1) == Some('(') {
                    return unr_res(
                        UnresolvedKind::ProcessSubstitution,
                        pos,
                        pos.saturating_add(2),
                        "process substitution `<(...)` / `>(...)`",
                    );
                }
                return unr_res(
                    UnresolvedKind::UnsupportedConstruct,
                    pos,
                    pos.saturating_add(1),
                    "POSIX redirection or here-document",
                );
            }
            ';' | '\n' | '\r' | '&' | '|' => {
                if ch == ';' && chars.get(i.saturating_add(1)).map(|c| c.1) == Some(';') {
                    return mal_res(
                        MalformedKind::SyntaxError,
                        pos,
                        pos.saturating_add(2),
                        "unexpected `;;` outside case statement",
                    );
                }
                if ch == '&' && chars.get(i.saturating_add(1)).map(|c| c.1) == Some('>') {
                    return unr_res(
                        UnresolvedKind::UnsupportedConstruct,
                        pos,
                        pos.saturating_add(2),
                        "bash `&>` redirect",
                    );
                }
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
                    ('&', _) => SegmentSep::Background,
                    _ => SegmentSep::Sequence,
                };
                if let Err(err) = wb.flush(&mut words, &mut total_words, limits) {
                    return Resolution::Unresolved(vec![err]);
                }
                if words.is_empty() {
                    if just_closed_subshell {
                        if let Some(last) = clauses.last_mut() {
                            last.separator = sep;
                        }
                        just_closed_subshell = false;
                        prev_sep = sep;
                    } else if ch == ';'
                        || matches!(
                            sep,
                            SegmentSep::And
                                | SegmentSep::Or
                                | SegmentSep::Pipe
                                | SegmentSep::Background
                        )
                    {
                        return mal_res(
                            MalformedKind::SyntaxError,
                            pos,
                            pos.saturating_add(1),
                            "unexpected operator before command",
                        );
                    }
                } else {
                    just_closed_subshell = false;
                    local_env.mark_stmt();
                    match finalize_posix_clause(
                        &words,
                        sep,
                        prev_sep,
                        &mut local_env,
                        &mut expanded_total,
                        limits,
                    ) {
                        Ok(clause) => clauses.push(clause),
                        Err(res) => return res,
                    }
                    words.clear();
                    prev_sep = sep;
                }
                allow_assign_tilde = false;
                i = i.saturating_add(1);
            }
            c if c.is_ascii_whitespace() => {
                if let Err(err) = wb.flush(&mut words, &mut total_words, limits) {
                    return Resolution::Unresolved(vec![err]);
                }
                allow_assign_tilde = false;
                i = i.saturating_add(1);
            }
            '~' if !just_closed_subshell && (wb.is_empty() || allow_assign_tilde) => {
                let in_assign_rhs = wb.assign_head == AssignHeadState::SeenEqValid;
                let mode = match chars.get(i.saturating_add(1)).map(|c| c.1) {
                    None | Some('/' | ';' | '&' | '|' | '\n' | '\r') => TildeMode::Home,
                    Some(':') if in_assign_rhs => TildeMode::Home,
                    Some(c) if c.is_ascii_whitespace() => TildeMode::Home,
                    Some(_) => TildeMode::User,
                };
                if wb.tilde != TildeMode::User {
                    wb.tilde = mode;
                }
                allow_assign_tilde = false;
                if let Err(r) = wb.push_unquoted_char(ch, &mut expanded_total, limits) {
                    return Resolution::Unresolved(vec![r]);
                }
                i = i.saturating_add(1);
            }
            '*' | '?' | '[' => {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                if wb.syntax == WordSyntax::Plain {
                    wb.syntax = WordSyntax::UnquotedGlob;
                }
                allow_assign_tilde = false;
                if let Err(r) = wb.push_unquoted_char(ch, &mut expanded_total, limits) {
                    return Resolution::Unresolved(vec![r]);
                }
                i = i.saturating_add(1);
            }
            other => {
                if just_closed_subshell {
                    return post_subshell_err(pos);
                }
                let prev_assign_head = wb.assign_head;
                if let Err(r) = wb.push_unquoted_char(other, &mut expanded_total, limits) {
                    return Resolution::Unresolved(vec![r]);
                }
                let all_leading_assigns = words.iter().all(|w| w.unquoted_assign_name);
                allow_assign_tilde = all_leading_assigns
                    && wb.assign_head == AssignHeadState::SeenEqValid
                    && ((other == '=' && prev_assign_head == AssignHeadState::PlainName)
                        || other == ':');
                i = i.saturating_add(1);
            }
        }
    }

    if quote.is_some() {
        return mal_res(
            MalformedKind::UnterminatedQuote,
            0,
            text.len(),
            "unterminated quote in POSIX command",
        );
    }
    if paren_depth > 0 {
        return mal_res(
            MalformedKind::UnmatchedDelimiter,
            0,
            text.len(),
            "unclosed `(` subshell in POSIX command",
        );
    }
    if let Err(err) = wb.flush(&mut words, &mut total_words, limits) {
        return Resolution::Unresolved(vec![err]);
    }
    if words.is_empty() {
        if matches!(
            prev_sep,
            SegmentSep::And | SegmentSep::Or | SegmentSep::Pipe
        ) {
            return mal_res(
                MalformedKind::UnexpectedEof,
                0,
                text.len(),
                "trailing operator with no following command",
            );
        }
    } else {
        match finalize_posix_clause(
            &words,
            SegmentSep::End,
            prev_sep,
            &mut local_env,
            &mut expanded_total,
            limits,
        ) {
            Ok(clause) => clauses.push(clause),
            Err(res) => return res,
        }
    }
    Resolution::Resolved(clauses)
}

fn post_subshell_err(pos: usize) -> Resolution<Vec<ParsedClause>> {
    mal_res(
        MalformedKind::SyntaxError,
        pos,
        pos.saturating_add(1),
        "unexpected token after closing subshell",
    )
}

fn mal_res(
    kind: MalformedKind,
    start: usize,
    end: usize,
    detail: &str,
) -> Resolution<Vec<ParsedClause>> {
    Resolution::Malformed(MalformedReason::new(
        kind,
        Span::from_usize(start, end),
        detail,
    ))
}

fn unr_res(
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
