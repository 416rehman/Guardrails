// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Helper routines for POSIX parameter expansion, word splitting, and clause finalization.

use std::collections::BTreeMap;

use crate::analyze::cmd_dialects::{
    ParsedClause, SegmentSep, flush_word, push_checked_char, push_checked_str,
};
use crate::analyze::cmd_posix_word::check_posix_command_position;
use crate::analyze::types::{
    MalformedKind, MalformedReason, Resolution, ShellLimits, Span, UnresolvedKind,
    UnresolvedReason, sanitize_detail_token,
};

const DYNAMIC_POSIX_VARS: &[&str] = &[
    "RANDOM",
    "SRANDOM",
    "SECONDS",
    "LINENO",
    "EPOCHSECONDS",
    "EPOCHREALTIME",
    "BASHPID",
    "PPID",
    "PWD",
    "OLDPWD",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WordSyntax {
    Plain,
    UnquotedGlob,
    UnquotedBrace,
    UnquotedExtglob,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum TildeMode {
    None,
    Home,
    User,
}

#[derive(Debug, Clone)]
pub(super) struct PosixWord {
    pub(super) text: String,
    pub(super) syntax: WordSyntax,
    pub(super) tilde: TildeMode,
    pub(super) unquoted_assign_name: bool,
}

pub(super) struct EnvOverlay<'a> {
    base: &'a BTreeMap<String, String>,
    frames: Vec<EnvFrame>,
}

struct EnvFrame {
    changes: BTreeMap<String, Option<String>>,
    has_stmt: bool,
}

pub(super) enum DollarErr {
    Malformed(MalformedReason),
    Unresolved(UnresolvedReason),
}

pub(super) struct DollarExpandState<'a> {
    pub(super) cur: &'a mut String,
    pub(super) word_active: &'a mut bool,
    pub(super) word_started: &'a mut bool,
    pub(super) word_syntax: &'a mut WordSyntax,
    pub(super) last_unquoted_char: &'a mut Option<char>,
    pub(super) word_split: bool,
    pub(super) prior_assigned: &'a [String],
    pub(super) words: Option<&'a mut Vec<PosixWord>>,
    pub(super) total_words: &'a mut u32,
    pub(super) expanded_total: &'a mut usize,
}

impl<'a> EnvOverlay<'a> {
    pub(super) fn new(base: &'a BTreeMap<String, String>) -> Self {
        Self {
            base,
            frames: vec![EnvFrame {
                changes: BTreeMap::new(),
                has_stmt: false,
            }],
        }
    }

    pub(super) fn get(&self, key: &str) -> Option<&str> {
        for frame in self.frames.iter().rev() {
            if let Some(val) = frame.changes.get(key) {
                return val.as_deref();
            }
        }
        self.base.get(key).map(String::as_str)
    }

    pub(super) fn contains_key(&self, key: &str) -> bool {
        self.get(key).is_some()
    }

    pub(super) fn insert(&mut self, key: String, val: String) {
        if let Some(top) = self.frames.last_mut() {
            top.changes.insert(key, Some(val));
        }
    }

    pub(super) fn remove(&mut self, key: &str) {
        if self.get(key).is_some()
            && let Some(top) = self.frames.last_mut()
        {
            top.changes.insert(key.to_owned(), None);
        }
    }

    pub(super) fn push_subshell(&mut self) {
        self.frames.push(EnvFrame {
            changes: BTreeMap::new(),
            has_stmt: false,
        });
    }

    pub(super) fn pop_subshell(&mut self) {
        if self.frames.len() > 1 {
            let _ = self.frames.pop();
        }
        if let Some(outer) = self.frames.last_mut() {
            outer.has_stmt = true;
        }
    }

    pub(super) fn had_stmt(&self) -> bool {
        self.frames.last().is_some_and(|f| f.has_stmt)
    }

    pub(super) fn mark_stmt(&mut self) {
        if let Some(top) = self.frames.last_mut() {
            top.has_stmt = true;
        }
    }
}

pub(super) fn handle_posix_dollar_into(
    chars: &[(usize, char)],
    start_idx: usize,
    env: &EnvOverlay<'_>,
    quoted: bool,
    in_arg_pos: bool,
    state: &mut DollarExpandState<'_>,
    limits: &ShellLimits,
) -> Result<usize, DollarErr> {
    *state.word_started = true;
    let start_pos = chars.get(start_idx).map_or(0, |c| c.0);
    let Some(&(_, next)) = chars.get(start_idx.saturating_add(1)) else {
        *state.word_active = true;
        push_checked_char(state.cur, '$', state.expanded_total, limits)
            .map_err(DollarErr::Unresolved)?;
        return Ok(start_idx.saturating_add(1));
    };

    if next == '(' {
        let is_arith = chars.get(start_idx.saturating_add(2)).map(|c| c.1) == Some('(');
        let kind = match (is_arith, in_arg_pos) {
            (true, false) => UnresolvedKind::ArithmeticInCommandPosition,
            (true, true) => UnresolvedKind::ArithmeticInWord,
            (false, false) => UnresolvedKind::SubstitutionInCommandPosition,
            (false, true) => UnresolvedKind::SubstitutionInWord,
        };
        return Err(DollarErr::Unresolved(UnresolvedReason {
            kind,
            span: Span::from_usize(start_pos, start_pos.saturating_add(2)),
            detail: "POSIX command/arithmetic substitution".into(),
        }));
    }

    let (name, next_idx) = extract_var_name(chars, start_idx, start_pos, next)?;
    if name == "IFS" {
        return Err(DollarErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::IfsExpansion,
            span: Span::from_usize(start_pos, start_pos.saturating_add(3)),
            detail: "`IFS` variable expansion".into(),
        }));
    }
    let safe_name = sanitize_detail_token(&name, 48);
    if state.prior_assigned.iter().any(|k| k == &name) {
        return Err(DollarErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(start_pos, start_pos.saturating_add(name.len())),
            detail: format!("same-clause assignment dependency on `{safe_name}`"),
        }));
    }
    if DYNAMIC_POSIX_VARS.contains(&name.as_str()) && !env.contains_key(&name) {
        return Err(DollarErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(start_pos, start_pos.saturating_add(name.len())),
            detail: format!("dynamic shell variable `{safe_name}` unset"),
        }));
    }
    let val = env.get(&name).ok_or_else(|| {
        DollarErr::Unresolved(UnresolvedReason {
            kind: UnresolvedKind::UnknownVariable,
            span: Span::from_usize(start_pos, start_pos.saturating_add(name.len())),
            detail: format!("unknown variable `{safe_name}`"),
        })
    })?;

    if quoted {
        if !val.is_empty() {
            *state.last_unquoted_char = None;
        }
        *state.word_active = true;
        push_checked_str(state.cur, val, state.expanded_total, limits)
            .map_err(DollarErr::Unresolved)?;
        return Ok(next_idx);
    }

    let mut prev_vc = *state.last_unquoted_char;
    for vc in val.chars() {
        if matches!(vc, ' ' | '\t' | '\n') {
            prev_vc = None;
            if state.word_split {
                flush_split_posix_word(state, limits)?;
            } else {
                *state.word_active = true;
                push_checked_char(state.cur, vc, state.expanded_total, limits)
                    .map_err(DollarErr::Unresolved)?;
            }
            continue;
        }
        *state.word_active = true;
        if vc == '(' && prev_vc.is_some_and(|p| matches!(p, '@' | '+' | '!' | '*' | '?')) {
            *state.word_syntax = WordSyntax::UnquotedExtglob;
        } else if matches!(vc, '*' | '?' | '[') && *state.word_syntax == WordSyntax::Plain {
            *state.word_syntax = WordSyntax::UnquotedGlob;
        }
        prev_vc = Some(vc);
        push_checked_char(state.cur, vc, state.expanded_total, limits)
            .map_err(DollarErr::Unresolved)?;
    }
    *state.last_unquoted_char = prev_vc;
    Ok(next_idx)
}

fn flush_split_posix_word(
    state: &mut DollarExpandState<'_>,
    limits: &ShellLimits,
) -> Result<(), DollarErr> {
    if !*state.word_active {
        return Ok(());
    }
    let mut flushed = Vec::new();
    flush_word(
        state.word_active,
        state.cur,
        &mut flushed,
        state.total_words,
        limits,
    )
    .map_err(DollarErr::Unresolved)?;
    if let Some(text) = flushed.into_iter().next()
        && let Some(words) = state.words.as_deref_mut()
    {
        words.push(PosixWord {
            text,
            syntax: *state.word_syntax,
            tilde: TildeMode::None,
            unquoted_assign_name: false,
        });
    }
    *state.word_syntax = WordSyntax::Plain;
    Ok(())
}

pub(super) fn collect_clause_assigned_vars(words: &[PosixWord]) -> Vec<String> {
    if words.first().is_none_or(|w| !w.unquoted_assign_name) {
        return Vec::new();
    }
    let mut vars = Vec::new();
    for word in words {
        if word.unquoted_assign_name
            && let Some((k, _)) = split_valid_assignment(&word.text)
        {
            vars.push(k);
        } else {
            break;
        }
    }
    vars
}

fn extract_var_name(
    chars: &[(usize, char)],
    start_idx: usize,
    start_pos: usize,
    next: char,
) -> Result<(String, usize), DollarErr> {
    if next == '{' {
        let mut cursor = start_idx.saturating_add(2);
        let mut inner = String::new();
        let mut closed = false;
        while let Some(&(_, c)) = chars.get(cursor) {
            if c == '}' {
                closed = true;
                cursor = cursor.saturating_add(1);
                break;
            }
            if !c.is_ascii_alphanumeric() && c != '_' {
                return Err(DollarErr::Unresolved(UnresolvedReason {
                    kind: UnresolvedKind::UnsupportedConstruct,
                    span: Span::from_usize(start_pos, start_pos.saturating_add(3)),
                    detail: "complex `${...}` modifier".into(),
                }));
            }
            inner.push(c);
            cursor = cursor.saturating_add(1);
        }
        if !closed {
            return Err(DollarErr::Malformed(MalformedReason::new(
                MalformedKind::UnexpectedEof,
                Span::from_usize(start_pos, cursor),
                "unterminated `${...}` parameter expansion",
            )));
        }
        let first_ok = inner
            .chars()
            .next()
            .is_some_and(|c| c.is_ascii_alphabetic() || c == '_');
        if !first_ok {
            return Err(DollarErr::Unresolved(UnresolvedReason {
                kind: UnresolvedKind::UnsupportedConstruct,
                span: Span::from_usize(start_pos, cursor),
                detail: "positional or special `${...}` expansion".into(),
            }));
        }
        return Ok((inner, cursor));
    }
    if next.is_ascii_alphabetic() || next == '_' {
        let mut cursor = start_idx.saturating_add(1);
        let mut inner = String::new();
        while let Some(&(_, c)) = chars.get(cursor) {
            if c.is_ascii_alphanumeric() || c == '_' {
                inner.push(c);
                cursor = cursor.saturating_add(1);
            } else {
                break;
            }
        }
        return Ok((inner, cursor));
    }
    Err(DollarErr::Unresolved(UnresolvedReason {
        kind: UnresolvedKind::UnknownVariable,
        span: Span::from_usize(start_pos, start_pos.saturating_add(2)),
        detail: "special or positional shell parameter".into(),
    }))
}

pub(super) fn finalize_posix_clause(
    words: &[PosixWord],
    sep: SegmentSep,
    prev_sep: SegmentSep,
    local_env: &mut EnvOverlay<'_>,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<ParsedClause, Resolution<Vec<ParsedClause>>> {
    for w in words {
        if w.syntax == WordSyntax::UnquotedExtglob {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::UnsupportedConstruct,
                span: Span::from_usize(0, w.text.len()),
                detail: "POSIX/bash extglob expression".into(),
            }]));
        }
        if w.syntax == WordSyntax::UnquotedBrace {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::UnsupportedConstruct,
                span: Span::from_usize(0, w.text.len()),
                detail: "POSIX brace expansion".into(),
            }]));
        }
        if w.tilde == TildeMode::User {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::UnsupportedConstruct,
                span: Span::from_usize(0, w.text.len()),
                detail: "tilde user expansion `~user`".into(),
            }]));
        }
    }

    let mut assignments = Vec::new();
    let mut cmd_start: usize = 0;
    for (idx, word) in words.iter().enumerate() {
        if word.unquoted_assign_name
            && let Some((k, v)) = split_valid_assignment(&word.text)
        {
            let expanded_v = if word.tilde == TildeMode::Home
                && let Some(home) = local_env.get("HOME")
            {
                let mut parts = Vec::new();
                for seg in v.split(':') {
                    if seg == "~" || seg.starts_with("~/") {
                        let rest = seg.strip_prefix('~').unwrap_or("");
                        let mut out = String::new();
                        push_checked_str(&mut out, home, expanded_total, limits)
                            .and_then(|()| push_checked_str(&mut out, rest, expanded_total, limits))
                            .map_err(|r| Resolution::Unresolved(vec![r]))?;
                        parts.push(out);
                    } else {
                        parts.push(seg.to_owned());
                    }
                }
                parts.join(":")
            } else {
                v
            };
            assignments.push((k, expanded_v));
            cmd_start = idx.saturating_add(1);
        } else {
            break;
        }
    }

    if assignments.iter().any(|(k, _)| k == "IFS") {
        return Err(Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::IfsExpansion,
            span: Span::from_usize(0, 3),
            detail: "`IFS` assignment disallowed".into(),
        }]));
    }

    let argv_words = words.get(cmd_start..).unwrap_or(&[]);
    if let Some(cmd0) = argv_words.first()
        && cmd0.syntax == WordSyntax::UnquotedGlob
    {
        return Err(Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(0, cmd0.text.len()),
            detail: "unquoted glob in command position".into(),
        }]));
    }

    let mut argv = Vec::with_capacity(argv_words.len());
    for w in argv_words {
        if w.tilde == TildeMode::Home
            && let Some(home) = local_env.get("HOME")
        {
            let rest = w.text.strip_prefix('~').unwrap_or("");
            let mut expanded = String::new();
            push_checked_str(&mut expanded, home, expanded_total, limits)
                .and_then(|()| push_checked_str(&mut expanded, rest, expanded_total, limits))
                .map_err(|r| Resolution::Unresolved(vec![r]))?;
            argv.push(expanded);
        } else {
            argv.push(w.text.clone());
        }
    }

    if argv.is_empty() {
        let unconditional = !matches!(
            prev_sep,
            SegmentSep::And | SegmentSep::Or | SegmentSep::Pipe | SegmentSep::Background
        );
        if unconditional
            && matches!(
                sep,
                SegmentSep::Sequence | SegmentSep::End | SegmentSep::And
            )
        {
            for (k, v) in &assignments {
                local_env.insert(k.clone(), v.clone());
            }
        } else {
            for (k, _) in &assignments {
                local_env.remove(k);
            }
        }
    }

    if let Some(cmd0) = argv.first() {
        check_posix_command_position(cmd0, &argv, &assignments, local_env)?;
    }

    Ok(ParsedClause {
        argv,
        assignments,
        redirects: Vec::new(),
        separator: sep,
    })
}

fn split_valid_assignment(word: &str) -> Option<(String, String)> {
    let (name, val) = word.split_once('=')?;
    let mut chars = name.chars();
    let first = chars.next()?;
    if !(first.is_ascii_alphabetic() || first == '_') {
        return None;
    }
    if chars.all(|c| c.is_ascii_alphanumeric() || c == '_') {
        Some((name.to_owned(), val.to_owned()))
    } else {
        None
    }
}
