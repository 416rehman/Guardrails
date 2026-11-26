// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Shared clause types and bounded word-expansion helpers for shell dialect parsers (`D-10`).

use std::collections::BTreeMap;
use std::fmt;

use grdr_model::DataClass;

use crate::analyze::cmd_posix::parse_posix_with_depth;
use crate::analyze::cmd_ps::parse_powershell_with_env;
use crate::analyze::cmd_win::parse_cmd_with_depth;
use crate::analyze::types::{
    LimitKind, Resolution, ShellDialect, ShellLimits, Span, UnresolvedKind, UnresolvedReason,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SegmentSep {
    End,
    Sequence,
    And,
    Or,
    Pipe,
    Background,
}

#[derive(Clone, PartialEq, Eq)]
pub struct ParsedClause {
    pub argv: Vec<String>,
    pub assignments: Vec<(String, String)>,
    pub redirects: Vec<String>,
    pub separator: SegmentSep,
}

impl fmt::Debug for ParsedClause {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("ParsedClause")
            .field("argv_count", &self.argv.len())
            .field("assignments_count", &self.assignments.len())
            .field("redirects_count", &self.redirects.len())
            .field("separator", &self.separator)
            .finish()
    }
}

impl ParsedClause {
    #[must_use]
    pub const fn data_class() -> DataClass {
        DataClass::Content
    }
}

pub fn parse_dialect_clauses(
    text: &str,
    dialect: ShellDialect,
    env: &BTreeMap<String, String>,
    limits: &ShellLimits,
) -> Resolution<Vec<ParsedClause>> {
    parse_dialect_clauses_with_depth(text, dialect, env, limits, 0)
}

pub fn parse_dialect_clauses_with_depth(
    text: &str,
    dialect: ShellDialect,
    env: &BTreeMap<String, String>,
    limits: &ShellLimits,
    base_depth: u32,
) -> Resolution<Vec<ParsedClause>> {
    match dialect {
        ShellDialect::Posix => parse_posix_with_depth(text, env, limits, base_depth),
        ShellDialect::PowerShell => parse_powershell_with_env(text, env, limits, base_depth),
        ShellDialect::Cmd => parse_cmd_with_depth(text, env, limits, base_depth),
    }
}

pub fn push_checked_char(
    buf: &mut String,
    ch: char,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<(), UnresolvedReason> {
    let add = ch.len_utf8();
    let max = usize::try_from(limits.expanded_max).unwrap_or(usize::MAX);
    if expanded_total.saturating_add(add) > max {
        return Err(UnresolvedReason {
            kind: UnresolvedKind::LimitExceeded(LimitKind::ExpandedBytes),
            span: Span::from_usize(0, *expanded_total),
            detail: "expanded command byte budget exceeded".into(),
        });
    }
    *expanded_total = expanded_total.saturating_add(add);
    buf.push(ch);
    Ok(())
}

pub fn push_checked_str(
    buf: &mut String,
    slice: &str,
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<(), UnresolvedReason> {
    let max = usize::try_from(limits.expanded_max).unwrap_or(usize::MAX);
    if expanded_total.saturating_add(slice.len()) > max {
        return Err(UnresolvedReason {
            kind: UnresolvedKind::LimitExceeded(LimitKind::ExpandedBytes),
            span: Span::from_usize(0, *expanded_total),
            detail: "expanded command byte budget exceeded".into(),
        });
    }
    *expanded_total = expanded_total.saturating_add(slice.len());
    buf.push_str(slice);
    Ok(())
}

pub fn flush_word(
    word_active: &mut bool,
    current: &mut String,
    words: &mut Vec<String>,
    total_words: &mut u32,
    limits: &ShellLimits,
) -> Result<(), UnresolvedReason> {
    if *word_active {
        *total_words = total_words.saturating_add(1);
        if *total_words > limits.words_max {
            return Err(UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::Words),
                span: Span::from_usize(0, 0),
                detail: "command word limit exceeded".into(),
            });
        }
        words.push(std::mem::take(current));
        *word_active = false;
    }
    Ok(())
}
