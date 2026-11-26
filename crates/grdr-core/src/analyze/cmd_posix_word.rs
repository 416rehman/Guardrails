// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! POSIX word-builder state and double/single-quoted character handler (`D-10`).

use crate::analyze::cmd_dialects::{ParsedClause, flush_word, push_checked_char};
use crate::analyze::cmd_posix_helpers::{
    DollarErr, DollarExpandState, EnvOverlay, PosixWord, TildeMode, WordSyntax,
    collect_clause_assigned_vars, handle_posix_dollar_into,
};
use crate::analyze::types::{
    MalformedKind, MalformedReason, Resolution, ShellLimits, Span, UnresolvedKind,
    UnresolvedReason, sanitize_detail_token,
};

const POSIX_STATE_BUILTINS: &[&str] = &[
    "export",
    "unset",
    "readonly",
    "declare",
    "typeset",
    "local",
    "read",
    "mapfile",
    "readarray",
    "getopts",
    "set",
    "shift",
    "trap",
    "unalias",
    "shopt",
    "enable",
    "let",
    "exec",
    "times",
];

const POSIX_SPECIAL_BUILTINS: &[&str] = &[
    ":", ".", "break", "continue", "eval", "exec", "exit", "export", "readonly", "return", "set",
    "shift", "times", "trap", "unset",
];

const POSIX_RESERVED_WORDS: &[&str] = &[
    "!", "{", "}", "if", "then", "elif", "else", "fi", "case", "esac", "for", "select", "while",
    "until", "do", "done", "function", "coproc", "[[", "]]", "time",
];

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum WordProgress {
    Empty,
    StartedUnquoted,
    Active,
}

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum AssignHeadState {
    PlainName,
    SeenEqValid,
    Tainted,
}

#[derive(Clone, Copy)]
struct BraceFrame {
    has_sep: bool,
    prev_dot: bool,
}

pub(super) struct WordBuilder {
    pub(super) progress: WordProgress,
    pub(super) assign_head: AssignHeadState,
    pub(super) syntax: WordSyntax,
    pub(super) tilde: TildeMode,
    pub(super) has_unquoted_brace: bool,
    pub(super) last_unquoted_char: Option<char>,
    brace_stack: Vec<BraceFrame>,
    pub(super) buf: String,
}

impl WordBuilder {
    pub(super) fn new() -> Self {
        Self {
            progress: WordProgress::Empty,
            assign_head: AssignHeadState::PlainName,
            syntax: WordSyntax::Plain,
            tilde: TildeMode::None,
            has_unquoted_brace: false,
            last_unquoted_char: None,
            brace_stack: Vec::new(),
            buf: String::new(),
        }
    }

    pub(super) fn is_empty(&self) -> bool {
        self.progress == WordProgress::Empty
    }

    pub(super) fn mark_quoted(&mut self) {
        self.progress = WordProgress::Active;
        if self.assign_head == AssignHeadState::PlainName {
            self.assign_head = AssignHeadState::Tainted;
        }
        if let Some(top) = self.brace_stack.last_mut() {
            top.prev_dot = false;
        }
    }

    pub(super) fn push_escaped_char(
        &mut self,
        ch: char,
        expanded_total: &mut usize,
        limits: &ShellLimits,
    ) -> Result<(), UnresolvedReason> {
        self.mark_quoted();
        self.last_unquoted_char = None;
        push_checked_char(&mut self.buf, ch, expanded_total, limits)
    }

    pub(super) fn push_unquoted_char(
        &mut self,
        ch: char,
        expanded_total: &mut usize,
        limits: &ShellLimits,
    ) -> Result<(), UnresolvedReason> {
        self.progress = WordProgress::Active;
        self.update_brace_state(ch);
        if self.assign_head == AssignHeadState::PlainName {
            if ch == '=' {
                self.assign_head = if self.buf.is_empty() {
                    AssignHeadState::Tainted
                } else {
                    AssignHeadState::SeenEqValid
                };
            } else {
                let valid = if self.buf.is_empty() {
                    ch.is_ascii_alphabetic() || ch == '_'
                } else {
                    ch.is_ascii_alphanumeric() || ch == '_'
                };
                if !valid {
                    self.assign_head = AssignHeadState::Tainted;
                }
            }
        }
        push_checked_char(&mut self.buf, ch, expanded_total, limits)?;
        self.last_unquoted_char = Some(ch);
        Ok(())
    }

    fn update_brace_state(&mut self, ch: char) {
        match ch {
            '{' => {
                if let Some(top) = self.brace_stack.last_mut() {
                    top.prev_dot = false;
                }
                self.brace_stack.push(BraceFrame {
                    has_sep: false,
                    prev_dot: false,
                });
            }
            ',' => {
                if let Some(top) = self.brace_stack.last_mut() {
                    top.has_sep = true;
                    top.prev_dot = false;
                }
            }
            '.' => {
                if let Some(top) = self.brace_stack.last_mut() {
                    if top.prev_dot {
                        top.has_sep = true;
                    }
                    top.prev_dot = true;
                }
            }
            '}' => {
                if let Some(frame) = self.brace_stack.pop()
                    && frame.has_sep
                {
                    self.has_unquoted_brace = true;
                    if self.syntax != WordSyntax::UnquotedExtglob {
                        self.syntax = WordSyntax::UnquotedBrace;
                    }
                }
            }
            _ => {
                if let Some(top) = self.brace_stack.last_mut() {
                    top.prev_dot = false;
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn expand_dollar(
        &mut self,
        chars: &[(usize, char)],
        start_idx: usize,
        local_env: &EnvOverlay<'_>,
        quoted: bool,
        in_arg_pos: bool,
        prior_words: &[PosixWord],
        words: Option<&mut Vec<PosixWord>>,
        total_words: &mut u32,
        expanded_total: &mut usize,
        limits: &ShellLimits,
    ) -> Result<usize, Resolution<Vec<ParsedClause>>> {
        if self.assign_head == AssignHeadState::PlainName {
            self.assign_head = AssignHeadState::Tainted;
        }
        if let Some(top) = self.brace_stack.last_mut() {
            top.prev_dot = false;
        }
        let prior = match words.as_deref() {
            Some(w) => w.as_slice(),
            None => prior_words,
        };
        let prior_assigned = collect_clause_assigned_vars(prior);
        let in_assign_rhs = self.assign_head == AssignHeadState::SeenEqValid
            && prior.iter().all(|w| w.unquoted_assign_name);
        let mut word_active = self.progress == WordProgress::Active;
        let mut word_started = self.progress != WordProgress::Empty;
        let mut dstate = DollarExpandState {
            cur: &mut self.buf,
            word_active: &mut word_active,
            word_started: &mut word_started,
            word_syntax: &mut self.syntax,
            last_unquoted_char: &mut self.last_unquoted_char,
            word_split: !quoted && !in_assign_rhs,
            prior_assigned: &prior_assigned,
            words,
            total_words,
            expanded_total,
        };
        let next_i = handle_posix_dollar_into(
            chars,
            start_idx,
            local_env,
            quoted,
            in_arg_pos,
            &mut dstate,
            limits,
        )
        .map_err(|err| match err {
            DollarErr::Malformed(m) => Resolution::Malformed(m),
            DollarErr::Unresolved(u) => Resolution::Unresolved(vec![u]),
        })?;
        self.progress = if word_active {
            WordProgress::Active
        } else if word_started {
            WordProgress::StartedUnquoted
        } else {
            WordProgress::Empty
        };
        Ok(next_i)
    }

    pub(super) fn flush(
        &mut self,
        words: &mut Vec<PosixWord>,
        total_words: &mut u32,
        limits: &ShellLimits,
    ) -> Result<(), UnresolvedReason> {
        let mut active = self.progress == WordProgress::Active;
        let mut flushed = Vec::new();
        flush_word(
            &mut active,
            &mut self.buf,
            &mut flushed,
            total_words,
            limits,
        )?;
        if let Some(text) = flushed.into_iter().next() {
            let syntax = if self.has_unquoted_brace && self.syntax != WordSyntax::UnquotedExtglob {
                WordSyntax::UnquotedBrace
            } else {
                self.syntax
            };
            words.push(PosixWord {
                text,
                syntax,
                tilde: self.tilde,
                unquoted_assign_name: self.assign_head == AssignHeadState::SeenEqValid,
            });
        }
        self.progress = WordProgress::Empty;
        self.assign_head = AssignHeadState::PlainName;
        self.syntax = WordSyntax::Plain;
        self.tilde = TildeMode::None;
        self.has_unquoted_brace = false;
        self.last_unquoted_char = None;
        self.brace_stack.clear();
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub(super) fn handle_quoted_char(
    chars: &[(usize, char)],
    i: &mut usize,
    pos: usize,
    ch: char,
    q: char,
    quote: &mut Option<char>,
    wb: &mut WordBuilder,
    local_env: &EnvOverlay<'_>,
    words: &[PosixWord],
    expanded_total: &mut usize,
    limits: &ShellLimits,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    if q == '\'' {
        if ch == '\'' {
            *quote = None;
        } else {
            wb.last_unquoted_char = None;
            push_checked_char(&mut wb.buf, ch, expanded_total, limits)
                .map_err(|r| Resolution::Unresolved(vec![r]))?;
        }
        *i = i.saturating_add(1);
        return Ok(());
    }
    if ch == '\\' {
        let Some(&(_, next_c)) = chars.get(i.saturating_add(1)) else {
            return Err(Resolution::Malformed(MalformedReason::new(
                MalformedKind::UnexpectedEof,
                Span::from_usize(pos, pos.saturating_add(1)),
                "trailing backslash inside double quotes",
            )));
        };
        if matches!(next_c, '$' | '`' | '"' | '\\') {
            push_checked_char(&mut wb.buf, next_c, expanded_total, limits)
                .map_err(|r| Resolution::Unresolved(vec![r]))?;
        } else {
            push_checked_char(&mut wb.buf, '\\', expanded_total, limits)
                .map_err(|r| Resolution::Unresolved(vec![r]))?;
            push_checked_char(&mut wb.buf, next_c, expanded_total, limits)
                .map_err(|r| Resolution::Unresolved(vec![r]))?;
        }
        wb.last_unquoted_char = None;
        *i = i.saturating_add(2);
        return Ok(());
    }
    if ch == '"' {
        *quote = None;
        *i = i.saturating_add(1);
        return Ok(());
    }
    if ch == '$' {
        let mut dummy_total = 0u32;
        let next_i = wb.expand_dollar(
            chars,
            *i,
            local_env,
            true,
            !words.is_empty(),
            words,
            None,
            &mut dummy_total,
            expanded_total,
            limits,
        )?;
        *i = next_i;
        return Ok(());
    }
    if ch == '`' {
        return Err(Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::SubstitutionInWord,
            span: Span::from_usize(pos, pos.saturating_add(1)),
            detail: "backtick command substitution in double quotes".into(),
        }]));
    }
    wb.last_unquoted_char = None;
    push_checked_char(&mut wb.buf, ch, expanded_total, limits)
        .map_err(|r| Resolution::Unresolved(vec![r]))?;
    *i = i.saturating_add(1);
    Ok(())
}

pub(super) fn check_posix_command_position(
    cmd0: &str,
    argv: &[String],
    assignments: &[(String, String)],
    local_env: &mut EnvOverlay<'_>,
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    if POSIX_RESERVED_WORDS.contains(&cmd0) {
        return Err(Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(0, cmd0.len()),
            detail: format!(
                "POSIX control-flow construct `{}`",
                sanitize_detail_token(cmd0, 24)
            ),
        }]));
    }
    match cmd0 {
        "eval" => {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::DynamicEval,
                span: Span::from_usize(0, cmd0.len()),
                detail: "`eval` construct".into(),
            }]));
        }
        "source" | "." => {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::DynamicSource,
                span: Span::from_usize(0, cmd0.len()),
                detail: "dynamic shell sourcing".into(),
            }]));
        }
        "alias" => {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::UndefinedAlias,
                span: Span::from_usize(0, cmd0.len()),
                detail: "shell alias definition".into(),
            }]));
        }
        "command" | "builtin" => return classify_command_or_builtin_wrapper(argv),
        "printf" => {
            for arg in argv.iter().skip(1) {
                if arg == "--" {
                    break;
                }
                if arg == "-v"
                    || arg.starts_with("-v")
                    || (arg.starts_with('-') && arg.contains('v'))
                {
                    return Err(Resolution::Unresolved(vec![UnresolvedReason {
                        kind: UnresolvedKind::UnsupportedConstruct,
                        span: Span::from_usize(0, arg.len()),
                        detail: "`printf -v` variable write".into(),
                    }]));
                }
            }
        }
        "cd" | "pushd" | "popd" => {
            local_env.remove("PWD");
            local_env.remove("OLDPWD");
        }
        other if POSIX_STATE_BUILTINS.contains(&other) => {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::UnsupportedConstruct,
                span: Span::from_usize(0, other.len()),
                detail: format!(
                    "state-mutating built-in `{}`",
                    sanitize_detail_token(other, 24)
                ),
            }]));
        }
        _ => {}
    }

    if !assignments.is_empty() && POSIX_SPECIAL_BUILTINS.contains(&cmd0) {
        return Err(Resolution::Unresolved(vec![UnresolvedReason {
            kind: UnresolvedKind::UnsupportedConstruct,
            span: Span::from_usize(0, cmd0.len()),
            detail: "prefix assignment on POSIX special built-in".into(),
        }]));
    }
    Ok(())
}

fn classify_command_or_builtin_wrapper(
    argv: &[String],
) -> Result<(), Resolution<Vec<ParsedClause>>> {
    let mut idx = 1usize;
    while let Some(arg) = argv.get(idx) {
        if arg == "--" {
            idx = idx.saturating_add(1);
            break;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            idx = idx.saturating_add(1);
            continue;
        }
        break;
    }
    let kind = match argv.get(idx).map(String::as_str) {
        Some("eval") => UnresolvedKind::DynamicEval,
        Some("source" | ".") => UnresolvedKind::DynamicSource,
        Some("alias") => UnresolvedKind::UndefinedAlias,
        _ => UnresolvedKind::UnsupportedConstruct,
    };
    Err(Resolution::Unresolved(vec![UnresolvedReason {
        kind,
        span: Span::from_usize(0, argv.first().map_or(0, String::len)),
        detail: "`command`/`builtin` wrapper invocation".into(),
    }]))
}
