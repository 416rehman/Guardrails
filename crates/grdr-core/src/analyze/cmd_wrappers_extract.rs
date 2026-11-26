// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Script payload extraction and argument quoting helpers for shell wrappers.

use crate::analyze::cmd_wrappers::detect_shell_dialect;
pub(super) use crate::analyze::cmd_wrappers_cmd::{
    extract_attached_cmd_c, extract_cmd_c_script, extract_head_cmd, has_cmd_c_invocation,
};
use crate::analyze::decode_pipe::is_ps_value_flag_name;
use crate::analyze::types::ShellDialect;

pub(super) fn extract_env_split_string(argv: &[String]) -> Option<(ShellDialect, String)> {
    let mut i = 1usize;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            return None;
        }
        if is_assign_token(arg) {
            i = i.saturating_add(1);
            continue;
        }
        if matches!(
            arg.as_str(),
            "-u" | "-C" | "-a" | "--unset" | "--chdir" | "--argv0"
        ) {
            i = i.saturating_add(2);
            continue;
        }
        if let Some(val) = arg.strip_prefix("--split-string=") {
            return combine_split_string_parts(val, argv.get(i.saturating_add(1)..));
        }
        if arg == "-S" || arg == "--split-string" {
            let script = argv.get(i.saturating_add(1))?;
            return combine_split_string_parts(script, argv.get(i.saturating_add(2)..));
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let body = arg.get(1..).unwrap_or("");
            let mut step = 1usize;
            for (idx, ch) in body.char_indices() {
                if ch == 'S' {
                    let after = body.get(idx.saturating_add(1)..).unwrap_or("");
                    if after.is_empty() {
                        let script = argv.get(i.saturating_add(1))?;
                        return combine_split_string_parts(script, argv.get(i.saturating_add(2)..));
                    }
                    return combine_split_string_parts(after, argv.get(i.saturating_add(1)..));
                }
                if matches!(ch, 'u' | 'C' | 'a') {
                    if idx.saturating_add(1) == body.len() {
                        step = 2;
                    }
                    break;
                }
            }
            i = i.saturating_add(step);
            continue;
        }
        if !arg.starts_with('-') {
            return None;
        }
        i = i.saturating_add(1);
    }
    None
}

fn combine_split_string_parts(
    head: &str,
    rest: Option<&[String]>,
) -> Option<(ShellDialect, String)> {
    let mut parts = vec![head.to_owned()];
    if let Some(tail) = rest
        && !tail.is_empty()
    {
        parts.extend(tail.iter().map(|t| quote_shell_arg(t, ShellDialect::Posix)));
    }
    let raw_script = parts.join(" ");
    let script = strip_leading_env_flags(&raw_script);
    if script.is_empty() {
        return None;
    }
    Some((detect_shell_dialect(script), script.to_owned()))
}

fn strip_leading_env_flags(script: &str) -> &str {
    let mut rest = script.trim_start();
    let mut skip_next = false;
    while !rest.is_empty() {
        let tok_end = scan_env_split_word_end(rest);
        let tok = rest.get(..tok_end).unwrap_or(rest);
        let after = rest.get(tok_end..).unwrap_or("").trim_start();
        if skip_next {
            skip_next = false;
            rest = after;
            continue;
        }
        if tok == "--" {
            return after;
        }
        if !tok.starts_with('-') {
            return rest;
        }
        if matches!(tok, "-u" | "-C" | "-a" | "--unset" | "--chdir" | "--argv0") {
            skip_next = true;
        } else if !tok.starts_with("--") {
            let body = tok.get(1..).unwrap_or("");
            for (idx, ch) in body.char_indices() {
                if matches!(ch, 'u' | 'C' | 'a') {
                    if idx.saturating_add(1) == body.len() {
                        skip_next = true;
                    }
                    break;
                }
            }
        }
        rest = after;
    }
    ""
}

fn scan_env_split_word_end(s: &str) -> usize {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in s.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if let Some(q) = quote {
            if q == '"' && ch == '\\' {
                escaped = true;
            } else if ch == q {
                quote = None;
            }
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote = Some(ch),
            c if c.is_ascii_whitespace() => return idx,
            _ => {}
        }
    }
    s.len()
}

pub(super) fn join_quoted_tokens(tokens: &[String]) -> (ShellDialect, String) {
    let dialect = tokens
        .first()
        .map_or(ShellDialect::Posix, |t| detect_shell_dialect(t));
    let joined = tokens
        .iter()
        .map(|t| quote_shell_arg(t, dialect))
        .collect::<Vec<_>>()
        .join(" ");
    (dialect, joined)
}

fn quote_shell_arg(arg: &str, dialect: ShellDialect) -> String {
    if !arg.is_empty()
        && arg.chars().all(|c| {
            c.is_ascii_alphanumeric()
                || matches!(c, '_' | '-' | '.' | '/' | ':' | '=' | '@' | '+' | ',')
        })
    {
        return arg.to_owned();
    }
    match dialect {
        ShellDialect::PowerShell => format!("'{}'", arg.replace('\'', "''")),
        ShellDialect::Cmd => {
            if !arg.contains('"') {
                format!("\"{arg}\"")
            } else {
                arg.to_owned()
            }
        }
        ShellDialect::Posix => format!("'{}'", arg.replace('\'', "'\\''")),
    }
}

pub(super) fn extract_posix_c_script(argv: &[String]) -> Option<(ShellDialect, String)> {
    let mut i = 1usize;
    let mut saw_c = false;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            i = i.saturating_add(1);
            break;
        }
        if matches!(arg.as_str(), "--rcfile" | "--init-file") {
            i = i.saturating_add(2);
            continue;
        }
        if arg.starts_with("--") {
            i = i.saturating_add(1);
            continue;
        }
        if (arg.starts_with('-') || arg.starts_with('+')) && arg.len() > 1 {
            let is_minus = arg.starts_with('-');
            let mut skip_next = false;
            let body = arg.get(1..).unwrap_or("");
            for (idx, ch) in body.char_indices() {
                if ch == 'o' || ch == 'O' {
                    if idx.saturating_add(ch.len_utf8()) == body.len() {
                        skip_next = true;
                    }
                    break;
                }
                if is_minus && ch == 'c' {
                    saw_c = true;
                }
            }
            i = i.saturating_add(if skip_next { 2 } else { 1 });
            continue;
        }
        break;
    }
    if !saw_c {
        return None;
    }
    argv.get(i).cloned().map(|s| (ShellDialect::Posix, s))
}

pub(super) fn extract_ps_c_script(argv: &[String]) -> Option<(ShellDialect, String)> {
    let mut i = 1usize;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            let rest = argv.get(i.saturating_add(1)..)?;
            return (!rest.is_empty()).then(|| (ShellDialect::PowerShell, rest.join(" ")));
        }
        if !has_ps_switch_prefix(arg) {
            let rest = argv.get(i..)?;
            return (!rest.is_empty()).then(|| (ShellDialect::PowerShell, rest.join(" ")));
        }
        let (flag_raw, attached) = match arg.find([':', '=']) {
            Some(sep) => (
                arg.get(..sep).unwrap_or(arg),
                arg.get(sep.saturating_add(1)..),
            ),
            None => (arg.as_str(), None),
        };
        let stripped = strip_ps_switch_prefix(flag_raw).to_ascii_lowercase();
        if stripped.is_empty() {
            i = i.saturating_add(1);
            continue;
        }
        if "file".starts_with(&stripped)
            || stripped == "ec"
            || "encodedcommand".starts_with(&stripped)
        {
            return None;
        }
        if "command".starts_with(&stripped) || "commandwithargs".starts_with(&stripped) {
            if let Some(inline) = attached {
                let mut parts = Vec::new();
                if !inline.is_empty() {
                    parts.push(inline.to_owned());
                }
                if let Some(tail) = argv.get(i.saturating_add(1)..) {
                    parts.extend(tail.iter().cloned());
                }
                return (!parts.is_empty()).then(|| (ShellDialect::PowerShell, parts.join(" ")));
            }
            let rest = argv.get(i.saturating_add(1)..)?;
            return (!rest.is_empty()).then(|| (ShellDialect::PowerShell, rest.join(" ")));
        }
        if attached.is_none() && is_ps_value_flag_name(&stripped) {
            i = i.saturating_add(2);
            continue;
        }
        i = i.saturating_add(1);
    }
    None
}

fn has_ps_switch_prefix(arg: &str) -> bool {
    arg.starts_with(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/'])
}

fn strip_ps_switch_prefix(flag: &str) -> &str {
    flag.trim_start_matches(['-', '\u{2013}', '\u{2014}', '\u{2212}', '/'])
}

pub(super) fn skip_env_options(
    argv: &[String],
    start: usize,
    value_flags: &[&str],
) -> Option<usize> {
    skip_options_inner(argv, start, value_flags, true, true)
}

pub(super) fn skip_options(
    argv: &[String],
    start: usize,
    value_flags: &[&str],
    skip_assignments: bool,
) -> Option<usize> {
    skip_options_inner(argv, start, value_flags, skip_assignments, false)
}

fn skip_options_inner(
    argv: &[String],
    start: usize,
    value_flags: &[&str],
    skip_assignments: bool,
    skip_bare_dash: bool,
) -> Option<usize> {
    let mut i = start;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            return Some(i.saturating_add(1));
        }
        if skip_bare_dash && arg == "-" {
            i = i.saturating_add(1);
            continue;
        }
        if skip_assignments && is_assign_token(arg) {
            i = i.saturating_add(1);
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            if arg.starts_with("--") {
                if !arg.contains('=') && value_flags.iter().any(|f| f == arg) {
                    i = i.saturating_add(2);
                } else {
                    i = i.saturating_add(1);
                }
                continue;
            }
            if arg.contains('=') {
                i = i.saturating_add(1);
                continue;
            }
            let body = arg.get(1..).unwrap_or("");
            let mut step = 1usize;
            for (idx, ch) in body.char_indices() {
                let mut buf = [b'-', 0, 0, 0, 0];
                let Some(tail_buf) = buf.get_mut(1..) else {
                    break;
                };
                let ch_str = ch.encode_utf8(tail_buf);
                let short_len = 1usize.saturating_add(ch_str.len());
                let candidate = std::str::from_utf8(buf.get(..short_len).unwrap_or(&[])).ok();
                if let Some(flag) = candidate
                    && value_flags.contains(&flag)
                {
                    if idx.saturating_add(ch.len_utf8()) == body.len() {
                        step = 2;
                    }
                    break;
                }
            }
            i = i.saturating_add(step);
            continue;
        }
        return Some(i);
    }
    None
}

pub(super) fn is_assign_token(tok: &str) -> bool {
    let Some((k, _)) = tok.split_once('=') else {
        return false;
    };
    !k.is_empty() && k.chars().all(|c| c.is_ascii_alphanumeric() || c == '_')
}
