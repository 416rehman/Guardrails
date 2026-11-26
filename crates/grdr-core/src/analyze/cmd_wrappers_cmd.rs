// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Windows `cmd.exe` head-command detection and `/c`/`/k`/`/r` switch chain extraction.

use crate::analyze::types::ShellDialect;

enum CmdSwitchChain<'a> {
    Found(&'a str),
    PreSwitchOnly,
    NotCmdSwitch,
}

pub(super) fn extract_head_cmd(raw: &str) -> String {
    let trimmed = raw.trim_start();
    let first = trimmed.split_whitespace().next().unwrap_or("");
    let (candidate, raw_candidate) = if let Some(after_at) = first.strip_prefix('@') {
        let low = after_at.to_ascii_lowercase();
        let head = low.split(['/', '\\', ',', ';', '=']).next().unwrap_or("");
        if head == "cmd" || head == "cmd.exe" {
            (after_at, trimmed.strip_prefix('@').unwrap_or(trimmed))
        } else {
            (first, trimmed)
        }
    } else {
        (first, trimmed)
    };
    if let Some(cmd_bin) = extract_cmd_bin_from_token(candidate, raw_candidate) {
        return cmd_bin;
    }
    candidate
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or("")
        .to_ascii_lowercase()
}

pub(crate) fn is_cmd_exec_prefix_switch_completed(tok: &str) -> bool {
    matches!(parse_cmd_switch_chain(tok), CmdSwitchChain::Found(tail) if tail.is_empty())
}

pub(crate) fn is_cmd_pre_switch(tok: &str) -> bool {
    matches!(parse_cmd_switch_chain(tok), CmdSwitchChain::PreSwitchOnly)
}

pub(super) fn has_cmd_c_invocation(lower: &str) -> bool {
    let mut cursor = 0usize;
    while let Some(rel) = lower.get(cursor..).and_then(|s| s.find("cmd")) {
        let idx = cursor.saturating_add(rel);
        let prev_ok = idx == 0
            || lower
                .get(..idx)
                .and_then(|s| s.chars().next_back())
                .is_some_and(|c| !c.is_ascii_alphanumeric() && c != '_' && c != '-');
        if prev_ok {
            let after_cmd = lower.get(idx.saturating_add(3)..).unwrap_or("");
            let (rest, is_exe) = match after_cmd.strip_prefix(".exe") {
                Some(after_exe) => (after_exe, true),
                None => (after_cmd, false),
            };
            let tok_start = lower
                .get(..idx)
                .and_then(|s| {
                    s.rfind(|c: char| {
                        c.is_ascii_whitespace() || matches!(c, '"' | '\'' | ';' | '&' | '|')
                    })
                })
                .map_or(0, |p| p.saturating_add(1));
            let tok_prefix = lower.get(tok_start..idx.saturating_add(3)).unwrap_or("");
            let posix_skip = !is_exe
                && is_cmd_posix_path_segment(
                    tok_prefix,
                    idx.saturating_sub(tok_start),
                    "cmd",
                    rest,
                );
            if !posix_skip && cmd_rest_has_exec_switch(rest) {
                return true;
            }
        }
        cursor = idx.saturating_add(3);
    }
    false
}

pub(super) fn extract_attached_cmd_c(
    first: &str,
    rest: &[String],
) -> Option<(ShellDialect, String)> {
    let mut offset = 0usize;
    let mut found_rest = None;
    for part in first.split(['/', '\\']) {
        let head_end = part.find([',', ';', '=']).unwrap_or(part.len());
        let head = part.get(..head_end).unwrap_or(part);
        if (head.eq_ignore_ascii_case("cmd") || head.eq_ignore_ascii_case("cmd.exe"))
            && let Some(suffix) = first.get(offset.saturating_add(head.len())..)
            && let Some(inline) = extract_cmd_switch_tail(suffix)
        {
            found_rest = Some(inline);
            break;
        }
        offset = offset.saturating_add(part.len()).saturating_add(1);
    }
    let inline = found_rest?;
    let mut parts = Vec::new();
    if !inline.is_empty() {
        parts.push(inline.to_owned());
    }
    parts.extend(rest.iter().cloned());
    if parts.is_empty() {
        None
    } else {
        Some((ShellDialect::Cmd, parts.join(" ")))
    }
}

pub(super) fn extract_cmd_c_script(argv: &[String]) -> Option<(ShellDialect, String)> {
    for (idx, arg) in argv.iter().enumerate().skip(1) {
        if let CmdSwitchChain::Found(inline) = parse_cmd_switch_chain(arg) {
            let mut parts = Vec::new();
            if !inline.is_empty() {
                parts.push(inline.to_owned());
            }
            if let Some(more) = argv.get(idx.saturating_add(1)..) {
                parts.extend(more.iter().cloned());
            }
            return (!parts.is_empty()).then(|| (ShellDialect::Cmd, parts.join(" ")));
        }
    }
    None
}

fn extract_cmd_bin_from_token(tok: &str, raw_full: &str) -> Option<String> {
    let mut offset = 0usize;
    for part in tok.split(['/', '\\']) {
        let head_end = part.find([',', ';', '=']).unwrap_or(part.len());
        let head = part.get(..head_end).unwrap_or(part);
        let head_low = head.to_ascii_lowercase();
        if (head_low == "cmd" || head_low == "cmd.exe")
            && let Some(rest) = tok.get(offset.saturating_add(head.len())..)
        {
            if rest.is_empty() {
                return Some(head_low);
            }
            if rest.starts_with([',', ';', '=']) {
                let raw_rest = raw_full
                    .get(offset.saturating_add(head.len())..)
                    .unwrap_or("");
                if cmd_rest_has_exec_switch(raw_rest) {
                    return Some(head_low);
                }
            } else if !is_cmd_posix_path_segment(tok, offset, &head_low, rest)
                && !matches!(parse_cmd_switch_chain(rest), CmdSwitchChain::NotCmdSwitch)
            {
                return Some(head_low);
            }
        }
        offset = offset.saturating_add(part.len()).saturating_add(1);
    }
    None
}

fn is_cmd_posix_path_segment(tok: &str, cmd_offset: usize, head_low: &str, rest: &str) -> bool {
    if cmd_offset == 0 || head_low != "cmd" || !rest.starts_with('/') {
        return false;
    }
    let before = tok.get(..cmd_offset).unwrap_or("");
    let has_win_prefix = before.contains('\\')
        || (before.as_bytes().get(1) == Some(&b':')
            && before
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic));
    if has_win_prefix || before.as_bytes().last() != Some(&b'/') {
        return false;
    }
    rest.get(2..)
        .and_then(|s| s.chars().next())
        .is_some_and(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
}

fn cmd_rest_has_exec_switch(mut rest: &str) -> bool {
    loop {
        rest = rest.trim_start_matches([' ', '\t', ',', ';', '=']);
        if !rest.starts_with('/') {
            return false;
        }
        let tok_end = rest
            .find(|c: char| c.is_ascii_whitespace() || matches!(c, '"' | '\'' | ',' | ';' | '='))
            .unwrap_or(rest.len());
        let tok = rest.get(..tok_end).unwrap_or(rest);
        match parse_cmd_switch_chain(tok) {
            CmdSwitchChain::Found(_) => return true,
            CmdSwitchChain::PreSwitchOnly => {
                rest = rest.get(tok_end..).unwrap_or("");
            }
            CmdSwitchChain::NotCmdSwitch => return false,
        }
    }
}

fn extract_cmd_switch_tail(mut suffix: &str) -> Option<&str> {
    loop {
        suffix = suffix.trim_start_matches([',', ';', '=']);
        let seg_end = suffix.find([',', ';', '=']).unwrap_or(suffix.len());
        let seg = suffix.get(..seg_end).unwrap_or(suffix);
        match parse_cmd_switch_chain(seg) {
            CmdSwitchChain::Found(inline) => {
                let offset = seg.len().saturating_sub(inline.len());
                return suffix.get(offset..);
            }
            CmdSwitchChain::PreSwitchOnly => {
                suffix = suffix.get(seg_end..).unwrap_or("");
            }
            CmdSwitchChain::NotCmdSwitch => return None,
        }
    }
}

fn parse_cmd_switch_chain(arg: &str) -> CmdSwitchChain<'_> {
    if !arg.starts_with('/') {
        return CmdSwitchChain::NotCmdSwitch;
    }
    let mut pos = 0usize;
    while let Some(after_slash) = arg.get(pos.saturating_add(1)..) {
        if after_slash
            .as_bytes()
            .first()
            .is_some_and(|b| matches!(b.to_ascii_lowercase(), b'c' | b'k' | b'r'))
        {
            let rest = after_slash.get(1..).unwrap_or("");
            return CmdSwitchChain::Found(rest.strip_prefix(':').unwrap_or(rest));
        }
        let next_slash = after_slash.find('/');
        let next_colon = after_slash.find(':');
        if let Some(colon) = next_colon
            && next_slash.is_none_or(|slash| colon < slash)
        {
            let seg_low = after_slash.get(..colon).unwrap_or("").to_ascii_lowercase();
            if matches!(seg_low.as_str(), "e" | "f" | "v" | "t") {
                if let Some(slash) = next_slash {
                    pos = pos.saturating_add(1).saturating_add(slash);
                    continue;
                }
                return CmdSwitchChain::PreSwitchOnly;
            }
            return CmdSwitchChain::NotCmdSwitch;
        }
        let seg_end = next_slash.unwrap_or(after_slash.len());
        let seg_low = after_slash
            .get(..seg_end)
            .unwrap_or("")
            .to_ascii_lowercase();
        if matches!(seg_low.as_str(), "q" | "d" | "a" | "u" | "s" | "x" | "y") {
            if let Some(slash) = next_slash {
                pos = pos.saturating_add(1).saturating_add(slash);
                continue;
            }
            return CmdSwitchChain::PreSwitchOnly;
        }
        return CmdSwitchChain::NotCmdSwitch;
    }
    CmdSwitchChain::NotCmdSwitch
}

pub(super) fn has_win_backslash_path(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut in_double = false;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'"' {
            in_double = !in_double;
            i = i.saturating_add(1);
            continue;
        }
        if !in_double
            && b == b'\''
            && let Some(rel) = bytes
                .get(i.saturating_add(1)..)
                .and_then(|s| s.iter().position(|&c| c == b'\''))
        {
            i = i.saturating_add(rel).saturating_add(2);
            continue;
        }
        if b == b':'
            && bytes.get(i.saturating_add(1)) == Some(&b'\\')
            && i.checked_sub(1)
                .and_then(|p| bytes.get(p))
                .is_some_and(u8::is_ascii_alphabetic)
        {
            let before_ok = i < 2
                || bytes.get(i.saturating_sub(2)).is_some_and(|p| {
                    matches!(
                        *p,
                        b' ' | b'\t' | b'"' | b'=' | b';' | b'&' | b'|' | b',' | b'('
                    )
                });
            if before_ok {
                return true;
            }
        }
        if b == b'\\'
            && bytes.get(i.saturating_add(1)) == Some(&b'\\')
            && (i == 0
                || bytes.get(i.saturating_sub(1)).is_some_and(|p| {
                    matches!(
                        *p,
                        b' ' | b'\t' | b'"' | b'=' | b';' | b'&' | b'|' | b',' | b'('
                    )
                }))
        {
            let after = raw.get(i.saturating_add(2)..).unwrap_or("");
            if let Some(rel) = after.find('\\')
                && rel > 0
                && after
                    .get(..rel)
                    .is_some_and(|h| !h.chars().any(char::is_whitespace))
            {
                return true;
            }
        }
        i = i.saturating_add(1);
    }
    false
}

pub(super) fn has_cmd_caret_outside_quotes(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut in_double = false;
    let mut i = 0usize;
    while let Some(&b) = bytes.get(i) {
        if b == b'"' {
            in_double = !in_double;
            i = i.saturating_add(1);
            continue;
        }
        if !in_double
            && b == b'\''
            && let Some(rel) = bytes
                .get(i.saturating_add(1)..)
                .and_then(|s| s.iter().position(|&c| c == b'\''))
        {
            i = i.saturating_add(rel).saturating_add(2);
            continue;
        }
        if !in_double && b == b'^' {
            let next = raw
                .get(i.saturating_add(1)..)
                .and_then(|s| s.chars().next());
            if next.is_some_and(|n| n.is_ascii_alphabetic() || matches!(n, '&' | '|' | '>' | '<')) {
                return true;
            }
            i = i.saturating_add(2);
            continue;
        }
        i = i.saturating_add(1);
    }
    false
}
