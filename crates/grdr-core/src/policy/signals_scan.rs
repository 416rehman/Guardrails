// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Bounded string/segment scanners for Cedar signal extraction (destructive, pipe-to-shell, host).

pub(crate) fn has_traversal_segment(s: &str) -> bool {
    s.trim().split(['/', '\\']).any(|seg| seg == "..")
}

pub(crate) fn contains_any(raw_lower: &str, norm_lower: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| raw_lower.contains(needle) || norm_lower.contains(needle))
}

pub(crate) fn contains_path_segment(haystack: &str, segment: &str) -> bool {
    let bytes = haystack.as_bytes();
    let mut start = 0usize;
    while let Some(rel) = haystack.get(start..).and_then(|s| s.find(segment)) {
        let idx = start.saturating_add(rel);
        let end = idx.saturating_add(segment.len());
        let left_ok = idx == 0
            || bytes.get(idx.saturating_sub(1)).is_some_and(|&b| {
                b.is_ascii_whitespace()
                    || matches!(
                        b,
                        b'/' | b':'
                            | b'='
                            | b'"'
                            | b'\''
                            | b'~'
                            | b'('
                            | b'`'
                            | b','
                            | b'{'
                            | b'<'
                            | b'|'
                    )
            });
        let right_ok = bytes.get(end).is_none_or(|&b| {
            b.is_ascii_whitespace()
                || matches!(
                    b,
                    b'/' | b'"'
                        | b'\''
                        | b';'
                        | b'&'
                        | b':'
                        | b'?'
                        | b')'
                        | b'`'
                        | b','
                        | b'}'
                        | b'>'
                        | b'|'
                )
        });
        if left_ok && right_ok {
            return true;
        }
        start = idx.saturating_add(1);
    }
    false
}

fn has_rec_and_force_flags(args: &[&str]) -> bool {
    let mut has_rec = false;
    let mut has_force = false;
    for flag in args {
        if matches!(*flag, "--recursive" | "--recurse" | "-recurse") {
            has_rec = true;
        } else if matches!(*flag, "--force" | "-force") {
            has_force = true;
        } else if flag.starts_with('-') && !flag.starts_with("--") {
            has_rec |= flag.contains('r');
            has_force |= flag.contains('f');
        }
    }
    has_rec && has_force
}

fn is_destructive_segment(seg: &str) -> bool {
    let words: Vec<&str> = seg.split_ascii_whitespace().collect();
    for (idx, word) in words.iter().enumerate() {
        let trimmed = word.trim_matches(|c: char| matches!(c, '$' | '\'' | '"'));
        let base = trimmed.rsplit('/').next().unwrap_or(trimmed);
        let rest = words.get(idx.saturating_add(1)..).unwrap_or(&[]);
        if base == "mkfs" || base.starts_with("mkfs.") {
            return true;
        }
        if base == "dd"
            && words.get(idx..).is_some_and(|tail| {
                tail.iter()
                    .any(|w| w.starts_with("of=/dev/") || w.starts_with("if=/dev/"))
            })
        {
            return true;
        }
        if base == "find" && rest.contains(&"-delete") {
            return true;
        }
        if matches!(base, "rm" | "remove-item") && has_rec_and_force_flags(rest) {
            return true;
        }
    }
    false
}

pub(crate) fn has_destructive_command(cmd: &str) -> bool {
    cmd.split([';', '\n', '|', '&', '(', ')', '`'])
        .any(is_destructive_segment)
}

fn is_env_assignment_tok(tok: &str) -> bool {
    if let Some((lhs, _)) = tok.split_once('=') {
        !lhs.is_empty() && lhs.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    } else {
        false
    }
}

fn unwrap_pipe_cmd_name(tok: &str) -> &str {
    tok.trim_start_matches('\\')
        .rsplit('/')
        .next()
        .unwrap_or(tok)
}

fn pipe_stage_command(rest: &str) -> String {
    let after_amp = rest.strip_prefix('&').unwrap_or(rest).trim_start();
    let mut tokens = after_amp.split_ascii_whitespace();
    let mut skip_flags = false;
    while let Some(raw_tok) = tokens.next() {
        let clean = unquote_pipe_token(raw_tok);
        if clean.is_empty() {
            continue;
        }
        if skip_flags {
            if clean == "--" {
                skip_flags = false;
                continue;
            }
            if matches!(clean.as_str(), "-I" | "-u" | "-n" | "-C") {
                let _ = tokens.next();
                continue;
            }
            if clean.starts_with('-') {
                continue;
            }
        }
        if is_env_assignment_tok(&clean) {
            continue;
        }
        let base = unwrap_pipe_cmd_name(&clean).to_owned();
        if matches!(
            base.as_str(),
            "env" | "sudo" | "doas" | "command" | "nohup" | "exec" | "xargs"
        ) {
            skip_flags = true;
            continue;
        }
        return base;
    }
    String::new()
}

pub(crate) fn has_pipe_to_shell(s: &str) -> bool {
    let shell_proc = ["bash <(", "sh <(", "zsh <(", "/bin/sh <(", "/bin/bash <("];
    if shell_proc.iter().any(|p| s.contains(p)) {
        return true;
    }
    let bytes = s.as_bytes();
    for (idx, &b) in bytes.iter().enumerate() {
        if b != b'|' {
            continue;
        }
        if bytes.get(idx.saturating_add(1)) == Some(&b'|')
            || idx.checked_sub(1).and_then(|i| bytes.get(i)) == Some(&b'|')
        {
            continue;
        }
        let rest = s.get(idx.saturating_add(1)..).unwrap_or("").trim_start();
        let base = pipe_stage_command(rest);
        if matches!(
            base.as_str(),
            "sh" | "bash" | "zsh" | "dash" | "ash" | "ksh" | "fish" | "pwsh" | "powershell" | "iex"
        ) {
            return true;
        }
    }
    false
}

fn unquote_pipe_token(tok: &str) -> String {
    let trimmed = tok.trim_start_matches(['(', '{']);
    let head = trimmed
        .split([';', '&', '|', '<', '>', ')', '}'])
        .next()
        .unwrap_or("");
    head.chars().filter(|&c| c != '\'' && c != '"').collect()
}

fn extract_url_hosts(s: &str) -> Vec<&str> {
    let mut hosts = Vec::new();
    for tok in s.split(|c: char| c.is_ascii_whitespace() || matches!(c, '"' | '\'')) {
        let Some(rel) = tok.find("://") else {
            continue;
        };
        let scheme = tok.get(..rel).unwrap_or("");
        if scheme.is_empty()
            || !scheme
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'-' | b'.'))
        {
            continue;
        }
        let after = tok.get(rel.saturating_add(3)..).unwrap_or("");
        let end = after.find(['/', '?', '#']).unwrap_or(after.len());
        let auth = after.get(..end).unwrap_or("");
        let host_port = auth.rsplit('@').next().unwrap_or(auth);
        let host = if host_port.starts_with('[') {
            host_port
                .trim_start_matches('[')
                .split(']')
                .next()
                .unwrap_or(host_port)
        } else {
            host_port.split(':').next().unwrap_or(host_port)
        };
        if !host.is_empty() {
            hosts.push(host);
        }
    }
    hosts
}

fn host_matches(host: &str, domain: &str) -> bool {
    host == domain
        || host
            .strip_suffix(domain)
            .is_some_and(|prefix| prefix.ends_with('.'))
}

pub(crate) fn detect_cloud_provider(raw: &str, norm: &str) -> String {
    let mut hosts = extract_url_hosts(raw);
    hosts.extend(extract_url_hosts(norm));
    if !hosts.is_empty() {
        for host in hosts {
            if matches!(
                host,
                "169.254.169.254"
                    | "169.254.170.2"
                    | "0xa9fea9fe"
                    | "fd00:ec2::254"
                    | "fd00:0ec2::254"
                    | "::ffff:169.254.169.254"
            ) || host_matches(host, "amazonaws.com")
                || host_matches(host, "aws.amazon.com")
            {
                return "aws".into();
            }
            if host_matches(host, "metadata.google.internal")
                || host_matches(host, "googleapis.com")
            {
                return "gcp".into();
            }
            if host_matches(host, "azure.com") {
                return "azure".into();
            }
        }
        return String::new();
    }
    if contains_path_segment(raw, "aws")
        || contains_path_segment(norm, "aws")
        || contains_path_segment(raw, "amazonaws.com")
        || contains_any(
            raw,
            norm,
            &[
                "169.254.169.254",
                "169.254.170.2",
                "0xa9fea9fe",
                "fd00:ec2::254",
                "fd00:0ec2::254",
                "::ffff:169.254.169.254",
            ],
        )
    {
        "aws".into()
    } else if contains_path_segment(raw, "gcloud")
        || contains_path_segment(raw, "metadata.google.internal")
    {
        "gcp".into()
    } else if contains_path_segment(raw, "az") || contains_path_segment(raw, "azure.com") {
        "azure".into()
    } else {
        String::new()
    }
}

pub(crate) fn detect_llm_provider(raw: &str, norm: &str) -> String {
    let mut hosts = extract_url_hosts(raw);
    hosts.extend(extract_url_hosts(norm));
    if !hosts.is_empty() {
        for host in hosts {
            if host_matches(host, "anthropic.com") || host_matches(host, "claude.ai") {
                return "anthropic".into();
            }
            if host_matches(host, "openai.com") {
                return "openai".into();
            }
            if matches!(host, "localhost" | "127.0.0.1" | "::1") {
                return "local".into();
            }
        }
        return "unknown".into();
    }
    if contains_path_segment(raw, "anthropic.com")
        || contains_path_segment(raw, "claude.ai")
        || contains_path_segment(raw, "anthropic")
        || contains_path_segment(raw, "claude")
    {
        "anthropic".into()
    } else if contains_path_segment(raw, "openai.com") || contains_path_segment(raw, "openai") {
        "openai".into()
    } else if contains_path_segment(raw, "ollama")
        || contains_path_segment(raw, "llamafile")
        || contains_path_segment(raw, "localhost")
        || contains_path_segment(raw, "127.0.0.1")
    {
        "local".into()
    } else {
        "unknown".into()
    }
}

fn split_camel_and_sep(raw: &str) -> Vec<String> {
    let mut tokens = Vec::new();
    let mut cur = String::new();
    let mut prev_lower = false;
    for ch in raw.chars() {
        if !ch.is_ascii_alphanumeric() {
            if !cur.is_empty() {
                tokens.push(std::mem::take(&mut cur));
            }
            prev_lower = false;
            continue;
        }
        if prev_lower && ch.is_ascii_uppercase() && !cur.is_empty() {
            tokens.push(std::mem::take(&mut cur));
        }
        cur.push(ch.to_ascii_lowercase());
        prev_lower = ch.is_ascii_lowercase() || ch.is_ascii_digit();
    }
    if !cur.is_empty() {
        tokens.push(cur);
    }
    tokens
}

pub(crate) fn is_mcp_write_capable(
    raw_target: &str,
    read_only_hint: Option<bool>,
    has_write_risk_tag: bool,
) -> bool {
    if has_write_risk_tag || read_only_hint == Some(false) {
        return true;
    }
    let trimmed = raw_target.trim();
    let without_scheme = trimmed.split_once("://").map_or(trimmed, |(_, rest)| rest);
    let tool_name = if let Some((_, after_slash)) = without_scheme.rsplit_once('/') {
        after_slash.split(':').next().unwrap_or(after_slash)
    } else if let Some((_, after_dot)) = without_scheme.rsplit_once('.') {
        after_dot
    } else {
        without_scheme
    };
    let write_tokens = [
        "write", "delete", "del", "push", "create", "execute", "exec", "shell", "run", "update",
        "put", "post", "patch", "remove", "rm", "drop", "send", "upload", "publish", "modify",
        "edit", "set", "add", "append", "insert", "mutate", "apply", "invoke", "trigger",
        "dispatch", "deploy", "email", "forward", "reply", "merge", "commit", "chmod", "chown",
        "kill", "eval", "sql",
    ];
    let read_tokens = [
        "read", "get", "list", "search", "query", "describe", "inspect", "status", "ping",
        "version", "fetch", "view", "info",
    ];
    let tokens = split_camel_and_sep(tool_name);
    if tokens.iter().any(|t| write_tokens.contains(&t.as_str())) {
        return true;
    }
    if read_only_hint == Some(true) {
        return false;
    }
    !tokens.iter().any(|t| read_tokens.contains(&t.as_str()))
}
