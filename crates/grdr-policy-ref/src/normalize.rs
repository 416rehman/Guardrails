// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Pure path/command normalization and Cedar stub checks for the reference evaluator.

use grdr_model::{ActionAttempt, ActionClass, CommandParseStatus};

use crate::list_yaml::default_ref_signal_lists;

pub(crate) struct TargetSignals {
    pub(crate) command_status: CommandParseStatus,
    pub(crate) risk_score: u32,
    pub(crate) sensitive_credential: bool,
    pub(crate) external_network: bool,
}

struct RefNormalizedCommand {
    status: CommandParseStatus,
    canonical_text: String,
}

pub(crate) fn analyze_attempt_signals(attempt: &ActionAttempt) -> TargetSignals {
    let Ok(lists) = default_ref_signal_lists() else {
        return TargetSignals {
            command_status: CommandParseStatus::Malformed,
            risk_score: 100,
            sensitive_credential: true,
            external_network: true,
        };
    };
    let raw_lower = attempt.target.replace('\\', "/").to_ascii_lowercase();
    let (normalized_target, command_status) =
        normalize_target_for_match(attempt.action_class, &attempt.target);
    let norm_lower = normalized_target.to_ascii_lowercase();
    let mut risk_score: u32 = 10;

    if command_status == CommandParseStatus::Malformed {
        risk_score = risk_score.saturating_add(75);
    } else if command_status == CommandParseStatus::Unresolved {
        risk_score = risk_score.saturating_add(55);
    }

    if matches_either(&raw_lower, &norm_lower, &lists.agent_control_risk_patterns) {
        risk_score = risk_score.saturating_add(70);
    }
    let sensitive_credential =
        matches_either(&raw_lower, &norm_lower, &lists.credential_risk_patterns);
    if sensitive_credential {
        risk_score = risk_score.saturating_add(65);
    }
    if matches_either(&raw_lower, &norm_lower, &lists.hook_bypass_risk_patterns) {
        risk_score = risk_score.saturating_add(75);
    }
    if matches_either(&raw_lower, &norm_lower, &lists.destructive_risk_patterns)
        || attempt.action_class == ActionClass::FileDelete
    {
        risk_score = risk_score.saturating_add(45);
    }
    if matches_either(
        &raw_lower,
        &norm_lower,
        &lists.privilege_escalation_patterns,
    ) || attempt.action_class == ActionClass::Elevate
    {
        risk_score = risk_score.saturating_add(50);
    }
    let external_network = matches_either(
        &raw_lower,
        &norm_lower,
        &lists.external_network_risk_patterns,
    ) || matches!(
        attempt.action_class,
        ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
    );
    if external_network {
        risk_score = risk_score.saturating_add(30);
    }

    TargetSignals {
        command_status,
        risk_score: risk_score.min(100),
        sensitive_credential,
        external_network,
    }
}

pub(crate) fn normalize_target_for_match(
    action_class: ActionClass,
    target: &str,
) -> (String, CommandParseStatus) {
    match action_class {
        ActionClass::FileRead
        | ActionClass::FileWrite
        | ActionClass::FileDelete
        | ActionClass::ConfigChange => {
            (canonicalize_path_ref(target), CommandParseStatus::Resolved)
        }
        ActionClass::Exec | ActionClass::Elevate => {
            let cmd = normalize_command_ref(target);
            (cmd.canonical_text, cmd.status)
        }
        _ => (
            target.trim().replace('\\', "/").to_ascii_lowercase(),
            CommandParseStatus::Resolved,
        ),
    }
}

fn matches_either(raw: &str, normalized: &str, needles: &[String]) -> bool {
    needles
        .iter()
        .any(|needle| raw.contains(needle.as_str()) || normalized.contains(needle.as_str()))
}

fn canonicalize_path_ref(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("file:///")
        .map(|rest| format!("/{rest}"))
        .or_else(|| {
            trimmed
                .strip_prefix("file://")
                .map(|rest| rest.trim().to_string())
        })
        .unwrap_or_else(|| trimmed.to_string());
    let slashed = without_scheme.replace('\\', "/");
    let (mut prefix, rest) = extract_path_root_ref(&slashed);

    let mut stack: Vec<&str> = Vec::new();
    let preserve_underflow = prefix.is_empty()
        || prefix.starts_with('~')
        || prefix.starts_with("//")
        || (prefix.len() == 2 && prefix.ends_with(':'));
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                if !stack.is_empty() && stack.last() != Some(&"..") {
                    let _ = stack.pop();
                } else if preserve_underflow {
                    stack.push("..");
                }
            }
            other => stack.push(other),
        }
    }
    let head = resolve_boundary_segments_ref(&mut prefix, &mut stack);
    let slice = stack.get(head..).unwrap_or(&[]);

    if prefix.is_empty() && slice.is_empty() {
        return ".".into();
    }
    let joined = slice.join("/");
    if prefix.is_empty() {
        let final_joined = joined.trim();
        if final_joined.is_empty() {
            ".".into()
        } else {
            final_joined.to_string()
        }
    } else {
        let final_joined = joined.trim_end();
        if final_joined.is_empty() {
            prefix
        } else {
            format!("{prefix}{final_joined}")
        }
    }
}

fn resolve_boundary_segments_ref(prefix: &mut String, stack: &mut Vec<&str>) -> usize {
    let mut head: usize = 0;
    loop {
        let mut changed = false;
        while stack.len() > head {
            let Some(tail) = stack.last().copied() else {
                break;
            };
            let trimmed_tail = if prefix.is_empty() && stack.len().saturating_sub(head) == 1 {
                tail.trim()
            } else {
                tail.trim_end()
            };
            match trimmed_tail {
                "" | "." => {
                    let _ = stack.pop();
                    changed = true;
                }
                ".." => {
                    let prior = stack.len().saturating_sub(head);
                    if prior >= 2 && stack.get(stack.len().saturating_sub(2)) != Some(&"..") {
                        let _ = stack.pop();
                        let _ = stack.pop();
                        changed = true;
                    } else {
                        break;
                    }
                }
                _ => break,
            }
        }
        if prefix.is_empty()
            && let Some(first) = stack.get(head).copied()
        {
            match first.trim_start() {
                "" => {
                    *prefix = "/".into();
                    head = head.saturating_add(1);
                    changed = true;
                }
                "." => {
                    head = head.saturating_add(1);
                    changed = true;
                }
                _ => {}
            }
        }
        if !changed {
            break;
        }
    }
    head
}

fn extract_path_root_ref(slashed: &str) -> (String, &str) {
    if let Some(rest) = slashed.strip_prefix("~/") {
        return ("~/".into(), rest);
    }
    if let Some(rest) = slashed.strip_prefix('~') {
        if let Some((user, tail)) = rest.split_once('/') {
            return (format!("~{user}/"), tail);
        }
        return (format!("~{rest}"), "");
    }
    if let Some(after_unc) = slashed.strip_prefix("//") {
        if let Some((srv, rest1)) = after_unc.split_once('/')
            && let Some((share, tail)) = rest1.split_once('/')
            && !srv.is_empty()
            && !share.is_empty()
        {
            return (format!("//{srv}/{share}/"), tail);
        }
        return ("//".into(), after_unc);
    }
    if let Some(rest) = slashed.strip_prefix('/') {
        return ("/".into(), rest);
    }
    let mut chars = slashed.chars();
    if let (Some(drive), Some(':'), third) = (chars.next(), chars.next(), chars.next())
        && drive.is_ascii_alphabetic()
    {
        if third == Some('/') {
            let prefix = format!("{drive}:/");
            let rest = slashed.strip_prefix(&prefix).unwrap_or("");
            return (prefix, rest);
        }
        let prefix = format!("{drive}:");
        let rest = slashed.strip_prefix(&prefix).unwrap_or("");
        return (prefix, rest);
    }
    (String::new(), slashed)
}

fn normalize_command_ref(raw: &str) -> RefNormalizedCommand {
    let mut quote_mode: Option<char> = None;
    let mut escaped = false;
    let mut current = String::new();
    let mut segments = Vec::new();
    let mut saw_subshell = false;

    let mut chars = raw.chars().peekable();
    while let Some(ch) = chars.next() {
        if escaped {
            current.push(ch);
            escaped = false;
            continue;
        }
        if let Some(q) = quote_mode {
            if q == '"' && ch == '\\' {
                escaped = true;
                continue;
            }
            if ch == q {
                quote_mode = None;
                continue;
            }
            if q == '"' && ((ch == '$' && chars.peek() == Some(&'(')) || ch == '`') {
                saw_subshell = true;
            }
            current.push(ch);
            continue;
        }
        match ch {
            '\\' => escaped = true,
            '\'' | '"' => quote_mode = Some(ch),
            '`' => {
                saw_subshell = true;
                current.push(ch);
            }
            '$' if chars.peek() == Some(&'(') => {
                saw_subshell = true;
                current.push(ch);
            }
            ';' | '\n' | '\r' => push_segment(&mut current, &mut segments),
            '&' => {
                if chars.peek() == Some(&'&') {
                    let _ = chars.next();
                }
                push_segment(&mut current, &mut segments);
            }
            '|' => {
                if chars.peek() == Some(&'|') {
                    let _ = chars.next();
                }
                push_segment(&mut current, &mut segments);
            }
            other => current.push(other),
        }
    }
    push_segment(&mut current, &mut segments);

    let canonical_text = if segments.is_empty() {
        collapse_ascii_ws(raw).to_ascii_lowercase()
    } else {
        segments.join(" ; ")
    };

    if quote_mode.is_some() || escaped {
        return RefNormalizedCommand {
            status: CommandParseStatus::Malformed,
            canonical_text,
        };
    }

    let Ok(lists) = default_ref_signal_lists() else {
        return RefNormalizedCommand {
            status: CommandParseStatus::Malformed,
            canonical_text,
        };
    };
    let padded = format!(" {canonical_text} ");
    let has_opaque = saw_subshell
        || lists
            .opaque_command_patterns
            .iter()
            .any(|pat| padded.contains(pat.as_str()) || canonical_text.contains(pat.as_str()));
    let status = if has_opaque {
        CommandParseStatus::Unresolved
    } else {
        CommandParseStatus::Resolved
    };
    RefNormalizedCommand {
        status,
        canonical_text,
    }
}

fn push_segment(current: &mut String, segments: &mut Vec<String>) {
    let collapsed = collapse_ascii_ws(current).to_ascii_lowercase();
    current.clear();
    if !collapsed.is_empty() {
        segments.push(collapsed);
    }
}

fn collapse_ascii_ws(raw: &str) -> String {
    let mut out = String::new();
    let mut prev_ws = false;
    for ch in raw.trim().chars() {
        if ch.is_ascii_whitespace() {
            if !prev_ws {
                out.push(' ');
                prev_ws = true;
            }
        } else {
            out.push(ch);
            prev_ws = false;
        }
    }
    out
}
