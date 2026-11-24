// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Pure path/command normalization and Cedar stub checks for the reference evaluator.

use grdr_model::{ActionAttempt, ActionClass, CommandParseStatus, PolicyRule};

const OPAQUE_PATTERNS: &[&str] = &[
    "$(",
    "`",
    "-encodedcommand",
    " -enc ",
    "eval ",
    "invoke-expression",
    "iex ",
    "frombase64string",
];

pub(crate) struct TargetSignals {
    pub(crate) normalized_target: String,
    pub(crate) command_status: CommandParseStatus,
    pub(crate) risk_score: u32,
    pub(crate) sensitive_credential: bool,
    pub(crate) external_network: bool,
}

struct RefNormalizedCommand {
    status: CommandParseStatus,
    canonical_text: String,
}

pub(crate) fn rule_is_final(rule: &PolicyRule) -> bool {
    if rule.locked {
        return true;
    }
    let Some(cedar) = rule.cedar.as_deref() else {
        return false;
    };
    let stripped: String = cedar.chars().filter(|c| !c.is_whitespace()).collect();
    stripped.contains("@final(\"true\")")
}

pub(crate) fn validate_inline_cedar_stub(source: &str) -> bool {
    let mut cleaned = String::with_capacity(source.len());
    for line in source.lines() {
        cleaned.push_str(line.split("//").next().unwrap_or(""));
        cleaned.push('\n');
    }
    let mut in_string = false;
    let mut escaped = false;
    let mut paren_depth: i32 = 0;
    let mut brace_depth: i32 = 0;
    for ch in cleaned.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        if in_string {
            if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }
        match ch {
            '"' => in_string = true,
            '(' => paren_depth = paren_depth.saturating_add(1),
            ')' => {
                paren_depth = paren_depth.saturating_sub(1);
                if paren_depth < 0 {
                    return false;
                }
            }
            '{' => brace_depth = brace_depth.saturating_add(1),
            '}' => {
                brace_depth = brace_depth.saturating_sub(1);
                if brace_depth < 0 {
                    return false;
                }
            }
            _ => {}
        }
    }
    if in_string || escaped || paren_depth != 0 || brace_depth != 0 {
        return false;
    }
    let trimmed = cleaned.trim();
    let compact: String = trimmed.chars().filter(|c| !c.is_whitespace()).collect();
    trimmed.ends_with(';') && compact.contains("forbid(") && !compact.contains("permit(")
}

pub(crate) fn analyze_attempt_signals(attempt: &ActionAttempt) -> TargetSignals {
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

    if matches_either(
        &raw_lower,
        &norm_lower,
        &[
            ".claude/",
            ".claude.json",
            ".cursor/",
            ".codex/",
            ".gemini/",
            "grdr-data/",
            "security/",
        ],
    ) {
        risk_score = risk_score.saturating_add(70);
    }
    let sensitive_credential = matches_either(
        &raw_lower,
        &norm_lower,
        &[
            ".ssh/",
            ".aws/",
            ".gnupg/",
            ".config/gh/",
            "id_rsa",
            "id_ed25519",
            ".env.production",
        ],
    );
    if sensitive_credential {
        risk_score = risk_score.saturating_add(65);
    }
    if matches_either(
        &raw_lower,
        &norm_lower,
        &[
            "--dangerously-skip-permissions",
            "--no-verify",
            "--disable-hooks",
            "grdr_disable",
        ],
    ) {
        risk_score = risk_score.saturating_add(75);
    }
    if matches_either(
        &raw_lower,
        &norm_lower,
        &[
            "rm -rf",
            "rm -fr",
            "remove-item -recurse -force",
            "git reset --hard",
            "mkfs.",
        ],
    ) || attempt.action_class == ActionClass::FileDelete
    {
        risk_score = risk_score.saturating_add(45);
    }
    if matches_either(
        &raw_lower,
        &norm_lower,
        &["sudo ", "doas ", "runas ", "verb runas"],
    ) || attempt.action_class == ActionClass::Elevate
    {
        risk_score = risk_score.saturating_add(50);
    }
    let external_network = matches_either(
        &raw_lower,
        &norm_lower,
        &[
            "curl ",
            "invoke-webrequest",
            "pastebin",
            "webhook.site",
            "transfer.sh",
        ],
    ) || matches!(
        attempt.action_class,
        ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
    );
    if external_network {
        risk_score = risk_score.saturating_add(30);
    }

    TargetSignals {
        normalized_target,
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

fn matches_either(raw: &str, normalized: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| raw.contains(needle) || normalized.contains(needle))
}

fn canonicalize_path_ref(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("file:///")
        .map(|rest| format!("/{rest}"))
        .or_else(|| trimmed.strip_prefix("file://").map(str::to_string))
        .unwrap_or_else(|| trimmed.to_string());
    let slashed = without_scheme.replace('\\', "/");
    let (prefix, rest) = extract_path_root_ref(&slashed);

    let mut stack: Vec<&str> = Vec::new();
    for seg in rest.split('/') {
        match seg {
            "" | "." => {}
            ".." => {
                let _ = stack.pop();
            }
            other => stack.push(other),
        }
    }
    if prefix.is_empty() && stack.is_empty() {
        return ".".into();
    }
    let joined = stack.join("/");
    if prefix.is_empty() {
        joined
    } else if joined.is_empty() {
        prefix
    } else {
        format!("{prefix}{joined}")
    }
}

fn extract_path_root_ref(slashed: &str) -> (String, &str) {
    if let Some(rest) = slashed.strip_prefix("~/") {
        return ("~/".into(), rest);
    }
    if let Some(rest) = slashed.strip_prefix('/') {
        return ("/".into(), rest);
    }
    let mut chars = slashed.chars();
    if let (Some(drive), Some(':'), Some('/')) = (chars.next(), chars.next(), chars.next())
        && drive.is_ascii_alphabetic()
    {
        let prefix = format!("{drive}:/");
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

    let padded = format!(" {canonical_text} ");
    let has_opaque = saw_subshell
        || OPAQUE_PATTERNS
            .iter()
            .any(|pat| padded.contains(pat) || canonical_text.contains(pat));
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
