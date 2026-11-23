// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::{ActionAttempt, ActionClass, CommandParseStatus};

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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NormalizedCommand {
    pub status: CommandParseStatus,
    pub segments: Vec<String>,
    pub canonical_text: String,
    pub opaque: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAnalysis {
    pub normalized_target: String,
    pub command_status: CommandParseStatus,
    pub risk_tags: Vec<String>,
    pub risk_score: u32,
}

pub fn classify_attempt(attempt: &ActionAttempt) -> TargetAnalysis {
    classify_target(attempt.action_class, &attempt.target)
}

pub fn normalize_attempt_target(
    action_class: ActionClass,
    target: &str,
) -> (String, CommandParseStatus) {
    match action_class {
        ActionClass::Exec | ActionClass::Elevate => {
            let cmd = normalize_command(target);
            (cmd.canonical_text, cmd.status)
        }
        ActionClass::FileRead
        | ActionClass::FileWrite
        | ActionClass::FileDelete
        | ActionClass::ConfigChange => (canonicalize_path(target), CommandParseStatus::Resolved),
        _ => (
            target.trim().replace('\\', "/").to_ascii_lowercase(),
            CommandParseStatus::Resolved,
        ),
    }
}

pub fn canonicalize_path(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_scheme = trimmed
        .strip_prefix("file:///")
        .map(|rest| format!("/{rest}"))
        .or_else(|| trimmed.strip_prefix("file://").map(str::to_string))
        .unwrap_or_else(|| trimmed.to_string());

    let slashed = without_scheme.replace('\\', "/");
    let (prefix, rest) = extract_path_root(&slashed);

    let mut stack: Vec<&str> = Vec::new();
    for segment in rest.split('/') {
        match segment {
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

pub fn normalize_command(raw: &str) -> NormalizedCommand {
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
            '\\' => {
                escaped = true;
            }
            '\'' | '"' => {
                quote_mode = Some(ch);
            }
            '`' => {
                saw_subshell = true;
                current.push(ch);
            }
            '$' if chars.peek() == Some(&'(') => {
                saw_subshell = true;
                current.push(ch);
            }
            ';' | '\n' | '\r' => {
                push_segment(&mut current, &mut segments);
            }
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
        return NormalizedCommand {
            status: CommandParseStatus::Malformed,
            segments,
            canonical_text,
            opaque: true,
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

    NormalizedCommand {
        status,
        segments,
        canonical_text,
        opaque: has_opaque,
    }
}

pub fn classify_target(action_class: ActionClass, target: &str) -> TargetAnalysis {
    let raw_lower = target.replace('\\', "/").to_ascii_lowercase();
    let (normalized_target, command_status) = normalize_attempt_target(action_class, target);
    let normalized_lower = normalized_target.to_ascii_lowercase();
    let mut risk_tags = Vec::new();
    let mut risk_score: u32 = 10;

    if command_status == CommandParseStatus::Malformed {
        risk_tags.push("exec.malformed".into());
        risk_score = risk_score.saturating_add(75);
    } else if command_status == CommandParseStatus::Unresolved {
        risk_tags.push("exec.opaque".into());
        risk_score = risk_score.saturating_add(55);
    }

    if matches_either(
        &raw_lower,
        &normalized_lower,
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
        risk_tags.push("agent-control-file".into());
        risk_score = risk_score.saturating_add(70);
    }

    if matches_either(
        &raw_lower,
        &normalized_lower,
        &[
            ".ssh/",
            ".aws/",
            ".gnupg/",
            ".config/gh/",
            "id_rsa",
            "id_ed25519",
            ".env.production",
        ],
    ) {
        risk_tags.push("sensitive-credential".into());
        risk_score = risk_score.saturating_add(65);
    }

    if matches_either(
        &raw_lower,
        &normalized_lower,
        &[
            "--dangerously-skip-permissions",
            "--no-verify",
            "--disable-hooks",
            "grdr_disable",
        ],
    ) {
        risk_tags.push("hook-bypass".into());
        risk_score = risk_score.saturating_add(75);
    }

    if matches_either(
        &raw_lower,
        &normalized_lower,
        &[
            "rm -rf",
            "rm -fr",
            "remove-item -recurse -force",
            "git reset --hard",
            "mkfs.",
        ],
    ) || action_class == ActionClass::FileDelete
    {
        risk_tags.push("destructive-action".into());
        risk_score = risk_score.saturating_add(45);
    }

    if matches_either(
        &raw_lower,
        &normalized_lower,
        &["sudo ", "doas ", "runas ", "verb runas"],
    ) || action_class == ActionClass::Elevate
    {
        risk_tags.push("privilege-escalation".into());
        risk_score = risk_score.saturating_add(50);
    }

    if matches_either(
        &raw_lower,
        &normalized_lower,
        &[
            "curl ",
            "invoke-webrequest",
            "pastebin",
            "webhook.site",
            "transfer.sh",
        ],
    ) || matches!(
        action_class,
        ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
    ) {
        risk_tags.push("external-network".into());
        risk_score = risk_score.saturating_add(30);
    }

    if matches!(action_class, ActionClass::McpCall | ActionClass::McpConnect)
        && matches_either(
            &raw_lower,
            &normalized_lower,
            &["write", "delete", "push", "create", "execute"],
        )
    {
        risk_tags.push("mcp-write".into());
        risk_score = risk_score.saturating_add(35);
    }

    TargetAnalysis {
        normalized_target,
        command_status,
        risk_tags,
        risk_score: risk_score.min(100),
    }
}

fn extract_path_root(slashed: &str) -> (String, &str) {
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

fn matches_either(raw: &str, normalized: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| raw.contains(needle) || normalized.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn path_canonicalizer_resolves_dot_segments_and_separators() {
        assert_eq!(
            canonicalize_path("workspace/repo/../../.claude/settings.json"),
            ".claude/settings.json"
        );
        assert_eq!(
            canonicalize_path(r"C:\Users\dev\..\dev\.ssh\id_rsa"),
            "C:/Users/dev/.ssh/id_rsa"
        );
        assert_eq!(
            canonicalize_path("file:///home/dev/./proj/../.ssh/id_rsa"),
            "/home/dev/.ssh/id_rsa"
        );
    }

    #[test]
    fn command_normalizer_strips_quotes_splits_chains_and_flags_opaque() {
        let quoted = normalize_command(r#"r"m" -rf /tmp/scratch && git status"#);
        assert_eq!(quoted.status, CommandParseStatus::Resolved);
        assert!(!quoted.opaque);
        assert_eq!(quoted.segments, vec!["rm -rf /tmp/scratch", "git status"]);
        assert_eq!(quoted.canonical_text, "rm -rf /tmp/scratch ; git status");

        let opaque = normalize_command("powershell -EncodedCommand ZQBjAGgAbwA=");
        assert_eq!(opaque.status, CommandParseStatus::Unresolved);
        assert!(opaque.opaque);

        let subshell = normalize_command("echo $(cat ~/.ssh/id_rsa)");
        assert_eq!(subshell.status, CommandParseStatus::Unresolved);
        assert!(subshell.opaque);

        let malformed = normalize_command(r#"bash -c "echo unclosed"#);
        assert_eq!(malformed.status, CommandParseStatus::Malformed);
        assert!(malformed.opaque);
    }

    #[test]
    fn classify_target_catches_traversal_and_quoted_obfuscation() {
        let traversal = classify_target(
            ActionClass::FileWrite,
            "src/app/../../../.claude/settings.json",
        );
        assert!(
            traversal
                .risk_tags
                .iter()
                .any(|t| t == "agent-control-file")
        );

        let obfuscated = classify_target(ActionClass::Exec, r#"s'u'do cat /etc/shadow"#);
        assert!(
            obfuscated
                .risk_tags
                .iter()
                .any(|t| t == "privilege-escalation")
        );
    }
}
