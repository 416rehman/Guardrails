// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::{ActionAttempt, ActionClass};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetAnalysis {
    pub normalized_target: String,
    pub risk_tags: Vec<String>,
    pub risk_score: u32,
}

pub fn classify_attempt(attempt: &ActionAttempt) -> TargetAnalysis {
    classify_target(attempt.action_class, &attempt.target)
}

pub fn classify_target(action_class: ActionClass, target: &str) -> TargetAnalysis {
    let normalized_target = target.replace('\\', "/").to_ascii_lowercase();
    let mut risk_tags = Vec::new();
    let mut risk_score: u32 = 10;

    if contains_any(
        &normalized_target,
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

    if contains_any(
        &normalized_target,
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

    if contains_any(
        &normalized_target,
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

    if contains_any(
        &normalized_target,
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

    if contains_any(
        &normalized_target,
        &["sudo ", "doas ", "runas ", "verb runas"],
    ) || action_class == ActionClass::Elevate
    {
        risk_tags.push("privilege-escalation".into());
        risk_score = risk_score.saturating_add(50);
    }

    if contains_any(
        &normalized_target,
        &[
            "curl ",
            "invoke-webrequest",
            "pastebin",
            "webhook.site",
            "transfer.sh",
        ],
    ) || matches!(
        action_class,
        ActionClass::NetRequest | ActionClass::DataFlow
    ) {
        risk_tags.push("external-network".into());
        risk_score = risk_score.saturating_add(30);
    }

    if matches!(action_class, ActionClass::McpCall | ActionClass::McpConnect)
        && contains_any(&normalized_target, &["write", "delete", "push", "create"])
    {
        risk_tags.push("mcp-write".into());
        risk_score = risk_score.saturating_add(35);
    }

    TargetAnalysis {
        normalized_target,
        risk_tags,
        risk_score: risk_score.min(100),
    }
}

fn contains_any(haystack: &str, needles: &[&str]) -> bool {
    needles.iter().any(|needle| haystack.contains(needle))
}
