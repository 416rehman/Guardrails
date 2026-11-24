// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extracts typed Cedar resource classes, facts, and command classes from normalized attempts.

use std::collections::BTreeSet;

use grdr_model::{ActionAttempt, CommandParseStatus, Mode, PolicyPack};

use crate::analyze::TargetAnalysis;

const DESTRUCTIVE_PATTERNS: &[&str] = &[
    "rm -rf",
    "rm -fr",
    "remove-item -recurse -force",
    "git reset --hard",
    "mkfs.",
];

const EGRESS_EXFIL_PATTERNS: &[&str] = &[
    "curl ",
    "invoke-webrequest",
    "pastebin",
    "webhook.site",
    "transfer.sh",
];

// grdr:allow-s4 orthogonal command signal attributes
#[derive(Debug, Clone)]
pub(crate) struct CedarSignals {
    pub(crate) resource_classes: BTreeSet<String>,
    pub(crate) facts: BTreeSet<String>,
    pub(crate) command_classes: BTreeSet<String>,
    pub(crate) recursive: bool,
    pub(crate) in_workspace: bool,
    pub(crate) write_capable: bool,
}

pub(crate) fn extract_cedar_signals(
    attempt: &ActionAttempt,
    analysis: &TargetAnalysis,
    packs: &[PolicyPack],
) -> CedarSignals {
    let raw_lower = attempt.target.replace('\\', "/").to_ascii_lowercase();
    let norm_lower = analysis.normalized_target.to_ascii_lowercase();

    let mut resource_classes = BTreeSet::new();
    let mut facts = BTreeSet::new();
    let mut command_classes = BTreeSet::new();

    if analysis.command_status == CommandParseStatus::Malformed {
        facts.insert("exec.malformed".into());
    } else if analysis.command_status == CommandParseStatus::Unresolved {
        facts.insert("exec.opaque".into());
    }

    if analysis.risk_tags.iter().any(|t| t == "agent-control-file") {
        resource_classes.insert("agent-control".into());
        resource_classes.insert("grdr-control".into());
        resource_classes.insert("monitoring-config".into());
    }

    if analysis
        .risk_tags
        .iter()
        .any(|t| t == "sensitive-credential")
    {
        resource_classes.insert("cred-store".into());
        if contains_any(&raw_lower, &norm_lower, &[".ssh/", "id_rsa", "id_ed25519"]) {
            resource_classes.insert("private-key".into());
        }
    }

    if analysis.risk_tags.iter().any(|t| t == "hook-bypass") {
        if contains_any(
            &raw_lower,
            &norm_lower,
            &["--dangerously-skip-permissions", "--no-verify"],
        ) {
            facts.insert("flag.bypass-permissions".into());
        }
        if contains_any(&raw_lower, &norm_lower, &["--disable-hooks"]) {
            facts.insert("flag.hooks-disabled".into());
        }
        if contains_any(&raw_lower, &norm_lower, &["grdr_disable"]) {
            facts.insert("grdr.disable".into());
        }
        if !facts.contains("flag.bypass-permissions")
            && !facts.contains("flag.hooks-disabled")
            && !facts.contains("grdr.disable")
        {
            facts.insert("flag.bypass-permissions".into());
        }
    }

    if contains_any(&raw_lower, &norm_lower, DESTRUCTIVE_PATTERNS) {
        resource_classes.insert("destructive-delete".into());
        command_classes.insert("destructive-delete".into());
    }

    if analysis
        .risk_tags
        .iter()
        .any(|t| t == "privilege-escalation")
    {
        resource_classes.insert("privilege-elevate".into());
        command_classes.insert("privilege-elevate".into());
    }

    if contains_any(&raw_lower, &norm_lower, EGRESS_EXFIL_PATTERNS) {
        resource_classes.insert("egress-exfil".into());
        command_classes.insert("egress-exfil".into());
    }

    let write_capable = analysis.risk_tags.iter().any(|t| t == "mcp-write");
    if write_capable {
        resource_classes.insert("mcp-write".into());
    }

    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            if target_matches_rule_lists(
                &raw_lower,
                &norm_lower,
                &rule.matcher.target_prefixes,
                &rule.matcher.target_contains,
            ) {
                resource_classes.insert(format!("match:{}", rule.id));
            }
        }
    }

    let recursive = contains_any(&raw_lower, &norm_lower, &["-rf", "-fr", "-r ", "-recurse"]);
    let in_workspace = !norm_lower.starts_with('/')
        && !norm_lower.starts_with("~/")
        && !norm_lower.contains(":/")
        && !norm_lower.starts_with("..");

    CedarSignals {
        resource_classes,
        facts,
        command_classes,
        recursive,
        in_workspace,
        write_capable,
    }
}

fn target_matches_rule_lists(
    raw_lower: &str,
    norm_lower: &str,
    prefixes: &[String],
    contains: &[String],
) -> bool {
    let prefix_hit = prefixes.iter().any(|prefix| {
        let p = prefix.replace('\\', "/").to_ascii_lowercase();
        !p.is_empty() && (raw_lower.starts_with(&p) || norm_lower.starts_with(&p))
    });
    let contains_hit = contains.iter().any(|needle| {
        let n = needle.replace('\\', "/").to_ascii_lowercase();
        !n.is_empty() && (raw_lower.contains(&n) || norm_lower.contains(&n))
    });
    prefix_hit || contains_hit
}

fn contains_any(raw_lower: &str, norm_lower: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| raw_lower.contains(needle) || norm_lower.contains(needle))
}
