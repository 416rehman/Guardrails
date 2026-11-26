// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Sound `D-12` compile-down fragments for Claude Code managed settings and Codex requirements.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{Effect, PolicySet};
use grdr_model::{ActionClass, Mode, PolicyPack, PolicyRule, RemedyCapability};

pub use super::compile_down_verify::{
    render_claude_settings_json, render_codex_requirements_toml, verify_compile_down_subset,
};
use super::compiler::CompiledRuleMeta;
use super::lint::extract_policy_actions;
use super::lint_scan::{cedar_body_slice, strip_comments_and_strings};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum CompileDownSkipReason {
    NotBlockMode,
    NotFinal,
    NotLocked,
    HasUnlessClause,
    RequiresSessionState,
    UnsupportedDynamicPredicate,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileDownSkip {
    pub rule_id: String,
    pub reason: CompileDownSkipReason,
}

// grdr:allow-s4 independent Claude Code managed-settings JSON booleans
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ClaudeCodeManagedSettings {
    pub disable_bypass_permissions_mode: &'static str,
    pub allow_managed_permission_rules_only: bool,
    pub allow_managed_hooks_only: bool,
    pub allow_managed_mcp_servers_only: bool,
    pub deny_rules: Vec<String>,
    pub compiled_rule_ids: Vec<String>,
    pub skipped: Vec<CompileDownSkip>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CodexRequirements {
    pub approval_policy: &'static str,
    pub sandbox_mode: &'static str,
    pub mcp_deny_patterns: Vec<String>,
    pub prefix_rules: Vec<String>,
    pub compiled_rule_ids: Vec<String>,
    pub skipped: Vec<CompileDownSkip>,
}

pub fn compile_down_claude_code(
    packs: &[PolicyPack],
    metas: &[CompiledRuleMeta],
) -> ClaudeCodeManagedSettings {
    let meta_index = build_meta_map(metas);
    let mut deny_rules = BTreeSet::new();
    let mut compiled_rule_ids = Vec::new();
    let mut skipped = Vec::new();

    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            if let Some(reason) = eligibility_gap(rule, &meta_index) {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason,
                });
                continue;
            }
            let patterns = claude_patterns_for_rule(rule);
            if patterns.is_empty() {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
                });
                continue;
            }
            for pat in patterns {
                deny_rules.insert(pat);
            }
            compiled_rule_ids.push(rule.id.clone());
        }
    }

    ClaudeCodeManagedSettings {
        disable_bypass_permissions_mode: "disable",
        allow_managed_permission_rules_only: true,
        allow_managed_hooks_only: true,
        allow_managed_mcp_servers_only: true,
        deny_rules: deny_rules.into_iter().collect(),
        compiled_rule_ids,
        skipped,
    }
}

pub fn compile_down_codex(packs: &[PolicyPack], metas: &[CompiledRuleMeta]) -> CodexRequirements {
    let meta_index = build_meta_map(metas);
    let mut prefix_rules = BTreeSet::new();
    let mut mcp_deny_patterns = BTreeSet::new();
    let mut compiled_rule_ids = Vec::new();
    let mut skipped = Vec::new();

    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            if let Some(reason) = eligibility_gap(rule, &meta_index) {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason,
                });
                continue;
            }
            let (cmds, mcps) = codex_patterns_for_rule(rule);
            if cmds.is_empty() && mcps.is_empty() {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
                });
                continue;
            }
            for cmd in cmds {
                prefix_rules.insert(cmd);
            }
            for mcp in mcps {
                mcp_deny_patterns.insert(mcp);
            }
            compiled_rule_ids.push(rule.id.clone());
        }
    }

    CodexRequirements {
        approval_policy: "on-request",
        sandbox_mode: "workspace-write",
        mcp_deny_patterns: mcp_deny_patterns.into_iter().collect(),
        prefix_rules: prefix_rules.into_iter().collect(),
        compiled_rule_ids,
        skipped,
    }
}

fn meta_eligibility_gap(m: &CompiledRuleMeta) -> Option<CompileDownSkipReason> {
    if m.mode != Mode::Block {
        return Some(CompileDownSkipReason::NotBlockMode);
    }
    if !m.locked {
        return Some(CompileDownSkipReason::NotLocked);
    }
    if !m.is_final {
        return Some(CompileDownSkipReason::NotFinal);
    }
    if m.has_unless {
        return Some(CompileDownSkipReason::HasUnlessClause);
    }
    if !m.stateless {
        return Some(CompileDownSkipReason::RequiresSessionState);
    }
    if m.remedy != RemedyCapability::Plain || !m.protect_list.is_empty() || !m.allow_list.is_empty()
    {
        return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
    }
    None
}

fn eligibility_gap(
    rule: &PolicyRule,
    meta_index: &BTreeMap<&str, &CompiledRuleMeta>,
) -> Option<CompileDownSkipReason> {
    if rule.mode != Mode::Block {
        return Some(CompileDownSkipReason::NotBlockMode);
    }
    if !rule.locked {
        return Some(CompileDownSkipReason::NotLocked);
    }
    if !rule.matcher.agents.is_empty()
        || rule.matcher.action_classes.is_empty()
        || rule.matcher.action_classes.contains(&ActionClass::Exec)
    {
        return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
    }

    if let Some(raw_cedar) = rule.cedar.as_deref().filter(|s| !s.trim().is_empty()) {
        let Ok(parsed_set) = PolicySet::from_str(raw_cedar) else {
            return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
        };
        let mut policies = parsed_set.policies();
        let (Some(policy), None) = (policies.next(), policies.next()) else {
            return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
        };
        if policy.effect() != Effect::Forbid || policy.annotation("remedy").is_some() {
            return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
        }
        let effective_id = policy.annotation("id").unwrap_or(&rule.id);
        let meta = meta_index
            .get(effective_id)
            .copied()
            .or_else(|| meta_index.get(rule.id.as_str()).copied());
        if let Some(reason) = meta.and_then(meta_eligibility_gap) {
            return Some(reason);
        }
        if policy.annotation("final") != Some("true") {
            return Some(CompileDownSkipReason::NotFinal);
        }
        let canonical = policy.to_string();
        let cedar_actions = extract_policy_actions(&canonical);
        if cedar_actions.is_empty()
            || !rule
                .matcher
                .action_classes
                .iter()
                .all(|a| cedar_actions.contains(a))
            || !cedar_actions
                .iter()
                .all(|a| rule.matcher.action_classes.contains(a))
        {
            return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
        }
        let body = strip_comments_and_strings(cedar_body_slice(&canonical), false);
        if body.contains("unless") {
            return Some(CompileDownSkipReason::HasUnlessClause);
        }
        if body.contains("context.session") {
            return Some(CompileDownSkipReason::RequiresSessionState);
        }
        let unsupported = [
            "context.",
            "principal in",
            "principal.",
            "principal is Grdr::Process",
            "resource.in_workspace",
            "resource.port",
            "resource.identity_pinned",
            "resource.manifest_pinned",
            "resource.write_capable",
            "resource.provider",
            "resource.transport",
            "resource.kind",
            "resource.digest_pinned",
            "resource.has_scripts",
            "resource.requests_broad_tools",
            "resource.bidi_obfuscation",
            " like ",
            "Grdr::Action::\"exec\"",
        ];
        if unsupported.iter().any(|tok| body.contains(tok)) {
            return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
        }
    } else if let Some(reason) = meta_index
        .get(rule.id.as_str())
        .copied()
        .and_then(meta_eligibility_gap)
    {
        return Some(reason);
    }
    None
}

fn claude_patterns_for_rule(rule: &PolicyRule) -> Vec<String> {
    let mut out = Vec::new();
    let has_edit_pair = rule
        .matcher
        .action_classes
        .contains(&ActionClass::FileWrite)
        && rule
            .matcher
            .action_classes
            .contains(&ActionClass::FileDelete);
    let has_net_pair = rule
        .matcher
        .action_classes
        .contains(&ActionClass::NetRequest)
        && rule
            .matcher
            .action_classes
            .contains(&ActionClass::NetConnect);
    for action in &rule.matcher.action_classes {
        if matches!(action, ActionClass::McpCall | ActionClass::McpConnect) {
            for pat in rule
                .matcher
                .target_prefixes
                .iter()
                .chain(&rule.matcher.target_contains)
            {
                if let Some(mcp) = format_claude_mcp_pattern(pat) {
                    out.push(mcp);
                }
            }
            continue;
        }
        let tool = match action {
            ActionClass::FileRead => "Read",
            ActionClass::FileWrite if has_edit_pair => "Edit",
            ActionClass::NetRequest if has_net_pair => "WebFetch",
            _ => continue,
        };
        for prefix in &rule.matcher.target_prefixes {
            let p = prefix.trim();
            if !p.is_empty() {
                out.push(format!("{tool}({p}*)"));
            }
        }
        for contain in &rule.matcher.target_contains {
            let c = contain.trim();
            if !c.is_empty() {
                out.push(format!("{tool}(*{c}*)"));
            }
        }
    }
    out
}

pub(super) fn format_claude_mcp_pattern(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.starts_with("mcp__") {
        return Some(trimmed.to_string());
    }
    let clean = trimmed
        .split("://")
        .last()
        .unwrap_or(trimmed)
        .trim_matches(['/', '*']);
    if clean.is_empty() {
        return None;
    }
    if let Some((srv, tool)) = clean.split_once('.')
        && !srv.is_empty()
        && !tool.is_empty()
    {
        return Some(format!("mcp__{srv}__{tool}"));
    }
    Some(format!("mcp__{clean}__*"))
}

fn codex_patterns_for_rule(rule: &PolicyRule) -> (Vec<String>, Vec<String>) {
    let mut mcps = Vec::new();
    for action in &rule.matcher.action_classes {
        if matches!(action, ActionClass::McpCall | ActionClass::McpConnect) {
            for pat in rule
                .matcher
                .target_prefixes
                .iter()
                .chain(&rule.matcher.target_contains)
            {
                let clean = pat.trim();
                if !clean.is_empty() {
                    mcps.push(clean.to_string());
                }
            }
        }
    }
    (Vec::new(), mcps)
}

fn build_meta_map(metas: &[CompiledRuleMeta]) -> BTreeMap<&str, &CompiledRuleMeta> {
    let mut map = BTreeMap::new();
    for m in metas {
        map.insert(m.rule_id.as_str(), m);
    }
    map
}
