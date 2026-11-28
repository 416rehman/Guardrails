// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Sound `D-12` compile-down fragments for Claude Code managed settings and Codex requirements.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::{Effect, PolicySet};
use grdr_model::{ActionClass, Mode, PolicyPack, PolicyRule, RemedyCapability};

use super::compile_down_render::{codex_patterns_for_rule, validate_static_cedar_clauses};
use super::compile_down_targets::{CompileTargetProfile, default_compile_targets};
pub use super::compile_down_verify::{
    render_claude_settings_json, render_codex_requirements_toml, verify_compile_down_subset,
};
use super::compiler::CompiledRuleMeta;
use super::lint::extract_policy_actions;

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
    pub approval_policy: String,
    pub sandbox_mode: String,
    pub mcp_deny_patterns: Vec<String>,
    pub prefix_rules: Vec<String>,
    pub compiled_rule_ids: Vec<String>,
    pub skipped: Vec<CompileDownSkip>,
}

pub fn compile_down_claude_code(
    packs: &[PolicyPack],
    metas: &[CompiledRuleMeta],
) -> ClaudeCodeManagedSettings {
    let Some(profile) = default_compile_targets()
        .ok()
        .and_then(|list| list.into_iter().find(|p| p.id == "claude-code"))
    else {
        return ClaudeCodeManagedSettings {
            disable_bypass_permissions_mode: "disable",
            allow_managed_permission_rules_only: true,
            allow_managed_hooks_only: true,
            allow_managed_mcp_servers_only: true,
            deny_rules: Vec::new(),
            compiled_rule_ids: Vec::new(),
            skipped: collect_all_enabled_skips(packs),
        };
    };
    compile_down_claude_code_with_profile(&profile, packs, metas)
}

pub(super) fn compile_down_claude_code_with_profile(
    profile: &CompileTargetProfile,
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
            if let Some(reason) = eligibility_gap_for_target(
                rule,
                &meta_index,
                profile.supports_allow_overrides,
                profile.supports_exec_rules,
            ) {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason,
                });
                continue;
            }
            let meta_opt = resolve_meta(rule, &meta_index);
            let Some(patterns) = claude_patterns_for_rule(profile, rule, meta_opt) else {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
                });
                continue;
            };
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
    let Some(profile) = default_compile_targets()
        .ok()
        .and_then(|list| list.into_iter().find(|p| p.id == "codex"))
    else {
        return CodexRequirements {
            approval_policy: "on-request".into(),
            sandbox_mode: "workspace-write".into(),
            mcp_deny_patterns: Vec::new(),
            prefix_rules: Vec::new(),
            compiled_rule_ids: Vec::new(),
            skipped: collect_all_enabled_skips(packs),
        };
    };
    compile_down_codex_with_profile(&profile, packs, metas)
}

pub(super) fn compile_down_codex_with_profile(
    profile: &CompileTargetProfile,
    packs: &[PolicyPack],
    metas: &[CompiledRuleMeta],
) -> CodexRequirements {
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
            if let Some(reason) = eligibility_gap_for_target(
                rule,
                &meta_index,
                profile.supports_allow_overrides,
                profile.supports_exec_rules,
            ) {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason,
                });
                continue;
            }
            let meta_opt = resolve_meta(rule, &meta_index);
            let Some((cmds, mcps)) = codex_patterns_for_rule(profile, rule, meta_opt) else {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
                });
                continue;
            };
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
        approval_policy: profile
            .approval_policy
            .clone()
            .unwrap_or_else(|| "on-request".into()),
        sandbox_mode: profile
            .sandbox_mode
            .clone()
            .unwrap_or_else(|| "workspace-write".into()),
        mcp_deny_patterns: mcp_deny_patterns.into_iter().collect(),
        prefix_rules: prefix_rules.into_iter().collect(),
        compiled_rule_ids,
        skipped,
    }
}

fn collect_all_enabled_skips(packs: &[PolicyPack]) -> Vec<CompileDownSkip> {
    let mut skips = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            if rule.enabled && rule.mode != Mode::Off {
                skips.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
                });
            }
        }
    }
    skips
}

pub(super) fn resolve_meta<'a>(
    rule: &PolicyRule,
    meta_index: &BTreeMap<&str, &'a CompiledRuleMeta>,
) -> Option<&'a CompiledRuleMeta> {
    if let Some(raw_cedar) = rule.cedar.as_deref().filter(|s| !s.trim().is_empty())
        && let Ok(parsed_set) = PolicySet::from_str(raw_cedar)
        && let Some(policy) = parsed_set.policies().next()
        && let Some(id) = policy.annotation("id")
        && let Some(m) = meta_index.get(id).copied()
    {
        return Some(m);
    }
    meta_index.get(rule.id.as_str()).copied()
}

fn meta_eligibility_gap(
    m: &CompiledRuleMeta,
    supports_allow_overrides: bool,
) -> Option<CompileDownSkipReason> {
    if m.mode != Mode::Block {
        return Some(CompileDownSkipReason::NotBlockMode);
    }
    if !m.locked {
        return Some(CompileDownSkipReason::NotLocked);
    }
    if !m.is_final {
        return Some(CompileDownSkipReason::NotFinal);
    }
    if m.has_unless && (!supports_allow_overrides || m.allow_list.is_empty()) {
        return Some(CompileDownSkipReason::HasUnlessClause);
    }
    if !m.stateless {
        return Some(CompileDownSkipReason::RequiresSessionState);
    }
    if m.remedy != RemedyCapability::Plain
        || (!supports_allow_overrides && !m.allow_list.is_empty())
    {
        return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
    }
    None
}

pub(super) fn eligibility_gap_for_target(
    rule: &PolicyRule,
    meta_index: &BTreeMap<&str, &CompiledRuleMeta>,
    supports_allow_overrides: bool,
    supports_exec_rules: bool,
) -> Option<CompileDownSkipReason> {
    if rule.mode != Mode::Block {
        return Some(CompileDownSkipReason::NotBlockMode);
    }
    if !rule.locked {
        return Some(CompileDownSkipReason::NotLocked);
    }
    if !rule.matcher.agents.is_empty() || rule.matcher.action_classes.is_empty() {
        return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
    }
    if !supports_exec_rules && rule.matcher.action_classes.contains(&ActionClass::Exec) {
        return Some(CompileDownSkipReason::UnsupportedDynamicPredicate);
    }
    let meta = resolve_meta(rule, meta_index);
    let has_static_patterns = rule
        .matcher
        .target_prefixes
        .iter()
        .chain(&rule.matcher.target_contains)
        .any(|p| !p.trim().is_empty())
        || meta.is_some_and(|m| m.protect_list.iter().any(|p| !p.trim().is_empty()));
    if !has_static_patterns {
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
        if let Some(reason) = meta.and_then(|m| meta_eligibility_gap(m, supports_allow_overrides)) {
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
        let effective_id = policy.annotation("id").unwrap_or(&rule.id);
        return validate_static_cedar_clauses(
            &canonical,
            effective_id,
            &rule.id,
            supports_allow_overrides,
            meta.is_some_and(|m| !m.allow_list.is_empty()),
        );
    } else if let Some(reason) =
        meta.and_then(|m| meta_eligibility_gap(m, supports_allow_overrides))
    {
        return Some(reason);
    }
    None
}

fn all_actions_covered_by_claude(actions: &[ActionClass], supports_exec_rules: bool) -> bool {
    let has_edit_pair =
        actions.contains(&ActionClass::FileWrite) && actions.contains(&ActionClass::FileDelete);
    let has_net_pair =
        actions.contains(&ActionClass::NetRequest) && actions.contains(&ActionClass::NetConnect);
    !actions.is_empty()
        && actions.iter().all(|a| match a {
            ActionClass::FileRead | ActionClass::McpCall | ActionClass::McpConnect => true,
            ActionClass::FileWrite | ActionClass::FileDelete => has_edit_pair,
            ActionClass::NetRequest | ActionClass::NetConnect => has_net_pair,
            ActionClass::Exec => supports_exec_rules,
            _ => false,
        })
}

fn has_unsafe_claude_pattern_chars(raw: &str) -> bool {
    raw.contains(['(', ')', '\r', '\n', '\0'])
}

fn claude_patterns_for_rule(
    profile: &CompileTargetProfile,
    rule: &PolicyRule,
    meta: Option<&CompiledRuleMeta>,
) -> Option<Vec<String>> {
    if !all_actions_covered_by_claude(&rule.matcher.action_classes, profile.supports_exec_rules) {
        return None;
    }
    let read_tool = profile.read_tool.as_deref().unwrap_or("Read");
    let write_tool = profile.write_tool.as_deref().unwrap_or("Edit");
    let exec_tool = profile.exec_tool.as_deref().unwrap_or("Bash");
    let net_tool = profile.net_tool.as_deref().unwrap_or("WebFetch");
    let exec_suffix = profile.exec_pattern_suffix.as_deref().unwrap_or(":*");

    let mut out = Vec::new();
    let mut seen_edit = false;
    let mut seen_net = false;
    for action in &rule.matcher.action_classes {
        if matches!(action, ActionClass::McpCall | ActionClass::McpConnect) {
            for pat in rule
                .matcher
                .target_prefixes
                .iter()
                .chain(&rule.matcher.target_contains)
                .chain(meta.into_iter().flat_map(|m| m.protect_list.iter()))
            {
                if has_unsafe_claude_pattern_chars(pat) {
                    return None;
                }
                if let Some(mcp) = format_claude_mcp_pattern(pat) {
                    out.push(mcp);
                }
            }
            continue;
        }
        let tool = match action {
            ActionClass::FileRead => read_tool,
            ActionClass::FileWrite | ActionClass::FileDelete => {
                if seen_edit {
                    continue;
                }
                seen_edit = true;
                write_tool
            }
            ActionClass::Exec => exec_tool,
            ActionClass::NetRequest | ActionClass::NetConnect => {
                if seen_net {
                    continue;
                }
                seen_net = true;
                net_tool
            }
            _ => return None,
        };
        let is_exec = *action == ActionClass::Exec;
        for prefix in &rule.matcher.target_prefixes {
            let p = prefix.trim();
            if p.is_empty() {
                continue;
            }
            if has_unsafe_claude_pattern_chars(p) {
                return None;
            }
            let suffix = if is_exec { exec_suffix } else { "*" };
            out.push(format!("{tool}({p}{suffix})"));
        }
        for contain in &rule.matcher.target_contains {
            let c = contain.trim();
            if c.is_empty() {
                continue;
            }
            if has_unsafe_claude_pattern_chars(c) {
                return None;
            }
            out.push(format!("{tool}(*{c}*)"));
        }
        if let Some(m) = meta {
            for prot in &m.protect_list {
                let p = prot.trim();
                if p.is_empty() {
                    continue;
                }
                if has_unsafe_claude_pattern_chars(p) {
                    return None;
                }
                if is_exec && !p.contains('*') {
                    out.push(format!("{tool}({p}{exec_suffix})"));
                } else {
                    out.push(format!("{tool}({p})"));
                }
            }
        }
    }
    Some(out)
}

pub(super) fn format_claude_mcp_pattern(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || has_unsafe_claude_pattern_chars(trimmed) {
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

fn build_meta_map(metas: &[CompiledRuleMeta]) -> BTreeMap<&str, &CompiledRuleMeta> {
    let mut map = BTreeMap::new();
    for m in metas {
        map.insert(m.rule_id.as_str(), m);
    }
    map
}
