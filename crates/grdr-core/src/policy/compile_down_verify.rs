// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Rendering and conformance-subset verification helpers for `D-12` compile-down.

use grdr_model::{ActionAttempt, ActionClass, IdentityMode, KillSwitchState, PolicyPack, Verdict};
use jiff::Timestamp;

use super::caps::{DeterministicEntropy, default_control_point_caps};
use super::compile_down::{
    ClaudeCodeManagedSettings, CodexRequirements, format_claude_mcp_pattern,
};
use super::compile_down_render::escape_quoted_string;
use super::compiler::{CompileOptions, compile_packs_with_options};
use super::request::{ActorKind, RequestBuildOptions, build_cedar_request_with_options};
use super::verdict::{VerdictEvalConfig, resolve_verdict};

pub fn render_claude_settings_json(settings: &ClaudeCodeManagedSettings) -> String {
    let deny_list: Vec<String> = settings
        .deny_rules
        .iter()
        .map(|r| format!("\"{}\"", escape_quoted_string(r)))
        .collect();
    format!(
        "{{\n  \"disableBypassPermissionsMode\": \"{}\",\n  \"allowManagedPermissionRulesOnly\": {},\n  \"allowManagedHooksOnly\": {},\n  \"allowManagedMcpServersOnly\": {},\n  \"permissions\": {{\n    \"deny\": [{}]\n  }}\n}}",
        escape_quoted_string(settings.disable_bypass_permissions_mode),
        settings.allow_managed_permission_rules_only,
        settings.allow_managed_hooks_only,
        settings.allow_managed_mcp_servers_only,
        deny_list.join(", ")
    )
}

pub fn render_codex_requirements_toml(req: &CodexRequirements) -> String {
    let mut out = format!(
        "approval_policy = \"{}\"\nsandbox_mode = \"{}\"\n",
        escape_quoted_string(&req.approval_policy),
        escape_quoted_string(&req.sandbox_mode)
    );
    for pat in &req.prefix_rules {
        out.push_str(&format!(
            "\n[[rules]]\naction = \"forbid\"\npattern = \"{}\"\n",
            escape_quoted_string(pat)
        ));
    }
    for mcp in &req.mcp_deny_patterns {
        out.push_str(&format!(
            "\n[mcp_servers.\"{}\"]\nallowed = false\n",
            escape_quoted_string(mcp)
        ));
    }
    out
}

pub fn verify_compile_down_subset(
    packs: &[PolicyPack],
    probes: &[ActionAttempt],
    settings: &ClaudeCodeManagedSettings,
    now: Timestamp,
) -> bool {
    for identity_mode in [IdentityMode::Named, IdentityMode::Pseudonymous] {
        let Ok(bundle) = compile_packs_with_options(
            packs,
            &KillSwitchState::Inactive,
            "",
            "",
            &CompileOptions {
                identity_mode,
                ..CompileOptions::default()
            },
            now,
        ) else {
            return false;
        };
        let opts = RequestBuildOptions {
            identity_mode,
            actor_kind: ActorKind::Agent,
            ..RequestBuildOptions::default()
        };
        for attempt in probes {
            let native_blocked = settings
                .deny_rules
                .iter()
                .any(|pattern| claude_rule_matches_attempt(pattern, attempt));
            if !native_blocked {
                continue;
            }
            let Ok(built) = build_cedar_request_with_options(
                attempt,
                packs,
                &bundle.active_rules,
                &[],
                None,
                &opts,
                now,
            ) else {
                return false;
            };
            let cfg = VerdictEvalConfig {
                host_profile: opts.host_profile,
                device_max_grade: grdr_model::ApprovalGrade::G3,
                timelock_enabled: false,
                observer: opts.observer,
                caps: default_control_point_caps(attempt.control_point, None),
                modify_attempts: 0,
            };
            let mut entropy = DeterministicEntropy::from_seed_bytes(attempt.id.as_bytes());
            let Ok(resolved) = resolve_verdict(attempt, &bundle, &built, &cfg, &mut entropy) else {
                return false;
            };
            if resolved.verdict != Verdict::Deny {
                return false;
            }
        }
    }
    true
}

fn claude_rule_matches_attempt(rule: &str, attempt: &ActionAttempt) -> bool {
    if rule.starts_with("mcp__") {
        if !matches!(
            attempt.action_class,
            ActionClass::McpCall | ActionClass::McpConnect
        ) {
            return false;
        }
        let target_norm = format_claude_mcp_pattern(&attempt.target)
            .unwrap_or_else(|| attempt.target.trim().to_ascii_lowercase());
        let pat_lower = rule.to_ascii_lowercase();
        let target_lower = target_norm.to_ascii_lowercase();
        if let Some(prefix) = pat_lower.strip_suffix('*') {
            return target_lower.starts_with(prefix)
                || attempt.target.to_ascii_lowercase().starts_with(prefix);
        }
        return target_lower == pat_lower || attempt.target.to_ascii_lowercase() == pat_lower;
    }
    let Some((tool, inner)) = rule
        .split_once('(')
        .and_then(|(t, rest)| rest.strip_suffix(')').map(|p| (t, p)))
    else {
        return false;
    };
    let tool_matches = matches!(
        (tool, attempt.action_class),
        ("Read", ActionClass::FileRead)
            | ("Edit", ActionClass::FileWrite | ActionClass::FileDelete)
            | ("Bash", ActionClass::Exec)
            | (
                "WebFetch",
                ActionClass::NetRequest | ActionClass::NetConnect
            )
    );
    if !tool_matches {
        return false;
    }
    let norm = attempt.target.replace('\\', "/").to_ascii_lowercase();
    let pat = inner.replace('\\', "/").to_ascii_lowercase();
    if let Some(prefix) = pat.strip_suffix(":*") {
        return !prefix.is_empty() && norm.starts_with(prefix);
    }
    if pat.starts_with('*') && pat.ends_with('*') {
        let mid = pat.trim_matches('*');
        return !mid.is_empty() && norm.contains(mid);
    }
    if pat.ends_with('*') {
        let prefix = pat.trim_end_matches('*');
        if prefix.is_empty() {
            return false;
        }
        return norm.starts_with(prefix);
    }
    if pat.starts_with('*') {
        let suffix = pat.trim_start_matches('*');
        return !suffix.is_empty() && norm.ends_with(suffix);
    }
    !pat.is_empty() && norm == pat
}
