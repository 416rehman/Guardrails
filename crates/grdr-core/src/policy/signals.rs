// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Extracts typed Cedar resource classes, facts, sinks, and command classes from normalized attempts.

use std::collections::BTreeSet;

use grdr_model::{ActionAttempt, ActionClass, CommandParseStatus, Mode, PolicyPack};

use super::request::RequestBuildOptions;
use super::signals_scan::{
    contains_any, contains_path_segment, detect_cloud_provider_with_catalog,
    detect_llm_provider_with_catalog, has_destructive_command, has_pipe_to_shell,
    has_traversal_segment, is_mcp_write_capable_with_catalog,
};
use crate::analyze::TargetAnalysis;
use crate::analyze::pack_lists::{
    NetEndpointCatalog, SignalPatternCatalog, default_net_endpoint_catalog,
    default_signal_pattern_catalog,
};

// grdr:allow-s4 orthogonal command signal attributes
#[derive(Debug, Clone)]
pub(crate) struct CedarSignals {
    pub(crate) resource_classes: BTreeSet<String>,
    pub(crate) facts: BTreeSet<String>,
    pub(crate) command_classes: BTreeSet<String>,
    pub(crate) sink_classes: BTreeSet<String>,
    pub(crate) http_classes: BTreeSet<String>,
    pub(crate) cloud_provider: String,
    pub(crate) cloud_account_classes: BTreeSet<String>,
    pub(crate) cloud_tenant_classes: BTreeSet<String>,
    pub(crate) mcp_arg_classes: BTreeSet<String>,
    pub(crate) llm_provider: String,
    pub(crate) llm_tenant_classes: BTreeSet<String>,
    pub(crate) recursive: bool,
    pub(crate) in_workspace: bool,
    pub(crate) write_capable: bool,
}

pub(crate) fn extract_cedar_signals(
    attempt: &ActionAttempt,
    analysis: &TargetAnalysis,
    packs: &[PolicyPack],
    opts: &RequestBuildOptions,
) -> Result<CedarSignals, super::PolicyError> {
    let signals = default_signal_pattern_catalog().map_err(|detail| {
        super::PolicyError::RequestBuildFailed {
            detail: detail.to_owned(),
        }
    })?;
    let endpoints = default_net_endpoint_catalog().map_err(|detail| {
        super::PolicyError::RequestBuildFailed {
            detail: detail.to_owned(),
        }
    })?;
    Ok(extract_cedar_signals_with_catalogs(
        attempt, analysis, packs, opts, signals, endpoints,
    ))
}

pub(crate) fn extract_cedar_signals_with_catalogs(
    attempt: &ActionAttempt,
    analysis: &TargetAnalysis,
    packs: &[PolicyPack],
    opts: &RequestBuildOptions,
    signals: &SignalPatternCatalog,
    endpoints: &NetEndpointCatalog,
) -> CedarSignals {
    let raw_lower = attempt.target.replace('\\', "/").to_ascii_lowercase();
    let norm_lower = analysis.normalized_target.to_ascii_lowercase();

    let mut resource_classes = BTreeSet::new();
    let mut facts = BTreeSet::new();
    let mut command_classes = BTreeSet::new();
    let mut sink_classes: BTreeSet<String> = BTreeSet::new();
    let mut http_classes = BTreeSet::new();
    let mut cloud_account_classes = BTreeSet::new();
    let mut cloud_tenant_classes = BTreeSet::new();
    let mut mcp_arg_classes = BTreeSet::new();
    let mut llm_tenant_classes = BTreeSet::new();

    if analysis.command_status == CommandParseStatus::Malformed {
        facts.insert("exec.malformed".into());
    } else if analysis.command_status == CommandParseStatus::Unresolved {
        facts.insert("exec.opaque".into());
    }

    if analysis.risk_tags.iter().any(|t| t == "agent-control-file")
        || signals.extra_control_segments.iter().any(|seg| {
            contains_path_segment(&raw_lower, seg) || contains_path_segment(&norm_lower, seg)
        })
        || (contains_any(&raw_lower, &norm_lower, &["security/"])
            || raw_lower.trim() == "security"
            || norm_lower.trim() == "security")
    {
        resource_classes.insert("agent-control".into());
        resource_classes.insert("grdr-control".into());
        resource_classes.insert("monitoring-config".into());
    }

    if contains_any(&raw_lower, &norm_lower, &["honeytoken"]) {
        resource_classes.insert("honeytoken".into());
    }

    if analysis
        .risk_tags
        .iter()
        .any(|t| t == "sensitive-credential")
        || signals.extra_cred_segments.iter().any(|seg| {
            contains_path_segment(&raw_lower, seg) || contains_path_segment(&norm_lower, seg)
        })
    {
        resource_classes.insert("cred-store".into());
        if contains_path_segment(&raw_lower, ".ssh")
            || contains_path_segment(&norm_lower, ".ssh")
            || contains_any(&raw_lower, &norm_lower, &["id_rsa", "id_ed25519"])
        {
            resource_classes.insert("private-key".into());
        }
    }

    if contains_any(&raw_lower, &norm_lower, &signals.secret_value_patterns) {
        resource_classes.insert("secret-material".into());
        facts.insert("content.secret".into());
    }

    if analysis.risk_tags.iter().any(|t| t == "hook-bypass")
        || contains_any(&raw_lower, &norm_lower, &signals.hook_bypass_risk_patterns)
    {
        if contains_any(&raw_lower, &norm_lower, &signals.bypass_permission_flags) {
            facts.insert("flag.bypass-permissions".into());
            command_classes.insert("flag.bypass-permissions".into());
        }
        if contains_any(&raw_lower, &norm_lower, &signals.hooks_disabled_flags) {
            facts.insert("flag.hooks-disabled".into());
        }
        if contains_any(&raw_lower, &norm_lower, &signals.no_sandbox_flags) {
            facts.insert("flag.no-sandbox".into());
            command_classes.insert("flag.no-sandbox".into());
        }
        if contains_any(&raw_lower, &norm_lower, &signals.grdr_disable_flags) {
            facts.insert("grdr.disable".into());
        }
        if !facts.contains("flag.bypass-permissions")
            && !facts.contains("flag.hooks-disabled")
            && !facts.contains("flag.no-sandbox")
            && !facts.contains("grdr.disable")
        {
            facts.insert("flag.bypass-permissions".into());
            command_classes.insert("flag.bypass-permissions".into());
        }
    }

    if contains_any(&raw_lower, &norm_lower, &signals.destructive_patterns)
        || has_destructive_command(&raw_lower)
        || has_destructive_command(&norm_lower)
    {
        resource_classes.insert("destructive-delete".into());
        command_classes.insert("destructive-delete".into());
    }

    let supply_risk_install = signals.unsafe_installers.iter().any(|item| {
        !item.starts_with('|')
            && !item.contains("publish")
            && !item.contains("upload")
            && (raw_lower.contains(item.as_str()) || norm_lower.contains(item.as_str()))
    });
    if supply_risk_install || has_pipe_to_shell(&raw_lower) || has_pipe_to_shell(&norm_lower) {
        resource_classes.insert("supply-chain-risk".into());
        command_classes.insert("supply-chain-risk".into());
    }
    if contains_any(&raw_lower, &norm_lower, &signals.pkg_publish_patterns) {
        sink_classes.insert("pkg.publish".into());
    }

    if contains_any(&raw_lower, &norm_lower, &signals.cloud_admin_patterns) {
        resource_classes.insert("cloud-admin".into());
        command_classes.insert("cloud-admin".into());
        cloud_account_classes.insert("privileged-role".into());
        cloud_tenant_classes.insert("production".into());
    }

    if analysis
        .risk_tags
        .iter()
        .any(|t| t == "privilege-escalation")
        || contains_any(
            &raw_lower,
            &norm_lower,
            &signals.privilege_escalation_patterns,
        )
    {
        resource_classes.insert("privilege-elevate".into());
        command_classes.insert("privilege-elevate".into());
    }

    if contains_any(&raw_lower, &norm_lower, &signals.egress_exfil_patterns)
        || contains_any(&raw_lower, &norm_lower, &endpoints.cloud_aws_ips)
    {
        resource_classes.insert("egress-exfil".into());
        command_classes.insert("egress-exfil".into());
        http_classes.insert("external-upload".into());
        sink_classes.insert("egress-outside-profile".into());
        if contains_any(&raw_lower, &norm_lower, &endpoints.cloud_metadata_hosts)
            || contains_any(&raw_lower, &norm_lower, &endpoints.cloud_aws_ips)
        {
            resource_classes.insert("metadata-endpoint".into());
            http_classes.insert("metadata-ssrf".into());
            command_classes.insert("metadata-ssrf".into());
        }
    }

    if contains_any(&raw_lower, &norm_lower, &["git push"])
        && contains_any(
            &raw_lower,
            &norm_lower,
            &["http://", "https://", "git@", "mirror"],
        )
    {
        sink_classes.insert("push-outside-org".into());
    }

    if contains_any(&raw_lower, &norm_lower, &signals.message_send_patterns) {
        sink_classes.insert("message.send".into());
    }

    let has_mcp_write_tag = analysis.risk_tags.iter().any(|t| t == "mcp-write");
    let write_capable = has_mcp_write_tag
        || (attempt.action_class == ActionClass::McpCall
            && is_mcp_write_capable_with_catalog(
                &attempt.target,
                opts.mcp_hints.read_only_hint,
                has_mcp_write_tag,
                signals,
            ));
    if write_capable {
        resource_classes.insert("mcp-write".into());
        mcp_arg_classes.insert("state-mutating".into());
        sink_classes.insert("mcp-unpinned-write".into());
    }

    if attempt.action_class == ActionClass::LlmRequest {
        llm_tenant_classes.insert("external-model".into());
        if !opts.verification.llm_tenant_verified {
            sink_classes.insert("llm-non-tenant".into());
        }
    } else if matches!(
        attempt.action_class,
        ActionClass::NetConnect | ActionClass::NetRequest
    ) {
        sink_classes.insert("egress-outside-profile".into());
    } else if attempt.action_class == ActionClass::DataFlow {
        let mut matched_sink = false;
        for sink in &signals.sink_classes {
            if raw_lower.contains(sink.as_str()) || norm_lower.contains(sink.as_str()) {
                sink_classes.insert(sink.clone());
                matched_sink = true;
            }
        }
        if !matched_sink {
            sink_classes.insert("egress-outside-profile".into());
        }
        for s in &sink_classes {
            resource_classes.insert(s.clone());
        }
    }

    let recursive = contains_any(
        &raw_lower,
        &norm_lower,
        &["-rf", "-fr", "-r ", "--recursive", "-recurse"],
    ) || norm_lower.trim().ends_with(" -r");
    let in_workspace = target_is_in_workspace(&raw_lower, &norm_lower);
    let mut extra_pack_matches = Vec::new();
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
                extra_pack_matches.push(format!("match:{}", rule.id));
            }
        }
    }
    resource_classes.extend(extra_pack_matches);
    let cloud_provider = detect_cloud_provider_with_catalog(&raw_lower, &norm_lower, endpoints);
    let llm_provider = detect_llm_provider_with_catalog(&raw_lower, &norm_lower, endpoints);

    CedarSignals {
        resource_classes,
        facts,
        command_classes,
        sink_classes,
        http_classes,
        cloud_provider,
        cloud_account_classes,
        cloud_tenant_classes,
        mcp_arg_classes,
        llm_provider,
        llm_tenant_classes,
        recursive,
        in_workspace,
        write_capable,
    }
}

fn is_outside_workspace_token(tok: &str) -> bool {
    let clean = tok.trim_matches(|c: char| matches!(c, '"' | '\'' | ';'));
    if clean.is_empty() || (clean.starts_with('-') && !clean.contains('/')) {
        return false;
    }
    let has_drive = clean.as_bytes().get(1) == Some(&b':')
        && clean
            .as_bytes()
            .first()
            .is_some_and(u8::is_ascii_alphabetic);
    let home_env = clean.starts_with("$home")
        || clean.starts_with("${home}")
        || clean.starts_with("$userprofile")
        || clean.starts_with("$env:userprofile")
        || clean.starts_with("$env:appdata")
        || clean.starts_with("$env:localappdata")
        || clean.starts_with("%home%")
        || clean.starts_with("%userprofile%")
        || clean.starts_with("%appdata%")
        || clean.starts_with("%localappdata%")
        || clean.starts_with("$xdg_config_home")
        || clean.starts_with("${xdg_config_home}");
    let unc_file = clean.starts_with("file://") && !clean.starts_with("file:///");
    clean.starts_with('/')
        || clean.starts_with('~')
        || home_env
        || has_drive
        || unc_file
        || clean.starts_with("file:///")
        || has_traversal_segment(clean)
}

fn target_is_in_workspace(raw_lower: &str, norm_lower: &str) -> bool {
    let trimmed = norm_lower.trim();
    if trimmed.is_empty() || raw_lower.trim().is_empty() {
        return false;
    }
    if has_traversal_segment(raw_lower) || has_traversal_segment(trimmed) {
        return false;
    }
    if is_outside_workspace_token(raw_lower.trim()) || is_outside_workspace_token(trimmed) {
        return false;
    }
    !raw_lower
        .split_ascii_whitespace()
        .any(is_outside_workspace_token)
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
