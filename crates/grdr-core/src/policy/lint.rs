// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Cedar source safety linting, AST depth bounds, `like<=64`, and read-set extraction.

use std::collections::BTreeSet;

use cedar_policy::{Effect, PolicySet};
use grdr_model::{ActionClass, IdentityMode};

use super::PolicyError;
pub(crate) use super::lint_scan::{
    MAX_CEDAR_NESTING_DEPTH, cedar_body_slice, check_cedar_nesting_depth, scope_header_slice,
    strip_comments_and_strings,
};
use super::request::ContextField;

const ALL_ACTIONS: [ActionClass; 15] = [
    ActionClass::Exec,
    ActionClass::FileRead,
    ActionClass::FileWrite,
    ActionClass::FileDelete,
    ActionClass::NetConnect,
    ActionClass::NetRequest,
    ActionClass::LlmRequest,
    ActionClass::McpConnect,
    ActionClass::McpCall,
    ActionClass::CredUse,
    ActionClass::AgentSpawn,
    ActionClass::ConfigChange,
    ActionClass::Elevate,
    ActionClass::UiAct,
    ActionClass::DataFlow,
];

const MAX_LIKE_PATTERN_LEN: usize = 64;
const ALLOWED_LIKE_PREFIXES: &[&str] = &[
    "principal.id",
    "resource.id",
    "context.control_point",
    "resource.provider",
    "resource.transport",
];

pub fn lint_cedar_source_extended(
    pack_id: &str,
    rule_id: &str,
    cedar_source: &str,
    declared_reads: Option<&BTreeSet<String>>,
    identity_mode: IdentityMode,
) -> Result<BTreeSet<ContextField>, PolicyError> {
    check_cedar_nesting_depth(rule_id, cedar_source)?;
    let policy_set = cedar_source
        .parse::<PolicySet>()
        .map_err(|e| PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: e.to_string(),
        })?;

    let mut reads = BTreeSet::new();
    for policy in policy_set.policies() {
        if pack_id != "grdr.base" && policy.effect() == Effect::Permit {
            return Err(PolicyError::PermitNotAllowed {
                rule_id: rule_id.into(),
            });
        }
        let printed = policy.to_string();
        let body_no_strings = strip_comments_and_strings(cedar_body_slice(&printed), false);
        let compact: String = body_no_strings
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        let body_with_strings = strip_comments_and_strings(cedar_body_slice(&printed), true);
        let compact_with_strings: String = body_with_strings
            .chars()
            .filter(|c| !c.is_whitespace())
            .collect();
        if identity_mode == IdentityMode::Pseudonymous && compact.contains("Grdr::User") {
            return Err(PolicyError::PrivacyViolation {
                rule_id: rule_id.into(),
                detail: "policies targeting Grdr::User are rejected in pseudonymous mode".into(),
            });
        }
        if compact_with_strings.contains("advisory.")
            || compact_with_strings.contains("model.advisory")
        {
            return Err(PolicyError::ValidationFailed {
                rule_id: rule_id.into(),
                detail: "advisory labels are forbidden inside enforcing Cedar conditions".into(),
            });
        }
        check_like_patterns(rule_id, &printed)?;
        for ann_key in ["message", "steer"] {
            if let Some(val) = policy.annotation(ann_key) {
                if val.len() > 1024 {
                    return Err(PolicyError::ValidationFailed {
                        rule_id: rule_id.into(),
                        detail: format!("@{ann_key} exceeds 1024-byte limit"),
                    });
                }
                let lower = val.to_ascii_lowercase();
                if lower.contains("http://")
                    || lower.contains("https://")
                    || lower.contains("file://")
                    || lower.contains("ftp://")
                    || lower.contains("javascript:")
                {
                    return Err(PolicyError::ValidationFailed {
                        rule_id: rule_id.into(),
                        detail: format!("@{ann_key} cannot contain URLs"),
                    });
                }
            }
        }
        reads.extend(compute_cedar_reads(&printed));
    }

    if let Some(declared) = declared_reads {
        for req_path in read_field_names(&reads) {
            if !declared.contains(req_path) && !declared.contains("*") {
                return Err(PolicyError::ValidationFailed {
                    rule_id: rule_id.into(),
                    detail: format!("rule accesses `{req_path}` missing from pack.toml [[reads]]"),
                });
            }
        }
    }
    Ok(reads)
}

fn compact_and_normalized(cedar_source: &str) -> (String, String) {
    let body = cedar_body_slice(cedar_source);
    let sanitized = strip_comments_and_strings(body, false);
    let compact: String = sanitized.chars().filter(|c| !c.is_whitespace()).collect();
    let with_str_compact: String = strip_comments_and_strings(body, true)
        .chars()
        .filter(|c| !c.is_whitespace())
        .collect();
    let normalized = with_str_compact
        .replace("[\"", ".")
        .replace("\"]", "")
        .replace("['", ".")
        .replace("']", "");
    (compact, normalized)
}

pub(crate) fn reads_session_label_epoch(cedar_source: &str) -> bool {
    let (compact, normalized) = compact_and_normalized(cedar_source);
    compact.contains("context.session.label_epoch")
        || normalized.contains("context.session.label_epoch")
}

pub fn compute_cedar_reads(cedar_source: &str) -> BTreeSet<ContextField> {
    let (compact, normalized) = compact_and_normalized(cedar_source);

    let mut reads = BTreeSet::new();
    let pairs: &[(&[&str], ContextField)] = &[
        (
            &[
                "context.session.labels",
                "context.session.label_epoch",
                "context.source_labels",
            ],
            ContextField::SessionLabels,
        ),
        (&["context.command.classes"], ContextField::CommandClasses),
        (&["resource.in_workspace"], ContextField::PathWorkspace),
        (&["context.recursive"], ContextField::RecursiveFlag),
        (
            &["resource.port", "endpoint.port"],
            ContextField::EndpointPort,
        ),
        (&["context.http"], ContextField::HttpClasses),
        (
            &[
                "context.cloud.account_classes",
                "context.cloud.tenant_classes",
                "context.cloud.provider",
                "context.cloud.verified",
            ],
            ContextField::CloudMeta,
        ),
        (
            &[
                "context.tenant.classes",
                "context.tenant.verified",
                "resource.provider",
            ],
            ContextField::LlmTenant,
        ),
        (&["resource.identity_pinned"], ContextField::McpServerPin),
        (&["resource.manifest_pinned"], ContextField::McpToolPin),
        (
            &["context.args.classes", "context.args.extracted"],
            ContextField::McpArgs,
        ),
        (&["context.child"], ContextField::ChildAgentMeta),
        (&["context.change_classes"], ContextField::ConfigClasses),
        (&["Grdr::User"], ContextField::UserIdentity),
        (
            &["resource.classes", "resource.write_capable"],
            ContextField::TargetClasses,
        ),
    ];
    for &(needles, field) in pairs {
        if needles
            .iter()
            .any(|needle| compact.contains(needle) || normalized.contains(needle))
        {
            reads.insert(field);
        }
    }
    reads
}

pub(crate) fn body_has_unless_clause(policy_text: &str) -> bool {
    let stripped = strip_comments_and_strings(cedar_body_slice(policy_text), false);
    let cleaned: String = stripped.chars().filter(|c| !c.is_whitespace()).collect();
    cleaned.contains("unless{")
}

pub(crate) fn extract_policy_actions(policy_text: &str) -> Vec<ActionClass> {
    let body = strip_comments_and_strings(cedar_body_slice(policy_text), true);
    let header = scope_header_slice(&body);
    if header.contains("Grdr::Action::\"any\"") {
        return Vec::new();
    }
    let mut actions = Vec::new();
    for ac in ALL_ACTIONS {
        let marker = format!("Grdr::Action::\"{}\"", ac.as_str());
        if header.contains(&marker) && !actions.contains(&ac) {
            actions.push(ac);
        }
    }
    let groups: &[(&str, &[ActionClass])] = &[
        (
            "Grdr::Action::\"file\"",
            &[
                ActionClass::FileRead,
                ActionClass::FileWrite,
                ActionClass::FileDelete,
            ],
        ),
        (
            "Grdr::Action::\"net\"",
            &[
                ActionClass::NetConnect,
                ActionClass::NetRequest,
                ActionClass::LlmRequest,
            ],
        ),
        (
            "Grdr::Action::\"mcp\"",
            &[ActionClass::McpConnect, ActionClass::McpCall],
        ),
    ];
    for &(needle, group_actions) in groups {
        if header.contains(needle) {
            for &ac in group_actions {
                if !actions.contains(&ac) {
                    actions.push(ac);
                }
            }
        }
    }
    actions
}

fn read_field_names(reads: &BTreeSet<ContextField>) -> Vec<&'static str> {
    reads
        .iter()
        .map(|f| match f {
            ContextField::SessionLabels => "context.session.labels",
            ContextField::CommandClasses => "command.classes",
            ContextField::PathWorkspace => "path.in_workspace",
            ContextField::RecursiveFlag => "context.recursive",
            ContextField::EndpointPort => "endpoint.port",
            ContextField::HttpClasses => "context.http.classes",
            ContextField::CloudMeta => "context.cloud",
            ContextField::LlmTenant => "context.tenant",
            ContextField::McpServerPin => "mcp.identity_pinned",
            ContextField::McpToolPin => "mcp.manifest_pinned",
            ContextField::McpArgs => "context.args",
            ContextField::ChildAgentMeta => "context.child",
            ContextField::ConfigClasses => "config.change_classes",
            ContextField::UserIdentity => "user.identity",
            ContextField::TargetClasses => "resource.classes",
        })
        .collect()
}

fn check_like_patterns(rule_id: &str, canonical: &str) -> Result<(), PolicyError> {
    let body = cedar_body_slice(canonical);
    let sanitized = strip_comments_and_strings(body, false);
    let mut idx_search: usize = 0;
    while let Some(rel) = sanitized.get(idx_search..).and_then(|s| s.find(" like ")) {
        let idx = idx_search.saturating_add(rel);
        let before = sanitized.get(..idx).unwrap_or("").trim_end();
        let valid_subject = ALLOWED_LIKE_PREFIXES.iter().any(|p| before.ends_with(p));
        if !valid_subject {
            return Err(PolicyError::ValidationFailed {
                rule_id: rule_id.into(),
                detail: "`like` operator is allowed only on identifier fields".into(),
            });
        }
        idx_search = idx.saturating_add(6);
    }
    let mut raw_search: usize = 0;
    while let Some(rel) = body.get(raw_search..).and_then(|s| s.find(" like ")) {
        let idx = raw_search.saturating_add(rel);
        let before_q = body.get(..idx).unwrap_or("").trim_end();
        if ALLOWED_LIKE_PREFIXES.iter().any(|p| before_q.ends_with(p)) {
            let after = body
                .get(idx..)
                .unwrap_or("")
                .trim_start_matches(" like ")
                .trim_start();
            if let Some(after_q) = after.strip_prefix('"') {
                let mut pat_chars: usize = 0;
                let mut escaped = false;
                for ch in after_q.chars() {
                    if escaped {
                        escaped = false;
                        pat_chars = pat_chars.saturating_add(1);
                        continue;
                    }
                    if ch == '\\' {
                        escaped = true;
                        continue;
                    }
                    if ch == '"' {
                        break;
                    }
                    pat_chars = pat_chars.saturating_add(1);
                }
                if pat_chars > MAX_LIKE_PATTERN_LEN {
                    return Err(PolicyError::ValidationFailed {
                        rule_id: rule_id.into(),
                        detail: format!("`like` pattern exceeds {MAX_LIKE_PATTERN_LEN} characters"),
                    });
                }
            }
        }
        raw_search = idx.saturating_add(6);
    }
    Ok(())
}
