// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Data-driven agent hook dialect detection, classification, and zero-`serde_json` encoding.

use std::fmt::Write as _;

use grdr_fastpath::FastActionClass;
use grdr_wire::messages::WireVerdict;

use crate::dialect_pack::{DialectRegistry, DialectSpec, ResponseEnvelope};

#[derive(Clone, Copy, Debug)]
pub struct HookDialect(&'static DialectSpec);

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct DecisionRenderExtras<'a> {
    pub retry_token: Option<&'a str>,
    pub modified_target: Option<&'a str>,
}

impl PartialEq for HookDialect {
    fn eq(&self, other: &Self) -> bool {
        self.0.id == other.0.id
    }
}

impl Eq for HookDialect {}

impl HookDialect {
    #[must_use]
    pub fn from_cli_name(raw: &str) -> Option<Self> {
        DialectRegistry::embedded().resolve(raw).map(Self)
    }

    #[must_use]
    pub fn default_dialect() -> Option<Self> {
        DialectRegistry::embedded().default_spec().map(Self)
    }

    #[must_use]
    pub fn as_agent_str(self) -> &'static str {
        if self.0.agent_id.is_empty() {
            &self.0.id
        } else {
            &self.0.agent_id
        }
    }

    #[must_use]
    pub fn id(self) -> &'static str {
        &self.0.id
    }

    #[must_use]
    pub fn default_event(self) -> &'static str {
        if self.0.default_event.is_empty() {
            "PreToolUse"
        } else {
            &self.0.default_event
        }
    }

    #[must_use]
    pub fn modify_field(self) -> &'static str {
        &self.0.modify_field
    }
}

#[must_use]
pub fn infer_dialect(event_name: &str, tool_name: &str) -> Option<HookDialect> {
    infer_dialect_with_session_key(event_name, tool_name, "")
}

#[must_use]
pub fn infer_dialect_with_session_key(
    event_name: &str,
    tool_name: &str,
    session_key_hint: &str,
) -> Option<HookDialect> {
    DialectRegistry::embedded()
        .infer(event_name, tool_name, session_key_hint)
        .map(HookDialect)
}

#[must_use]
pub fn is_shell_tool(tool_name: &str) -> bool {
    let rules = &DialectRegistry::embedded().classification;
    let lower = tool_name.trim().to_ascii_lowercase();
    rules.exec_exact.iter().any(|k| k == &lower)
        || rules
            .exec_substrings
            .iter()
            .any(|s| lower.contains(s.as_str()))
}

#[must_use]
pub fn classify_action(tool_name: &str, event_name: &str, url: &str) -> FastActionClass {
    let rules = &DialectRegistry::embedded().classification;
    let lower = tool_name.to_ascii_lowercase();
    if rules
        .mcp_prefixes
        .iter()
        .any(|p| lower.starts_with(p.as_str()))
        || rules.mcp_events.iter().any(|e| e == event_name)
    {
        FastActionClass::McpCall
    } else if rules.prompt_events.iter().any(|e| e == event_name) {
        FastActionClass::LlmRequest
    } else if rules.exec_exact.iter().any(|k| k == &lower)
        || rules
            .exec_substrings
            .iter()
            .any(|s| lower.contains(s.as_str()))
        || rules.exec_events.iter().any(|e| e == event_name)
    {
        FastActionClass::Exec
    } else if rules.delete_exact.iter().any(|k| k == &lower)
        || rules
            .delete_substrings
            .iter()
            .any(|s| lower.contains(s.as_str()))
    {
        FastActionClass::FileDelete
    } else if rules.write_exact.iter().any(|k| k == &lower)
        || rules
            .write_substrings
            .iter()
            .any(|s| lower.contains(s.as_str()))
        || rules.write_events.iter().any(|e| e == event_name)
    {
        FastActionClass::FileWrite
    } else if rules
        .read_substrings
        .iter()
        .any(|s| lower.contains(s.as_str()))
        || rules.read_events.iter().any(|e| e == event_name)
    {
        FastActionClass::FileRead
    } else if !url.is_empty()
        || rules
            .net_substrings
            .iter()
            .any(|s| lower.contains(s.as_str()))
    {
        FastActionClass::NetRequest
    } else if rules
        .mcp_substrings
        .iter()
        .any(|s| lower.contains(s.as_str()))
    {
        FastActionClass::McpCall
    } else {
        FastActionClass::Exec
    }
}

#[must_use]
pub fn classify_control_point(event_name: &str) -> u32 {
    let rules = &DialectRegistry::embedded().classification;
    if rules
        .post_event_prefixes
        .iter()
        .any(|p| event_name.starts_with(p.as_str()))
    {
        2
    } else {
        1
    }
}

#[must_use]
pub fn format_dialect_decision(
    dialect: HookDialect,
    event_name: &str,
    verdict: WireVerdict,
    reason: &str,
    rule_id: &str,
) -> String {
    format_dialect_decision_ext(
        dialect,
        event_name,
        verdict,
        reason,
        rule_id,
        DecisionRenderExtras::default(),
    )
}

#[must_use]
pub fn format_dialect_decision_ext(
    dialect: HookDialect,
    event_name: &str,
    verdict: WireVerdict,
    reason: &str,
    rule_id: &str,
    extras: DecisionRenderExtras<'_>,
) -> String {
    let base_reason = if reason.is_empty() { rule_id } else { reason };
    let owned_token = extras
        .retry_token
        .filter(|t| !t.trim().is_empty())
        .map(str::to_owned);
    let guided_reason = match verdict {
        WireVerdict::Ask => {
            if let Some(tok) = &owned_token {
                format!(
                    "Approval required (step-up): {base_reason} (approve via grdr approve --token {tok} before retrying)"
                )
            } else {
                format!(
                    "Approval required (step-up): {base_reason} (escalate or approve via grdr approve before retrying)"
                )
            }
        }
        WireVerdict::Allow | WireVerdict::Block | WireVerdict::Unspecified => {
            base_reason.to_string()
        }
    };
    let esc_reason = escape_json(&guided_reason);
    let esc_event = escape_json(if event_name.is_empty() {
        dialect.default_event()
    } else {
        event_name
    });
    let decision = match verdict {
        WireVerdict::Allow => "allow",
        WireVerdict::Ask | WireVerdict::Block | WireVerdict::Unspecified => "deny",
    };

    let token_prop = match (verdict, &owned_token) {
        (WireVerdict::Ask, Some(tok)) => format!(",\"retry_token\":\"{}\"", escape_json(tok)),
        _ => String::new(),
    };
    let modify_prop = match (verdict, extras.modified_target, dialect.modify_field()) {
        (WireVerdict::Allow, Some(rewritten), field)
            if !field.is_empty() && !rewritten.is_empty() =>
        {
            format!(",\"{}\":\"{}\"", escape_json(field), escape_json(rewritten))
        }
        _ => String::new(),
    };

    match dialect.0.response_format {
        ResponseEnvelope::HookSpecificOutput => format!(
            "{{\"hookSpecificOutput\":{{\"hookEventName\":\"{esc_event}\",\"permissionDecision\":\"{decision}\",\"permissionDecisionReason\":\"{esc_reason}\"{modify_prop}}}{token_prop}}}"
        ),
        ResponseEnvelope::ContinuePermission => {
            let cont = matches!(verdict, WireVerdict::Allow);
            format!(
                "{{\"continue\":{cont},\"permission\":\"{decision}\",\"user_message\":\"{esc_reason}\",\"agent_message\":\"{esc_reason}\"{modify_prop}{token_prop}}}"
            )
        }
        ResponseEnvelope::DecisionReason => format!(
            "{{\"decision\":\"{decision}\",\"reason\":\"{esc_reason}\"{modify_prop}{token_prop}}}"
        ),
        ResponseEnvelope::PermissionDecision => format!(
            "{{\"permissionDecision\":\"{decision}\",\"permissionDecisionReason\":\"{esc_reason}\"{modify_prop}{token_prop}}}"
        ),
    }
}

#[must_use]
pub fn escape_json(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if c.is_control() => {
                let _ = write!(out, "\\u{:04x}", u32::from(c));
            }
            c => out.push(c),
        }
    }
    out
}
