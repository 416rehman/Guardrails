// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Agent hook dialect detection, classification, and zero-`serde_json` output encoding.

use std::fmt::Write as _;

use grdr_fastpath::FastActionClass;
use grdr_wire::messages::WireVerdict;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HookDialect {
    ClaudeCode,
    Cursor,
    Codex,
    Gemini,
    CopilotCli,
}

impl HookDialect {
    #[must_use]
    pub fn from_cli_name(raw: &str) -> Option<Self> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "auto" | "" => None,
            "claude" | "claude-code" | "claude_code" => Some(Self::ClaudeCode),
            "cursor" => Some(Self::Cursor),
            "codex" | "codex-cli" => Some(Self::Codex),
            "gemini" | "gemini-cli" | "antigravity" | "agy" => Some(Self::Gemini),
            "copilot" | "copilot-cli" => Some(Self::CopilotCli),
            _ => None,
        }
    }

    #[must_use]
    pub const fn as_agent_str(self) -> &'static str {
        match self {
            Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
            Self::CopilotCli => "copilot-cli",
        }
    }
}

#[must_use]
pub fn infer_dialect(event_name: &str, tool_name: &str) -> HookDialect {
    match event_name {
        "beforeShellExecution"
        | "beforeReadFile"
        | "afterFileEdit"
        | "beforeMCPExecution"
        | "beforeSubmitPrompt"
        | "preToolUse" => HookDialect::Cursor,
        "BeforeTool" | "BeforeAgent" => HookDialect::Gemini,
        _ if tool_name == "write_to_file"
            || tool_name == "run_command"
            || tool_name == "view_file"
            || tool_name == "replace_file_content" =>
        {
            HookDialect::Gemini
        }
        _ => HookDialect::ClaudeCode,
    }
}

#[must_use]
pub fn classify_action(tool_name: &str, event_name: &str, url: &str) -> FastActionClass {
    let lower = tool_name.to_ascii_lowercase();
    if lower.starts_with("mcp__") || event_name == "beforeMCPExecution" {
        FastActionClass::McpCall
    } else if event_name == "beforeSubmitPrompt" || event_name == "UserPromptSubmit" {
        FastActionClass::LlmRequest
    } else if matches!(
        lower.as_str(),
        "exec" | "sh" | "cmd" | "pwsh" | "powershell"
    ) || lower.contains("bash")
        || lower.contains("shell")
        || lower.contains("command")
        || event_name == "beforeShellExecution"
    {
        FastActionClass::Exec
    } else if lower == "unlink" || lower.contains("delete") || lower.contains("remove") {
        FastActionClass::FileDelete
    } else if matches!(lower.as_str(), "create_file" | "save_file")
        || lower.contains("write")
        || lower.contains("edit")
        || lower.contains("patch")
        || lower.contains("replace_file")
        || event_name == "afterFileEdit"
    {
        FastActionClass::FileWrite
    } else if lower.contains("read") || lower.contains("view") || event_name == "beforeReadFile" {
        FastActionClass::FileRead
    } else if !url.is_empty()
        || lower.contains("fetch")
        || lower.contains("web")
        || lower.contains("http")
    {
        FastActionClass::NetRequest
    } else if lower.contains("mcp") {
        FastActionClass::McpCall
    } else {
        FastActionClass::Exec
    }
}

#[must_use]
pub fn classify_control_point(event_name: &str) -> u32 {
    if event_name.starts_with("Post")
        || event_name.starts_with("after")
        || event_name.starts_with("After")
    {
        2
    } else {
        1
    }
}

/// Format verdict into the host agent's expected JSON schema.
/// `WireVerdict::Ask` encodes fail-closed `deny` with step-up guidance across every dialect
/// so harnesses lacking native ask support never fall through open.
#[must_use]
pub fn format_dialect_decision(
    dialect: HookDialect,
    event_name: &str,
    verdict: WireVerdict,
    reason: &str,
    rule_id: &str,
) -> String {
    let base_reason = if reason.is_empty() { rule_id } else { reason };
    let guided_reason = match verdict {
        WireVerdict::Ask => format!(
            "Approval required (step-up): {base_reason} (escalate or approve via grdr approve before retrying)"
        ),
        WireVerdict::Allow | WireVerdict::Block | WireVerdict::Unspecified => {
            base_reason.to_string()
        }
    };
    let esc_reason = escape_json(&guided_reason);
    let esc_event = escape_json(if event_name.is_empty() {
        "PreToolUse"
    } else {
        event_name
    });
    let decision = match verdict {
        WireVerdict::Allow => "allow",
        WireVerdict::Ask | WireVerdict::Block | WireVerdict::Unspecified => "deny",
    };
    match dialect {
        HookDialect::ClaudeCode | HookDialect::Codex => {
            format!(
                "{{\"hookSpecificOutput\":{{\"hookEventName\":\"{esc_event}\",\"permissionDecision\":\"{decision}\",\"permissionDecisionReason\":\"{esc_reason}\"}}}}"
            )
        }
        HookDialect::Cursor => {
            let cont = matches!(verdict, WireVerdict::Allow);
            format!(
                "{{\"continue\":{cont},\"permission\":\"{decision}\",\"user_message\":\"{esc_reason}\",\"agent_message\":\"{esc_reason}\"}}"
            )
        }
        HookDialect::Gemini => {
            format!("{{\"decision\":\"{decision}\",\"reason\":\"{esc_reason}\"}}")
        }
        HookDialect::CopilotCli => {
            format!(
                "{{\"permissionDecision\":\"{decision}\",\"permissionDecisionReason\":\"{esc_reason}\"}}"
            )
        }
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
