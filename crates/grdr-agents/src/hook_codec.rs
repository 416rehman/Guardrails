// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::Deserialize;
use serde_json::Value;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HarnessKind {
    Auto,
    ClaudeCode,
    Cursor,
    Codex,
    Gemini,
}

#[derive(Debug, Deserialize)]
struct GenericHookPayload {
    session_id: Option<String>,
    conversation_id: Option<String>,
    thread_id: Option<String>,
    hook_event_name: Option<String>,
    tool_name: Option<String>,
    tool: Option<String>,
    event: Option<String>,
    command: Option<String>,
    file_path: Option<String>,
    path: Option<String>,
    tool_input: Option<Value>,
}

impl HarnessKind {
    pub fn from_name(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "claude" | "claude-code" | "claude_code" => Self::ClaudeCode,
            "cursor" => Self::Cursor,
            "codex" | "codex-cli" => Self::Codex,
            "gemini" | "gemini-cli" | "antigravity" => Self::Gemini,
            _ => Self::Auto,
        }
    }

    pub fn as_agent_name(self) -> &'static str {
        match self {
            Self::Auto | Self::ClaudeCode => "claude-code",
            Self::Cursor => "cursor",
            Self::Codex => "codex",
            Self::Gemini => "gemini",
        }
    }
}

pub fn parse_claude_hook_stdin(raw: &str, device_name: &str) -> Result<ActionAttempt, String> {
    parse_hook_stdin(HarnessKind::ClaudeCode, raw, device_name)
}

pub fn parse_hook_stdin(
    harness: HarnessKind,
    raw: &str,
    device_name: &str,
) -> Result<ActionAttempt, String> {
    let parsed: GenericHookPayload =
        serde_json::from_str(raw).map_err(|e| format!("invalid hook JSON: {e}"))?;

    let effective_harness = match harness {
        HarnessKind::Auto => infer_harness(&parsed),
        other => other,
    };

    let session_id = parsed
        .session_id
        .as_deref()
        .or(parsed.conversation_id.as_deref())
        .or(parsed.thread_id.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| format!("sess-{}", uuid::Uuid::now_v7().simple()));

    let tool = parsed
        .tool_name
        .as_deref()
        .or(parsed.tool.as_deref())
        .or(parsed.hook_event_name.as_deref())
        .or(parsed.event.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("shell");

    let input = parsed.tool_input.as_ref();
    let (action_class, target) = map_harness_action(&parsed, tool, input);
    let summary = format!("{tool} -> {target}");

    Ok(ActionAttempt {
        id: format!("att_{}", uuid::Uuid::now_v7().simple()),
        session_id,
        device_id: format!("dev-{device_name}"),
        device_name: device_name.into(),
        agent_name: effective_harness.as_agent_name().into(),
        action_class,
        control_point: ControlPoint::Hook,
        target,
        summary,
        timestamp: Timestamp::now(),
        ..Default::default()
    })
}

fn infer_harness(parsed: &GenericHookPayload) -> HarnessKind {
    if parsed.conversation_id.is_some()
        || matches!(
            parsed.hook_event_name.as_deref(),
            Some("beforeShellExecution" | "beforeReadFile" | "afterFileEdit" | "preToolUse")
        )
    {
        return HarnessKind::Cursor;
    }
    if parsed.thread_id.is_some() || parsed.event.is_some() {
        return HarnessKind::Codex;
    }
    if matches!(
        parsed.hook_event_name.as_deref(),
        Some("BeforeTool" | "BeforeAgent")
    ) || matches!(
        parsed.tool_name.as_deref(),
        Some("run_command" | "write_to_file" | "view_file" | "replace_file_content")
    ) {
        return HarnessKind::Gemini;
    }
    HarnessKind::ClaudeCode
}

fn map_harness_action(
    payload: &GenericHookPayload,
    tool: &str,
    input: Option<&Value>,
) -> (ActionClass, String) {
    match tool {
        "Bash"
        | "PowerShell"
        | "Shell"
        | "RunCommand"
        | "run_command"
        | "beforeShellExecution"
        | "shell"
        | "exec" => {
            let cmd = extract_string(
                input,
                &["command", "CommandLine", "cmd", "script", "command_line"],
            )
            .or_else(|| payload.command.clone())
            .unwrap_or_else(|| tool.into());
            (ActionClass::Exec, cmd)
        }
        "Read" | "ViewFile" | "view_file" | "beforeReadFile" | "read_file" => {
            let path = extract_string(input, &["file_path", "AbsolutePath", "path", "target_file"])
                .or_else(|| payload.file_path.clone())
                .or_else(|| payload.path.clone())
                .unwrap_or_else(|| "unknown-path".into());
            (ActionClass::FileRead, path)
        }
        "Write"
        | "Edit"
        | "MultiEdit"
        | "EditFile"
        | "WriteToFile"
        | "write_to_file"
        | "replace_file_content"
        | "multi_replace_file_content"
        | "afterFileEdit"
        | "write_file" => {
            let path = extract_string(input, &["file_path", "TargetFile", "path", "target_file"])
                .or_else(|| payload.file_path.clone())
                .or_else(|| payload.path.clone())
                .unwrap_or_else(|| "unknown-path".into());
            (ActionClass::FileWrite, path)
        }
        "Delete" | "RemoveFile" | "delete_file" => {
            let path = extract_string(input, &["file_path", "TargetFile", "path"])
                .or_else(|| payload.file_path.clone())
                .or_else(|| payload.path.clone())
                .unwrap_or_else(|| "unknown-path".into());
            (ActionClass::FileDelete, path)
        }
        "WebFetch" | "WebSearch" | "read_url_content" | "search_web" | "web_fetch" => {
            let url =
                extract_string(input, &["url", "Url", "query"]).unwrap_or_else(|| "web".into());
            (ActionClass::NetRequest, url)
        }
        other if other.starts_with("mcp__") => (ActionClass::McpCall, other.into()),
        _ => {
            if let Some(cmd) = extract_string(input, &["command", "CommandLine", "cmd"])
                .or_else(|| payload.command.clone())
            {
                return (ActionClass::Exec, cmd);
            }
            let arg = extract_string(
                input,
                &[
                    "file_path",
                    "TargetFile",
                    "AbsolutePath",
                    "path",
                    "target",
                    "url",
                ],
            )
            .or_else(|| payload.file_path.clone())
            .or_else(|| payload.path.clone())
            .unwrap_or_else(|| tool.into());
            (ActionClass::Exec, arg)
        }
    }
}

fn extract_string(input: Option<&Value>, keys: &[&str]) -> Option<String> {
    let obj = input?.as_object()?;
    for key in keys {
        if let Some(val) = obj.get(*key).and_then(Value::as_str)
            && !val.trim().is_empty()
        {
            return Some(val.to_string());
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn maps_claude_cursor_codex_and_gemini_payloads() {
        let write = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(write.agent_name, "claude-code");
        assert_eq!(write.action_class, ActionClass::FileWrite);
        assert_eq!(write.target, ".claude/settings.json");

        let cursor = parse_hook_stdin(
            HarnessKind::Auto,
            r#"{"conversation_id":"cur-1","hook_event_name":"beforeShellExecution","command":"rm -rf /tmp/x"}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(cursor.agent_name, "cursor");
        assert_eq!(cursor.session_id, "cur-1");
        assert_eq!(cursor.action_class, ActionClass::Exec);
        assert_eq!(cursor.target, "rm -rf /tmp/x");

        let codex = parse_hook_stdin(
            HarnessKind::Auto,
            r#"{"thread_id":"th-9","event":"exec","command":"git status"}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(codex.agent_name, "codex");
        assert_eq!(codex.session_id, "th-9");
        assert_eq!(codex.action_class, ActionClass::Exec);
        assert_eq!(codex.target, "git status");

        let gemini = parse_hook_stdin(
            HarnessKind::Auto,
            r#"{"session_id":"gem-1","hook_event_name":"BeforeTool","tool_name":"write_to_file","tool_input":{"TargetFile":".gemini/settings.json"}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(gemini.agent_name, "gemini");
        assert_eq!(gemini.action_class, ActionClass::FileWrite);
        assert_eq!(gemini.target, ".gemini/settings.json");

        let mcp = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"mcp__github__create_issue","tool_input":{}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(mcp.action_class, ActionClass::McpCall);
        assert_eq!(mcp.target, "mcp__github__create_issue");

        assert!(parse_hook_stdin(HarnessKind::Auto, "{not-valid-json", "devbox").is_err());
    }
}
