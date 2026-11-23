// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::Deserialize;
use serde_json::Value;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

#[derive(Debug, Deserialize)]
struct ClaudeHookPayload {
    session_id: Option<String>,
    tool_name: String,
    tool_input: Option<Value>,
}

pub fn parse_claude_hook_stdin(raw: &str, device_name: &str) -> Result<ActionAttempt, String> {
    let parsed: ClaudeHookPayload =
        serde_json::from_str(raw).map_err(|e| format!("invalid Claude Code hook JSON: {e}"))?;
    let session_id = parsed
        .session_id
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| format!("sess-{}", uuid::Uuid::now_v7().simple()));

    let tool = parsed.tool_name.trim();
    let input = parsed.tool_input.as_ref();

    let (action_class, target) = map_tool_action(tool, input);
    let summary = format!("{tool} -> {target}");

    Ok(ActionAttempt {
        id: format!("att_{}", uuid::Uuid::now_v7().simple()),
        session_id,
        device_id: format!("dev-{device_name}"),
        device_name: device_name.into(),
        agent_name: "claude-code".into(),
        action_class,
        control_point: ControlPoint::Hook,
        target,
        summary,
        timestamp: Timestamp::now(),
    })
}

fn map_tool_action(tool: &str, input: Option<&Value>) -> (ActionClass, String) {
    match tool {
        "Bash" | "PowerShell" | "Shell" | "RunCommand" => {
            let cmd =
                extract_string(input, &["command", "cmd", "script"]).unwrap_or_else(|| tool.into());
            (ActionClass::Exec, cmd)
        }
        "Read" | "ViewFile" => {
            let path = extract_string(input, &["file_path", "path", "target_file"])
                .unwrap_or_else(|| "unknown-path".into());
            (ActionClass::FileRead, path)
        }
        "Write" | "Edit" | "MultiEdit" | "EditFile" | "WriteToFile" => {
            let path = extract_string(input, &["file_path", "path", "target_file"])
                .unwrap_or_else(|| "unknown-path".into());
            (ActionClass::FileWrite, path)
        }
        "Delete" | "RemoveFile" => {
            let path = extract_string(input, &["file_path", "path"])
                .unwrap_or_else(|| "unknown-path".into());
            (ActionClass::FileDelete, path)
        }
        "WebFetch" | "WebSearch" => {
            let url = extract_string(input, &["url", "query"]).unwrap_or_else(|| "web".into());
            (ActionClass::NetRequest, url)
        }
        other if other.starts_with("mcp__") => (ActionClass::McpCall, other.into()),
        other => {
            let arg = extract_string(input, &["path", "file_path", "command", "target"])
                .unwrap_or_else(|| other.into());
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
    fn maps_claude_tool_payloads_to_action_attempts() {
        let write = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(write.action_class, ActionClass::FileWrite);
        assert_eq!(write.target, ".claude/settings.json");

        let bash = parse_claude_hook_stdin(
            r#"{"tool_name":"Bash","tool_input":{"command":"git status"}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(bash.action_class, ActionClass::Exec);
        assert_eq!(bash.target, "git status");

        let mcp = parse_claude_hook_stdin(
            r#"{"session_id":"s1","tool_name":"mcp__github__create_issue","tool_input":{}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(mcp.action_class, ActionClass::McpCall);
        assert_eq!(mcp.target, "mcp__github__create_issue");
    }
}
