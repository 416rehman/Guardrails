// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dynamic hook stdin payload normalization driven by P14 agent manifests.

use std::sync::OnceLock;

use jiff::Timestamp;
use serde::Deserialize;
use serde_json::Value;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

use crate::catalogue::{AgentCatalogue, AgentManifest};

const MAX_HOOK_STDIN_BYTES: usize = 1_048_576;
static EMBEDDED_CODEC_CATALOGUE: OnceLock<Option<AgentCatalogue>> = OnceLock::new();

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

pub fn parse_hook_stdin_with_dialect(
    dialect: &str,
    raw: &str,
    device_name: &str,
) -> Result<ActionAttempt, String> {
    let catalogue = EMBEDDED_CODEC_CATALOGUE
        .get_or_init(|| AgentCatalogue::embedded().ok())
        .as_ref()
        .ok_or_else(|| "GRDR-AGENTS-0004: embedded agent catalogue unavailable".to_string())?;
    parse_hook_stdin_with_catalogue(dialect, raw, device_name, catalogue)
}

pub fn parse_hook_stdin_with_catalogue(
    dialect: &str,
    raw: &str,
    device_name: &str,
    catalogue: &AgentCatalogue,
) -> Result<ActionAttempt, String> {
    if raw.len() > MAX_HOOK_STDIN_BYTES {
        return Err(format!(
            "GRDR-AGENTS-0002: hook stdin payload exceeds {MAX_HOOK_STDIN_BYTES} bytes"
        ));
    }
    let clean_raw = raw.trim_start_matches('\u{FEFF}');
    let root: Value =
        serde_json::from_str(clean_raw).map_err(|e| format!("invalid hook JSON: {e}"))?;
    let parsed: GenericHookPayload =
        serde_json::from_value(root.clone()).map_err(|e| format!("invalid hook payload: {e}"))?;
    let (agent_label, matched_manifest) = resolve_dialect_label(dialect, &parsed, &root, catalogue);
    normalize_hook_payload(parsed, &root, matched_manifest, &agent_label, device_name)
}

fn manifest_dialect_label(manifest: &AgentManifest) -> String {
    if manifest.hook.dialect.is_empty() {
        manifest.id.clone()
    } else {
        manifest.hook.dialect.clone()
    }
}

fn manifest_has_session_key(
    manifest: &AgentManifest,
    root_obj: Option<&serde_json::Map<String, Value>>,
) -> bool {
    let Some(obj) = root_obj else {
        return false;
    };
    manifest
        .hook
        .payload_session_keys
        .iter()
        .any(|key| obj.contains_key(key.as_str()))
}

fn manifest_matches_event(manifest: &AgentManifest, ev: &str) -> bool {
    manifest.hook.events.iter().any(|e| e == ev) || manifest.hook.all_events.iter().any(|e| e == ev)
}

fn resolve_dialect_label<'a>(
    dialect: &str,
    parsed: &GenericHookPayload,
    root: &Value,
    catalogue: &'a AgentCatalogue,
) -> (String, Option<&'a AgentManifest>) {
    let trimmed = dialect.trim();
    if !trimmed.is_empty() && !trimmed.eq_ignore_ascii_case("auto") {
        if let Some(manifest) = catalogue.resolve(trimmed) {
            return (manifest_dialect_label(manifest), Some(manifest));
        }
        return (trimmed.to_ascii_lowercase(), None);
    }

    let root_obj = root.as_object();
    if let Some(ev) = parsed
        .hook_event_name
        .as_deref()
        .or(parsed.event.as_deref())
        .map(str::trim)
        .filter(|s| !s.is_empty())
    {
        if let Some(manifest) = catalogue.agents().iter().find(|a| {
            a.hook.supported
                && manifest_matches_event(a, ev)
                && manifest_has_session_key(a, root_obj)
        }) {
            return (manifest_dialect_label(manifest), Some(manifest));
        }
        if let Some(manifest) = catalogue
            .agents()
            .iter()
            .find(|a| a.hook.supported && manifest_matches_event(a, ev))
        {
            return (manifest_dialect_label(manifest), Some(manifest));
        }
    }

    if let Some(manifest) = catalogue
        .agents()
        .iter()
        .find(|a| a.hook.supported && manifest_has_session_key(a, root_obj))
    {
        return (manifest_dialect_label(manifest), Some(manifest));
    }

    catalogue
        .hook_targets()
        .first()
        .map(|m| (manifest_dialect_label(m), Some(*m)))
        .unwrap_or_else(|| ("unknown-agent".to_owned(), None))
}

fn normalize_hook_payload(
    parsed: GenericHookPayload,
    root: &Value,
    matched_manifest: Option<&AgentManifest>,
    agent_name: &str,
    device_name: &str,
) -> Result<ActionAttempt, String> {
    let manifest_session = matched_manifest.and_then(|manifest| {
        let obj = root.as_object()?;
        manifest.hook.payload_session_keys.iter().find_map(|key| {
            obj.get(key.as_str())
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
    });
    let session_id = manifest_session
        .or_else(|| {
            parsed
                .session_id
                .as_deref()
                .or(parsed.conversation_id.as_deref())
                .or(parsed.thread_id.as_deref())
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_string)
        })
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
        agent_name: agent_name.into(),
        action_class,
        control_point: ControlPoint::Hook,
        target,
        summary,
        timestamp: Timestamp::now(),
        ..Default::default()
    })
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
        let write = parse_hook_stdin_with_dialect(
            "claude-code",
            r#"{"session_id":"s1","tool_name":"Write","tool_input":{"file_path":".claude/settings.json"}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(write.agent_name, "claude-code");
        assert_eq!(write.action_class, ActionClass::FileWrite);
        assert_eq!(write.target, ".claude/settings.json");

        let cursor = parse_hook_stdin_with_dialect(
            "auto",
            r#"{"conversation_id":"cur-1","hook_event_name":"beforeShellExecution","command":"rm -rf /tmp/x"}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(cursor.agent_name, "cursor");
        assert_eq!(cursor.session_id, "cur-1");
        assert_eq!(cursor.action_class, ActionClass::Exec);
        assert_eq!(cursor.target, "rm -rf /tmp/x");

        let codex = parse_hook_stdin_with_dialect(
            "auto",
            r#"{"thread_id":"th-9","event":"exec","command":"git status"}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(codex.agent_name, "codex");
        assert_eq!(codex.session_id, "th-9");
        assert_eq!(codex.action_class, ActionClass::Exec);
        assert_eq!(codex.target, "git status");

        let gemini = parse_hook_stdin_with_dialect(
            "auto",
            r#"{"session_id":"gem-1","hook_event_name":"BeforeTool","tool_name":"write_to_file","tool_input":{"TargetFile":".gemini/settings.json"}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(gemini.agent_name, "gemini");
        assert_eq!(gemini.action_class, ActionClass::FileWrite);
        assert_eq!(gemini.target, ".gemini/settings.json");

        let mcp = parse_hook_stdin_with_dialect(
            "claude-code",
            r#"{"session_id":"s1","tool_name":"mcp__github__create_issue","tool_input":{}}"#,
            "devbox",
        )
        .unwrap();
        assert_eq!(mcp.action_class, ActionClass::McpCall);
        assert_eq!(mcp.target, "mcp__github__create_issue");

        assert!(parse_hook_stdin_with_dialect("auto", "{not-valid-json", "devbox").is_err());
        assert!(parse_hook_stdin_with_dialect("auto", r#"{" " :4e022222}"#, "devbox").is_err());

        let with_bom = parse_hook_stdin_with_dialect(
            "claude-code",
            "\u{FEFF}{\"session_id\":\"s-bom\",\"tool_name\":\"Bash\",\"tool_input\":{\"command\":\"git status\"}}",
            "devbox",
        )
        .unwrap();
        assert_eq!(with_bom.session_id, "s-bom");
        assert_eq!(with_bom.target, "git status");
    }
}
