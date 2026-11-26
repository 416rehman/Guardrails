// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Zero-`serde_json` bounded RFC 8259 field scanner (`depth <= 4`) for hook payloads.

use grdr_crypto::sha256_hex;
use grdr_fastpath::FastActionClass;
use grdr_wire::limits::embedded_limits;
use thiserror::Error;

use crate::dialect::{HookDialect, classify_action, classify_control_point, infer_dialect};
use crate::json_lexer::{JsonScanner, bounded_utf8_prefix, first_non_empty};

pub const MAX_HOOK_STDIN_BYTES: usize = 1024 * 1024;
pub const MAX_RAW_PAYLOAD_STORE_BYTES: usize = 4096;
pub const MAX_SCAN_DEPTH: usize = 4;

#[derive(Debug, Clone, PartialEq, Eq, Error)]
pub enum HookCodecError {
    #[error("GRDR-HOOK-0001: hook payload exceeds {max} byte bound")]
    PayloadTooLarge { max: usize },
    #[error("GRDR-HOOK-0002: empty or non-JSON hook stdin payload")]
    EmptyPayload,
    #[error("GRDR-HOOK-0003: malformed JSON hook payload: {detail}")]
    MalformedJson { detail: String },
    #[error("GRDR-HOOK-0004: hook payload missing required action target or command")]
    MissingTarget,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScannedHookInput {
    pub dialect: HookDialect,
    pub session_id: String,
    pub event_name: String,
    pub tool_name: String,
    pub target: String,
    pub command_line: String,
    pub cwd: String,
    pub payload_sha256: String,
    pub raw_payload: String,
    pub action_class: FastActionClass,
    pub control_point: u32,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum ExtractScope {
    Root,
    ToolInput,
    Ignored,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum DialectHint {
    #[default]
    None,
    Cursor,
    Codex,
}

#[derive(Default, Clone, Copy, PartialEq, Eq)]
enum EventOrigin {
    #[default]
    None,
    FallbackEvent,
    ExplicitHookEvent,
}

#[derive(Default)]
struct ExtractedFields {
    session_id: String,
    dialect_hint: DialectHint,
    event_origin: EventOrigin,
    event_name: String,
    tool_name: String,
    root_command: String,
    input_command: String,
    root_file_path: String,
    input_file_path: String,
    root_url: String,
    input_url: String,
    root_cwd: String,
    input_cwd: String,
    root_prompt: String,
    input_prompt: String,
}

impl ExtractedFields {
    fn clear_tool_input(&mut self) {
        self.input_command.clear();
        self.input_file_path.clear();
        self.input_url.clear();
        self.input_cwd.clear();
        self.input_prompt.clear();
    }
}

#[must_use]
pub fn max_hook_stdin_bytes() -> usize {
    embedded_limits().map_or(MAX_HOOK_STDIN_BYTES, |l| l.max_frame_bytes)
}

pub fn scan_hook_json(
    raw: &[u8],
    agent_override: &str,
) -> Result<ScannedHookInput, HookCodecError> {
    let max_bytes = max_hook_stdin_bytes();
    if raw.len() > max_bytes {
        return Err(HookCodecError::PayloadTooLarge { max: max_bytes });
    }
    let clean = raw.strip_prefix(&[0xEF, 0xBB, 0xBF]).unwrap_or(raw);
    if clean.iter().all(|b| b.is_ascii_whitespace()) {
        return Err(HookCodecError::EmptyPayload);
    }

    let mut scanner = JsonScanner::new(clean);
    let mut fields = ExtractedFields::default();
    scan_object(&mut scanner, 1, ExtractScope::Root, &mut fields)?;
    scanner.skip_ws();
    if scanner.pos() != clean.len() {
        return Err(HookCodecError::MalformedJson {
            detail: "trailing data after JSON root object".to_string(),
        });
    }

    let dialect =
        HookDialect::from_cli_name(agent_override).unwrap_or_else(|| match fields.dialect_hint {
            DialectHint::Cursor => HookDialect::Cursor,
            DialectHint::Codex => HookDialect::Codex,
            DialectHint::None => infer_dialect(&fields.event_name, &fields.tool_name),
        });
    let command = first_non_empty(&[fields.input_command.as_str(), fields.root_command.as_str()]);
    let file_path = first_non_empty(&[
        fields.input_file_path.as_str(),
        fields.root_file_path.as_str(),
    ]);
    let url = first_non_empty(&[fields.input_url.as_str(), fields.root_url.as_str()]);
    let prompt = first_non_empty(&[fields.input_prompt.as_str(), fields.root_prompt.as_str()]);
    let cwd = first_non_empty(&[fields.input_cwd.as_str(), fields.root_cwd.as_str()]).to_string();

    let action_class = classify_action(&fields.tool_name, &fields.event_name, url);
    let control_point = classify_control_point(&fields.event_name);
    let resolved_target = select_target(
        action_class,
        &fields.tool_name,
        command,
        file_path,
        url,
        prompt,
    );
    if resolved_target.trim().is_empty() {
        return Err(HookCodecError::MissingTarget);
    }

    let payload_sha256 = sha256_hex(clean);
    let raw_payload = bounded_utf8_prefix(clean, MAX_RAW_PAYLOAD_STORE_BYTES);

    Ok(ScannedHookInput {
        dialect,
        session_id: fields.session_id,
        event_name: fields.event_name,
        tool_name: fields.tool_name,
        target: resolved_target,
        command_line: command.to_string(),
        cwd,
        payload_sha256,
        raw_payload,
        action_class,
        control_point,
    })
}

fn scan_object(
    scanner: &mut JsonScanner<'_>,
    depth: usize,
    scope: ExtractScope,
    out: &mut ExtractedFields,
) -> Result<(), HookCodecError> {
    if depth > MAX_SCAN_DEPTH {
        return Err(HookCodecError::MalformedJson {
            detail: "JSON nesting depth exceeds maximum".to_string(),
        });
    }
    scanner.skip_ws();
    if scanner.next() != Some(b'{') {
        return Err(HookCodecError::MalformedJson {
            detail: "expected JSON object".to_string(),
        });
    }
    scanner.skip_ws();
    if scanner.peek() == Some(b'}') {
        scanner.advance(1);
        return Ok(());
    }
    loop {
        scanner.skip_ws();
        let key = scanner.read_string()?;
        scanner.skip_ws();
        if scanner.next() != Some(b':') {
            return Err(HookCodecError::MalformedJson {
                detail: "expected ':' after key".to_string(),
            });
        }
        scanner.skip_ws();
        let child_scope = match (scope, key.as_str()) {
            (
                ExtractScope::Root,
                "tool_input" | "toolInput" | "toolArgs" | "tool_args" | "arguments" | "args",
            ) => ExtractScope::ToolInput,
            _ => ExtractScope::Ignored,
        };
        scan_value(scanner, &key, depth, scope, child_scope, out)?;
        scanner.skip_ws();
        match scanner.next() {
            Some(b',') => continue,
            Some(b'}') => return Ok(()),
            _ => {
                return Err(HookCodecError::MalformedJson {
                    detail: "expected ',' or '}' in JSON object".to_string(),
                });
            }
        }
    }
}

fn scan_value(
    scanner: &mut JsonScanner<'_>,
    key: &str,
    depth: usize,
    scope: ExtractScope,
    child_scope: ExtractScope,
    out: &mut ExtractedFields,
) -> Result<(), HookCodecError> {
    scanner.skip_ws();
    match scanner.peek() {
        Some(b'"') => {
            let val = scanner.read_string()?;
            if child_scope == ExtractScope::ToolInput && val.trim_start().starts_with('{') {
                out.clear_tool_input();
                let mut embedded = JsonScanner::new(val.as_bytes());
                scan_object(
                    &mut embedded,
                    depth.saturating_add(1),
                    ExtractScope::ToolInput,
                    out,
                )?;
                embedded.skip_ws();
                if embedded.pos() != val.len() {
                    return Err(HookCodecError::MalformedJson {
                        detail: "trailing data inside stringified toolArgs object".to_string(),
                    });
                }
            } else {
                assign_field(scope, key, val, out);
            }
            Ok(())
        }
        Some(b'{') => {
            if child_scope == ExtractScope::ToolInput {
                out.clear_tool_input();
            }
            scan_object(scanner, depth.saturating_add(1), child_scope, out)
        }
        Some(b'[') => scan_array(scanner, depth.saturating_add(1), out),
        Some(b't' | b'f' | b'n') => scanner.skip_keyword(),
        Some(b'-' | b'0'..=b'9') => scanner.skip_number(),
        _ => Err(HookCodecError::MalformedJson {
            detail: "unexpected JSON token".to_string(),
        }),
    }
}

fn scan_array(
    scanner: &mut JsonScanner<'_>,
    depth: usize,
    out: &mut ExtractedFields,
) -> Result<(), HookCodecError> {
    if depth > MAX_SCAN_DEPTH {
        return Err(HookCodecError::MalformedJson {
            detail: "JSON array nesting depth exceeds maximum".to_string(),
        });
    }
    let _ = scanner.next();
    scanner.skip_ws();
    if scanner.peek() == Some(b']') {
        scanner.advance(1);
        return Ok(());
    }
    loop {
        scan_value(
            scanner,
            "",
            depth,
            ExtractScope::Ignored,
            ExtractScope::Ignored,
            out,
        )?;
        scanner.skip_ws();
        match scanner.next() {
            Some(b',') => continue,
            Some(b']') => return Ok(()),
            _ => {
                return Err(HookCodecError::MalformedJson {
                    detail: "expected ',' or ']' in array".to_string(),
                });
            }
        }
    }
}

fn assign_field(scope: ExtractScope, key: &str, val: String, out: &mut ExtractedFields) {
    match (scope, key) {
        (ExtractScope::Root, "session_id" | "sessionId") => set_non_blank(&mut out.session_id, val),
        (ExtractScope::Root, "conversation_id") => {
            if out.dialect_hint == DialectHint::None {
                out.dialect_hint = DialectHint::Cursor;
            }
            set_non_blank(&mut out.session_id, val);
        }
        (ExtractScope::Root, "thread_id") => {
            if out.dialect_hint == DialectHint::None {
                out.dialect_hint = DialectHint::Codex;
            }
            set_non_blank(&mut out.session_id, val);
        }
        (ExtractScope::Root, "hook_event_name" | "hookEventName" | "event_name" | "eventName") => {
            if !val.trim().is_empty() {
                out.event_name = val;
                out.event_origin = EventOrigin::ExplicitHookEvent;
            }
        }
        (ExtractScope::Root, "event") => {
            if out.dialect_hint == DialectHint::None {
                out.dialect_hint = DialectHint::Codex;
            }
            if out.event_origin != EventOrigin::ExplicitHookEvent && !val.trim().is_empty() {
                out.event_name = val;
                out.event_origin = EventOrigin::FallbackEvent;
            }
        }
        (ExtractScope::Root, "tool_name" | "toolName" | "tool") => {
            set_non_blank(&mut out.tool_name, val);
        }
        (ExtractScope::Root, "command" | "cmd" | "CommandLine" | "command_line") => {
            set_non_blank(&mut out.root_command, val);
        }
        (
            ExtractScope::ToolInput,
            "command" | "cmd" | "CommandLine" | "script" | "command_line",
        ) => set_non_blank(&mut out.input_command, val),
        (
            ExtractScope::Root,
            "file_path" | "filePath" | "path" | "TargetFile" | "target_file" | "AbsolutePath",
        ) => set_non_blank(&mut out.root_file_path, val),
        (
            ExtractScope::ToolInput,
            "file_path" | "filePath" | "path" | "TargetFile" | "target_file" | "AbsolutePath"
            | "target",
        ) => set_non_blank(&mut out.input_file_path, val),
        (ExtractScope::Root, "url" | "uri" | "ServerUrl" | "Url") => {
            set_non_blank(&mut out.root_url, val);
        }
        (ExtractScope::ToolInput, "url" | "uri" | "ServerUrl" | "Url") => {
            set_non_blank(&mut out.input_url, val);
        }
        (ExtractScope::Root, "cwd" | "working_directory") => {
            set_non_blank(&mut out.root_cwd, val);
        }
        (ExtractScope::ToolInput, "cwd" | "working_directory") => {
            set_non_blank(&mut out.input_cwd, val);
        }
        (ExtractScope::Root, "prompt") => set_non_blank(&mut out.root_prompt, val),
        (ExtractScope::ToolInput, "prompt") => set_non_blank(&mut out.input_prompt, val),
        _ => {}
    }
}

fn set_non_blank(slot: &mut String, val: String) {
    if !val.trim().is_empty() {
        *slot = val;
    }
}

fn select_target(
    action_class: FastActionClass,
    tool_name: &str,
    command: &str,
    file_path: &str,
    url: &str,
    prompt: &str,
) -> String {
    if matches!(
        action_class,
        FastActionClass::McpCall | FastActionClass::McpConnect
    ) {
        let arg = first_non_empty(&[url, command, file_path, prompt]);
        if tool_name.trim().is_empty() {
            return arg.to_string();
        }
        if arg.is_empty() || arg == tool_name {
            return tool_name.to_string();
        }
        return format!("{tool_name} {arg}");
    }
    match action_class {
        FastActionClass::FileRead
        | FastActionClass::FileWrite
        | FastActionClass::FileDelete
        | FastActionClass::ConfigChange => {
            first_non_empty(&[file_path, command, url, prompt, tool_name]).to_string()
        }
        FastActionClass::NetConnect
        | FastActionClass::NetRequest
        | FastActionClass::LlmRequest
        | FastActionClass::DataFlow => {
            first_non_empty(&[url, command, file_path, prompt, tool_name]).to_string()
        }
        _ => first_non_empty(&[command, file_path, url, prompt, tool_name]).to_string(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn validates_utf16_surrogates_rfc8259_numbers_and_tool_input_precedence() {
        let parsed = scan_hook_json(
            br#"{"tool_name":"Bash","command":"echo old","extra":{"command":"echo ignored"},"tool_input":{"command":"echo \uD83D\uDE80"},"count":-1.5e+2}"#,
            "auto",
        )
        .expect("valid hook json");
        assert_eq!(parsed.target, "echo \u{1F680}");
        assert_eq!(parsed.command_line, "echo \u{1F680}");

        let dup_last = scan_hook_json(
            br#"{"tool_name":"Write","tool_input":{"file_path":"a.txt","file_path":"b.txt"}}"#,
            "auto",
        )
        .expect("last-wins duplicate key");
        assert_eq!(dup_last.target, "b.txt");

        let dup_obj = scan_hook_json(
            br#"{"tool_name":"Bash","tool_input":{"command":"rm -rf /"},"tool_input":{"command":"echo safe"}}"#,
            "auto",
        )
        .expect("duplicate tool_input resets prior fields");
        assert_eq!(dup_obj.target, "echo safe");
        assert_eq!(dup_obj.command_line, "echo safe");

        let copilot_str = scan_hook_json(
            br#"{"sessionId":"cp-1","hookEventName":"preToolUse","toolName":"pwsh","toolArgs":"{\"command\":\"Get-ChildItem\"}"}"#,
            "auto",
        )
        .expect("copilot stringified toolArgs");
        assert_eq!(copilot_str.target, "Get-ChildItem");
        assert_eq!(copilot_str.command_line, "Get-ChildItem");

        let copilot_obj = scan_hook_json(
            br#"{"sessionId":"cp-2","hookEventName":"preToolUse","toolName":"create_file","toolArgs":{"file_path":"/tmp/x"}}"#,
            "copilot",
        )
        .expect("copilot object toolArgs");
        assert_eq!(copilot_obj.action_class, FastActionClass::FileWrite);
        assert_eq!(copilot_obj.target, "/tmp/x");

        let non_blank = scan_hook_json(
            br#"{"tool_name":"Bash","tool_input":{"command":"id","cmd":"   "}}"#,
            "auto",
        )
        .expect("blank alias should not erase valid command");
        assert_eq!(non_blank.target, "id");

        let event_prec = scan_hook_json(
            br#"{"hook_event_name":"PreToolUse","event":"PostToolUse","tool_name":"Bash","tool_input":{"command":"id"}}"#,
            "auto",
        )
        .expect("explicit hook_event_name wins over fallback event");
        assert_eq!(event_prec.event_name, "PreToolUse");
        assert_eq!(event_prec.control_point, 1);

        let web_search = scan_hook_json(
            br#"{"tool_name":"WebSearch","tool_input":{"query":"rust async","url":"https://docs.rs"}}"#,
            "auto",
        )
        .expect("query must not overwrite url");
        assert_eq!(web_search.target, "https://docs.rs");

        let mcp_with_cmd = scan_hook_json(
            br#"{"tool_name":"mcp__shell__exec","tool_input":{"command":"rm -rf /"}}"#,
            "auto",
        )
        .expect("mcp target retains mcp tool_name");
        assert!(mcp_with_cmd.target.contains("mcp__shell__exec"));
        assert!(mcp_with_cmd.target.contains("rm -rf /"));

        for bad in [
            br#"{"tool_name":"Bash","command":"\uD83D"}"#.as_slice(),
            br#"{"tool_name":"Bash","command":"\uDE80"}"#.as_slice(),
            br#"{"tool_name":"Bash","command":"ok","n":01}"#.as_slice(),
            br#"{"tool_name":"Bash","command":"ok","n":--}"#.as_slice(),
            br#"{"tool_name":"Bash","command":"ok","n":1.}"#.as_slice(),
            br#"{"tool_name":"Bash","command":"ok","n":1e+}"#.as_slice(),
            br#"{"tool_name":"Bash","command":"ok"} trailing"#.as_slice(),
        ] {
            assert!(
                scan_hook_json(bad, "auto").is_err(),
                "expected error for invalid payload: {:?}",
                String::from_utf8_lossy(bad)
            );
        }
    }
}
