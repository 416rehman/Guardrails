// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod a2a;
pub mod bedrock_stream;
pub mod compression;
pub mod error;
mod inflate;
pub mod jws;
pub mod providers;
pub mod realtime;
pub mod schema;
pub mod stream;
pub mod strict_json;

pub use error::ProtoError;

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use grdr_model::{DecisionReceipt, Verdict};
use strict_json::{MAX_JSON_DEPTH, MAX_LLM_REQUEST_BYTES, MAX_TOOL_CALLS, parse_strict_json_str};

pub const JSONRPC_ERR_DENIED: i64 = -32001;
pub const JSONRPC_ERR_STEP_UP: i64 = -32002;
pub const JSONRPC_ERR_DEFERRED: i64 = -32003;

const STRUCTURAL_TARGET_KEYS: &[&str] = &["path", "file_path", "url", "command", "repo"];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum McpRequestKind {
    Initialize,
    ToolsList,
    ToolsCall {
        tool_name: String,
        argument_keys: Vec<String>,
        target_hint: Option<String>,
    },
    Notification {
        method: String,
    },
    Other {
        method: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ParsedMcpMessage {
    pub id: Option<Value>,
    pub method: Option<String>,
    pub kind: McpRequestKind,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LlmRequestMeta {
    pub provider: String,
    pub model: Option<String>,
    pub tool_names: Vec<String>,
    pub message_count: usize,
    pub has_system_prompt: bool,
}

pub fn parse_mcp_jsonrpc_line(line: &str) -> Result<ParsedMcpMessage, ProtoError> {
    let val = parse_strict_json_str(line, MAX_LLM_REQUEST_BYTES, MAX_JSON_DEPTH)?;
    let obj = val
        .as_object()
        .ok_or_else(|| ProtoError::Parse("JSON-RPC frame must be an object".into()))?;

    let id = obj.get("id").filter(|v| !v.is_null()).cloned();
    let method = obj
        .get("method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let kind = match method.as_deref() {
        Some("initialize") => McpRequestKind::Initialize,
        Some("tools/list") => McpRequestKind::ToolsList,
        Some("tools/call") => {
            let params = obj
                .get("params")
                .and_then(Value::as_object)
                .ok_or_else(|| ProtoError::Parse("tools/call missing params object".into()))?;
            let tool_name = params
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or_else(|| ProtoError::Parse("tools/call missing params.name".into()))?
                .to_string();

            let mut argument_keys = Vec::new();
            let mut target_hint = None;
            if let Some(args) = params.get("arguments").and_then(Value::as_object) {
                argument_keys = args.keys().cloned().collect();
                argument_keys.sort();
                for key in STRUCTURAL_TARGET_KEYS {
                    if let Some(hint) = args.get(*key).and_then(Value::as_str)
                        && !hint.trim().is_empty()
                    {
                        target_hint = Some(hint.trim().to_string());
                        break;
                    }
                }
            }

            McpRequestKind::ToolsCall {
                tool_name,
                argument_keys,
                target_hint,
            }
        }
        Some(other) if id.is_none() => McpRequestKind::Notification {
            method: other.to_string(),
        },
        Some(other) => McpRequestKind::Other {
            method: other.to_string(),
        },
        None => McpRequestKind::Other {
            method: "response".into(),
        },
    };

    Ok(ParsedMcpMessage { id, method, kind })
}

pub fn build_mcp_target(server_name: &str, tool_name: &str) -> String {
    let trimmed_tool = tool_name.trim();
    if trimmed_tool.starts_with("mcp__") {
        return trimmed_tool.to_string();
    }
    let clean_server = server_name.trim();
    if clean_server.is_empty() {
        format!("mcp__default__{trimmed_tool}")
    } else {
        format!("mcp__{clean_server}__{trimmed_tool}")
    }
}

pub fn build_jsonrpc_denial(
    id: Option<Value>,
    receipt: &DecisionReceipt,
) -> Result<String, ProtoError> {
    let code = match receipt.verdict {
        Verdict::StepUp => JSONRPC_ERR_STEP_UP,
        Verdict::Defer => JSONRPC_ERR_DEFERRED,
        _ => JSONRPC_ERR_DENIED,
    };
    let rule = receipt.rule_id.as_deref().unwrap_or("policy.mcp");
    let message = format!(
        "Guardrails ADR {:?} [{rule}]: {}",
        receipt.verdict, receipt.reason
    );
    let resp = json!({
        "jsonrpc": "2.0",
        "id": id.unwrap_or(Value::Null),
        "error": {
            "code": code,
            "message": message,
            "data": {
                "verdict": receipt.verdict,
                "rule_id": receipt.rule_id,
                "receipt_id": receipt.receipt_id,
                "receipt_digest": receipt.receipt_digest,
                "next_step": receipt.next_step,
            }
        }
    });
    serde_json::to_string(&resp).map_err(|e| ProtoError::Serialize(e.to_string()))
}

pub fn parse_llm_request_metadata(
    provider: &str,
    body: &str,
) -> Result<LlmRequestMeta, ProtoError> {
    let val = parse_strict_json_str(body, MAX_LLM_REQUEST_BYTES, MAX_JSON_DEPTH)?;
    let obj = val
        .as_object()
        .ok_or_else(|| ProtoError::Parse("LLM request body must be a JSON object".into()))?;

    let model = obj
        .get("model")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_string);

    let mut tool_names = Vec::new();
    if let Some(tools) = obj.get("tools").and_then(Value::as_array) {
        if tools.len() > MAX_TOOL_CALLS {
            return Err(ProtoError::PayloadTooLarge);
        }
        for tool in tools {
            if let Some(name) = tool
                .get("name")
                .and_then(Value::as_str)
                .or_else(|| {
                    tool.get("function")
                        .and_then(|f| f.get("name"))
                        .and_then(Value::as_str)
                })
                .map(str::trim)
                .filter(|s| !s.is_empty())
            {
                tool_names.push(name.to_string());
            }
        }
    }

    let messages = obj.get("messages").and_then(Value::as_array);
    let message_count = messages.map_or(0, Vec::len);
    let has_system_field = obj
        .get("system")
        .is_some_and(|v| !v.is_null() && v.as_str().is_none_or(|s| !s.trim().is_empty()));
    let has_system_role = messages.is_some_and(|msgs| {
        msgs.iter().any(|m| {
            matches!(
                m.get("role").and_then(Value::as_str),
                Some("system" | "developer")
            )
        })
    });

    Ok(LlmRequestMeta {
        provider: provider.trim().to_ascii_lowercase(),
        model,
        tool_names,
        message_count,
        has_system_prompt: has_system_field || has_system_role,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::{ActionClass, ControlPoint, Mode};
    use jiff::Timestamp;

    #[test]
    fn parses_mcp_jsonrpc_requests_and_notifications() {
        let init =
            parse_mcp_jsonrpc_line(r#"{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}"#)
                .unwrap();
        assert_eq!(init.id, Some(json!(1)));
        assert_eq!(init.kind, McpRequestKind::Initialize);

        let list =
            parse_mcp_jsonrpc_line(r#"{"jsonrpc":"2.0","id":2,"method":"tools/list"}"#).unwrap();
        assert_eq!(list.kind, McpRequestKind::ToolsList);

        let notif =
            parse_mcp_jsonrpc_line(r#"{"jsonrpc":"2.0","method":"notifications/initialized"}"#)
                .unwrap();
        assert_eq!(
            notif.kind,
            McpRequestKind::Notification {
                method: "notifications/initialized".into()
            }
        );

        let call = parse_mcp_jsonrpc_line(
            r#"{"jsonrpc":"2.0","id":"req-9","method":"tools/call","params":{"name":"create_issue","arguments":{"title":"bug","repo":"org/repo"}}}"#,
        )
        .unwrap();
        assert_eq!(call.id, Some(json!("req-9")));
        assert_eq!(
            call.kind,
            McpRequestKind::ToolsCall {
                tool_name: "create_issue".into(),
                argument_keys: vec!["repo".into(), "title".into()],
                target_hint: Some("org/repo".into()),
            }
        );
        assert_eq!(
            build_mcp_target("github", "create_issue"),
            "mcp__github__create_issue"
        );
        assert!(parse_mcp_jsonrpc_line("{bad").is_err());
    }

    #[test]
    fn builds_jsonrpc_denial_and_step_up_with_receipt_data() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let mut receipt = DecisionReceipt {
            receipt_id: "rcp_123".into(),
            attempt_id: "att_123".into(),
            session_id: "s1".into(),
            device_id: "d1".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::McpCall,
            control_point: ControlPoint::McpBroker,
            target: "mcp__github__delete_repo".into(),
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some("custom.block-delete".into()),
            pack_id: Some("pack-1".into()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason: "Repo deletion blocked".into(),
            next_step: "Use console".into(),
            receipt_digest: "abc123".into(),
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        };

        let deny_raw = build_jsonrpc_denial(Some(json!(42)), &receipt).unwrap();
        let deny_val: Value = serde_json::from_str(&deny_raw).unwrap();
        assert_eq!(deny_val["id"], 42);
        assert_eq!(deny_val["error"]["code"], JSONRPC_ERR_DENIED);
        assert_eq!(deny_val["error"]["data"]["receipt_id"], "rcp_123");

        receipt.verdict = Verdict::StepUp;
        let step_raw = build_jsonrpc_denial(Some(json!(43)), &receipt).unwrap();
        let step_val: Value = serde_json::from_str(&step_raw).unwrap();
        assert_eq!(step_val["error"]["code"], JSONRPC_ERR_STEP_UP);
    }

    #[test]
    fn extracts_llm_metadata_without_prompt_text() {
        let openai = parse_llm_request_metadata(
            "OpenAI",
            r#"{
                "model": "gpt-5",
                "messages": [
                    {"role": "system", "content": "SECRET_SYSTEM_PROMPT"},
                    {"role": "user", "content": "CONFIDENTIAL_USER_PROMPT"}
                ],
                "tools": [{"type": "function", "function": {"name": "read_file"}}]
            }"#,
        )
        .unwrap();
        assert_eq!(openai.provider, "openai");
        assert_eq!(openai.model.as_deref(), Some("gpt-5"));
        assert_eq!(openai.tool_names, vec!["read_file"]);
        assert_eq!(openai.message_count, 2);
        assert!(openai.has_system_prompt);
        let serialized = serde_json::to_string(&openai).unwrap();
        assert!(!serialized.contains("CONFIDENTIAL_USER_PROMPT"));
        assert!(!serialized.contains("SECRET_SYSTEM_PROMPT"));

        let anthropic = parse_llm_request_metadata(
            "anthropic",
            r#"{
                "model": "claude-sonnet-4",
                "system": "Guard prompt",
                "messages": [{"role": "user", "content": "hi"}],
                "tools": [{"name": "bash"}]
            }"#,
        )
        .unwrap();
        assert!(anthropic.has_system_prompt);
        assert_eq!(anthropic.tool_names, vec!["bash"]);
    }
}
