// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Strict JSON-RPC 2.0 MCP message parsing, tool pinning, and attempt translation.

pub mod pinning;
pub mod progressive;
pub mod strict_json;

pub use pinning::*;
pub use progressive::*;
pub use strict_json::{MAX_MCP_DEPTH, MAX_MCP_FRAME_BYTES, parse_strict_mcp_json};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use serde_json::Value;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

pub const JSONRPC_VERSION: &str = "2.0";
pub const JSONRPC_ERR_STEP_UP_OAUTH: i64 = -32042;

const TARGET_HINT_KEYS: &[&str] = &["path", "file_path", "uri", "url", "command", "repo", "sql"];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum McpProtoError {
    #[error("GRDR-MCP-0001: invalid JSON-RPC 2.0 MCP frame: {0}")]
    InvalidFrame(String),
    #[error("GRDR-MCP-0002: unsupported or malformed MCP method: {0}")]
    UnsupportedMethod(String),
    #[error("GRDR-MCP-0003: tool call missing target tool name")]
    UnknownTool,
    #[error("GRDR-MCP-0004: tool pin mismatch for {tool_name}: expected {expected}, got {actual}")]
    PinMismatch {
        tool_name: String,
        expected: String,
        actual: String,
    },
    #[error("GRDR-MCP-0005: tool descriptor for {tool_name} flagged for poisoning: {detail}")]
    PoisonedDescriptor { tool_name: String, detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum McpMethod {
    Initialize,
    ToolsList,
    ToolsCall,
    ResourcesList,
    ResourcesRead,
    ResourcesSubscribe,
    PromptsList,
    PromptsGet,
    SamplingCreateMessage,
    ElicitationCreate,
    RootsList,
    Custom(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRequest {
    pub id: Option<Value>,
    pub method: McpMethod,
    pub tool_name: Option<String>,
    pub arguments: Value,
    pub target_hint: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpResponse {
    pub jsonrpc: String,
    pub id: Value,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<McpRpcError>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpRpcError {
    pub code: i64,
    pub message: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<Value>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct McpAttemptContext {
    pub attempt_id: String,
    pub session_id: String,
    pub device_id: String,
    pub device_name: String,
    pub agent_name: String,
    pub server_name: String,
    pub timestamp: Timestamp,
}

impl McpMethod {
    #[must_use]
    pub fn from_wire(raw: &str) -> Self {
        match raw.trim() {
            "initialize" => Self::Initialize,
            "tools/list" => Self::ToolsList,
            "tools/call" => Self::ToolsCall,
            "resources/list" => Self::ResourcesList,
            "resources/read" => Self::ResourcesRead,
            "resources/subscribe" => Self::ResourcesSubscribe,
            "prompts/list" => Self::PromptsList,
            "prompts/get" => Self::PromptsGet,
            "sampling/createMessage" => Self::SamplingCreateMessage,
            "elicitation/create" => Self::ElicitationCreate,
            "roots/list" => Self::RootsList,
            other => Self::Custom(other.to_owned()),
        }
    }

    #[must_use]
    pub fn as_wire(&self) -> &str {
        match self {
            Self::Initialize => "initialize",
            Self::ToolsList => "tools/list",
            Self::ToolsCall => "tools/call",
            Self::ResourcesList => "resources/list",
            Self::ResourcesRead => "resources/read",
            Self::ResourcesSubscribe => "resources/subscribe",
            Self::PromptsList => "prompts/list",
            Self::PromptsGet => "prompts/get",
            Self::SamplingCreateMessage => "sampling/createMessage",
            Self::ElicitationCreate => "elicitation/create",
            Self::RootsList => "roots/list",
            Self::Custom(s) => s.as_str(),
        }
    }
}

pub fn parse_mcp_request(raw: &str) -> Result<McpRequest, McpProtoError> {
    let value = parse_strict_mcp_json(raw)?;
    let obj = value
        .as_object()
        .ok_or_else(|| McpProtoError::InvalidFrame("frame must be a JSON object".into()))?;

    let version = obj
        .get("jsonrpc")
        .and_then(Value::as_str)
        .ok_or_else(|| McpProtoError::InvalidFrame("missing jsonrpc field".into()))?;
    if version != JSONRPC_VERSION {
        return Err(McpProtoError::InvalidFrame(format!(
            "expected jsonrpc 2.0, got {version}"
        )));
    }

    let raw_method = obj
        .get("method")
        .and_then(Value::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| McpProtoError::UnsupportedMethod("missing method name".into()))?;

    let method = McpMethod::from_wire(raw_method);
    let id = obj.get("id").filter(|v| !v.is_null()).cloned();
    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    let (tool_name, arguments, target_hint) = match method {
        McpMethod::ToolsCall => {
            let p_obj = params.as_object().ok_or_else(|| {
                McpProtoError::InvalidFrame("tools/call requires params object".into())
            })?;
            let name = p_obj
                .get("name")
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .ok_or(McpProtoError::UnknownTool)?
                .to_owned();
            let args = p_obj
                .get("arguments")
                .cloned()
                .unwrap_or_else(|| Value::Object(serde_json::Map::new()));
            let hint = extract_target_hint(&args);
            (Some(name), args, hint)
        }
        McpMethod::ResourcesRead | McpMethod::ResourcesSubscribe => {
            let uri = params
                .as_object()
                .and_then(|o| o.get("uri"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            (None, params, uri)
        }
        McpMethod::PromptsGet => {
            let name = params
                .as_object()
                .and_then(|o| o.get("name"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            (name.clone(), params, name)
        }
        McpMethod::SamplingCreateMessage => {
            let model_hint = params
                .as_object()
                .and_then(|o| o.get("modelPreferences"))
                .and_then(|m| m.get("hints"))
                .and_then(Value::as_array)
                .and_then(|a| a.first())
                .and_then(|h| h.get("name"))
                .and_then(Value::as_str)
                .map(str::to_owned)
                .or_else(|| Some("sampling/createMessage".to_owned()));
            (None, params, model_hint)
        }
        McpMethod::ElicitationCreate => {
            let mode = params
                .as_object()
                .and_then(|o| o.get("mode"))
                .and_then(Value::as_str)
                .unwrap_or("form");
            let url = params
                .as_object()
                .and_then(|o| o.get("url"))
                .and_then(Value::as_str)
                .map(str::trim)
                .filter(|s| !s.is_empty())
                .map(str::to_owned);
            let hint = if mode == "url" {
                url
            } else {
                Some("elicitation:form".to_owned())
            };
            (None, params, hint)
        }
        _ => (None, params, None),
    };

    Ok(McpRequest {
        id,
        method,
        tool_name,
        arguments,
        target_hint,
    })
}

pub fn mcp_call_to_attempt(
    req: &McpRequest,
    ctx: &McpAttemptContext,
) -> Result<ActionAttempt, McpProtoError> {
    let (action_class, target) = match req.method {
        McpMethod::ToolsCall => {
            let tool = req.tool_name.as_deref().ok_or(McpProtoError::UnknownTool)?;
            let target = match req.target_hint.as_deref() {
                Some(hint) => format!("{}/{tool}:{hint}", ctx.server_name),
                None => format!("{}/{tool}", ctx.server_name),
            };
            (ActionClass::McpCall, target)
        }
        McpMethod::ResourcesRead | McpMethod::ResourcesSubscribe => {
            let uri = req.target_hint.as_deref().unwrap_or("unknown");
            let lower = uri.to_ascii_lowercase();
            let class = if lower.starts_with("http://") || lower.starts_with("https://") {
                ActionClass::NetRequest
            } else {
                ActionClass::FileRead
            };
            (class, uri.to_owned())
        }
        McpMethod::PromptsGet => {
            let prompt = req.target_hint.as_deref().unwrap_or("unknown");
            (
                ActionClass::McpCall,
                format!("{}/prompt:{prompt}", ctx.server_name),
            )
        }
        McpMethod::SamplingCreateMessage => (
            ActionClass::LlmRequest,
            format!(
                "{}/sampling/{}",
                ctx.server_name,
                req.target_hint.as_deref().unwrap_or("default")
            ),
        ),
        McpMethod::ElicitationCreate => {
            let mode = req
                .arguments
                .get("mode")
                .and_then(Value::as_str)
                .unwrap_or("form");
            if mode == "url" {
                let url = req.target_hint.as_deref().unwrap_or("unknown-url");
                (ActionClass::NetRequest, url.to_owned())
            } else {
                (
                    ActionClass::UiAct,
                    format!("{}/elicitation/form", ctx.server_name),
                )
            }
        }
        _ => (
            ActionClass::McpConnect,
            format!("{}/{}", ctx.server_name, req.method.as_wire()),
        ),
    };

    Ok(ActionAttempt {
        id: ctx.attempt_id.clone(),
        session_id: ctx.session_id.clone(),
        device_id: ctx.device_id.clone(),
        device_name: ctx.device_name.clone(),
        agent_name: ctx.agent_name.clone(),
        action_class,
        control_point: ControlPoint::McpBroker,
        target: target.clone(),
        summary: format!("MCP {} ({})", req.method.as_wire(), target),
        timestamp: ctx.timestamp,
        ..Default::default()
    })
}

fn extract_target_hint(args: &Value) -> Option<String> {
    let obj = args.as_object()?;
    for key in TARGET_HINT_KEYS {
        if let Some(s) = obj.get(*key).and_then(Value::as_str) {
            let trimmed = s.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_owned());
            }
        }
    }
    None
}
