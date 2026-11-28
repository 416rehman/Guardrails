// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! ACP protocol version negotiation (v1 vs v2), capability claims, `grdr-mcp` injection,
//! and `session/new` / `session/prompt` / `session/update` claim observation (`docs/design/07`).

use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use grdr_model::{ActionClass, Verdict};

use crate::conductor::AcpConductorConfig;
use crate::conductor_fs::{
    current_ts, evaluate_or_jsonrpc, extract_session, jsonrpc_error, make_control_call,
};
use crate::{AcpError, DecisionClient, build_attempt, classify_action_kind};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AcpCapabilityLevel {
    Gate,
    Observe,
    Partial,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AcpCapabilityClaims {
    pub protocol_era: String,
    pub fs_read: AcpCapabilityLevel,
    pub fs_write: AcpCapabilityLevel,
    pub terminal: AcpCapabilityLevel,
    pub permission: AcpCapabilityLevel,
    pub session_update: AcpCapabilityLevel,
    pub mcp_broker: AcpCapabilityLevel,
}

#[must_use]
pub fn is_acp_v2_version(raw: &str) -> bool {
    let lower = raw.trim().to_ascii_lowercase();
    lower == "2"
        || lower == "v2"
        || lower.starts_with("2.")
        || lower.starts_with("v2.")
        || lower.contains("alpha")
}

#[must_use]
pub fn capability_claims_for_version(
    version: &str,
    mcp_broker_configured: bool,
) -> AcpCapabilityClaims {
    let is_v2 = is_acp_v2_version(version);
    let delegated = if is_v2 {
        AcpCapabilityLevel::Unavailable
    } else {
        AcpCapabilityLevel::Gate
    };
    let mcp_broker = if mcp_broker_configured {
        AcpCapabilityLevel::Gate
    } else {
        AcpCapabilityLevel::Unavailable
    };
    AcpCapabilityClaims {
        protocol_era: if is_v2 {
            "v2".to_string()
        } else {
            "v1".to_string()
        },
        fs_read: delegated,
        fs_write: delegated,
        terminal: delegated,
        permission: AcpCapabilityLevel::Partial,
        session_update: AcpCapabilityLevel::Observe,
        mcp_broker,
    }
}

pub fn inject_mcp_broker_config(
    params: &Value,
    cfg: &AcpConductorConfig,
) -> Result<Value, AcpError> {
    let Some(cmd) = cfg
        .mcp_broker_command
        .as_deref()
        .filter(|s| !s.trim().is_empty())
    else {
        return Ok(params.clone());
    };
    let mut updated = match params {
        Value::Object(map) => Value::Object(map.clone()),
        Value::Null => json!({}),
        _ => {
            return Err(AcpError::InvalidPayload(
                "session/new params must be a JSON object".to_string(),
            ));
        }
    };
    let mut args = cfg.mcp_broker_args.clone();
    if args.is_empty() {
        args.push("--stdio".to_string());
    }
    let broker_entry = json!({
        "name": "grdr-mcp",
        "command": cmd,
        "args": args,
        "env": [{ "name": "GRDR_SESSION", "value": extract_session(params, &cfg.session_id) }],
    });
    if let Some(obj) = updated.as_object_mut() {
        let entry = obj
            .entry("mcpServers".to_string())
            .or_insert_with(|| Value::Array(Vec::new()));
        if entry.is_null() {
            *entry = Value::Array(Vec::new());
        }
        if let Some(arr) = entry.as_array_mut() {
            if arr.iter().any(|item| !item.is_object()) {
                return Err(AcpError::InvalidPayload(
                    "params.mcpServers array entries must be JSON objects".to_string(),
                ));
            }
            let exists = arr.iter().any(|item| {
                item.get("name")
                    .and_then(Value::as_str)
                    .is_some_and(|n| n == "grdr-mcp")
            });
            if !exists {
                arr.push(broker_entry);
            }
        } else if let Some(map) = entry.as_object_mut() {
            if map.values().any(|item| !item.is_object()) {
                return Err(AcpError::InvalidPayload(
                    "params.mcpServers map entries must be JSON objects".to_string(),
                ));
            }
            map.entry("grdr-mcp".to_string()).or_insert(broker_entry);
        } else {
            return Err(AcpError::InvalidPayload(
                "params.mcpServers must be an array or object".to_string(),
            ));
        }
    }
    Ok(updated)
}

pub(crate) fn build_initialize_result(
    req_id: Value,
    client_proto: &str,
    cfg: &AcpConductorConfig,
) -> String {
    let is_v2 = is_acp_v2_version(client_proto);
    let claims = capability_claims_for_version(client_proto, cfg.mcp_broker_command.is_some());
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": {
            "protocolVersion": client_proto,
            "clientCapabilities": {
                "fs": { "readTextFile": !is_v2, "writeTextFile": !is_v2 },
                "terminal": !is_v2,
                "permission": true
            },
            "mcpBrokerInjected": cfg.mcp_broker_command.is_some(),
            "capabilityClaims": claims,
            "guardrailsProfile": "acp-conductor"
        }
    }))
    .unwrap_or_default()
}

pub(crate) async fn handle_session_new<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    req_id: Value,
    params: &Value,
) -> String {
    let sid = extract_session(params, &cfg.session_id);
    let enriched = match inject_mcp_broker_config(params, cfg) {
        Ok(v) => v,
        Err(err) => return jsonrpc_error(req_id, -32602, &err.to_string()).unwrap_or_default(),
    };
    let call = make_control_call(
        &req_id,
        &cfg.agent_name,
        sid.clone(),
        ActionClass::AgentSpawn,
        &cfg.agent_name,
        "ACP session/new".to_string(),
    );
    let servers = enriched
        .get("mcpServers")
        .cloned()
        .unwrap_or_else(|| json!([]));
    evaluate_or_jsonrpc(
        client,
        cfg,
        &call,
        req_id,
        json!({ "sessionId": sid, "mcpServers": servers }),
    )
    .await
}

pub(crate) async fn handle_session_prompt<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    req_id: Value,
    params: &Value,
) -> String {
    let sid = extract_session(params, &cfg.session_id);
    let call = make_control_call(
        &req_id,
        &cfg.agent_name,
        sid,
        ActionClass::LlmRequest,
        "acp:session/prompt",
        "ACP session/prompt".to_string(),
    );
    evaluate_or_jsonrpc(client, cfg, &call, req_id, json!({ "allowed": true })).await
}

pub(crate) async fn observe_session_update_claim<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    params: &Value,
) {
    let update = params.get("update").unwrap_or(params);
    let update_kind = update
        .get("sessionUpdate")
        .and_then(Value::as_str)
        .unwrap_or("");
    if !matches!(update_kind, "tool_call" | "tool_call_update") {
        return;
    }
    let tool_id = update
        .get("toolCallId")
        .and_then(Value::as_str)
        .unwrap_or("claim");
    let kind = update
        .get("kind")
        .and_then(Value::as_str)
        .unwrap_or("mcp_call");
    let title = update
        .get("title")
        .and_then(Value::as_str)
        .unwrap_or(tool_id);
    let target = update
        .get("rawInput")
        .and_then(|r| {
            r.get("path")
                .or_else(|| r.get("command"))
                .or_else(|| r.get("url"))
        })
        .and_then(Value::as_str)
        .unwrap_or(title);
    let Ok(now) = current_ts() else {
        return;
    };
    let call = make_control_call(
        &json!(tool_id),
        &cfg.agent_name,
        extract_session(params, &cfg.session_id),
        classify_action_kind(kind, title),
        target,
        format!("ACP claim {update_kind} {tool_id} {title}"),
    );
    let attempt = build_attempt(&call, now);
    if let Err(err) = client.decide(&attempt).await {
        tracing::warn!(error = %err, "ACP session/update claim decide failed");
    }
}

pub(crate) fn v2_removed_method_error(req_id: Value, method: &str) -> String {
    jsonrpc_error(
        req_id,
        -32601,
        &format!("ACP v2 removed delegated method `{method}`; enforce via grdr-mcp"),
    )
    .unwrap_or_default()
}

pub(crate) fn permission_outcome_payload(
    verdict: Option<Verdict>,
    receipt_id: &str,
    retry_token: Option<&str>,
    allow_option: &str,
    reject_option: Option<&str>,
) -> Value {
    let outcome = match verdict {
        Some(Verdict::Allow) => json!({ "outcome": "selected", "optionId": allow_option }),
        _ => match reject_option {
            Some(reject_id) => json!({ "outcome": "selected", "optionId": reject_id }),
            None => json!({ "outcome": "cancelled" }),
        },
    };
    let mut result = json!({ "outcome": outcome });
    if let Some(obj) = result.as_object_mut() {
        match verdict {
            Some(Verdict::Allow) => {
                obj.insert("forwardToPerson".to_string(), Value::Bool(true));
                obj.insert(
                    "receiptId".to_string(),
                    Value::String(receipt_id.to_string()),
                );
            }
            Some(Verdict::StepUp) => {
                if let Some(tok) = retry_token {
                    obj.insert("retryToken".to_string(), Value::String(tok.to_string()));
                    obj.insert(
                        "stepUpGuidance".to_string(),
                        Value::String(format!("Approval required: run grdr approve --token {tok}")),
                    );
                } else {
                    obj.insert(
                        "stepUpGuidance".to_string(),
                        Value::String(
                            "Approval required: escalate or approve via grdr approve".to_string(),
                        ),
                    );
                }
                obj.insert(
                    "receiptId".to_string(),
                    Value::String(receipt_id.to_string()),
                );
            }
            _ => {}
        }
    }
    result
}
