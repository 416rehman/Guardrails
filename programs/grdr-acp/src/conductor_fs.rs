// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::path::{Path, PathBuf};

use grdr_crypto::sha256_hex;
use grdr_model::{ActionAttempt, ActionClass, DecisionReceipt, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_strings::sanitize_untrusted_text;
use jiff::Timestamp;
use serde_json::{Value, json};

use crate::conductor::AcpConductorConfig;
pub(crate) use crate::path_confine::{
    resolve_confined_path, validate_modify_target, validate_terminal_create_params,
};
use crate::{
    AcpError, DecisionClient, NormalizedControlCall, build_attempt, extract_daemon_retry_token,
};

const ACP_PROTOCOL_VERSION: &str = "2025-03-26";
const MAX_SESSION_ID_CHARS: usize = 256;

pub fn default_workspace_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn current_ts() -> Result<Timestamp, AcpError> {
    SystemClock::new()
        .now_wall()
        .map_err(|err| AcpError::Transport(format!("wall clock unavailable: {err}")))
}

pub(crate) fn extract_session(params: &Value, default_session: &str) -> String {
    let raw = params
        .get("sessionId")
        .and_then(Value::as_str)
        .unwrap_or(default_session);
    sanitize_session_id(raw, default_session)
}

pub(crate) fn sanitize_session_id(raw: &str, fallback: &str) -> String {
    let cleaned = sanitize_untrusted_text(raw);
    let trimmed: String = cleaned.trim().chars().take(MAX_SESSION_ID_CHARS).collect();
    if trimmed.is_empty() {
        let clean_fb = sanitize_untrusted_text(fallback);
        let fb_trimmed = clean_fb.trim();
        if fb_trimmed.is_empty() {
            "acp-session".to_string()
        } else {
            fb_trimmed.chars().take(MAX_SESSION_ID_CHARS).collect()
        }
    } else {
        trimmed
    }
}

pub(crate) fn make_control_call(
    req_id: &Value,
    agent_name: &str,
    session_id: String,
    action_class: ActionClass,
    target: &str,
    summary: String,
) -> NormalizedControlCall {
    let request_id = match req_id {
        Value::String(s) if !s.is_empty() => s.clone(),
        Value::Null => "acp-req".to_string(),
        other => other.to_string(),
    };
    NormalizedControlCall {
        request_id,
        spec_version: ACP_PROTOCOL_VERSION.to_string(),
        session_id,
        agent_name: agent_name.to_string(),
        action_class,
        target: target.to_string(),
        summary,
    }
}

pub(crate) fn jsonrpc_error(id: Value, code: i64, message: &str) -> Result<String, AcpError> {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message }
    }))
    .map_err(|e| AcpError::InvalidPayload(e.to_string()))
}

pub(crate) fn jsonrpc_error_with_data(
    id: Value,
    code: i64,
    message: &str,
    data: Value,
) -> Result<String, AcpError> {
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": id,
        "error": { "code": code, "message": message, "data": data }
    }))
    .map_err(|e| AcpError::InvalidPayload(e.to_string()))
}

pub(crate) async fn evaluate_or_jsonrpc<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    call: &NormalizedControlCall,
    req_id: Value,
    mut allow_payload: Value,
) -> String {
    let Ok(now) = current_ts() else {
        return encode_err_fallback(req_id, -32001, "wall clock unavailable");
    };
    let attempt = build_attempt(call, now);
    match client.decide(&attempt).await {
        Ok(receipt) if receipt.verdict == Verdict::Allow => {
            if let Some(obj) = allow_payload.as_object_mut() {
                obj.insert("receiptId".to_string(), Value::String(receipt.receipt_id));
            }
            encode_jsonrpc_ok(req_id, allow_payload)
        }
        Ok(receipt) if receipt.verdict == Verdict::Modify => {
            evaluate_modify_rewrite(client, cfg, call, &attempt, receipt, req_id, allow_payload)
                .await
        }
        Ok(receipt) => {
            let code = if receipt.verdict == Verdict::StepUp {
                -32002
            } else {
                -32001
            };
            if receipt.verdict == Verdict::StepUp {
                let retry_token = extract_daemon_retry_token(&receipt);
                let reason = if let Some(ref tok) = retry_token {
                    format!("{} (retry_token={tok})", receipt.reason)
                } else {
                    receipt.reason.clone()
                };
                let mut data = json!({
                    "verdict": "step_up",
                    "receiptId": receipt.receipt_id,
                    "nextStep": receipt.next_step,
                });
                if let (Some(tok), Some(obj)) = (retry_token, data.as_object_mut()) {
                    obj.insert("retryToken".to_string(), Value::String(tok));
                }
                return jsonrpc_error_with_data(req_id.clone(), code, &reason, data)
                    .unwrap_or_else(|_| encode_err_fallback(req_id, code, &reason));
            }
            encode_err_fallback(req_id, code, &receipt.reason)
        }
        Err(err) => encode_err_fallback(req_id, -32001, &err.to_string()),
    }
}

pub(crate) async fn evaluate_modify_decision<C: DecisionClient>(
    client: &C,
    workspace_root: &Path,
    call: &NormalizedControlCall,
    attempt: &ActionAttempt,
    receipt: &DecisionReceipt,
) -> Result<(DecisionReceipt, String), String> {
    let candidate = extract_rewritten_target(receipt, &call.target)
        .ok_or_else(|| "modify verdict missing target; failing closed".to_string())?;
    let rewritten = validate_modify_target(workspace_root, call.action_class, &candidate)
        .map_err(|err| format!("unsafe rewrite: {err}"))?;
    let mut recheck = attempt.clone();
    recheck.target = rewritten.clone();
    recheck.summary = format!("{} [modified]", call.summary);
    let mut final_receipt = client
        .decide(&recheck)
        .await
        .map_err(|_| "rewrite re-evaluation unavailable".to_string())?;
    if final_receipt.verdict != Verdict::Allow {
        return Err(final_receipt.reason);
    }
    final_receipt.verdict = Verdict::Modify;
    final_receipt.target = rewritten.clone();
    final_receipt.key_id = None;
    final_receipt.signature = None;
    final_receipt.signature_verified = None;
    final_receipt.receipt_digest =
        grdr_core::policy::compute_receipt_digest(&grdr_core::policy::ReceiptDigestInput {
            attempt_id: &final_receipt.attempt_id,
            session_id: &final_receipt.session_id,
            agent_name: &final_receipt.agent_name,
            action_class: final_receipt.action_class,
            target: &final_receipt.target,
            verdict: final_receipt.verdict,
            rule_id: final_receipt.rule_id.as_deref(),
            decided_at: final_receipt.decided_at,
        });
    Ok((final_receipt, rewritten))
}

async fn evaluate_modify_rewrite<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    call: &NormalizedControlCall,
    attempt: &ActionAttempt,
    receipt: DecisionReceipt,
    req_id: Value,
    mut allow_payload: Value,
) -> String {
    let (final_receipt, rewritten) = match evaluate_modify_decision(
        client,
        &cfg.workspace_root,
        call,
        attempt,
        &receipt,
    )
    .await
    {
        Ok(res) => res,
        Err(reason) => return encode_err_fallback(req_id, -32001, &reason),
    };
    if let Some(obj) = allow_payload.as_object_mut() {
        obj.insert(
            "receiptId".to_string(),
            Value::String(final_receipt.receipt_id),
        );
        obj.insert("modified".to_string(), Value::Bool(true));
        obj.insert(
            "originalDigest".to_string(),
            Value::String(sha256_hex(call.target.as_bytes())),
        );
        obj.insert(
            "rewrittenDigest".to_string(),
            Value::String(sha256_hex(rewritten.as_bytes())),
        );
        obj.insert(
            "rewrittenTarget".to_string(),
            Value::String(rewritten.clone()),
        );
        if obj.contains_key("path") {
            obj.insert("path".to_string(), Value::String(rewritten));
        }
    }
    encode_jsonrpc_ok(req_id, allow_payload)
}

pub(crate) fn extract_rewritten_target(
    receipt: &DecisionReceipt,
    original_target: &str,
) -> Option<String> {
    let trimmed_target = receipt.target.trim();
    if !trimmed_target.is_empty() && trimmed_target != original_target {
        return Some(trimmed_target.to_string());
    }
    let next = receipt.next_step.trim();
    if let Some(rest) = next
        .strip_prefix("modify:")
        .or_else(|| next.strip_prefix("rewrite:"))
    {
        let clean = rest.trim();
        if !clean.is_empty() {
            return Some(clean.to_string());
        }
    }
    None
}

pub(crate) async fn handle_fs_read<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    req_id: Value,
    params: &Value,
) -> String {
    let Some(raw_path) = params.get("path").and_then(Value::as_str) else {
        return encode_err_fallback(req_id, -32602, "fs/read_text_file requires string path");
    };
    let confined = match resolve_confined_path(&cfg.workspace_root, raw_path, false) {
        Ok(p) => p,
        Err(err) => return encode_err_fallback(req_id, -32602, err),
    };
    let call = make_control_call(
        &req_id,
        &cfg.agent_name,
        extract_session(params, &cfg.session_id),
        ActionClass::FileRead,
        &confined,
        format!("ACP fs/read_text_file {confined}"),
    );
    evaluate_or_jsonrpc(
        client,
        cfg,
        &call,
        req_id,
        json!({ "allowed": true, "path": confined }),
    )
    .await
}

pub(crate) async fn handle_fs_write<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    req_id: Value,
    params: &Value,
) -> String {
    let Some(raw_path) = params.get("path").and_then(Value::as_str) else {
        return encode_err_fallback(req_id, -32602, "fs/write_text_file requires string path");
    };
    let confined = match resolve_confined_path(&cfg.workspace_root, raw_path, false) {
        Ok(p) => p,
        Err(err) => return encode_err_fallback(req_id, -32602, err),
    };
    let digest = params
        .get("content")
        .and_then(Value::as_str)
        .map(|c| sha256_hex(c.as_bytes()))
        .unwrap_or_else(|| "empty".to_string());
    let call = make_control_call(
        &req_id,
        &cfg.agent_name,
        extract_session(params, &cfg.session_id),
        ActionClass::FileWrite,
        &confined,
        format!("ACP fs/write_text_file {confined} sha256:{digest}"),
    );
    evaluate_or_jsonrpc(
        client,
        cfg,
        &call,
        req_id,
        json!({ "allowed": true, "path": confined }),
    )
    .await
}

pub(crate) async fn handle_terminal_create<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    req_id: Value,
    params: &Value,
) -> String {
    let spec = match validate_terminal_create_params(&cfg.workspace_root, params) {
        Ok(s) => s,
        Err(err) => return encode_err_fallback(req_id, -32602, err),
    };
    let call = make_control_call(
        &req_id,
        &cfg.agent_name,
        extract_session(params, &cfg.session_id),
        ActionClass::Exec,
        &spec.target,
        spec.summary,
    );
    evaluate_or_jsonrpc(client, cfg, &call, req_id, json!({ "allowed": true })).await
}

fn encode_jsonrpc_ok(id: Value, result: Value) -> String {
    match serde_json::to_string(&json!({ "jsonrpc": "2.0", "id": id, "result": result })) {
        Ok(line) => line,
        Err(err) => encode_err_fallback(id, -32603, &err.to_string()),
    }
}

fn encode_err_fallback(id: Value, code: i64, message: &str) -> String {
    jsonrpc_error(id, code, message)
        .unwrap_or_else(|_| r#"{"jsonrpc":"2.0","id":null,"error":{"code":-32603,"message":"internal serialization failure"}}"#.to_string())
}
