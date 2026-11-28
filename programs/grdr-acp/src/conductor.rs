// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;
use std::path::PathBuf;
use std::sync::Arc;

use grdr_llm_proto::strict_json::{MAX_JSON_DEPTH, MAX_SSE_EVENT_BYTES, parse_strict_json_str};
use grdr_wire::peer_auth::Profile;
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader};
use tokio::sync::{Mutex, Semaphore, mpsc};
use zeroize::Zeroizing;

use crate::acs_hmac::{AcsReplayGuard, SignedAcsJsonRpcFrame, verify_owasp_acs_jsonrpc};
use crate::conductor_caps::{
    build_initialize_result, handle_session_new, handle_session_prompt, is_acp_v2_version,
    observe_session_update_claim, permission_outcome_payload, v2_removed_method_error,
};
use crate::conductor_fs::{
    current_ts, default_workspace_root, evaluate_or_jsonrpc, extract_session, handle_fs_read,
    handle_fs_write, handle_terminal_create, jsonrpc_error, make_control_call,
};
use crate::{
    AcpError, DecisionClient, build_attempt, classify_action_kind, extract_daemon_retry_token,
};

const ACP_PROTOCOL_VERSION: &str = "2025-03-26";
const MAX_STDIO_LINE_BYTES: usize = MAX_SSE_EVENT_BYTES;
const OUTBOUND_QUEUE_DEPTH: usize = 128;
const MAX_CONCURRENT_REQUESTS: usize = 32;
const MAX_ACS_SKEW_SECONDS: i64 = 60;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum NegotiatedProtocolState {
    Uninitialized,
    V1,
    V2Locked,
}

#[derive(Clone)]
pub struct AcpConductorConfig {
    pub agent_name: String,
    pub session_id: String,
    pub profile: Profile,
    pub acs_hmac_key: Option<Zeroizing<Vec<u8>>>,
    pub workspace_root: PathBuf,
    pub mcp_broker_command: Option<String>,
    pub mcp_broker_args: Vec<String>,
}

impl fmt::Debug for AcpConductorConfig {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("AcpConductorConfig")
            .field("agent_name", &self.agent_name)
            .field("session_id", &self.session_id)
            .field("profile", &self.profile)
            .field(
                "acs_hmac_key",
                &self.acs_hmac_key.as_ref().map(|_| "<redacted>"),
            )
            .field("workspace_root", &self.workspace_root)
            .field("mcp_broker_command", &self.mcp_broker_command)
            .finish()
    }
}

impl Default for AcpConductorConfig {
    fn default() -> Self {
        Self {
            agent_name: "acp-conductor".to_string(),
            session_id: "acp-session".to_string(),
            profile: Profile::User,
            acs_hmac_key: None,
            workspace_root: default_workspace_root(),
            mcp_broker_command: Some("grdr-mcp".to_string()),
            mcp_broker_args: vec!["--stdio".to_string()],
        }
    }
}

pub async fn run_bidirectional_stdio_conductor<C, R, W>(
    client: Arc<C>,
    cfg: AcpConductorConfig,
    reader: R,
    mut writer: W,
) -> Result<(), AcpError>
where
    C: DecisionClient + 'static,
    R: AsyncRead + Unpin + Send,
    W: AsyncWrite + Unpin + Send + 'static,
{
    let (tx, mut rx) = mpsc::channel::<String>(OUTBOUND_QUEUE_DEPTH);
    let writer_handle = tokio::spawn(async move {
        while let Some(line) = rx.recv().await {
            if writer.write_all(line.as_bytes()).await.is_err()
                || writer.write_all(b"\n").await.is_err()
                || writer.flush().await.is_err()
            {
                return Err(AcpError::Transport(
                    "stdout conductor write failed".to_string(),
                ));
            }
        }
        Ok::<(), AcpError>(())
    });

    let replay = Arc::new(Mutex::new(AcsReplayGuard::new(4_096, MAX_ACS_SKEW_SECONDS)));
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_REQUESTS));
    let proto_state = Arc::new(Mutex::new(NegotiatedProtocolState::Uninitialized));
    let mut lines = BufReader::new(reader);
    let mut tasks = tokio::task::JoinSet::new();
    let mut buf = Vec::new();
    loop {
        buf.clear();
        let read_res = read_bounded_line(&mut lines, &mut buf, MAX_STDIO_LINE_BYTES).await;
        match read_res {
            Ok(0) => break,
            Ok(_) => {
                let raw = String::from_utf8(buf.clone())
                    .map_err(|_| AcpError::InvalidPayload("non-UTF8 stdio frame".to_string()))?;
                let trimmed = raw.trim().to_string();
                if trimmed.is_empty() {
                    continue;
                }
                if is_initialize_line(&trimmed) {
                    if let Some(reply) = handle_conductor_line_with_state(
                        &*client,
                        &cfg,
                        &replay,
                        &proto_state,
                        &trimmed,
                    )
                    .await
                        && tx.send(reply).await.is_err()
                    {
                        return Err(AcpError::Transport(
                            "stdout conductor outbound queue closed".to_string(),
                        ));
                    }
                    continue;
                }
                let permit =
                    sem.clone().acquire_owned().await.map_err(|_| {
                        AcpError::Transport("conductor semaphore closed".to_string())
                    })?;
                let client_cl = Arc::clone(&client);
                let cfg_cl = cfg.clone();
                let tx_cl = tx.clone();
                let replay_cl = Arc::clone(&replay);
                let state_cl = Arc::clone(&proto_state);
                tasks.spawn(async move {
                    let _permit = permit;
                    if let Some(reply) = handle_conductor_line_with_state(
                        &*client_cl,
                        &cfg_cl,
                        &replay_cl,
                        &state_cl,
                        &trimmed,
                    )
                    .await
                        && tx_cl.send(reply).await.is_err()
                    {
                        return Err(AcpError::Transport(
                            "stdout conductor outbound queue closed".to_string(),
                        ));
                    }
                    Ok::<(), AcpError>(())
                });
            }
            Err(err) => {
                let err_line =
                    jsonrpc_error(Value::Null, -32700, &err.to_string()).unwrap_or_default();
                if tx.send(err_line).await.is_err() {
                    tracing::warn!("failed queuing stdio parse error frame");
                }
                break;
            }
        }
    }
    let mut task_err: Option<AcpError> = None;
    while let Some(joined) = tasks.join_next().await {
        match joined {
            Ok(Ok(())) => {}
            Ok(Err(err)) if task_err.is_none() => task_err = Some(err),
            Ok(Err(_)) => {}
            Err(err) if task_err.is_none() => {
                task_err = Some(AcpError::Transport(format!("conductor task join: {err}")));
            }
            Err(_) => {}
        }
    }
    drop(tx);
    writer_handle
        .await
        .map_err(|err| AcpError::Transport(format!("writer task join failed: {err}")))??;
    if let Some(err) = task_err {
        return Err(err);
    }
    Ok(())
}

async fn read_bounded_line<R: AsyncBufReadExt + Unpin>(
    reader: &mut R,
    out: &mut Vec<u8>,
    max_bytes: usize,
) -> Result<usize, AcpError> {
    let mut total = 0usize;
    loop {
        let available = reader
            .fill_buf()
            .await
            .map_err(|e| AcpError::Transport(e.to_string()))?;
        if available.is_empty() {
            return Ok(total);
        }
        let nl = available.iter().position(|&b| b == b'\n');
        let consume = nl.map_or(available.len(), |idx| idx.saturating_add(1));
        if total.saturating_add(consume) > max_bytes {
            return Err(AcpError::InvalidPayload(
                "stdio JSON-RPC line exceeds maximum size".to_string(),
            ));
        }
        if let Some(slice) = available.get(..consume) {
            out.extend_from_slice(slice);
        }
        reader.consume(consume);
        total = total.saturating_add(consume);
        if nl.is_some() {
            return Ok(total);
        }
    }
}

fn is_initialize_line(trimmed: &str) -> bool {
    parse_strict_json_str(trimmed, MAX_STDIO_LINE_BYTES, MAX_JSON_DEPTH)
        .ok()
        .and_then(|v| v.get("method").and_then(Value::as_str).map(str::to_owned))
        .is_some_and(|m| m == "initialize")
}

pub async fn handle_conductor_line<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    replay: &Mutex<AcsReplayGuard>,
    raw_line: &str,
) -> Option<String> {
    let proto_state = Mutex::new(NegotiatedProtocolState::Uninitialized);
    handle_conductor_line_with_state(client, cfg, replay, &proto_state, raw_line).await
}

pub(crate) async fn handle_conductor_line_with_state<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    replay: &Mutex<AcsReplayGuard>,
    proto_state: &Mutex<NegotiatedProtocolState>,
    raw_line: &str,
) -> Option<String> {
    let val = match parse_strict_json_str(raw_line, MAX_STDIO_LINE_BYTES, MAX_JSON_DEPTH) {
        Ok(v) => v,
        Err(err) => return jsonrpc_error(Value::Null, -32700, &err.to_string()).ok(),
    };
    let Some(obj) = val.as_object() else {
        return jsonrpc_error(Value::Null, -32600, "JSON-RPC frame must be an object").ok();
    };
    let id = obj.get("id").filter(|v| !v.is_null()).cloned();
    let req_id = id.clone().unwrap_or(Value::Null);
    let Some(method) = obj.get("method").and_then(Value::as_str) else {
        return jsonrpc_error(req_id, -32600, "JSON-RPC frame requires string method").ok();
    };
    let params = obj.get("params").cloned().unwrap_or(Value::Null);

    let is_v2 = *proto_state.lock().await == NegotiatedProtocolState::V2Locked;
    if is_v2
        && matches!(
            method,
            "fs/read_text_file" | "fs/write_text_file" | "terminal/create"
        )
    {
        return Some(v2_removed_method_error(req_id, method));
    }

    let sensitive_method = matches!(
        method,
        "fs/read_text_file"
            | "fs/write_text_file"
            | "terminal/create"
            | "session/request_permission"
            | "session/update"
            | "acs/evaluate"
    );
    if (sensitive_method && cfg.acs_hmac_key.is_some())
        || obj.contains_key("hmac_hex")
        || method == "acs/evaluate"
    {
        if let Err(err_resp) = verify_acs_signature(cfg, replay, &val, req_id.clone()).await {
            if method == "session/update" && id.is_none() {
                tracing::warn!("rejected unauthenticated or replayed session/update notification");
                return None;
            }
            return Some(err_resp);
        }
        if method == "acs/evaluate" || !sensitive_method {
            return Some(handle_acs_signed_payload(client, cfg, &params, req_id).await);
        }
    }

    if method == "session/update" && id.is_none() {
        observe_session_update_claim(client, cfg, &params).await;
        return None;
    }
    if method.starts_with("notifications/") {
        return None;
    }

    match method {
        "initialize" => Some(handle_initialize(req_id, &params, cfg, proto_state).await),
        "session/new" => Some(handle_session_new(client, cfg, req_id, &params).await),
        "session/prompt" => Some(handle_session_prompt(client, cfg, req_id, &params).await),
        "fs/read_text_file" => Some(handle_fs_read(client, cfg, req_id, &params).await),
        "fs/write_text_file" => Some(handle_fs_write(client, cfg, req_id, &params).await),
        "terminal/create" => Some(handle_terminal_create(client, cfg, req_id, &params).await),
        "session/request_permission" => {
            Some(handle_request_permission(client, cfg, req_id, &params).await)
        }
        _ => jsonrpc_error(req_id, -32601, "unsupported ACP method").ok(),
    }
}

async fn verify_acs_signature(
    cfg: &AcpConductorConfig,
    replay: &Mutex<AcsReplayGuard>,
    val: &Value,
    req_id: Value,
) -> Result<(), String> {
    let Some(key) = cfg.acs_hmac_key.as_ref() else {
        return Err(
            jsonrpc_error(req_id, -32001, "ACS HMAC key not configured").unwrap_or_default()
        );
    };
    let Ok(signed_frame) = serde_json::from_value::<SignedAcsJsonRpcFrame>(val.clone()) else {
        return Err(
            jsonrpc_error(req_id, -32602, "invalid signed OWASP ACS JSON-RPC frame")
                .unwrap_or_default(),
        );
    };
    let Ok(now_ts) = current_ts() else {
        return Err(jsonrpc_error(req_id, -32001, "wall clock unavailable").unwrap_or_default());
    };
    let mut guard = replay.lock().await;
    if let Err(err) = verify_owasp_acs_jsonrpc(&signed_frame, key, &mut guard, now_ts.as_second()) {
        return Err(jsonrpc_error(req_id, -32001, &err.to_string()).unwrap_or_default());
    }
    Ok(())
}

async fn handle_initialize(
    req_id: Value,
    params: &Value,
    cfg: &AcpConductorConfig,
    proto_state: &Mutex<NegotiatedProtocolState>,
) -> String {
    let client_proto = params
        .get("protocolVersion")
        .and_then(Value::as_str)
        .unwrap_or(ACP_PROTOCOL_VERSION);
    let wants_v2 = is_acp_v2_version(client_proto);
    let mut guard = proto_state.lock().await;
    if *guard == NegotiatedProtocolState::V2Locked && !wants_v2 {
        return jsonrpc_error(req_id, -32600, "cannot downgrade ACP v2 session back to v1")
            .unwrap_or_default();
    }
    *guard = if wants_v2 {
        NegotiatedProtocolState::V2Locked
    } else {
        NegotiatedProtocolState::V1
    };
    build_initialize_result(req_id, client_proto, cfg)
}

async fn handle_request_permission<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    req_id: Value,
    params: &Value,
) -> String {
    let tool_call = params.get("toolCall");
    let kind = tool_call
        .and_then(|t| t.get("kind"))
        .and_then(Value::as_str)
        .unwrap_or("mcp_call");
    let title = tool_call
        .and_then(|t| t.get("title"))
        .and_then(Value::as_str)
        .unwrap_or("acp_permission");
    let target = tool_call
        .and_then(|t| t.get("rawInput"))
        .and_then(|r| {
            r.get("path")
                .or_else(|| r.get("command"))
                .or_else(|| r.get("url"))
        })
        .and_then(Value::as_str)
        .unwrap_or(title);
    let reject_option = find_option_id(params, &["reject_once", "reject_always", "reject"]);
    let allow_option = find_option_id(params, &["allow_once", "allow_always", "allow"])
        .unwrap_or_else(|| "allow_once".to_string());
    let (verdict, receipt_id, retry_token) = match current_ts() {
        Ok(now) => {
            let call = make_control_call(
                &req_id,
                &cfg.agent_name,
                extract_session(params, &cfg.session_id),
                classify_action_kind(kind, title),
                target,
                format!("ACP session/request_permission {title}"),
            );
            let attempt = build_attempt(&call, now);
            match client.decide(&attempt).await {
                Ok(receipt) => {
                    let rty = extract_daemon_retry_token(&receipt);
                    (Some(receipt.verdict), receipt.receipt_id, rty)
                }
                Err(_) => (None, String::new(), None),
            }
        }
        Err(_) => (None, String::new(), None),
    };
    let result = permission_outcome_payload(
        verdict,
        &receipt_id,
        retry_token.as_deref(),
        &allow_option,
        reject_option.as_deref(),
    );
    serde_json::to_string(&json!({
        "jsonrpc": "2.0",
        "id": req_id,
        "result": result
    }))
    .unwrap_or_default()
}

async fn handle_acs_signed_payload<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    params: &Value,
    req_id: Value,
) -> String {
    let tool = params
        .get("tool")
        .and_then(Value::as_str)
        .unwrap_or("acs.tool");
    let target = params.get("target").and_then(Value::as_str).unwrap_or(tool);
    let kind = params
        .get("action")
        .and_then(Value::as_str)
        .unwrap_or("mcp_call");
    let call = make_control_call(
        &req_id,
        &cfg.agent_name,
        extract_session(params, &cfg.session_id),
        classify_action_kind(kind, tool),
        target,
        format!("OWASP ACS {tool} ({target})"),
    );
    evaluate_or_jsonrpc(
        client,
        cfg,
        &call,
        req_id,
        json!({ "verified": true, "allowed": true }),
    )
    .await
}

fn find_option_id(params: &Value, preferred_kinds: &[&str]) -> Option<String> {
    let options = params.get("options")?.as_array()?;
    for want in preferred_kinds {
        for opt in options {
            let kind = opt.get("kind").and_then(Value::as_str).unwrap_or("");
            let id = opt.get("optionId").and_then(Value::as_str).unwrap_or("");
            if kind != *want || id.is_empty() || id.chars().any(char::is_control) {
                continue;
            }
            let id_lower = id.to_ascii_lowercase();
            if want.starts_with("reject") && id_lower.contains("allow") {
                continue;
            }
            if want.starts_with("allow")
                && (id_lower.contains("reject") || id_lower.contains("deny"))
            {
                continue;
            }
            return Some(id.to_string());
        }
    }
    None
}
