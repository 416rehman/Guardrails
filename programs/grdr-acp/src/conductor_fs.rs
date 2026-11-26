// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::ErrorKind;
use std::path::{Component, Path, PathBuf};

use grdr_crypto::sha256_hex;
use grdr_model::{ActionClass, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use jiff::Timestamp;
use serde_json::{Value, json};

use crate::conductor::AcpConductorConfig;
use crate::{AcpError, DecisionClient, NormalizedControlCall, build_attempt};

const ACP_PROTOCOL_VERSION: &str = "2025-03-26";

pub(crate) struct ValidatedTerminalSpec {
    pub(crate) target: String,
    pub(crate) summary: String,
}

pub fn default_workspace_root() -> PathBuf {
    std::env::current_dir().unwrap_or_else(|_| PathBuf::from("."))
}

pub(crate) fn current_ts() -> Result<Timestamp, AcpError> {
    SystemClock::new()
        .now_wall()
        .map_err(|err| AcpError::Transport(format!("wall clock unavailable: {err}")))
}

pub(crate) fn extract_session(params: &Value, default_session: &str) -> String {
    params
        .get("sessionId")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or(default_session)
        .to_string()
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

pub(crate) async fn evaluate_or_jsonrpc<C: DecisionClient>(
    client: &C,
    call: &NormalizedControlCall,
    req_id: Value,
    mut allow_payload: Value,
) -> String {
    let Ok(now) = current_ts() else {
        return jsonrpc_error(req_id, -32001, "wall clock unavailable").unwrap_or_default();
    };
    let attempt = build_attempt(call, now);
    match client.decide(&attempt).await {
        Ok(receipt) if receipt.verdict == Verdict::Allow => {
            if let Some(obj) = allow_payload.as_object_mut() {
                obj.insert("receiptId".to_string(), Value::String(receipt.receipt_id));
            }
            serde_json::to_string(
                &json!({ "jsonrpc": "2.0", "id": req_id, "result": allow_payload }),
            )
            .unwrap_or_default()
        }
        Ok(receipt) => {
            let code = if receipt.verdict == Verdict::StepUp {
                -32002
            } else {
                -32001
            };
            jsonrpc_error(req_id, code, &receipt.reason).unwrap_or_default()
        }
        Err(err) => jsonrpc_error(req_id, -32001, &err.to_string()).unwrap_or_default(),
    }
}

pub(crate) async fn handle_fs_read<C: DecisionClient>(
    client: &C,
    cfg: &AcpConductorConfig,
    req_id: Value,
    params: &Value,
) -> String {
    let Some(raw_path) = params.get("path").and_then(Value::as_str) else {
        return jsonrpc_error(req_id, -32602, "fs/read_text_file requires string path")
            .unwrap_or_default();
    };
    let confined = match resolve_confined_path(&cfg.workspace_root, raw_path, false) {
        Ok(p) => p,
        Err(err) => return jsonrpc_error(req_id, -32602, err).unwrap_or_default(),
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
        return jsonrpc_error(req_id, -32602, "fs/write_text_file requires string path")
            .unwrap_or_default();
    };
    let confined = match resolve_confined_path(&cfg.workspace_root, raw_path, false) {
        Ok(p) => p,
        Err(err) => return jsonrpc_error(req_id, -32602, err).unwrap_or_default(),
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
        Err(err) => return jsonrpc_error(req_id, -32602, err).unwrap_or_default(),
    };
    let call = make_control_call(
        &req_id,
        &cfg.agent_name,
        extract_session(params, &cfg.session_id),
        ActionClass::Exec,
        &spec.target,
        spec.summary,
    );
    evaluate_or_jsonrpc(client, &call, req_id, json!({ "allowed": true })).await
}

/// Resolve a caller-supplied path and confine it inside `workspace_root`.
/// Rejects empty strings, control characters, traversal components (`..`),
/// root escapes, symlinks, and Windows reparse points.
pub(crate) fn resolve_confined_path(
    workspace_root: &Path,
    raw_path: &str,
    require_existing_dir: bool,
) -> Result<String, &'static str> {
    if raw_path.trim().is_empty() || raw_path.chars().any(char::is_control) {
        return Err("path contains empty or control characters");
    }
    if workspace_root.as_os_str().is_empty() {
        return Err("workspace_root is empty");
    }
    let root_meta =
        std::fs::symlink_metadata(workspace_root).map_err(|_| "workspace_root inaccessible")?;
    if is_symlink_or_reparse(&root_meta) {
        return Err("workspace_root cannot be a symlink or reparse point");
    }
    let canon_root = std::fs::canonicalize(workspace_root).map_err(|_| "invalid workspace_root")?;

    let candidate = Path::new(raw_path);
    let rel_path = if candidate.is_absolute() {
        candidate
            .strip_prefix(workspace_root)
            .or_else(|_| candidate.strip_prefix(&canon_root))
            .map_err(|_| "absolute path escapes workspace_root")?
    } else {
        candidate
    };

    let mut normal_segments = Vec::new();
    for component in rel_path.components() {
        match component {
            Component::Normal(seg) => normal_segments.push(seg),
            Component::CurDir => {}
            Component::ParentDir | Component::RootDir | Component::Prefix(_) => {
                return Err("path traversal or root prefix is prohibited");
            }
        }
    }
    if normal_segments.is_empty() && !require_existing_dir {
        return Err("file path must reference a child inside workspace_root");
    }

    let mut cur = canon_root.clone();
    let mut missing_seen = false;
    for seg in normal_segments {
        cur.push(seg);
        if missing_seen {
            continue;
        }
        match std::fs::symlink_metadata(&cur) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) {
                    return Err("symlink or reparse point rejected");
                }
                let canon_cur =
                    std::fs::canonicalize(&cur).map_err(|_| "canonicalize child failed")?;
                if !canon_cur.starts_with(&canon_root) {
                    return Err("canonical child escapes workspace_root");
                }
            }
            Err(err) if err.kind() == ErrorKind::NotFound => {
                missing_seen = true;
            }
            Err(_) => return Err("path metadata inspection failed"),
        }
    }

    if require_existing_dir {
        let dir_meta =
            std::fs::symlink_metadata(&cur).map_err(|_| "cwd does not exist inside workspace")?;
        if is_symlink_or_reparse(&dir_meta) || !dir_meta.is_dir() {
            return Err("cwd must be a real non-symlink directory inside workspace");
        }
    }
    Ok(cur.to_string_lossy().into_owned())
}

pub(crate) fn validate_terminal_create_params(
    workspace_root: &Path,
    params: &Value,
) -> Result<ValidatedTerminalSpec, &'static str> {
    let Some(cmd) = params
        .get("command")
        .and_then(Value::as_str)
        .filter(|c| !c.trim().is_empty() && !c.chars().any(char::is_control))
    else {
        return Err("terminal/create requires valid non-control command string");
    };

    let mut arg_tokens = Vec::new();
    if let Some(raw_args) = params.get("args") {
        let Some(arr) = raw_args.as_array() else {
            return Err("terminal/create args must be an array of strings");
        };
        for item in arr {
            let Some(arg) = item.as_str() else {
                return Err("terminal/create args elements must be strings");
            };
            if arg.chars().any(char::is_control) {
                return Err("terminal/create arg contains prohibited control characters");
            }
            arg_tokens.push(arg);
        }
    }

    let confined_cwd = match params.get("cwd") {
        None | Some(Value::Null) => resolve_confined_path(workspace_root, ".", true)?,
        Some(Value::String(raw_cwd)) => resolve_confined_path(workspace_root, raw_cwd, true)?,
        Some(_) => return Err("terminal/create cwd must be a string"),
    };

    let mut env_keys = Vec::new();
    if let Some(raw_env) = params.get("env") {
        let Some(obj) = raw_env.as_object() else {
            return Err("terminal/create env must be an object");
        };
        for (k, v) in obj {
            if k.trim().is_empty()
                || k.contains('=')
                || k.chars().any(char::is_control)
                || !v.is_string()
            {
                return Err(
                    "terminal/create env entries must have safe key names and string values",
                );
            }
            env_keys.push(k.as_str());
        }
        env_keys.sort_unstable();
    }

    let full_cmd = if arg_tokens.is_empty() {
        cmd.to_string()
    } else {
        format!("{cmd} {}", arg_tokens.join(" "))
    };
    let env_tag = if env_keys.is_empty() {
        "none".to_string()
    } else {
        env_keys.join(",")
    };
    let summary = format!("ACP terminal/create {full_cmd} cwd={confined_cwd} env_keys={env_tag}");
    let target = format!("{full_cmd} [cwd:{confined_cwd} env:{env_tag}]");
    Ok(ValidatedTerminalSpec { target, summary })
}

fn is_symlink_or_reparse(meta: &std::fs::Metadata) -> bool {
    if meta.file_type().is_symlink() {
        return true;
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return true;
        }
    }
    false
}
