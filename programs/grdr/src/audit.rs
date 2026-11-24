// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use serde::Serialize;
use serde_json::{Map, Value};

use grdr_agents::{detect_home_dir, detect_state_dir};
use grdr_core::audit::{
    AuditChainRecordInput, AuditLogFormat, AuditVerifyError, AuditVerifySummary,
    verify_audit_chain, verify_receipt_wal_digests,
};
use grdr_model::DecisionReceipt;

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditVerifyJsonOutput {
    verified: bool,
    entries: usize,
    format: AuditLogFormat,
    head_hash: String,
    path: String,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct AuditVerifyErrorJsonOutput {
    verified: bool,
    error_code: String,
    error: String,
}

struct OwnedChainEntry {
    line: usize,
    seq: Option<u64>,
    prev_hash: String,
    entry_hash: String,
    canonical_payload: Vec<u8>,
}

pub fn run_audit_verify(json: bool, path: Option<PathBuf>) -> ExitCode {
    let target_path = match path {
        Some(p) => p,
        None => match resolve_default_audit_path() {
            Ok(p) => p,
            Err(err) => return emit_verify_error(json, &err),
        },
    };

    match verify_audit_file(&target_path) {
        Ok(summary) => {
            if json {
                let out = AuditVerifyJsonOutput {
                    verified: summary.verified,
                    entries: summary.entries,
                    format: summary.format,
                    head_hash: summary.head_hash,
                    path: target_path.display().to_string(),
                };
                match serde_json::to_string(&out) {
                    Ok(text) => println!("{text}"),
                    Err(err) => {
                        eprintln!("GRDR-AUDIT-0003: failed serializing audit verify output: {err}");
                        return ExitCode::FAILURE;
                    }
                }
            } else {
                let fmt = match summary.format {
                    AuditLogFormat::HashChain => "hash-chain",
                    AuditLogFormat::ReceiptWal => "receipt-wal",
                };
                println!(
                    "Audit log verified ({}, entries={}, head={}, path={}).",
                    fmt,
                    summary.entries,
                    summary.head_hash,
                    target_path.display()
                );
            }
            ExitCode::SUCCESS
        }
        Err(err) => emit_verify_error(json, &err),
    }
}

fn emit_verify_error(json: bool, err: &AuditVerifyError) -> ExitCode {
    eprintln!("{err}");
    if json {
        let payload = AuditVerifyErrorJsonOutput {
            verified: false,
            error_code: err.code().to_string(),
            error: err.to_string(),
        };
        if let Ok(text) = serde_json::to_string(&payload) {
            println!("{text}");
        }
    }
    ExitCode::FAILURE
}

fn resolve_default_audit_path() -> Result<PathBuf, AuditVerifyError> {
    let Some(home) = detect_home_dir() else {
        return Err(AuditVerifyError::NotFound {
            path: "HOME/USERPROFILE unavailable".into(),
        });
    };
    let state_dir = detect_state_dir(&home);
    let chain_path = state_dir.join("audit.jsonl");
    if chain_path.is_file() {
        return Ok(chain_path);
    }

    let wal_path = default_daemon_wal_path(&home);
    if wal_path.is_file() {
        return Ok(wal_path);
    }

    Err(AuditVerifyError::NotFound {
        path: chain_path.display().to_string(),
    })
}

fn default_daemon_wal_path(home: &Path) -> PathBuf {
    #[cfg(windows)]
    {
        if let Some(local_app_data) = std::env::var_os("LOCALAPPDATA")
            && !local_app_data.is_empty()
        {
            return PathBuf::from(local_app_data)
                .join("grdr")
                .join("daemon")
                .join("receipts.wal.jsonl");
        }
        home.join("AppData")
            .join("Local")
            .join("grdr")
            .join("daemon")
            .join("receipts.wal.jsonl")
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg_data) = std::env::var_os("XDG_DATA_HOME")
            && !xdg_data.is_empty()
        {
            return PathBuf::from(xdg_data)
                .join("grdr")
                .join("daemon")
                .join("receipts.wal.jsonl");
        }
        home.join(".local")
            .join("share")
            .join("grdr")
            .join("daemon")
            .join("receipts.wal.jsonl")
    }
}

pub fn verify_audit_file(path: &Path) -> Result<AuditVerifySummary, AuditVerifyError> {
    if !path.is_file() {
        return Err(AuditVerifyError::NotFound {
            path: path.display().to_string(),
        });
    }
    let raw = fs::read_to_string(path).map_err(|e| AuditVerifyError::MalformedEntry {
        line: 0,
        detail: format!("failed reading {}: {e}", path.display()),
    })?;

    let mut non_empty_lines: Vec<(usize, &str)> = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        non_empty_lines.push((idx.saturating_add(1), trimmed));
    }

    let Some((first_line_no, first_text)) = non_empty_lines.first().copied() else {
        return Err(AuditVerifyError::EmptyLog);
    };

    let first_val: Value =
        serde_json::from_str(first_text).map_err(|e| AuditVerifyError::MalformedEntry {
            line: first_line_no,
            detail: format!("invalid JSON: {e}"),
        })?;
    let Some(first_obj) = first_val.as_object() else {
        return Err(AuditVerifyError::MalformedEntry {
            line: first_line_no,
            detail: "audit entry must be a JSON object".into(),
        });
    };

    if has_chain_fields(first_obj) {
        return verify_chain_lines(&non_empty_lines);
    }

    verify_wal_lines(&non_empty_lines)
}

fn has_chain_fields(obj: &Map<String, Value>) -> bool {
    obj.contains_key("prev_hash")
        || obj.contains_key("entry_hash")
        || obj.contains_key("prev")
        || obj.contains_key("hash")
        || obj.contains_key("integrity")
}

fn verify_chain_lines(lines: &[(usize, &str)]) -> Result<AuditVerifySummary, AuditVerifyError> {
    let mut owned = Vec::with_capacity(lines.len());
    for &(line_no, text) in lines {
        let val: Value =
            serde_json::from_str(text).map_err(|e| AuditVerifyError::MalformedEntry {
                line: line_no,
                detail: format!("invalid JSON: {e}"),
            })?;
        let obj = val
            .as_object()
            .ok_or_else(|| AuditVerifyError::MalformedEntry {
                line: line_no,
                detail: "audit entry must be a JSON object".into(),
            })?;
        owned.push(extract_chain_entry(line_no, obj)?);
    }

    let inputs: Vec<AuditChainRecordInput<'_>> = owned
        .iter()
        .map(|item| AuditChainRecordInput {
            line: item.line,
            seq: item.seq,
            prev_hash: &item.prev_hash,
            entry_hash: &item.entry_hash,
            canonical_payload: &item.canonical_payload,
        })
        .collect();

    verify_audit_chain(&inputs)
}

fn extract_chain_entry(
    line: usize,
    obj: &Map<String, Value>,
) -> Result<OwnedChainEntry, AuditVerifyError> {
    let seq = match obj.get("seq") {
        Some(v) => Some(v.as_u64().ok_or_else(|| AuditVerifyError::MalformedEntry {
            line,
            detail: "seq must be an unsigned integer".into(),
        })?),
        None => None,
    };

    if let Some(integrity) = obj.get("integrity").and_then(Value::as_object) {
        let prev_hash = integrity
            .get("prev")
            .and_then(Value::as_str)
            .ok_or_else(|| AuditVerifyError::MalformedEntry {
                line,
                detail: "missing string integrity.prev".into(),
            })?
            .to_string();
        let entry_hash = integrity
            .get("digest")
            .and_then(Value::as_str)
            .ok_or_else(|| AuditVerifyError::MalformedEntry {
                line,
                detail: "missing string integrity.digest".into(),
            })?
            .to_string();

        let mut payload_map = obj.clone();
        if let Some(Value::Object(int_map)) = payload_map.get_mut("integrity") {
            int_map.remove("digest");
        }
        let canonical_payload = canonical_json_bytes(&Value::Object(payload_map))?;
        return Ok(OwnedChainEntry {
            line,
            seq,
            prev_hash,
            entry_hash,
            canonical_payload,
        });
    }

    let prev_hash = obj
        .get("prev_hash")
        .or_else(|| obj.get("prev"))
        .and_then(Value::as_str)
        .ok_or_else(|| AuditVerifyError::MalformedEntry {
            line,
            detail: "missing string prev_hash".into(),
        })?
        .to_string();

    let (hash_key, entry_hash) = if let Some(h) = obj.get("entry_hash").and_then(Value::as_str) {
        ("entry_hash", h.to_string())
    } else if let Some(h) = obj.get("hash").and_then(Value::as_str) {
        ("hash", h.to_string())
    } else {
        return Err(AuditVerifyError::MalformedEntry {
            line,
            detail: "missing string entry_hash".into(),
        });
    };

    let mut payload_map = obj.clone();
    payload_map.remove(hash_key);
    let canonical_payload = canonical_json_bytes(&Value::Object(payload_map))?;

    Ok(OwnedChainEntry {
        line,
        seq,
        prev_hash,
        entry_hash,
        canonical_payload,
    })
}

fn verify_wal_lines(lines: &[(usize, &str)]) -> Result<AuditVerifySummary, AuditVerifyError> {
    let mut receipts = Vec::with_capacity(lines.len());
    for &(line_no, text) in lines {
        let val: Value =
            serde_json::from_str(text).map_err(|e| AuditVerifyError::MalformedEntry {
                line: line_no,
                detail: format!("invalid JSON: {e}"),
            })?;
        let Some(obj) = val.as_object() else {
            return Err(AuditVerifyError::MalformedEntry {
                line: line_no,
                detail: "WAL entry must be a JSON object".into(),
            });
        };
        if has_chain_fields(obj) {
            return Err(AuditVerifyError::MalformedEntry {
                line: line_no,
                detail: "unexpected chain field in receipt WAL".into(),
            });
        }
        let receipt: DecisionReceipt =
            serde_json::from_value(val).map_err(|e| AuditVerifyError::MalformedEntry {
                line: line_no,
                detail: format!("invalid DecisionReceipt entry: {e}"),
            })?;
        receipts.push(receipt);
    }

    verify_receipt_wal_digests(&receipts)
}

fn canonical_json_bytes(value: &Value) -> Result<Vec<u8>, AuditVerifyError> {
    let sorted = sort_json_keys(value);
    serde_json::to_vec(&sorted).map_err(|e| AuditVerifyError::MalformedEntry {
        line: 0,
        detail: format!("failed canonicalizing JSON payload: {e}"),
    })
}

fn sort_json_keys(value: &Value) -> Value {
    match value {
        Value::Object(map) => {
            let mut sorted: BTreeMap<&str, Value> = BTreeMap::new();
            for (k, v) in map {
                sorted.insert(k.as_str(), sort_json_keys(v));
            }
            let mut out = Map::new();
            for (k, v) in sorted {
                out.insert(k.to_string(), v);
            }
            Value::Object(out)
        }
        Value::Array(items) => Value::Array(items.iter().map(sort_json_keys).collect()),
        other => other.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_core::audit::{GENESIS_PREV_HASH, compute_chain_hash};
    use grdr_model::{ActionAttempt, ActionClass, ControlPoint, KillSwitchState};
    use jiff::Timestamp;
    use serde_json::json;

    fn make_chained_line(seq: u64, prev_hash: &str, event: &str) -> (String, String) {
        let mut obj = Map::new();
        obj.insert("seq".into(), json!(seq));
        obj.insert("prev_hash".into(), json!(prev_hash));
        obj.insert("event".into(), json!(event));
        let canonical = canonical_json_bytes(&Value::Object(obj.clone())).unwrap();
        let entry_hash = compute_chain_hash(prev_hash, &canonical);
        obj.insert("entry_hash".into(), json!(entry_hash));
        let line = serde_json::to_string(&Value::Object(obj)).unwrap();
        (line, entry_hash)
    }

    #[test]
    fn verify_audit_file_validates_hash_chain_and_rejects_tamper_or_truncation() {
        let dir = std::env::temp_dir().join(format!("grdr-audit-cli-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("audit.jsonl");

        let (l0, h0) = make_chained_line(0, GENESIS_PREV_HASH, "session.start");
        let (l1, h1) = make_chained_line(1, &h0, "decision.receipt");
        fs::write(&path, format!("{l0}\n{l1}\n")).unwrap();

        let ok = verify_audit_file(&path).unwrap();
        assert!(ok.verified);
        assert_eq!(ok.entries, 2);
        assert_eq!(ok.format, AuditLogFormat::HashChain);
        assert_eq!(ok.head_hash, h1);

        let tampered = format!("{l0}\n{}\n", l1.replace("decision.receipt", "tampered"));
        fs::write(&path, tampered).unwrap();
        let err = verify_audit_file(&path).unwrap_err();
        assert_eq!(err.code(), "GRDR-AUDIT-0005");

        fs::write(&path, "").unwrap();
        let empty_err = verify_audit_file(&path).unwrap_err();
        assert_eq!(empty_err.code(), "GRDR-AUDIT-0002");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_audit_file_validates_receipt_wal_and_rejects_tamper() {
        let dir = std::env::temp_dir().join(format!("grdr-audit-wal-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("receipts.wal.jsonl");

        let attempt = ActionAttempt {
            id: "att-1".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            device_name: "host".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Hook,
            target: "git commit --no-verify".into(),
            summary: "test".into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
            ..Default::default()
        };
        let receipt = grdr_core::policy::evaluate(
            &attempt,
            &[grdr_core::policy::essentials_pack()],
            &[],
            &KillSwitchState::Inactive,
            attempt.timestamp,
        );
        let line = serde_json::to_string(&receipt).unwrap();
        fs::write(&path, format!("{line}\n")).unwrap();

        let ok = verify_audit_file(&path).unwrap();
        assert!(ok.verified);
        assert_eq!(ok.entries, 1);
        assert_eq!(ok.format, AuditLogFormat::ReceiptWal);

        fs::write(&path, line.replace("\"deny\"", "\"allow\"")).unwrap();
        let err = verify_audit_file(&path).unwrap_err();
        assert_eq!(err.code(), "GRDR-AUDIT-0005");

        let _ = fs::remove_dir_all(&dir);
    }
}
