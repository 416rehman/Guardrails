// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod json_strict;
mod lane;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use grdr_agents::{detect_home_dir, detect_state_dir};
use grdr_core::audit::{
    AuditChainRecordInput, AuditLogFormat, AuditVerifyError, AuditVerifySummary, ExpectedAnchor,
    normalize_prefixed_digest, verify_audit_chain_with_expected,
    verify_receipt_wal_digests_with_lines,
};
use grdr_crypto::constant_time_eq;
use grdr_model::DecisionReceipt;
use json_strict::{
    canonical_json_bytes, is_symlink_or_reparse, parse_line_obj_strict, read_bounded_audit_utf8,
};
use serde::Serialize;
use serde_json::{Map, Value};

use crate::fs_safe::{FsSafeError, reject_symlinks_on_existing_prefixes};

const MAX_AUDIT_LOG_BYTES: u64 = 16 * 1024 * 1024;
const MAX_AUDIT_LINE_BYTES: usize = 512 * 1024;
const MAX_AUDIT_ENTRIES: usize = 100_000;

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ExpectedAuditAnchor {
    pub device_id: Option<String>,
    pub epoch: Option<u64>,
    pub head_hash: Option<String>,
}

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedLogObservations {
    pub total_observations: u64,
    pub covered_observations: u64,
    pub sample_ids: Vec<String>,
}

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
    run_audit_verify_with_anchor(json, path, None)
}

pub fn run_audit_verify_with_anchor(
    json: bool,
    path: Option<PathBuf>,
    expected: Option<&ExpectedAuditAnchor>,
) -> ExitCode {
    let target_path = match path {
        Some(p) => p,
        None => match resolve_default_audit_path() {
            Ok(p) => p,
            Err(err) => return emit_verify_error(json, &err),
        },
    };
    match verify_audit_file_with_anchor(&target_path, expected) {
        Ok(summary) => emit_verify_success(json, &target_path, summary),
        Err(err) => emit_verify_error(json, &err),
    }
}

fn emit_verify_success(json: bool, target_path: &Path, summary: AuditVerifySummary) -> ExitCode {
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
            Err(_) => {
                eprintln!("GRDR-AUDIT-0003: failed serializing audit verify output");
                return ExitCode::FAILURE;
            }
        }
    } else {
        let fmt = match summary.format {
            AuditLogFormat::HashChain => "hash-chain",
            AuditLogFormat::ReceiptWal => "receipt-wal",
            AuditLogFormat::LaneChain => "lane-chain",
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
    let env_var = if cfg!(windows) {
        "LOCALAPPDATA"
    } else {
        "XDG_DATA_HOME"
    };
    let wal_override = std::env::var_os(env_var)
        .filter(|v| !v.is_empty())
        .map(PathBuf::from);
    resolve_default_audit_path_for(&state_dir, &home, wal_override.as_deref())
}

fn resolve_default_audit_path_for(
    state_dir: &Path,
    home: &Path,
    wal_data_base: Option<&Path>,
) -> Result<PathBuf, AuditVerifyError> {
    let chain_path = state_dir.join("audit.jsonl");
    reject_symlinks_on_existing_prefixes(&chain_path).map_err(|e| match e {
        FsSafeError::SymlinkForbidden(_) => malformed(0, "default audit parent symlink forbidden"),
        _ => malformed(0, "unable to inspect default audit path prefixes"),
    })?;
    match fs::symlink_metadata(&chain_path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.is_file() {
                return Err(malformed(
                    0,
                    "default audit log path is symlink or non-regular file",
                ));
            }
            return Ok(chain_path);
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
        Err(_) => return Err(malformed(0, "unable to inspect default audit log path")),
    }
    let wal_path = default_daemon_wal_path(home, wal_data_base);
    reject_symlinks_on_existing_prefixes(&wal_path).map_err(|e| match e {
        FsSafeError::SymlinkForbidden(_) => malformed(0, "default WAL parent symlink forbidden"),
        _ => malformed(0, "unable to inspect default WAL path prefixes"),
    })?;
    match fs::symlink_metadata(&wal_path) {
        Ok(meta) => {
            if is_symlink_or_reparse(&meta) || !meta.is_file() {
                return Err(malformed(
                    0,
                    "default WAL path is symlink or non-regular file",
                ));
            }
            Ok(wal_path)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Err(AuditVerifyError::NotFound {
            path: chain_path.display().to_string(),
        }),
        Err(_) => Err(malformed(0, "unable to inspect default WAL path")),
    }
}

fn default_daemon_wal_path(home: &Path, wal_data_base: Option<&Path>) -> PathBuf {
    let base = match wal_data_base {
        Some(p) => p.to_path_buf(),
        None => {
            let fallback: &[&str] = if cfg!(windows) {
                &["AppData", "Local"]
            } else {
                &[".local", "share"]
            };
            fallback
                .iter()
                .fold(home.to_path_buf(), |acc, seg| acc.join(seg))
        }
    };
    base.join("grdr").join("daemon").join("receipts.wal.jsonl")
}

pub fn verify_audit_file(path: &Path) -> Result<AuditVerifySummary, AuditVerifyError> {
    verify_audit_file_with_anchor(path, None)
}

pub fn verify_audit_file_with_anchor(
    path: &Path,
    expected: Option<&ExpectedAuditAnchor>,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    let raw = read_bounded_audit_utf8(path, MAX_AUDIT_LOG_BYTES)?;
    verify_audit_raw_inner(&raw, expected)
}

#[cfg(test)]
pub fn verify_and_collect_observations(
    path: &Path,
) -> Result<(AuditVerifySummary, VerifiedLogObservations), AuditVerifyError> {
    let raw = read_bounded_audit_utf8(path, MAX_AUDIT_LOG_BYTES)?;
    let summary = verify_audit_raw_inner(&raw, None)?;
    let lines: Vec<(usize, &str)> = raw
        .lines()
        .enumerate()
        .filter_map(|(idx, line)| {
            let trimmed = line.trim();
            (!trimmed.is_empty()).then_some((idx.saturating_add(1), trimmed))
        })
        .collect();
    let obs = collect_observations_from_lines(&lines, summary.entries)?;
    Ok((summary, obs))
}

fn verify_audit_raw_inner(
    raw: &str,
    expected: Option<&ExpectedAuditAnchor>,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    let mut non_empty = Vec::new();
    for (idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.len() > MAX_AUDIT_LINE_BYTES {
            return Err(malformed(
                idx.saturating_add(1),
                "audit entry line exceeds byte limit",
            ));
        }
        if non_empty.len() >= MAX_AUDIT_ENTRIES {
            return Err(malformed(
                idx.saturating_add(1),
                "audit log exceeds maximum entry count",
            ));
        }
        non_empty.push((idx.saturating_add(1), trimmed));
    }

    let Some(&(first_line_no, first_text)) = non_empty.first() else {
        return Err(AuditVerifyError::EmptyLog);
    };
    let first_obj = parse_line_obj_strict(first_line_no, first_text)?;
    let core_expected = expected.map(|e| ExpectedAnchor {
        device_id: e.device_id.clone(),
        epoch: e.epoch,
        head_hash: e.head_hash.clone(),
    });
    if lane::has_lane_fields(&first_obj) {
        lane::verify_lane_lines(&non_empty, core_expected.as_ref())
    } else if has_chain_fields(&first_obj) {
        verify_chain_lines(&non_empty, core_expected.as_ref())
    } else {
        verify_wal_lines(&non_empty, core_expected.as_ref())
    }
}

#[cfg(test)]
fn collect_observations_from_lines(
    lines: &[(usize, &str)],
    total_entries: usize,
) -> Result<VerifiedLogObservations, AuditVerifyError> {
    let mut sample_ids = Vec::new();
    let mut covered: u64 = 0;
    for &(line_no, text) in lines {
        let obj = parse_line_obj_strict(line_no, text)?;
        let id = obj
            .get("receipt_id")
            .and_then(Value::as_str)
            .filter(|s| !s.trim().is_empty())
            .or_else(|| {
                obj.get("entry_hash")
                    .or_else(|| obj.get("hash"))
                    .or_else(|| obj.get("integrity").and_then(|i| i.get("digest")))
                    .and_then(Value::as_str)
                    .filter(|s| !s.trim().is_empty())
            });
        if let Some(token) = id {
            covered = covered.saturating_add(1);
            if sample_ids.len() < 10 {
                sample_ids.push(token.to_owned());
            }
        }
    }
    let total = u64::try_from(total_entries).unwrap_or(u64::MAX);
    Ok(VerifiedLogObservations {
        total_observations: total,
        covered_observations: covered.min(total),
        sample_ids,
    })
}

fn has_chain_fields(obj: &Map<String, Value>) -> bool {
    obj.contains_key("prev_hash")
        || obj.contains_key("entry_hash")
        || obj.contains_key("prev")
        || obj.contains_key("hash")
        || obj.contains_key("integrity")
}

pub(crate) fn malformed(line: usize, detail: impl Into<String>) -> AuditVerifyError {
    AuditVerifyError::MalformedEntry {
        line,
        detail: detail.into(),
    }
}

pub(crate) fn gap_err(line: usize, detail: impl Into<String>) -> AuditVerifyError {
    AuditVerifyError::InvalidGapRecord {
        line,
        detail: detail.into(),
    }
}

pub(crate) fn lane_err(line: usize, detail: impl Into<String>) -> AuditVerifyError {
    AuditVerifyError::InvalidLaneRecord {
        line,
        detail: detail.into(),
    }
}

pub(crate) fn extract_hash_strings(
    line: usize,
    obj: &Map<String, Value>,
) -> Result<(String, String, Option<&'static str>), AuditVerifyError> {
    match obj.get("integrity") {
        Some(int_val) => {
            let int_obj = int_val
                .as_object()
                .ok_or_else(|| malformed(line, "integrity field must be a JSON object"))?;
            if obj.contains_key("prev_hash")
                || obj.contains_key("prev")
                || obj.contains_key("entry_hash")
                || obj.contains_key("hash")
            {
                return Err(malformed(
                    line,
                    "conflicting top-level and integrity hash fields",
                ));
            }
            let p = int_obj
                .get("prev")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(line, "missing string integrity.prev"))?;
            let d = int_obj
                .get("digest")
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(line, "missing string integrity.digest"))?;
            Ok((p.to_owned(), d.to_owned(), None))
        }
        None => {
            if obj.contains_key("prev_hash") && obj.contains_key("prev") {
                return Err(malformed(line, "conflicting prev_hash and prev fields"));
            }
            if obj.contains_key("entry_hash") && obj.contains_key("hash") {
                return Err(malformed(line, "conflicting entry_hash and hash fields"));
            }
            let p = obj
                .get("prev_hash")
                .or_else(|| obj.get("prev"))
                .and_then(Value::as_str)
                .ok_or_else(|| malformed(line, "missing string prev_hash"))?;
            let (k, h) = if let Some(h) = obj.get("entry_hash").and_then(Value::as_str) {
                ("entry_hash", h)
            } else if let Some(h) = obj.get("hash").and_then(Value::as_str) {
                ("hash", h)
            } else {
                return Err(malformed(line, "missing string entry_hash"));
            };
            Ok((p.to_owned(), h.to_owned(), Some(k)))
        }
    }
}

pub(crate) fn extract_hash_envelope(
    line: usize,
    obj: &Map<String, Value>,
) -> Result<(String, String, Vec<u8>), AuditVerifyError> {
    let (prev, hash, remove_key) = extract_hash_strings(line, obj)?;
    let mut payload_map = obj.clone();
    match remove_key {
        None => {
            if let Some(Value::Object(m)) = payload_map.get_mut("integrity") {
                m.remove("digest");
            }
        }
        Some(k) => {
            payload_map.remove(k);
        }
    }
    Ok((
        prev,
        hash,
        canonical_json_bytes(line, &Value::Object(payload_map))?,
    ))
}

fn verify_chain_lines(
    lines: &[(usize, &str)],
    expected: Option<&ExpectedAnchor>,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    if expected.is_some_and(|e| e.device_id.is_some() || e.epoch.is_some()) {
        return Err(lane_err(0, "hash-chain log lacks device/epoch anchor"));
    }
    let mut owned = Vec::with_capacity(lines.len());
    for &(line, text) in lines {
        let obj = parse_line_obj_strict(line, text)?;
        if lane::has_lane_fields(&obj) || lane::has_lane_only_meta(&obj) {
            return Err(malformed(
                line,
                "unexpected lane field in hash-chain audit log",
            ));
        }
        let seq = match obj.get("seq") {
            Some(v) => Some(
                v.as_u64()
                    .ok_or_else(|| malformed(line, "seq must be an unsigned integer"))?,
            ),
            None => None,
        };
        let (prev_hash, entry_hash, canonical_payload) = extract_hash_envelope(line, &obj)?;
        owned.push(OwnedChainEntry {
            line,
            seq,
            prev_hash,
            entry_hash,
            canonical_payload,
        });
    }
    let inputs: Vec<AuditChainRecordInput<'_>> = owned
        .iter()
        .map(|i| AuditChainRecordInput {
            line: i.line,
            seq: i.seq,
            prev_hash: &i.prev_hash,
            entry_hash: &i.entry_hash,
            canonical_payload: &i.canonical_payload,
        })
        .collect();
    verify_audit_chain_with_expected(&inputs, expected.and_then(|e| e.head_hash.as_deref()))
}

fn verify_wal_lines(
    lines: &[(usize, &str)],
    expected: Option<&ExpectedAnchor>,
) -> Result<AuditVerifySummary, AuditVerifyError> {
    if expected.is_some_and(|e| e.device_id.is_some() || e.epoch.is_some()) {
        return Err(lane_err(0, "receipt-wal log lacks device/epoch anchor"));
    }
    let mut receipts = Vec::with_capacity(lines.len());
    for &(line, text) in lines {
        let obj = parse_line_obj_strict(line, text)?;
        if has_chain_fields(&obj) || lane::has_lane_fields(&obj) || lane::has_lane_only_meta(&obj) {
            return Err(malformed(
                line,
                "unexpected chain or lane field in receipt WAL",
            ));
        }
        let parsed: DecisionReceipt = serde_json::from_value(Value::Object(obj))
            .map_err(|_| malformed(line, "invalid DecisionReceipt schema"))?;
        receipts.push((line, parsed));
    }
    let refs: Vec<(usize, &DecisionReceipt)> = receipts.iter().map(|(l, r)| (*l, r)).collect();
    let summary = verify_receipt_wal_digests_with_lines(&refs)?;
    if let Some(exp_head_raw) = expected.and_then(|e| e.head_hash.as_deref()) {
        let last_line = receipts.last().map_or(0, |(l, _)| *l);
        let exp_head = normalize_prefixed_digest(exp_head_raw)
            .ok_or_else(|| malformed(last_line, "invalid expected head_hash"))?;
        if !constant_time_eq(summary.head_hash.as_bytes(), exp_head.as_bytes()) {
            return Err(AuditVerifyError::HashMismatch {
                line: last_line,
                expected: exp_head,
                actual: summary.head_hash,
            });
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_core::audit::{
        AuditLane, GENESIS_PREV_HASH, LaneEntryKind, build_five_way_commitments,
        compute_chain_hash, compute_commitment_root_digest, compute_lane_entry_hash,
        lane_genesis_hash, merkle_consistency_proof, merkle_inclusion_proof, merkle_root_hex,
    };
    use grdr_model::{ActionAttempt, ActionClass, ControlPoint, KillSwitchState};
    use jiff::Timestamp;
    use serde_json::json;

    fn make_chained_line(seq: u64, prev_hash: &str, event: &str) -> (String, String) {
        let mut obj = Map::new();
        obj.insert("seq".into(), json!(seq));
        obj.insert("prev_hash".into(), json!(prev_hash));
        obj.insert("event".into(), json!(event));
        let canonical = canonical_json_bytes(0, &Value::Object(obj.clone())).unwrap();
        let entry_hash = compute_chain_hash(prev_hash, &canonical);
        obj.insert("entry_hash".into(), json!(entry_hash));
        (
            serde_json::to_string(&Value::Object(obj)).unwrap(),
            entry_hash,
        )
    }

    fn expected_anchor(dev: &str, ep: u64, head: &str) -> ExpectedAuditAnchor {
        ExpectedAuditAnchor {
            device_id: Some(dev.into()),
            epoch: Some(ep),
            head_hash: Some(head.into()),
        }
    }

    #[test]
    fn verify_audit_file_validates_hash_chain_and_rejects_mixed_symlink_dup_keys() {
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
        assert_eq!(
            verify_audit_file_with_anchor(
                &path,
                Some(&ExpectedAuditAnchor {
                    head_hash: Some(h0.clone()),
                    ..Default::default()
                })
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0005"
        );

        let tampered = format!("{l0}\n{}\n", l1.replace("decision.receipt", "tampered"));
        fs::write(&path, tampered).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0005"
        );

        let dup_line = format!(
            "{{\"seq\":0,\"seq\":1,\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"entry_hash\":\"{h0}\"}}"
        );
        fs::write(&path, format!("{dup_line}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        let bogus_lane = format!(
            "{{\"lane\":\"event\",\"epoch\":1,\"seq\":1,\"prev_hash\":\"{h0}\",\"entry_hash\":\"{h1}\"}}"
        );
        fs::write(&path, format!("{l0}\n{bogus_lane}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        let dir_as_file = dir.join("subdir");
        fs::create_dir_all(&dir_as_file).unwrap();
        assert_eq!(
            verify_audit_file(&dir_as_file).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        fs::write(&path, "").unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0002"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn verify_audit_file_validates_receipt_wal_and_preserves_line_numbers() {
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
        let mut receipt = grdr_core::policy::evaluate(
            &attempt,
            &[grdr_core::policy::essentials_pack()],
            &[],
            &KillSwitchState::Inactive,
            attempt.timestamp,
        );
        let l1 = serde_json::to_string(&receipt).unwrap();
        receipt.receipt_id = "rcp_secret_must_not_leak".into();
        let l3 = serde_json::to_string(&receipt).unwrap();
        fs::write(&path, format!("{l1}\n\n{l3}\n")).unwrap();
        let err = verify_audit_file(&path).unwrap_err();
        assert_eq!(err.code(), "GRDR-AUDIT-0005");
        assert!(
            err.to_string().contains("line 3"),
            "expected physical line 3: {err}"
        );
        assert!(!err.to_string().contains("rcp_secret_must_not_leak"));

        fs::write(&path, format!("{l1}\n")).unwrap();
        let ok = verify_audit_file(&path).unwrap();
        assert_eq!(ok.format, AuditLogFormat::ReceiptWal);

        // ReceiptWal ExpectedAuditAnchor checks: matching head_hash passes; mismatch (0005), malformed+P8 (0003), device/epoch (0010) fail.
        let wal_ok =
            verify_audit_file_with_anchor(&path, Some(&expected_anchor_head(&ok.head_hash)))
                .unwrap();
        assert_eq!(wal_ok.head_hash, ok.head_hash);

        assert_eq!(
            verify_audit_file_with_anchor(&path, Some(&expected_anchor_head(GENESIS_PREV_HASH)),)
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0005"
        );
        let bad_head_err = verify_audit_file_with_anchor(
            &path,
            Some(&expected_anchor_head("WAL_SECRET_BAD_DIGEST")),
        )
        .unwrap_err();
        assert_eq!(bad_head_err.code(), "GRDR-AUDIT-0003");
        assert!(!bad_head_err.to_string().contains("WAL_SECRET_BAD_DIGEST"));
        assert_eq!(
            verify_audit_file_with_anchor(
                &path,
                Some(&ExpectedAuditAnchor {
                    device_id: Some("dev-1".into()),
                    epoch: None,
                    head_hash: None,
                }),
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0010"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    fn expected_anchor_head(head: &str) -> ExpectedAuditAnchor {
        ExpectedAuditAnchor {
            device_id: None,
            epoch: None,
            head_hash: Some(head.to_owned()),
        }
    }

    #[test]
    fn verify_audit_file_validates_reduced_copy_from_chained_full_and_rejects_smuggling() {
        let dir = std::env::temp_dir().join(format!("grdr-audit-lane-{}", uuid::Uuid::now_v7()));
        fs::create_dir_all(&dir).unwrap();
        let path = dir.join("lane.jsonl");

        let salts = [
            &[1u8; 32][..],
            &[2u8; 32][..],
            &[3u8; 32][..],
            &[4u8; 32][..],
            &[5u8; 32][..],
        ];
        let payloads = [
            &b"alice@org"[..],
            &b"exec"[..],
            &b"risk=high"[..],
            &b"cat /etc/passwd"[..],
            &b"body"[..],
        ];
        let full_comm = build_five_way_commitments(salts, payloads).unwrap();
        let root_digest = compute_commitment_root_digest(&full_comm).unwrap();
        let mut reduced_comm = full_comm.clone();
        reduced_comm.salt_identifier = None;
        reduced_comm.salt_argument = None;
        reduced_comm.salt_body = None;

        let genesis =
            lane_genesis_hash("dev-1", 1, AuditLane::Event, Some(GENESIS_PREV_HASH)).unwrap();
        let ev_kind = LaneEntryKind::Event {
            commitments: &full_comm,
            commitment_root_digest: &root_digest,
            payloads: [
                Some(payloads[0]),
                Some(payloads[1]),
                Some(payloads[2]),
                Some(payloads[3]),
                Some(payloads[4]),
            ],
            withheld_classes: None,
            merkle: None,
            merkle_consistency: None,
        };
        let h0 = compute_lane_entry_hash(&genesis, 1, AuditLane::Event, 0, &ev_kind).unwrap();

        let gap_kind = LaneEntryKind::Gap {
            start_seq: 1,
            end_seq: 2,
            dropped_count: 2,
            reason: "ringbuffer_drop",
        };
        let h_gap = compute_lane_entry_hash(&h0, 1, AuditLane::Event, 1, &gap_kind).unwrap();
        let h3 = compute_lane_entry_hash(&h_gap, 1, AuditLane::Event, 3, &ev_kind).unwrap();

        let leaves: [&[u8]; 3] = [h0.as_bytes(), root_digest.as_bytes(), h3.as_bytes()];
        let mroot2 = merkle_root_hex(&leaves[..2]);
        let mroot3 = merkle_root_hex(&leaves);
        let inc2 = merkle_inclusion_proof(&leaves, 2).unwrap();
        let cons23 = merkle_consistency_proof(&leaves, 2).unwrap();

        let l0_full = json!({
            "anchor": { "device_id": "dev-1", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH },
            "lane": "event",
            "epoch": 1,
            "seq": 0,
            "integrity": { "prev": genesis, "digest": h0, "commitments": full_comm, "commitment_root_digest": root_digest },
            "payloads": { "identifier": "alice@org", "structural": "exec", "derived": "risk=high", "content.argument": "cat /etc/passwd", "content.body": "body" },
            "capture_level": "full_content"
        });
        let l0_reduced_from_full = json!({
            "anchor": { "device_id": "dev-1", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH },
            "lane": "event",
            "epoch": 1,
            "seq": 0,
            "integrity": { "prev": genesis, "digest": h0, "commitments": reduced_comm, "commitment_root_digest": root_digest },
            "payloads": { "structural": "exec", "derived": "risk=high" },
            "capture_level": "metadata",
            "redaction": { "withheld_classes": ["identifier", "content.argument", "content.body"] }
        });
        let l_gap = json!({
            "lane": "event", "epoch": 1, "seq": 1, "kind": "gap",
            "prev_hash": h0, "entry_hash": h_gap,
            "gap": { "start_seq": 1, "end_seq": 2, "dropped_count": 2, "reason": "ringbuffer_drop" }
        });
        let l3 = json!({
            "lane": "event", "epoch": 1, "seq": 3, "prev_hash": h_gap, "entry_hash": h3,
            "commitments": full_comm, "commitment_root_digest": root_digest,
            "payloads": { "identifier": "alice@org", "structural": "exec", "derived": "risk=high", "content.argument": "cat /etc/passwd", "content.body": "body" },
            "merkle": { "leaf": h3, "leaf_index": 2, "tree_size": 3, "audit_path": inc2, "expected_root": mroot3 },
            "merkle_consistency": { "first_size": 2, "second_size": 3, "first_root": mroot2, "second_root": mroot3, "proof": cons23 }
        });

        fs::write(&path, format!("{l0_full}\n{l_gap}\n{l3}\n")).unwrap();
        let full_sum = verify_audit_file(&path).unwrap();
        assert_eq!(full_sum.head_hash, h3);

        // Reduced copy derived from chained l0_full keeps exact entry_hash & head_hash.
        fs::write(&path, format!("{l0_reduced_from_full}\n{l_gap}\n{l3}\n")).unwrap();
        let red_sum =
            verify_audit_file_with_anchor(&path, Some(&expected_anchor("dev-1", 1, &h3))).unwrap();
        assert_eq!(red_sum.head_hash, h3);

        // Smuggling gap inside event kind, gap+merkle, dual hash, missing epoch, conflicting anchors rejected.
        let mut smuggled = l0_full.clone();
        smuggled["kind"] = json!("event");
        smuggled["gap"] =
            json!({ "start_seq": 0, "end_seq": 0, "dropped_count": 1, "reason": "x" });
        fs::write(&path, format!("{smuggled}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        let mut gap_with_merkle = l_gap.clone();
        gap_with_merkle["merkle"] = l3["merkle"].clone();
        fs::write(&path, format!("{l0_full}\n{gap_with_merkle}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0009"
        );

        let mut dual_hash = l3.clone();
        dual_hash["integrity"] = json!({ "prev": h_gap, "digest": h3 });
        fs::write(&path, format!("{dual_hash}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        let mut no_epoch = l3.clone();
        no_epoch.as_object_mut().unwrap().remove("epoch");
        fs::write(&path, format!("{no_epoch}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        let mut bad_anchor = l3.clone();
        bad_anchor["anchor"] =
            json!({ "device_id": "dev-2", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH });
        fs::write(&path, format!("{l0_full}\n{l_gap}\n{bad_anchor}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0010"
        );

        let bad_lane = json!({
            "anchor": { "device_id": "dev-1", "epoch": 1, "prev_epoch_final_hash": GENESIS_PREV_HASH },
            "lane": "SECRET_LANE_TOKEN",
            "epoch": 1,
            "seq": 0,
            "prev_hash": genesis,
            "entry_hash": h0,
            "commitments": reduced_comm,
            "commitment_root_digest": root_digest
        });
        fs::write(&path, format!("{bad_lane}\n")).unwrap();
        let lane_err = verify_audit_file(&path).unwrap_err();
        assert_eq!(lane_err.code(), "GRDR-AUDIT-0010");
        assert!(!lane_err.to_string().contains("SECRET_LANE_TOKEN"));

        // Missing anchor on line 1 fails GRDR-AUDIT-0010.
        let mut no_anchor = l0_full.clone();
        no_anchor.as_object_mut().unwrap().remove("anchor");
        fs::write(&path, format!("{no_anchor}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0010"
        );

        // capture_level metadata without redaction succeeds with pseudonymous identifier; contradicting redaction fails.
        let mut l0_meta_no_red = l0_full.clone();
        l0_meta_no_red["capture_level"] = json!("metadata");
        l0_meta_no_red["payloads"] =
            json!({ "identifier": "alice@org", "structural": "exec", "derived": "risk=high" });
        l0_meta_no_red["integrity"]["commitments"] = {
            let mut m = full_comm.clone();
            m.salt_argument = None;
            m.salt_body = None;
            serde_json::to_value(m).unwrap()
        };
        fs::write(&path, format!("{l0_meta_no_red}\n")).unwrap();
        assert!(verify_audit_file(&path).is_ok());

        let mut l0_meta_undercut = l0_full.clone();
        l0_meta_undercut["capture_level"] = json!("metadata");
        l0_meta_undercut["redaction"] = json!({ "withheld_classes": [] });
        fs::write(&path, format!("{l0_meta_undercut}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        let mut l0_full_redacted = l0_full.clone();
        l0_full_redacted["capture_level"] = json!("full_content");
        l0_full_redacted["redaction"] = json!({ "withheld_classes": ["content.body"] });
        fs::write(&path, format!("{l0_full_redacted}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0007"
        );

        // verify_and_collect_observations recognizes integrity.digest in single pass.
        fs::write(&path, format!("{l0_full}\n")).unwrap();
        let (obs_sum, obs) = verify_and_collect_observations(&path).unwrap();
        assert_eq!(obs_sum.entries, 1);
        assert_eq!(obs.covered_observations, 1);
        assert_eq!(obs.sample_ids, vec![h0.clone()]);

        // ExpectedAuditAnchor mismatches (device, epoch, head).
        assert_eq!(
            verify_audit_file_with_anchor(&path, Some(&expected_anchor("other", 1, &h0)))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );
        assert_eq!(
            verify_audit_file_with_anchor(&path, Some(&expected_anchor("dev-1", 2, &h0)))
                .unwrap_err()
                .code(),
            "GRDR-AUDIT-0010"
        );
        assert_eq!(
            verify_audit_file_with_anchor(
                &path,
                Some(&expected_anchor("dev-1", 1, GENESIS_PREV_HASH))
            )
            .unwrap_err()
            .code(),
            "GRDR-AUDIT-0005"
        );

        // Nested duplicate JSON keys, unicode-escaped duplicate keys, trailing JSON, deep JSON, and oversized line.
        let nested_dup = format!(
            "{{\"outer\":{{\"a\":1,\"a\":2}},\"lane\":\"event\",\"epoch\":1,\"seq\":0,\"prev_hash\":\"{genesis}\",\"entry_hash\":\"{h0}\"}}"
        );
        fs::write(&path, format!("{nested_dup}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );
        let esc_dup = format!(
            "{{\"outer\":{{\"a\":1,\"\\u0061\":2}},\"lane\":\"event\",\"epoch\":1,\"seq\":0,\"prev_hash\":\"{genesis}\",\"entry_hash\":\"{h0}\"}}"
        );
        fs::write(&path, format!("{esc_dup}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );
        fs::write(&path, format!("{l0_full} trailing\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );
        let deep = format!(
            "{{\"x\":{}{}0{}{}}}",
            "[".repeat(70),
            "",
            "]".repeat(70),
            ""
        );
        fs::write(&path, format!("{deep}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );
        fs::write(
            &path,
            format!("{{\"x\":\"{}\"}}\n", "a".repeat(MAX_AUDIT_LINE_BYTES + 16)),
        )
        .unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        // Cross-line Merkle checkpoint errors (growth without proof, equal-size root fork).
        let h1_b = compute_lane_entry_hash(&h0, 1, AuditLane::Event, 1, &ev_kind).unwrap();
        let l1_grow_no_proof = json!({
            "lane": "event", "epoch": 1, "seq": 1, "prev_hash": h0, "entry_hash": h1_b,
            "commitments": full_comm, "commitment_root_digest": root_digest,
            "payloads": { "identifier": "alice@org", "structural": "exec", "derived": "risk=high", "content.argument": "cat /etc/passwd", "content.body": "body" },
            "merkle": { "leaf": h1_b, "leaf_index": 2, "tree_size": 3, "audit_path": merkle_inclusion_proof(&[h0.as_bytes(), root_digest.as_bytes(), h1_b.as_bytes()], 2).unwrap(), "expected_root": merkle_root_hex(&[h0.as_bytes(), root_digest.as_bytes(), h1_b.as_bytes()]) }
        });
        let mut l0_with_m = l0_full.clone();
        l0_with_m["merkle"] = json!({
            "leaf": h0, "leaf_index": 0, "tree_size": 2,
            "audit_path": merkle_inclusion_proof(&[h0.as_bytes(), root_digest.as_bytes()], 0).unwrap(),
            "expected_root": mroot2
        });
        fs::write(&path, format!("{l0_with_m}\n{l1_grow_no_proof}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0008"
        );

        // Junction / symlink refusal.
        #[cfg(unix)]
        {
            let link_path = dir.join("sym.jsonl");
            std::os::unix::fs::symlink(&path, &link_path).unwrap();
            assert_eq!(
                verify_audit_file(&link_path).unwrap_err().code(),
                "GRDR-AUDIT-0003"
            );
        }
        #[cfg(windows)]
        {
            let junc_dir = dir.join("junc_dir");
            let real_sub = dir.join("real_sub");
            fs::create_dir_all(&real_sub).unwrap();
            fs::write(real_sub.join("a.jsonl"), format!("{l0_full}\n")).unwrap();
            if std::process::Command::new("cmd")
                .args(["/C", "mklink", "/J"])
                .arg(&junc_dir)
                .arg(&real_sub)
                .output()
                .is_ok_and(|o| o.status.success())
            {
                assert_eq!(
                    verify_audit_file(&junc_dir.join("a.jsonl"))
                        .unwrap_err()
                        .code(),
                    "GRDR-AUDIT-0003"
                );
            }
        }

        // Reject unknown/unhashed fields (`receipt_id`, `withheld`, unknown integrity fields) and mixed format line 2.
        let mut forged_rid = l0_full.clone();
        forged_rid["receipt_id"] = json!("forged-rid");
        fs::write(&path, format!("{forged_rid}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );
        let mut forged_int = l0_full.clone();
        forged_int["integrity"]["bogus"] = json!(true);
        fs::write(&path, format!("{forged_int}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );
        let mixed_line2 = format!(
            "{{\"seq\":0,\"prev_hash\":\"{GENESIS_PREV_HASH}\",\"entry_hash\":\"{h0}\",\"lane\":\"event\"}}"
        );
        let (_, _, ch0_txt) = make_chained_pair();
        fs::write(&path, format!("{ch0_txt}\n{mixed_line2}\n")).unwrap();
        assert_eq!(
            verify_audit_file(&path).unwrap_err().code(),
            "GRDR-AUDIT-0003"
        );

        // Preserve line >1 in malformed LaneLineJson error.
        let mut bad_l2 = l3.clone();
        bad_l2["extra_untrusted"] = json!(1);
        fs::write(&path, format!("{l0_full}\n{l_gap}\n{bad_l2}\n")).unwrap();
        let l3_err = verify_audit_file(&path).unwrap_err();
        assert_eq!(l3_err.code(), "GRDR-AUDIT-0003");
        assert!(l3_err.to_string().contains("line 3"), "got: {l3_err}");

        // resolve_default_audit_path_for resolves chain, falls back to WAL, and rejects symlinks/junctions.
        let def_root = dir.join("default_home");
        let state_dir = def_root.join("state");
        let wal_base = dir.join("wal_base");
        let wal_file = default_daemon_wal_path(&def_root, Some(&wal_base));
        fs::create_dir_all(wal_file.parent().unwrap()).unwrap();
        fs::write(&wal_file, "wal\n").unwrap();
        assert_eq!(
            resolve_default_audit_path_for(&state_dir, &def_root, Some(&wal_base)).unwrap(),
            wal_file
        );
        fs::create_dir_all(&state_dir).unwrap();
        let chain_file = state_dir.join("audit.jsonl");
        fs::write(&chain_file, "chain\n").unwrap();
        assert_eq!(
            resolve_default_audit_path_for(&state_dir, &def_root, Some(&wal_base)).unwrap(),
            chain_file
        );
        #[cfg(unix)]
        {
            let _ = fs::remove_file(&chain_file);
            std::os::unix::fs::symlink(&wal_file, &chain_file).unwrap();
            assert_eq!(
                resolve_default_audit_path_for(&state_dir, &def_root, Some(&wal_base))
                    .unwrap_err()
                    .code(),
                "GRDR-AUDIT-0003"
            );
        }

        let _ = fs::remove_dir_all(&dir);
    }

    fn make_chained_pair() -> (String, String, String) {
        let mut obj = Map::new();
        obj.insert("seq".into(), json!(0));
        obj.insert("prev_hash".into(), json!(GENESIS_PREV_HASH));
        obj.insert("event".into(), json!("boot"));
        let canonical = canonical_json_bytes(0, &Value::Object(obj)).unwrap();
        let entry_hash = compute_chain_hash(GENESIS_PREV_HASH, &canonical);
        let line = json!({
            "seq": 0,
            "prev_hash": GENESIS_PREV_HASH,
            "entry_hash": entry_hash,
            "event": "boot"
        })
        .to_string();
        (GENESIS_PREV_HASH.into(), entry_hash, line)
    }
}
