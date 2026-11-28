// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Independent zero-crypto, zero-core offline audit verifier (`04-15`).

mod commitments;
mod json_strict;
mod lane;
mod lane_chain;
mod merkle;
mod sha256;
mod types;
mod verify_chain;

#[cfg(test)]
mod tests;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use grdr_agents::{detect_home_dir, detect_state_dir};
use grdr_model::DecisionReceipt;
use json_strict::{
    canonical_json_bytes, is_symlink_or_reparse, parse_line_obj_strict, read_bounded_audit_utf8,
};
use serde::Serialize;
use serde_json::{Map, Value};
use sha256::constant_time_eq;
use types::{
    AuditChainRecordInput, CODE_AUDIT_MALFORMED_ENTRY, ExpectedAnchor, normalize_prefixed_digest,
};
use verify_chain::{verify_audit_chain_with_expected, verify_receipt_wal_digests_with_lines};

pub use types::{AuditLogFormat, AuditVerifyError, AuditVerifySummary};

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
                eprintln!("{CODE_AUDIT_MALFORMED_ENTRY}: failed serializing audit verify output");
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
    crate::fs_safe::reject_symlinks_on_existing_prefixes(&chain_path).map_err(|e| match e {
        crate::fs_safe::FsSafeError::SymlinkForbidden(_) => {
            malformed(0, "default audit parent symlink forbidden")
        }
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
    crate::fs_safe::reject_symlinks_on_existing_prefixes(&wal_path).map_err(|e| match e {
        crate::fs_safe::FsSafeError::SymlinkForbidden(_) => {
            malformed(0, "default WAL parent symlink forbidden")
        }
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
