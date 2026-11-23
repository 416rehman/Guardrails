// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::Path;

use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::detect;
use grdr_model::error::CODE_STORE_IO;
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ApprovalGrade, ApprovalRequest, ApprovalState, CodedError, DecisionReceipt,
    PolicyPack, Verdict,
};

use super::{MAX_RETAINED_EVENTS, StoreData};

pub(crate) fn persist_snapshot(dir: &Path, data: &StoreData) -> Result<(), CodedError> {
    fs::create_dir_all(dir).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Unable to create {}: {e}", dir.display()),
            "Verify disk permissions.",
        )
    })?;
    let tmp = dir.join("state.json.tmp");
    let final_path = dir.join("state.json");
    let json = serde_json::to_string_pretty(data).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Failed serializing snapshot: {e}"),
            "Retry persistence.",
        )
    })?;
    fs::write(&tmp, json).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Failed writing temp snapshot {}: {e}", tmp.display()),
            "Check free disk space.",
        )
    })?;
    fs::rename(&tmp, &final_path).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Failed committing snapshot {}: {e}", final_path.display()),
            "Verify target is writable.",
        )
    })
}

pub(crate) fn load_from_dir(dir: &Path) -> Result<StoreData, CodedError> {
    fs::create_dir_all(dir).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Unable to create data directory {}: {e}", dir.display()),
            "Verify filesystem permissions for --data-dir.",
        )
    })?;
    let snapshot_path = dir.join("state.json");
    if !snapshot_path.exists() {
        return Ok(StoreData::default());
    }
    let raw = fs::read_to_string(&snapshot_path).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Failed reading {}: {e}", snapshot_path.display()),
            "Ensure state.json is readable or start with --memory.",
        )
    })?;
    serde_json::from_str(&raw).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Corrupt state snapshot {}: {e}", snapshot_path.display()),
            "Inspect or remove the corrupt state.json file.",
        )
    })
}

pub(crate) fn record_attempt_and_receipt(
    guard: &mut StoreData,
    attempt: ActionAttempt,
    receipt: DecisionReceipt,
    now: Timestamp,
) {
    bump_rule_counters(&mut guard.packs, &receipt);

    if receipt.verdict == Verdict::StepUp {
        let (rule_title, required_grade) =
            find_rule_metadata(&guard.packs, receipt.rule_id.as_deref());
        guard.approvals.insert(
            0,
            ApprovalRequest {
                id: format!("apr_{}", Uuid::now_v7().simple()),
                receipt_id: receipt.receipt_id.clone(),
                session_id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                device_name: attempt.device_name.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                target: attempt.target.clone(),
                rule_id: receipt
                    .rule_id
                    .clone()
                    .unwrap_or_else(|| "essentials.credential-stores".into()),
                rule_title,
                required_grade,
                reason: receipt.reason.clone(),
                requested_at: now,
                state: ApprovalState::Pending {
                    expires_at: add_seconds(now, 1800),
                },
            },
        );
    }

    if let Some(finding) = detect::finding_from_receipt(&receipt, &attempt.device_name) {
        guard.findings.insert(0, finding);
    }

    guard.attempts.push(attempt);
    guard.receipts.push(receipt);
    trim_retained(guard);
}

pub(crate) fn trim_retained(guard: &mut StoreData) {
    if guard.attempts.len() > MAX_RETAINED_EVENTS {
        let drop_count = guard.attempts.len().saturating_sub(MAX_RETAINED_EVENTS);
        guard.attempts.drain(..drop_count);
    }
    if guard.receipts.len() > MAX_RETAINED_EVENTS {
        let drop_count = guard.receipts.len().saturating_sub(MAX_RETAINED_EVENTS);
        guard.receipts.drain(..drop_count);
    }
    if guard.audit.len() > MAX_RETAINED_EVENTS {
        guard.audit.truncate(MAX_RETAINED_EVENTS);
    }
}

pub(crate) fn bump_rule_counters(packs: &mut [PolicyPack], receipt: &DecisionReceipt) {
    let Some(rule_id) = &receipt.rule_id else {
        return;
    };
    for pack in packs {
        if let Some(rule) = pack.rules.iter_mut().find(|r| &r.id == rule_id) {
            rule.hits = rule.hits.saturating_add(1);
            if receipt.verdict == Verdict::StepUp {
                rule.would_ask_hits = rule.would_ask_hits.saturating_add(1);
            } else if receipt.verdict == Verdict::Deny {
                rule.would_block_hits = rule.would_block_hits.saturating_add(1);
            }
        }
    }
}

pub(crate) fn find_rule_metadata(
    packs: &[PolicyPack],
    rule_id: Option<&str>,
) -> (String, ApprovalGrade) {
    let Some(target) = rule_id else {
        return ("Policy approval required".into(), ApprovalGrade::G1);
    };
    packs
        .iter()
        .flat_map(|p| p.rules.iter())
        .find(|r| r.id == target)
        .map(|r| (r.title.clone(), r.min_grade))
        .unwrap_or_else(|| (target.into(), ApprovalGrade::G1))
}

pub(crate) fn expire_pending_approvals(approvals: &mut [ApprovalRequest], now: Timestamp) -> bool {
    let mut changed = false;
    for approval in approvals {
        if let ApprovalState::Pending { expires_at } = approval.state
            && expires_at <= now
        {
            approval.state = ApprovalState::Expired { expired_at: now };
            changed = true;
        }
    }
    changed
}
