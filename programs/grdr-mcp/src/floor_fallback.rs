// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::Read;
use std::path::Path;

use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_model::{ActionAttempt, ActionClass, DecisionReceipt, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use grdr_peer_os::fs_open::{
    OpenNofollowAccess, open_nofollow_dir, open_nofollow_file, verify_open_dir_trust,
    verify_open_file_trust,
};
use grdr_wire::floor_bin::{
    FloorRuleRecord, FloorTableFreshness, MAX_FLOOR_BYTES, floor_verdict_rank,
    verify_and_decode_floor_table,
};
use jiff::Timestamp;

use crate::decision::{build_mcp_receipt, synthetic_floor_receipt};
use crate::ipc_transport::system_state_dir;

const MAX_FLOOR_PUB_BYTES: usize = 512;

pub(crate) fn evaluate_signed_floor(
    attempt: &ActionAttempt,
    state_dir: &Path,
    protected: bool,
    daemon_err: &str,
) -> Option<DecisionReceipt> {
    if protected && state_dir != system_state_dir() {
        return Some(synthetic_deny_receipt(
            attempt,
            "GRDR-MCP-0006",
            "protected profile prohibits custom floor state directory",
        ));
    }
    let dir_file = open_nofollow_dir(state_dir).ok()?;
    verify_open_dir_trust(&dir_file, state_dir, protected).ok()?;
    let floor_bytes =
        read_trusted_bounded_file(&state_dir.join("floor.bin"), MAX_FLOOR_BYTES, protected).ok()?;
    let pub_bytes =
        read_trusted_bounded_file(&state_dir.join("floor.pub"), MAX_FLOOR_PUB_BYTES, protected)
            .ok()?;
    let pub_text = std::str::from_utf8(&pub_bytes).ok()?;
    let (key_id, key_b64) = pub_text.trim().split_once(':')?;
    let now = SystemClock::new().now_wall().ok()?;
    let verified = verify_and_decode_floor_table(
        &floor_bytes,
        &[(key_id.trim(), key_b64.trim())],
        now.as_second(),
    )
    .ok()?;
    let stale_tag = if matches!(verified.freshness, FloorTableFreshness::Stale { .. }) {
        "-stale"
    } else {
        ""
    };
    let fast_action = model_to_fast_action(attempt.action_class);
    let matched = highest_severity_match(
        &verified.document.rules,
        fast_action,
        &attempt.agent_name,
        &attempt.target,
    );
    match matched {
        Some(rule) => Some(rule_to_receipt(attempt, rule, stale_tag, now)),
        None => Some(synthetic_deny_receipt(
            attempt,
            "floor.fail-closed",
            &format!("daemon unreachable ({daemon_err}); no signed floor rule matched"),
        )),
    }
}

pub(crate) fn synthetic_deny_receipt(
    attempt: &ActionAttempt,
    rule_id: &str,
    reason: &str,
) -> DecisionReceipt {
    synthetic_floor_receipt(attempt, Verdict::Deny, Some(rule_id), reason)
}

fn read_trusted_bounded_file(
    path: &Path,
    max_bytes: usize,
    protected: bool,
) -> Result<Vec<u8>, String> {
    let file =
        open_nofollow_file(path, OpenNofollowAccess::ReadOnly, 0o600).map_err(|e| e.to_string())?;
    verify_open_file_trust(&file, protected).map_err(|e| e.to_string())?;
    let meta = file.metadata().map_err(|e| e.to_string())?;
    if usize::try_from(meta.len()).unwrap_or(usize::MAX) > max_bytes {
        return Err("file exceeds size bound".to_string());
    }
    let mut out = Vec::new();
    file.take(u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX))
        .read_to_end(&mut out)
        .map_err(|e| e.to_string())?;
    if out.len() > max_bytes {
        return Err("file grew past size bound".to_string());
    }
    Ok(out)
}

fn highest_severity_match<'a>(
    rules: &'a [FloorRuleRecord],
    action: FastActionClass,
    agent: &str,
    target: &str,
) -> Option<&'a FloorRuleRecord> {
    rules
        .iter()
        .filter(|rule| rule.matches(action, agent, target))
        .max_by_key(|rule| floor_verdict_rank(rule.verdict))
}

fn rule_to_receipt(
    attempt: &ActionAttempt,
    rule: &FloorRuleRecord,
    stale_tag: &str,
    now: Timestamp,
) -> DecisionReceipt {
    let verdict = match rule.verdict {
        FastVerdict::Allow => Verdict::Allow,
        FastVerdict::StepUp => Verdict::StepUp,
        FastVerdict::Deny => Verdict::Deny,
    };
    let next_step = match verdict {
        Verdict::Allow => "",
        Verdict::StepUp => "Step-up approval required while daemon offline",
        _ => "Blocked by signed floor rule",
    };
    build_mcp_receipt(
        attempt,
        verdict,
        Some(&rule.rule_id),
        &format!("signed floor{stale_tag} matched rule {}", rule.rule_id),
        next_step,
        None,
        now,
    )
}

fn model_to_fast_action(class: ActionClass) -> FastActionClass {
    match class {
        ActionClass::Exec => FastActionClass::Exec,
        ActionClass::FileRead => FastActionClass::FileRead,
        ActionClass::FileWrite => FastActionClass::FileWrite,
        ActionClass::FileDelete => FastActionClass::FileDelete,
        ActionClass::NetConnect => FastActionClass::NetConnect,
        ActionClass::NetRequest => FastActionClass::NetRequest,
        ActionClass::LlmRequest => FastActionClass::LlmRequest,
        ActionClass::McpConnect => FastActionClass::McpConnect,
        ActionClass::McpCall => FastActionClass::McpCall,
        ActionClass::CredUse => FastActionClass::CredUse,
        ActionClass::AgentSpawn => FastActionClass::AgentSpawn,
        ActionClass::ConfigChange => FastActionClass::ConfigChange,
        ActionClass::Elevate => FastActionClass::Elevate,
        ActionClass::UiAct => FastActionClass::UiAct,
        ActionClass::DataFlow => FastActionClass::DataFlow,
    }
}
