// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Signed binary floor fallback evaluator (`GRDRFLT1`) with non-symlink, size-bounded,
//! and profile-enforced ownership/DACL/mode validation (`docs/design/07`, `docs/design/11`).

use std::io::Read;
use std::path::Path;

use grdr_fastpath::FastVerdict;
use grdr_os_clock::{Clock, SystemClock};
use grdr_peer_os::fs_open::{
    OpenNofollowAccess, open_nofollow_dir, open_nofollow_file, verify_open_dir_trust,
    verify_open_file_trust,
};
use grdr_wire::floor_bin::{
    FloorRuleRecord, FloorTableFreshness, MAX_FLOOR_BYTES, floor_verdict_rank,
    verify_and_decode_floor_table,
};
use grdr_wire::messages::WireVerdict;

use crate::json_scan::ScannedHookInput;
use crate::offline_spool::system_state_dir;

const MAX_FLOOR_PUB_BYTES: usize = 512;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HookVerdictOutcome {
    pub verdict: WireVerdict,
    pub rule_id: String,
    pub reason: String,
    pub receipt_id: String,
    pub floor_fallback: bool,
    pub degraded_reason: String,
    pub retry_token: Option<String>,
    pub modified_target: Option<String>,
    pub run_provider_ids: Vec<String>,
}

pub fn evaluate_signed_floor_fallback(
    input: &ScannedHookInput,
    state_dir: &Path,
    protected: bool,
    daemon_err: &str,
) -> HookVerdictOutcome {
    if protected && state_dir != system_state_dir() {
        return fail_closed_outcome(
            input.control_point,
            "protected profile prohibits custom floor state directory",
        );
    }
    let floor_path = state_dir.join("floor.bin");
    let pub_path = state_dir.join("floor.pub");
    if let Err(err) = validate_floor_dir_trust(state_dir, protected) {
        return fail_closed_outcome(
            input.control_point,
            &format!("daemon unreachable ({daemon_err}); unsafe floor directory: {err}"),
        );
    }

    let Ok(floor_bytes) = read_trusted_bounded_file(&floor_path, MAX_FLOOR_BYTES, protected) else {
        return fail_closed_outcome(
            input.control_point,
            &format!("daemon unreachable ({daemon_err}) and untrusted or unreadable floor table"),
        );
    };
    let Ok(pub_bytes) = read_trusted_bounded_file(&pub_path, MAX_FLOOR_PUB_BYTES, protected) else {
        return fail_closed_outcome(
            input.control_point,
            &format!("daemon unreachable ({daemon_err}) and untrusted or unreadable floor pubkey"),
        );
    };
    let Ok(pubkey_str) = std::str::from_utf8(&pub_bytes) else {
        return fail_closed_outcome(
            input.control_point,
            &format!("daemon unreachable ({daemon_err}); malformed floor pubkey"),
        );
    };

    let Ok(wall) = SystemClock::new().now_wall() else {
        return fail_closed_outcome(
            input.control_point,
            &format!("daemon unreachable ({daemon_err}); system clock unavailable"),
        );
    };
    let now_unix_s = wall.as_second();

    let pub_trimmed = pubkey_str.trim();
    let Some((key_id, key_b64)) = pub_trimmed.split_once(':') else {
        return fail_closed_outcome(
            input.control_point,
            &format!("daemon unreachable ({daemon_err}); floor pubkey must use `<key_id>:<b64>`"),
        );
    };
    let doc = match verify_and_decode_floor_table(
        &floor_bytes,
        &[(key_id.trim(), key_b64.trim())],
        now_unix_s,
    ) {
        Ok(d) => d,
        Err(err) => {
            return fail_closed_outcome(
                input.control_point,
                &format!("daemon unreachable ({daemon_err}); invalid floor table: {err}"),
            );
        }
    };

    let stale_tag = if matches!(doc.freshness, FloorTableFreshness::Stale { .. }) {
        "-stale"
    } else {
        ""
    };
    let matched = highest_severity_match(
        &doc.document.rules,
        input.action_class,
        input.dialect.as_agent_str(),
        &input.target,
    );
    if let Some(rule) = matched {
        let product = &crate::brand::HookBrandConfig::embedded().product_name;
        let wire_verdict = match rule.verdict {
            FastVerdict::Allow => WireVerdict::Allow,
            FastVerdict::StepUp => WireVerdict::Ask,
            FastVerdict::Deny => WireVerdict::Block,
        };
        // Doc 07: stateless floor fallback never mints a retry_token; daemon issues CSPRNG `rty_`.
        return HookVerdictOutcome {
            verdict: wire_verdict,
            rule_id: rule.rule_id.clone(),
            reason: format!(
                "{product} offline rule {} ({daemon_err}; run grdr doctor)",
                rule.rule_id
            ),
            receipt_id: String::new(),
            floor_fallback: true,
            degraded_reason: format!("daemon-unreachable-floor-hit{stale_tag}"),
            retry_token: None,
            modified_target: None,
            run_provider_ids: Vec::new(),
        };
    }

    if input.control_point == 2 {
        HookVerdictOutcome {
            verdict: WireVerdict::Allow,
            rule_id: "FLOOR-POST-ALLOW".to_string(),
            reason: format!("post-action logged offline ({daemon_err})"),
            receipt_id: String::new(),
            floor_fallback: true,
            degraded_reason: format!("daemon-unreachable-offline{stale_tag}"),
            retry_token: None,
            modified_target: None,
            run_provider_ids: Vec::new(),
        }
    } else {
        HookVerdictOutcome {
            verdict: WireVerdict::Allow,
            rule_id: "FLOOR-VERIFIED-ALLOW".to_string(),
            reason: format!("signed floor table active; no deny match ({daemon_err})"),
            receipt_id: String::new(),
            floor_fallback: true,
            degraded_reason: format!("daemon-unreachable-floor{stale_tag}"),
            retry_token: None,
            modified_target: None,
            run_provider_ids: Vec::new(),
        }
    }
}

fn highest_severity_match<'a>(
    rules: &'a [FloorRuleRecord],
    action: grdr_fastpath::FastActionClass,
    agent: &str,
    target: &str,
) -> Option<&'a FloorRuleRecord> {
    let mut best: Option<&FloorRuleRecord> = None;
    for rule in rules {
        if !rule.matches(action, agent, target) {
            continue;
        }
        let replace = match best {
            None => true,
            Some(prev) => floor_verdict_rank(rule.verdict) > floor_verdict_rank(prev.verdict),
        };
        if replace {
            best = Some(rule);
        }
    }
    best
}

fn validate_floor_dir_trust(state_dir: &Path, protected: bool) -> Result<(), String> {
    let dir_file = open_nofollow_dir(state_dir).map_err(|e| e.to_string())?;
    verify_open_dir_trust(&dir_file, state_dir, protected).map_err(|e| e.to_string())
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

pub(crate) fn fail_closed_outcome(control_point: u32, detail: &str) -> HookVerdictOutcome {
    if control_point == 2 {
        return HookVerdictOutcome {
            verdict: WireVerdict::Allow,
            rule_id: "HOOK-POST-AUDIT".to_string(),
            reason: detail.to_string(),
            receipt_id: String::new(),
            floor_fallback: true,
            degraded_reason: "daemon-unreachable".to_string(),
            retry_token: None,
            modified_target: None,
            run_provider_ids: Vec::new(),
        };
    }
    HookVerdictOutcome {
        verdict: WireVerdict::Block,
        rule_id: "HOOK-FAIL-CLOSED".to_string(),
        reason: detail.to_string(),
        receipt_id: String::new(),
        floor_fallback: false,
        degraded_reason: "fail-closed".to_string(),
        retry_token: None,
        modified_target: None,
        run_provider_ids: Vec::new(),
    }
}
