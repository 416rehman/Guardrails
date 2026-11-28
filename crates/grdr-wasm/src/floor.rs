// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_fastpath::{
    FLOOR_FORMAT_VERSION, FloorRuleRef, HostRuleRequirements, REQ_COMMAND_PARSER,
    REQ_NET_EGRESS_SENSOR, REQ_OS_FILE_SENSOR, REQ_SESSION_STORE, REQ_USER_IDENTITY,
    evaluate_floor_entries,
};
use jiff::Timestamp;

use crate::eval::rule_matches_attempt;
use crate::model_dto::{
    EMBEDDED_ESSENTIALS_JSON, WasmActionAttempt, WasmActionClass, WasmCodedError,
    WasmCompiledFloorRule, WasmCompiledFloorTable, WasmMode, WasmPolicyPack, WasmPolicyRule,
    WasmReplaySample, WasmReplaySummary, WasmVerdict,
};
use crate::types::WasmSessionState;

const MAX_REPLAY_SAMPLES: usize = 25;

pub fn essentials_pack_dto() -> Result<WasmPolicyPack, WasmCodedError> {
    serde_json::from_str(EMBEDDED_ESSENTIALS_JSON).map_err(|e| {
        WasmCodedError::invalid_input(
            format!("Failed parsing embedded Essentials manifest: {e}"),
            "Inspect crates/grdr-wasm/manifests/essentials-pack.json.",
        )
    })
}

pub fn collect_pack_requirements(pack: &WasmPolicyPack) -> (HostRuleRequirements, bool) {
    let mut req = HostRuleRequirements::empty();
    let mut has_enforced = false;
    for rule in &pack.rules {
        if !rule.enabled || rule.mode == WasmMode::Off {
            continue;
        }
        if matches!(rule.mode, WasmMode::Ask | WasmMode::Block) {
            has_enforced = true;
        }
        for ac in &rule.matcher.action_classes {
            match ac {
                WasmActionClass::FileRead
                | WasmActionClass::FileWrite
                | WasmActionClass::FileDelete => {
                    req = req.with(REQ_OS_FILE_SENSOR);
                }
                WasmActionClass::Exec => {
                    req = req.with(REQ_COMMAND_PARSER);
                }
                WasmActionClass::NetConnect
                | WasmActionClass::NetRequest
                | WasmActionClass::DataFlow => {
                    req = req.with(REQ_NET_EGRESS_SENSOR);
                }
                _ => {}
            }
        }
        let cedar_src = rule.cedar.as_deref().unwrap_or("");
        if cedar_src.contains("Grdr::User") || cedar_src.contains("user.") {
            req = req.with(REQ_USER_IDENTITY);
        }
        if cedar_src.contains("context.session")
            || cedar_src.contains("session.")
            || cedar_src.contains("labels.")
        {
            req = req.with(REQ_SESSION_STORE);
        }
    }
    (req, has_enforced)
}

pub fn compile_wasm_floor_table(
    packs: &[WasmPolicyPack],
    now: Timestamp,
) -> WasmCompiledFloorTable {
    let mut rules = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode != WasmMode::Block || !rule.locked {
                continue;
            }
            if rule.matcher.action_classes.is_empty()
                || (rule.matcher.target_prefixes.is_empty()
                    && rule.matcher.target_contains.is_empty())
            {
                continue;
            }
            let cedar = rule.cedar.as_deref().unwrap_or("");
            if cedar.contains("context.session")
                || cedar.contains("labels.")
                || cedar.contains("unless")
            {
                continue;
            }
            rules.push(WasmCompiledFloorRule {
                rule_id: rule.id.clone(),
                action_classes: rule.matcher.action_classes.clone(),
                target_prefixes: rule.matcher.target_prefixes.clone(),
                target_contains: rule.matcher.target_contains.clone(),
                agents: rule.matcher.agents.clone(),
                verdict: WasmVerdict::Deny,
                reason: rule.reason_template.clone(),
            });
        }
    }
    WasmCompiledFloorTable {
        version: FLOOR_FORMAT_VERSION,
        compiled_at: now,
        rules,
        key_id: None,
        signature: None,
    }
}

pub fn evaluate_wasm_floor(
    table: &WasmCompiledFloorTable,
    action_class: WasmActionClass,
    agent: &str,
    target: &str,
) -> Option<(String, WasmVerdict, String)> {
    let prefix_slices: Vec<Vec<&str>> = table
        .rules
        .iter()
        .map(|r| r.target_prefixes.iter().map(String::as_str).collect())
        .collect();
    let contains_slices: Vec<Vec<&str>> = table
        .rules
        .iter()
        .map(|r| r.target_contains.iter().map(String::as_str).collect())
        .collect();
    let agent_slices: Vec<Vec<&str>> = table
        .rules
        .iter()
        .map(|r| r.agents.iter().map(String::as_str).collect())
        .collect();

    let mut entries = Vec::with_capacity(table.rules.len());
    for (idx, rule) in table.rules.iter().enumerate() {
        let action_mask = rule
            .action_classes
            .iter()
            .fold(0u32, |mask, c| mask | c.to_fast().bit());
        entries.push(FloorRuleRef {
            rule_id: &rule.rule_id,
            action_mask,
            prefixes: prefix_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            contains: contains_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            agents: agent_slices.get(idx).map(Vec::as_slice).unwrap_or(&[]),
            verdict: rule.verdict.to_fast(),
        });
    }

    let hit = evaluate_floor_entries(&entries, action_class.to_fast(), agent, target)?;
    let reason = table
        .rules
        .iter()
        .find(|r| r.rule_id == hit.rule_id)
        .map(|r| r.reason.clone())
        .unwrap_or_default();
    Some((
        hit.rule_id.to_owned(),
        WasmVerdict::from_fast(hit.verdict),
        reason,
    ))
}

pub fn replay_wasm_rule(
    attempts: &[WasmActionAttempt],
    rule: &WasmPolicyRule,
    candidate_mode: WasmMode,
) -> WasmReplaySummary {
    let mut total_scanned: u64 = 0;
    let mut matched: u64 = 0;
    let mut would_ask: u64 = 0;
    let mut would_block: u64 = 0;
    let mut not_matched: u64 = 0;
    let mut samples = Vec::new();
    let empty_session = WasmSessionState::default();

    for attempt in attempts {
        total_scanned = total_scanned.saturating_add(1);
        let is_hit = rule_matches_attempt(rule, attempt, &empty_session);
        let current_verdict = if is_hit && rule.mode != WasmMode::Off {
            verdict_for_mode(rule.mode)
        } else {
            WasmVerdict::Allow
        };
        let candidate_verdict = if is_hit && candidate_mode != WasmMode::Off {
            verdict_for_mode(candidate_mode)
        } else {
            WasmVerdict::Allow
        };
        if is_hit && candidate_mode != WasmMode::Off {
            matched = matched.saturating_add(1);
            match candidate_mode {
                WasmMode::Ask => would_ask = would_ask.saturating_add(1),
                WasmMode::Block => would_block = would_block.saturating_add(1),
                WasmMode::Off | WasmMode::Watch => {}
            }
            if samples.len() < MAX_REPLAY_SAMPLES {
                samples.push(WasmReplaySample {
                    attempt_id: attempt.id.clone(),
                    session_id: attempt.session_id.clone(),
                    agent_name: attempt.agent_name.clone(),
                    action_class: attempt.action_class,
                    target: attempt.target.clone(),
                    current_verdict,
                    candidate_verdict,
                    timestamp: attempt.timestamp,
                });
            }
        } else {
            not_matched = not_matched.saturating_add(1);
        }
    }

    WasmReplaySummary {
        rule_id: rule.id.clone(),
        candidate_mode,
        window_label: format!("{total_scanned} historical actions"),
        total_scanned,
        matched,
        would_ask,
        would_block,
        not_matched,
        samples,
    }
}

fn verdict_for_mode(mode: WasmMode) -> WasmVerdict {
    match mode {
        WasmMode::Off | WasmMode::Watch => WasmVerdict::Allow,
        WasmMode::Ask => WasmVerdict::StepUp,
        WasmMode::Block => WasmVerdict::Deny,
    }
}
