// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod abi;
pub mod engine;
pub mod eval;
pub mod floor;
pub mod model_dto;
pub mod sha256;
pub mod types;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_fastpath::FLOOR_FORMAT_VERSION;

pub use abi::{
    WASM_ABI_VERSION, grdr_alloc, grdr_free, grdr_result_len, grdr_result_ptr,
    grdr_wasm_abi_version, grdr_wasm_eval_attempt,
};
pub use engine::WasmEngine;
use eval::evaluate_wasm_with_session;
use floor::{compile_wasm_floor_table, essentials_pack_dto, evaluate_wasm_floor, replay_wasm_rule};
pub use model_dto::{
    CODE_INVALID_INPUT, WasmActionAttempt, WasmActionClass, WasmApprovalGrade, WasmCodedError,
    WasmCompiledFloorRule, WasmCompiledFloorTable, WasmControlPoint, WasmDecisionReceipt,
    WasmGrant, WasmGrantScope, WasmKillScope, WasmKillSwitchState, WasmMode, WasmPolicyPack,
    WasmPolicyRule, WasmProvenanceSource, WasmReplaySample, WasmReplaySummary, WasmRuleMatch,
    WasmSecondaryAction, WasmSpanKind, WasmVerdict,
};
pub use types::{
    DEFAULT_WASM_STEP_BUDGET, WasmAssuranceKind, WasmBrandManifest, WasmCapPresence,
    WasmCheckpoint, WasmHostProfile, WasmInterestSummary, WasmPackAssurance, WasmRequiredSignal,
    WasmSessionState, WasmSnapshotSummary, WasmStepOutput,
};

#[derive(Debug, Clone, Deserialize)]
pub struct WasmEvalInput {
    pub attempt: WasmActionAttempt,
    #[serde(default)]
    pub packs: Vec<WasmPolicyPack>,
    #[serde(default)]
    pub grants: Vec<WasmGrant>,
    #[serde(default = "default_kill_switch")]
    pub kill_switch: WasmKillSwitchState,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WasmReplayInput {
    pub attempts: Vec<WasmActionAttempt>,
    pub rule: WasmPolicyRule,
    pub candidate_mode: WasmMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmFloorMatch {
    pub rule_id: String,
    pub verdict: WasmVerdict,
    pub reason: String,
    pub floor_version: u32,
}

fn default_kill_switch() -> WasmKillSwitchState {
    WasmKillSwitchState::Inactive
}

pub fn essentials_pack_json() -> Result<String, WasmCodedError> {
    let pack = essentials_pack_dto()?;
    serde_json::to_string(&pack).map_err(|e| {
        WasmCodedError::invalid_input(format!("Failed serializing Essentials pack: {e}"), "Retry.")
    })
}

pub fn compile_floor_json(packs_json: &str) -> Result<String, WasmCodedError> {
    compile_floor_json_at(packs_json, 0)
}

pub fn compile_floor_json_at(
    packs_json: &str,
    timestamp_seconds: i64,
) -> Result<String, WasmCodedError> {
    let packs: Vec<WasmPolicyPack> = serde_json::from_str(packs_json).map_err(|e| {
        WasmCodedError::invalid_input(
            format!("Invalid PolicyPack array JSON: {e}"),
            "Provide valid Vec<PolicyPack> JSON.",
        )
    })?;
    if packs.is_empty() {
        return Err(WasmCodedError::invalid_input(
            "Policy packs are required for floor compilation.",
            "Provide at least one PolicyPack.",
        ));
    }
    let ts = Timestamp::from_second(timestamp_seconds).unwrap_or(Timestamp::UNIX_EPOCH);
    let table = compile_wasm_floor_table(&packs, ts);
    serde_json::to_string(&table).map_err(|e| {
        WasmCodedError::invalid_input(
            format!("Failed serializing CompiledFloorTable: {e}"),
            "Retry.",
        )
    })
}

pub fn evaluate_attempt_receipt(input_json: &str) -> Result<WasmDecisionReceipt, WasmCodedError> {
    let mut input: WasmEvalInput = serde_json::from_str(input_json).map_err(|e| {
        WasmCodedError::invalid_input(
            format!("Invalid WasmEvalInput JSON: {e}"),
            "Provide valid WasmEvalInput JSON.",
        )
    })?;
    if input.packs.is_empty() {
        return Err(WasmCodedError::invalid_input(
            "Policy packs are required; implicit Essentials fallback is disabled.",
            "Provide an explicit non-empty packs array (or load essentials_pack_json).",
        ));
    }
    let mut session = WasmSessionState::default();
    Ok(evaluate_wasm_with_session(
        &input.attempt,
        &input.packs,
        &mut input.grants,
        &input.kill_switch,
        &mut session,
        input.attempt.timestamp,
    ))
}

pub fn evaluate_attempt_json(input_json: &str) -> Result<String, WasmCodedError> {
    let receipt = evaluate_attempt_receipt(input_json)?;
    serde_json::to_string(&receipt).map_err(|e| {
        WasmCodedError::invalid_input(format!("Failed serializing DecisionReceipt: {e}"), "Retry.")
    })
}

pub fn replay_rule_json(input_json: &str) -> Result<String, WasmCodedError> {
    let input: WasmReplayInput = serde_json::from_str(input_json).map_err(|e| {
        WasmCodedError::invalid_input(
            format!("Invalid WasmReplayInput JSON: {e}"),
            "Provide valid WasmReplayInput JSON.",
        )
    })?;
    let summary = replay_wasm_rule(&input.attempts, &input.rule, input.candidate_mode);
    serde_json::to_string(&summary).map_err(|e| {
        WasmCodedError::invalid_input(format!("Failed serializing ReplaySummary: {e}"), "Retry.")
    })
}

pub fn evaluate_floor_json(
    table_json: &str,
    action_class: WasmActionClass,
    agent: &str,
    target: &str,
) -> Result<Option<String>, WasmCodedError> {
    let table: WasmCompiledFloorTable = serde_json::from_str(table_json).map_err(|e| {
        WasmCodedError::invalid_input(
            format!("Invalid CompiledFloorTable JSON: {e}"),
            "Compile floor table before calling evaluate_floor_json.",
        )
    })?;
    let matched =
        evaluate_wasm_floor(&table, action_class, agent, target).map(|(id, v, reason)| {
            WasmFloorMatch {
                rule_id: id,
                verdict: v,
                reason,
                floor_version: FLOOR_FORMAT_VERSION,
            }
        });
    match matched {
        Some(m) => {
            let json = serde_json::to_string(&m).map_err(|e| {
                WasmCodedError::invalid_input(
                    format!("Failed serializing floor match: {e}"),
                    "Retry.",
                )
            })?;
            Ok(Some(json))
        }
        None => Ok(None),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wasm_api_requires_explicit_packs_and_matches_floor_parity() {
        let pack = essentials_pack_dto().unwrap();
        let packs_json = serde_json::to_string(&vec![pack.clone()]).unwrap();
        let floor_json = compile_floor_json_at(&packs_json, 1_700_000_000).unwrap();

        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        let attempt = WasmActionAttempt {
            id: "att-wasm-1".into(),
            session_id: "sess-wasm".into(),
            device_id: "dev-wasm".into(),
            device_name: "browser-host".into(),
            agent_name: "claude-code".into(),
            action_class: WasmActionClass::FileWrite,
            control_point: WasmControlPoint::Hook,
            target: ".claude/settings.json".into(),
            summary: "Edit protected settings".into(),
            timestamp: ts,
            ..Default::default()
        };

        let missing_packs = serde_json::json!({ "attempt": attempt }).to_string();
        assert!(evaluate_attempt_json(&missing_packs).is_err());

        let eval_input = serde_json::json!({ "attempt": attempt, "packs": [pack] }).to_string();
        let receipt_json = evaluate_attempt_json(&eval_input).unwrap();
        let receipt: WasmDecisionReceipt = serde_json::from_str(&receipt_json).unwrap();
        assert_eq!(receipt.verdict, WasmVerdict::Deny);

        let floor_hit_json = evaluate_floor_json(
            &floor_json,
            WasmActionClass::FileWrite,
            "claude-code",
            ".claude/settings.json",
        )
        .unwrap()
        .unwrap();
        let floor_hit: WasmFloorMatch = serde_json::from_str(&floor_hit_json).unwrap();
        assert_eq!(floor_hit.verdict, receipt.verdict);
        assert_eq!(Some(floor_hit.rule_id), receipt.rule_id);

        let pack2 = essentials_pack_dto().unwrap();
        let replay_input = serde_json::json!({
            "attempts": [attempt],
            "rule": pack2.rules.first(),
            "candidate_mode": WasmMode::Block,
        })
        .to_string();
        let summary_json = replay_rule_json(&replay_input).unwrap();
        let summary: WasmReplaySummary = serde_json::from_str(&summary_json).unwrap();
        assert_eq!(summary.total_scanned, 1);
    }
}
