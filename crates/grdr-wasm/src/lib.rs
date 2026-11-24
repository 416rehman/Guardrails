// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_core::compile::{FloorMatch, compile_floor_table, evaluate_compiled_floor};
use grdr_core::policy::{essentials_pack, evaluate_with_session, replay_rule};
use grdr_core::session::SessionRuleState;
use grdr_fastpath::FLOOR_FORMAT_VERSION;
use grdr_model::error::CODE_INVALID_INPUT;
use grdr_model::{
    ActionAttempt, ActionClass, CodedError, CompiledFloorTable, DecisionReceipt, Grant,
    KillSwitchState, Mode, PolicyPack, PolicyRule, ReplaySummary, Verdict,
};

#[derive(Debug, Clone, Deserialize)]
pub struct WasmEvalInput {
    pub attempt: ActionAttempt,
    #[serde(default)]
    pub packs: Vec<PolicyPack>,
    #[serde(default)]
    pub grants: Vec<Grant>,
    #[serde(default = "default_kill_switch")]
    pub kill_switch: KillSwitchState,
}

#[derive(Debug, Clone, Deserialize)]
pub struct WasmReplayInput {
    pub attempts: Vec<ActionAttempt>,
    pub rule: PolicyRule,
    pub candidate_mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WasmFloorMatch {
    pub rule_id: String,
    pub verdict: Verdict,
    pub reason: String,
    pub floor_version: u32,
}

fn default_kill_switch() -> KillSwitchState {
    KillSwitchState::Inactive
}

impl From<FloorMatch> for WasmFloorMatch {
    fn from(m: FloorMatch) -> Self {
        Self {
            rule_id: m.rule_id,
            verdict: m.verdict,
            reason: m.reason,
            floor_version: FLOOR_FORMAT_VERSION,
        }
    }
}

pub fn essentials_pack_json() -> Result<String, CodedError> {
    serde_json::to_string(&essentials_pack()).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Failed serializing Essentials pack: {e}"),
            "Retry.",
        )
    })
}

pub fn compile_floor_json(packs_json: &str) -> Result<String, CodedError> {
    let packs: Vec<PolicyPack> = serde_json::from_str(packs_json).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Invalid PolicyPack array JSON: {e}"),
            "Provide valid Vec<PolicyPack> JSON.",
        )
    })?;
    let table = compile_floor_table(&packs, Timestamp::now());
    serde_json::to_string(&table).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Failed serializing CompiledFloorTable: {e}"),
            "Retry.",
        )
    })
}

pub fn evaluate_attempt_json(input_json: &str) -> Result<String, CodedError> {
    let mut input: WasmEvalInput = serde_json::from_str(input_json).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Invalid WasmEvalInput JSON: {e}"),
            "Provide valid WasmEvalInput JSON.",
        )
    })?;
    if input.packs.is_empty() {
        input.packs.push(essentials_pack());
    }
    let mut session = SessionRuleState::default();
    let receipt: DecisionReceipt = evaluate_with_session(
        &input.attempt,
        &input.packs,
        &mut input.grants,
        &input.kill_switch,
        &mut session,
        input.attempt.timestamp,
    );
    serde_json::to_string(&receipt).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Failed serializing DecisionReceipt: {e}"),
            "Retry.",
        )
    })
}

pub fn replay_rule_json(input_json: &str) -> Result<String, CodedError> {
    let input: WasmReplayInput = serde_json::from_str(input_json).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Invalid WasmReplayInput JSON: {e}"),
            "Provide valid WasmReplayInput JSON.",
        )
    })?;
    let summary: ReplaySummary = replay_rule(&input.attempts, &input.rule, input.candidate_mode);
    serde_json::to_string(&summary).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Failed serializing ReplaySummary: {e}"),
            "Retry.",
        )
    })
}

pub fn evaluate_floor_json(
    table_json: &str,
    action_class: ActionClass,
    agent: &str,
    target: &str,
) -> Result<Option<String>, CodedError> {
    let table: CompiledFloorTable = serde_json::from_str(table_json).map_err(|e| {
        CodedError::new(
            CODE_INVALID_INPUT,
            format!("Invalid CompiledFloorTable JSON: {e}"),
            "Compile floor table before calling evaluate_floor_json.",
        )
    })?;
    let matched =
        evaluate_compiled_floor(&table, action_class, agent, target).map(WasmFloorMatch::from);
    match matched {
        Some(m) => {
            let json = serde_json::to_string(&m).map_err(|e| {
                CodedError::new(
                    CODE_INVALID_INPUT,
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
    use grdr_model::ControlPoint;

    #[test]
    fn wasm_api_evaluates_replays_and_matches_fastpath_floor_parity() {
        let packs_json = format!("[{}]", essentials_pack_json().unwrap());
        let floor_json = compile_floor_json(&packs_json).unwrap();

        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        let attempt = ActionAttempt {
            id: "att-wasm-1".into(),
            session_id: "sess-wasm".into(),
            device_id: "dev-wasm".into(),
            device_name: "browser-host".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileWrite,
            control_point: ControlPoint::Hook,
            target: ".claude/settings.json".into(),
            summary: "Edit protected settings".into(),
            timestamp: ts,
        };

        let eval_input = serde_json::json!({ "attempt": attempt }).to_string();
        let receipt_json = evaluate_attempt_json(&eval_input).unwrap();
        let receipt: DecisionReceipt = serde_json::from_str(&receipt_json).unwrap();
        assert_eq!(receipt.verdict, Verdict::Deny);

        let floor_hit_json = evaluate_floor_json(
            &floor_json,
            ActionClass::FileWrite,
            "claude-code",
            ".claude/settings.json",
        )
        .unwrap()
        .unwrap();
        let floor_hit: WasmFloorMatch = serde_json::from_str(&floor_hit_json).unwrap();
        assert_eq!(floor_hit.verdict, receipt.verdict);
        assert_eq!(Some(floor_hit.rule_id), receipt.rule_id);

        let pack = essentials_pack();
        let replay_input = serde_json::json!({
            "attempts": [attempt],
            "rule": pack.rules.first(),
            "candidate_mode": Mode::Block,
        })
        .to_string();
        let summary_json = replay_rule_json(&replay_input).unwrap();
        let summary: ReplaySummary = serde_json::from_str(&summary_json).unwrap();
        assert_eq!(summary.total_scanned, 1);
    }
}
