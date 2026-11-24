// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! Executable CSA AARM R1-R9, broker fail-safe bounds, containment, and compile-down suite.

pub mod aarm;
pub mod broker_bounds;
pub mod containment;

use serde::{Deserialize, Serialize};

pub use aarm::run_aarm_r1_to_r9;
pub use broker_bounds::{
    HOOK_ACK_BUDGET_MS, SHIM_MAX_EXIT_MS, merge_provider_verdicts, run_broker_and_bounds_checks,
    simulate_shim_fail_safe_eval,
};
pub use containment::{
    CompiledNativeRule, NativeTargetKind, compile_down_sound_rules,
    run_containment_and_compile_down_checks,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConformanceError {
    #[error("GRDR-CONF-0001: conformance scenario `{scenario_id}` failed: {detail}")]
    ScenarioFailed { scenario_id: String, detail: String },
    #[error("GRDR-CONF-0002: multiple MODIFY providers configured for single action class")]
    MultipleModifyProviders,
    #[error("GRDR-CONF-0003: handover deadline {requested_ms}ms exceeds 2000ms ceiling")]
    HandoverCeilingExceeded { requested_ms: u64 },
    #[error("GRDR-CONF-0004: compile-down soundness check failed for `{rule_id}`: {detail}")]
    UnsoundCompileDown { rule_id: String, detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCategory {
    Aarm,
    BrokerBounds,
    Containment,
    CompileDown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioOutcome {
    Pass,
    Fail,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScenarioResult {
    pub id: String,
    pub category: ScenarioCategory,
    pub title: String,
    pub outcome: ScenarioOutcome,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConformanceReport {
    pub spec_version: String,
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub results: Vec<ScenarioResult>,
}

impl ConformanceReport {
    pub fn all_passed(&self) -> bool {
        self.failed == 0 && self.passed == self.total
    }
}

pub fn run_full_conformance_suite() -> Result<ConformanceReport, ConformanceError> {
    let mut results = Vec::new();
    results.extend(run_aarm_r1_to_r9()?);
    results.extend(run_broker_and_bounds_checks()?);
    results.extend(run_containment_and_compile_down_checks()?);

    let total = results.len();
    let passed = results
        .iter()
        .filter(|r| r.outcome == ScenarioOutcome::Pass)
        .count();
    let failed = total.saturating_sub(passed);

    Ok(ConformanceReport {
        spec_version: "AARM-1.0".into(),
        total,
        passed,
        failed,
        results,
    })
}
