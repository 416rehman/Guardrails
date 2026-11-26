// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! Executable conformance runner covering CSA AARM R1-R9, broker bounds, and D-12/D-21 invariants.

pub mod aarm;
mod aarm_tail;
pub mod airgap_s31;
pub mod broker_bounds;
pub mod containment;
mod pack_compliance;
mod pack_fixture_eval;
mod pack_fixtures;
mod pack_manifest;
mod pack_policy_vectors;
mod pack_toml;
mod pack_trust;
pub mod pack_verify;

use serde::{Deserialize, Serialize};

pub use aarm::run_aarm_r1_to_r9;
pub use airgap_s31::run_airgap_s31_checks;
pub use broker_bounds::{
    FailSafeEvalResult, HOOK_ACK_BUDGET_MS, HandoverAck, ProviderResponse, SHIM_MAX_EXIT_MS,
    merge_provider_verdicts, run_broker_and_bounds_checks, sign_handover_ack,
    simulate_shim_fail_safe_eval,
};
pub use containment::{
    CompiledNativeRule, NativeTargetKind, compile_down_sound_rules, is_compile_down_eligible,
    run_containment_and_compile_down_checks,
};
pub use pack_manifest::parse_pack_manifest_toml;
pub use pack_trust::load_pack_trust_roots;
pub use pack_verify::{
    DEFAULT_PACK_SIGNER_REF, PackFileDigest, PackSignatureDoc, PackValidationSummary,
    build_signed_pack_doc, validate_live_packs, verify_signed_pack_dir,
    verify_signed_pack_dir_with_trusted,
};

pub const AARM_SPEC_VERSION: &str = "AARM-1.0";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ConformanceError {
    #[error("GRDR-CONF-0001: conformance scenario `{scenario_id}` failed: {detail}")]
    ScenarioFailed { scenario_id: String, detail: String },
    #[error("GRDR-CONF-0002: multiple hook providers requested payload MODIFY")]
    MultipleModifyProviders,
    #[error("GRDR-CONF-0003: handover deadline {requested_ms}ms exceeds 2000ms hard ceiling")]
    HandoverCeilingExceeded { requested_ms: u64 },
    #[error("GRDR-CONF-0004: unsound native compile-down for rule `{rule_id}`: {detail}")]
    UnsoundCompileDown { rule_id: String, detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScenarioCategory {
    Aarm,
    BrokerBounds,
    Containment,
    CompileDown,
    Airgap,
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
    results.extend(run_airgap_s31_checks()?);

    let total = results.len();
    let passed = results
        .iter()
        .filter(|r| r.outcome == ScenarioOutcome::Pass)
        .count();
    let failed = total.saturating_sub(passed);

    Ok(ConformanceReport {
        spec_version: AARM_SPEC_VERSION.to_owned(),
        total,
        passed,
        failed,
        results,
    })
}
