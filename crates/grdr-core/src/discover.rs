// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Sans-IO 4-pass agent discovery: program identity grammar, behavioral classifier,
//! reachability/could-not-look reasons, and coverage summary (`docs/design/05`).

pub mod behavior;
pub mod identity;

pub use behavior::{
    AgenticIndicator, BehaviorVerdict, BehavioralAssessment, BehavioralObservation,
    BuildingBlockRole, ClassifierConfig, ClassifierDisposition, ClassifierWeights,
    CouldNotLookReason, DiscoveryAdvisoryFact, DiscoveryEvidence, DiscoveryVisibilityTier,
    ExecutionEnvironmentSignal, FleetCoverageSummary, ScanBlockedReason, classify_agentic_loop,
    classify_behavioral_loop_v2, summarize_coverage,
};
pub use identity::{
    IdentityHints, Pass1MatchState, ProgramIdentity, canonical_sha256_hex, evaluate_pass1_routes,
    evaluate_pass1_with_attributes,
};
