// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Sans-IO 4-pass agent discovery, program identity, behavioral classification,
//! inventory diffing, and ABOM synthesis (`docs/design/05`).

use std::collections::BTreeSet;

use grdr_crypto::sha256_hex;
use grdr_model::{AssuranceLevel, CodedError, Device};
use serde::{Deserialize, Serialize};

const BP_SCALE: u64 = 10_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetCoverageSummary {
    pub total_agents: usize,
    pub guided_or_higher: usize,
    pub coverage_percent: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProgramIdentity {
    CodeSigned {
        signer: String,
        digest: String,
    },
    PackageOwned {
        ecosystem: String,
        package: String,
        version: String,
    },
    ImageDigest {
        sha256: String,
    },
    SourceTree {
        workspace: String,
        digest: String,
    },
    RawPath {
        path: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct IdentityHints {
    pub code_signer: Option<String>,
    pub binary_digest: Option<String>,
    pub ecosystem: Option<String>,
    pub package_name: Option<String>,
    pub package_version: Option<String>,
    pub image_sha256: Option<String>,
    pub workspace_id: Option<String>,
    pub tree_digest: Option<String>,
    pub executable_path: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Pass1MatchState {
    NotFound,
    Candidate,
    InstalledMatched,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BuildingBlockRole {
    Orchestrator,
    ProtocolBridge,
    LlmSdk,
    Runtime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AgenticIndicator {
    Yes,
    Corroborated,
    No,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ScanBlockedReason {
    PermissionDenied,
    BudgetExceeded,
    ProtectedContainer,
    Unreachable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BehaviorVerdict {
    Unclassified,
    LlmClient,
    AgentSuspected,
    AgentClassified,
    ScanBlocked(ScanBlockedReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClassifierDisposition {
    AdvisoryOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExecutionEnvironmentSignal {
    WorkspaceOrSandbox,
    HeadlessEnvMarker,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifierWeights {
    pub llm_stream_then_tool_bp: u16,
    pub multi_turn_cadence_bp: u16,
    pub sandbox_or_workspace_access_bp: u16,
    pub orchestrator_package_bp: u16,
    pub headless_env_markers_bp: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClassifierConfig {
    pub window_secs: u64,
    pub min_cycles: u32,
    pub coincidence_window_ms: u64,
    pub min_coincidence_ratio_bp: u16,
    pub llm_client_min_calls: usize,
    pub candidate_scan_budget_ms: u64,
    pub suspected_threshold_bp: u16,
    pub classified_threshold_bp: u16,
    pub weights: ClassifierWeights,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct BehavioralObservation {
    pub process_name: String,
    pub llm_request_timestamps_ms: Vec<u64>,
    pub tool_effect_timestamps_ms: Vec<u64>,
    pub environment_signals: BTreeSet<ExecutionEnvironmentSignal>,
    pub orchestrator_blocks: Vec<String>,
    pub protocol_bridge_blocks: Vec<String>,
    pub scan_blocked: Option<ScanBlockedReason>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BehavioralAssessment {
    pub process_name: String,
    pub verdict: BehaviorVerdict,
    pub disposition: ClassifierDisposition,
    pub cycle_count: u32,
    pub coincidence_ratio_bp: u16,
    pub noisy_or_score_bp: u16,
    pub reason: String,
}

impl ProgramIdentity {
    #[must_use]
    pub fn canonical_id(&self) -> String {
        match self {
            Self::CodeSigned { signer, digest } => format!("sig:{signer}:{digest}"),
            Self::PackageOwned {
                ecosystem,
                package,
                version,
            } => {
                format!("pkg:{ecosystem}:{package}@{version}")
            }
            Self::ImageDigest { sha256 } => format!("img:{sha256}"),
            Self::SourceTree { workspace, digest } => format!("src:{workspace}:{digest}"),
            Self::RawPath { path } => format!("path:{}", sha256_hex(path.as_bytes())),
        }
    }

    #[must_use]
    pub fn from_hints(h: &IdentityHints) -> Self {
        fn ne(o: &Option<String>) -> Option<&str> {
            o.as_deref().filter(|s| !s.is_empty())
        }
        if let (Some(signer), Some(digest)) = (ne(&h.code_signer), ne(&h.binary_digest)) {
            return Self::CodeSigned {
                signer: signer.into(),
                digest: digest.into(),
            };
        }
        if let (Some(eco), Some(pkg)) = (ne(&h.ecosystem), ne(&h.package_name)) {
            let version = ne(&h.package_version).unwrap_or("unknown").into();
            return Self::PackageOwned {
                ecosystem: eco.into(),
                package: pkg.into(),
                version,
            };
        }
        if let Some(sha) = ne(&h.image_sha256) {
            return Self::ImageDigest { sha256: sha.into() };
        }
        if let (Some(ws), Some(digest)) = (ne(&h.workspace_id), ne(&h.tree_digest)) {
            return Self::SourceTree {
                workspace: ws.into(),
                digest: digest.into(),
            };
        }
        Self::RawPath {
            path: h.executable_path.clone(),
        }
    }
}

impl Default for ClassifierWeights {
    fn default() -> Self {
        Self {
            llm_stream_then_tool_bp: 3500,
            multi_turn_cadence_bp: 2500,
            sandbox_or_workspace_access_bp: 2500,
            orchestrator_package_bp: 4000,
            headless_env_markers_bp: 1500,
        }
    }
}

impl Default for ClassifierConfig {
    fn default() -> Self {
        Self {
            window_secs: 60,
            min_cycles: 3,
            coincidence_window_ms: 2000,
            min_coincidence_ratio_bp: 5000,
            llm_client_min_calls: 2,
            candidate_scan_budget_ms: 500,
            suspected_threshold_bp: 5500,
            classified_threshold_bp: 7500,
            weights: ClassifierWeights::default(),
        }
    }
}

impl ClassifierConfig {
    pub fn validate(&self) -> Result<(), CodedError> {
        let bps = [
            self.min_coincidence_ratio_bp,
            self.suspected_threshold_bp,
            self.classified_threshold_bp,
            self.weights.llm_stream_then_tool_bp,
            self.weights.multi_turn_cadence_bp,
            self.weights.sandbox_or_workspace_access_bp,
            self.weights.orchestrator_package_bp,
            self.weights.headless_env_markers_bp,
        ];
        if bps.into_iter().any(|bp| u64::from(bp) > BP_SCALE) {
            let fix = "Set classifier basis-point thresholds and weights within 0..=10000.";
            return Err(CodedError::new(
                "GRDR-DISC-0001",
                "basis-point threshold or weight exceeds 10000",
                fix,
            ));
        }
        if self.suspected_threshold_bp > self.classified_threshold_bp {
            return Err(CodedError::new(
                "GRDR-DISC-0001",
                "suspected_threshold_bp exceeds classified_threshold_bp",
                "Ensure suspected_threshold_bp <= classified_threshold_bp.",
            ));
        }
        if self.window_secs == 0
            || self.min_cycles == 0
            || self.coincidence_window_ms == 0
            || self.candidate_scan_budget_ms == 0
        {
            let fix = "Set positive classifier windows and min_cycles in classifier.yaml.";
            return Err(CodedError::new(
                "GRDR-DISC-0002",
                "classifier window or min_cycles must be positive",
                fix,
            ));
        }
        Ok(())
    }
}

impl BehavioralAssessment {
    #[must_use]
    pub fn is_advisory_only(&self) -> bool {
        matches!(self.disposition, ClassifierDisposition::AdvisoryOnly)
    }
}

pub fn summarize_coverage(devices: &[Device]) -> FleetCoverageSummary {
    let total = devices
        .iter()
        .fold(0usize, |acc, d| acc.saturating_add(d.agents.len()));
    let guided = devices
        .iter()
        .flat_map(|d| &d.agents)
        .filter(|a| a.assurance_level >= AssuranceLevel::Al2Guided)
        .count();
    let pct = if total == 0 {
        100
    } else {
        guided.saturating_mul(100).checked_div(total).unwrap_or(0)
    };
    FleetCoverageSummary {
        total_agents: total,
        guided_or_higher: guided,
        coverage_percent: pct,
    }
}

#[must_use]
pub fn evaluate_pass1_routes(matched_route_count: usize) -> Pass1MatchState {
    match matched_route_count {
        0 => Pass1MatchState::NotFound,
        1 => Pass1MatchState::Candidate,
        _ => Pass1MatchState::InstalledMatched,
    }
}

#[must_use]
pub fn classify_agentic_loop(
    obs: &BehavioralObservation,
    cfg: &ClassifierConfig,
) -> BehavioralAssessment {
    let (verdict, cycles, ratio, score, reason) = if let Some(why) = obs.scan_blocked {
        (
            BehaviorVerdict::ScanBlocked(why),
            0,
            0,
            0,
            format!("scan incomplete: {why:?}"),
        )
    } else {
        let horizon = cfg.window_secs.saturating_mul(1000);
        let (cycles, ratio) = count_cycles(
            &obs.llm_request_timestamps_ms,
            &obs.tool_effect_timestamps_ms,
            cfg.coincidence_window_ms,
            horizon,
        );
        let score = noisy_or_bp(obs, cfg, cycles, ratio);
        let has_ws = obs
            .environment_signals
            .contains(&ExecutionEnvironmentSignal::WorkspaceOrSandbox);
        let has_comp =
            !obs.orchestrator_blocks.is_empty() || !obs.protocol_bridge_blocks.is_empty() || has_ws;
        let v = if cycles >= cfg.min_cycles && ratio >= cfg.min_coincidence_ratio_bp && has_comp {
            BehaviorVerdict::AgentClassified
        } else if cycles >= 1
            || score >= cfg.suspected_threshold_bp
            || !obs.orchestrator_blocks.is_empty()
        {
            BehaviorVerdict::AgentSuspected
        } else if obs.llm_request_timestamps_ms.len() >= cfg.llm_client_min_calls {
            BehaviorVerdict::LlmClient
        } else {
            BehaviorVerdict::Unclassified
        };
        (
            v,
            cycles,
            ratio,
            score,
            format!("cycles={cycles} coincidence_bp={ratio} noisy_or_bp={score}"),
        )
    };
    BehavioralAssessment {
        process_name: obs.process_name.clone(),
        verdict,
        disposition: ClassifierDisposition::AdvisoryOnly,
        cycle_count: cycles,
        coincidence_ratio_bp: ratio,
        noisy_or_score_bp: score,
        reason,
    }
}

fn count_cycles(llm_ts: &[u64], tool_ts: &[u64], win_ms: u64, horizon_ms: u64) -> (u32, u16) {
    if llm_ts.is_empty() {
        return (0, 0);
    }
    let (mut llm, mut tool) = (llm_ts.to_vec(), tool_ts.to_vec());
    llm.sort_unstable();
    tool.sort_unstable();
    let cutoff = llm.last().copied().unwrap_or(0).saturating_sub(horizon_ms);
    let recent: Vec<u64> = llm.into_iter().filter(|ts| *ts >= cutoff).collect();
    if recent.is_empty() {
        return (0, 0);
    }
    let (mut matched, mut t_idx): (u64, usize) = (0, 0);
    for t_llm in &recent {
        while let Some(t) = tool.get(t_idx).copied() {
            if t < *t_llm {
                t_idx = t_idx.saturating_add(1);
            } else {
                break;
            }
        }
        if let Some(t) = tool.get(t_idx).copied()
            && t.saturating_sub(*t_llm) <= win_ms
        {
            matched = matched.saturating_add(1);
            t_idx = t_idx.saturating_add(1);
        }
    }
    let total = u64::try_from(recent.len()).unwrap_or(u64::MAX);
    let ratio = matched
        .saturating_mul(BP_SCALE)
        .checked_div(total)
        .unwrap_or(0)
        .min(BP_SCALE);
    (
        u32::try_from(matched).unwrap_or(u32::MAX),
        u16::try_from(ratio).unwrap_or(10_000),
    )
}

fn noisy_or_bp(
    obs: &BehavioralObservation,
    cfg: &ClassifierConfig,
    cycles: u32,
    ratio: u16,
) -> u16 {
    use ExecutionEnvironmentSignal as E;
    let w = &cfg.weights;
    let env = &obs.environment_signals;
    let signals = [
        (
            cycles >= 1 && ratio >= cfg.min_coincidence_ratio_bp,
            w.llm_stream_then_tool_bp,
        ),
        (cycles >= cfg.min_cycles, w.multi_turn_cadence_bp),
        (
            env.contains(&E::WorkspaceOrSandbox),
            w.sandbox_or_workspace_access_bp,
        ),
        (
            !obs.orchestrator_blocks.is_empty(),
            w.orchestrator_package_bp,
        ),
        (
            env.contains(&E::HeadlessEnvMarker),
            w.headless_env_markers_bp,
        ),
    ];
    let surv = signals
        .into_iter()
        .filter(|(hit, _)| *hit)
        .fold(BP_SCALE, |acc, (_, wt)| {
            let comp = BP_SCALE.saturating_sub(u64::from(wt).min(BP_SCALE));
            acc.saturating_mul(comp).checked_div(BP_SCALE).unwrap_or(0)
        });
    u16::try_from(BP_SCALE.saturating_sub(surv)).unwrap_or(10_000)
}

#[must_use]
pub fn canonical_sha256_hex(bytes: &[u8]) -> String {
    sha256_hex(bytes)
}
