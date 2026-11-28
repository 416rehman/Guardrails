// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 3 behavioral loop classifier, reachability visibility tiers, could-not-look reporting,
//! and advisory-only `DiscoveryEvidence` (`docs/design/05`).

use std::collections::BTreeSet;

use grdr_model::{AssuranceLevel, CodedError, Device};
use serde::{Deserialize, Serialize};

const BP_SCALE: u64 = 10_000;
const CHILD_CYCLE_EXIT_WINDOW_MS: u64 = 30_000;
const CHILD_CREATION_WINDOW_MS: u64 = 120_000;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FleetCoverageSummary {
    pub total_agents: usize,
    pub guided_or_higher: usize,
    pub coverage_percent: usize,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryVisibilityTier {
    ConnectSni,
    ConnectOnlyNoFlowTiming,
    NetIndirect,
    ExplicitListener,
    SdkOrHooks,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CouldNotLookReason {
    NoFlowTiming,
    NetIndirect,
    EnvUnavailable,
    CompositionSkipped,
    CompositionBudget,
    SandboxedRuntime,
    ConnectorCap,
    PermissionDenied,
    Excluded,
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum DiscoveryAdvisoryFact {
    AgentSuspected,
    LlmClient,
    Blocked,
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
    pub visibility_tier: Option<DiscoveryVisibilityTier>,
    pub child_exec_timestamps_ms: Vec<u64>,
    pub mcp_stdin_write_timestamps_ms: Vec<u64>,
    pub has_mcp_server_or_flow: bool,
    pub suppressed_housekeeping_hits: u32,
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

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryEvidence {
    pub process_name: String,
    pub program_id: String,
    pub visibility_tier: DiscoveryVisibilityTier,
    pub could_not_look: Option<CouldNotLookReason>,
    pub advisory_fact: Option<DiscoveryAdvisoryFact>,
    pub assessment: BehavioralAssessment,
    pub retain_local_only: bool,
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
            return Err(CodedError::new(
                "GRDR-DISC-0001",
                "basis-point threshold or weight exceeds 10000",
                "Set classifier basis-point thresholds and weights within 0..=10000.",
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
            return Err(CodedError::new(
                "GRDR-DISC-0002",
                "classifier window or min_cycles must be positive",
                "Set positive classifier windows and min_cycles in classifier.yaml.",
            ));
        }
        Ok(())
    }
}

impl DiscoveryAdvisoryFact {
    #[must_use]
    pub const fn is_policy_readable(self) -> bool {
        false
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
pub fn classify_agentic_loop(
    obs: &BehavioralObservation,
    cfg: &ClassifierConfig,
) -> BehavioralAssessment {
    classify_behavioral_loop_v2(obs, cfg, "").assessment
}

#[must_use]
pub fn classify_behavioral_loop_v2(
    obs: &BehavioralObservation,
    cfg: &ClassifierConfig,
    program_id: &str,
) -> DiscoveryEvidence {
    let tier = obs
        .visibility_tier
        .unwrap_or(DiscoveryVisibilityTier::ConnectSni);
    let mut could_not_look = match tier {
        DiscoveryVisibilityTier::ConnectOnlyNoFlowTiming => Some(CouldNotLookReason::NoFlowTiming),
        DiscoveryVisibilityTier::NetIndirect => Some(CouldNotLookReason::NetIndirect),
        _ => None,
    };
    let effective_blocked = obs.scan_blocked.or_else(|| {
        (tier == DiscoveryVisibilityTier::NetIndirect).then_some(ScanBlockedReason::Unreachable)
    });

    let (verdict, cycles, ratio, score, reason) = if let Some(why) = effective_blocked {
        could_not_look.get_or_insert(match why {
            ScanBlockedReason::PermissionDenied => CouldNotLookReason::PermissionDenied,
            ScanBlockedReason::BudgetExceeded => CouldNotLookReason::CompositionBudget,
            ScanBlockedReason::ProtectedContainer => CouldNotLookReason::SandboxedRuntime,
            ScanBlockedReason::Unreachable => CouldNotLookReason::NetIndirect,
        });
        (
            BehaviorVerdict::ScanBlocked(why),
            0,
            0,
            0,
            format!("scan incomplete: {why:?}"),
        )
    } else if tier == DiscoveryVisibilityTier::ConnectOnlyNoFlowTiming
        && obs.tool_effect_timestamps_ms.is_empty()
        && obs.child_exec_timestamps_ms.is_empty()
        && obs.mcp_stdin_write_timestamps_ms.is_empty()
    {
        let v = if obs.llm_request_timestamps_ms.len() >= cfg.llm_client_min_calls {
            BehaviorVerdict::LlmClient
        } else {
            BehaviorVerdict::Unclassified
        };
        (
            v,
            0,
            0,
            0,
            "could-not-look=no-flow-timing; retained at connect-only tier".to_string(),
        )
    } else {
        let horizon = cfg.window_secs.saturating_mul(1000);
        let mut combined_effects = obs.tool_effect_timestamps_ms.clone();
        combined_effects.extend_from_slice(&obs.child_exec_timestamps_ms);
        combined_effects.extend_from_slice(&obs.mcp_stdin_write_timestamps_ms);
        let cycle_window = if obs.tool_effect_timestamps_ms.is_empty()
            && !obs.mcp_stdin_write_timestamps_ms.is_empty()
        {
            CHILD_CREATION_WINDOW_MS
        } else if obs.tool_effect_timestamps_ms.is_empty()
            && !obs.child_exec_timestamps_ms.is_empty()
        {
            CHILD_CYCLE_EXIT_WINDOW_MS
        } else {
            cfg.coincidence_window_ms
        };

        let (cycles, ratio) = count_cycles(
            &obs.llm_request_timestamps_ms,
            &combined_effects,
            cycle_window,
            horizon,
        );
        let corroborated_bridge =
            !obs.protocol_bridge_blocks.is_empty() && obs.has_mcp_server_or_flow;
        let has_ws = obs
            .environment_signals
            .contains(&ExecutionEnvironmentSignal::WorkspaceOrSandbox);
        let has_comp = !obs.orchestrator_blocks.is_empty() || corroborated_bridge || has_ws;
        let score = noisy_or_bp(obs, cfg, cycles, ratio);
        let v = if cycles >= cfg.min_cycles && ratio >= cfg.min_coincidence_ratio_bp && has_comp {
            BehaviorVerdict::AgentClassified
        } else if cycles >= 1
            || score >= cfg.suspected_threshold_bp
            || !obs.orchestrator_blocks.is_empty()
            || corroborated_bridge
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

    let advisory_fact = match verdict {
        BehaviorVerdict::AgentSuspected | BehaviorVerdict::AgentClassified => {
            Some(DiscoveryAdvisoryFact::AgentSuspected)
        }
        BehaviorVerdict::LlmClient => Some(DiscoveryAdvisoryFact::LlmClient),
        BehaviorVerdict::ScanBlocked(_) => Some(DiscoveryAdvisoryFact::Blocked),
        BehaviorVerdict::Unclassified => None,
    };
    let retain_local_only = matches!(
        verdict,
        BehaviorVerdict::LlmClient | BehaviorVerdict::Unclassified
    );

    DiscoveryEvidence {
        process_name: obs.process_name.clone(),
        program_id: program_id.to_owned(),
        visibility_tier: tier,
        could_not_look,
        advisory_fact,
        assessment: BehavioralAssessment {
            process_name: obs.process_name.clone(),
            verdict,
            disposition: ClassifierDisposition::AdvisoryOnly,
            cycle_count: cycles,
            coincidence_ratio_bp: ratio,
            noisy_or_score_bp: score,
            reason,
        },
        retain_local_only,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mcp_sdk_without_flow_stays_llm_client_and_advisory_fact_never_policy_readable() {
        let obs = BehavioralObservation {
            process_name: "batch-summarizer".into(),
            llm_request_timestamps_ms: vec![1_000, 10_000, 20_000],
            protocol_bridge_blocks: vec!["mcp-sdks".into()],
            has_mcp_server_or_flow: false,
            suppressed_housekeeping_hits: 3,
            ..BehavioralObservation::default()
        };
        let ev = classify_behavioral_loop_v2(&obs, &ClassifierConfig::default(), "pkg:pypi:sum");
        assert_eq!(ev.assessment.verdict, BehaviorVerdict::LlmClient);
        assert!(ev.retain_local_only);
        assert_eq!(ev.advisory_fact, Some(DiscoveryAdvisoryFact::LlmClient));
        assert!(!DiscoveryAdvisoryFact::AgentSuspected.is_policy_readable());
    }

    #[test]
    fn visibility_tiers_report_no_flow_timing_and_net_indirect_reasons() {
        let mac_obs = BehavioralObservation {
            process_name: "mac-agent".into(),
            llm_request_timestamps_ms: vec![1_000, 5_000],
            visibility_tier: Some(DiscoveryVisibilityTier::ConnectOnlyNoFlowTiming),
            ..BehavioralObservation::default()
        };
        let mac_ev = classify_behavioral_loop_v2(&mac_obs, &ClassifierConfig::default(), "sig:m");
        assert_eq!(
            mac_ev.could_not_look,
            Some(CouldNotLookReason::NoFlowTiming)
        );
        assert_eq!(mac_ev.assessment.verdict, BehaviorVerdict::LlmClient);

        let proxy_obs = BehavioralObservation {
            process_name: "proxied".into(),
            visibility_tier: Some(DiscoveryVisibilityTier::NetIndirect),
            ..BehavioralObservation::default()
        };
        let proxy_ev =
            classify_behavioral_loop_v2(&proxy_obs, &ClassifierConfig::default(), "path:p");
        assert_eq!(
            proxy_ev.could_not_look,
            Some(CouldNotLookReason::NetIndirect)
        );
        assert_eq!(
            proxy_ev.assessment.verdict,
            BehaviorVerdict::ScanBlocked(ScanBlockedReason::Unreachable)
        );
    }
}
