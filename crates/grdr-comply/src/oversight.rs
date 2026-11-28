// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Quarterly oversight-quality reports, P8 minimum-group guard, NCSC ladders, and Five Eyes (`29` s.7).

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::{ApprovalGrade, AssuranceLevel, IdentityMode};
use jiff::{Timestamp, tz::TimeZone};
use serde::{Deserialize, Serialize};

use crate::{ComplyError, markdown_safe};

const MIN_GROUP_SIZE_FOR_DISCLOSURE: usize = 5;
const RUBBER_STAMP_MIN_DECIDED: u64 = 20;
const RUBBER_STAMP_THRESHOLD_BP: u64 = 9_800;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum NetworkLadderLevel {
    Unrestricted = 1,
    DomainAllowList = 2,
    ModelApiOnly = 3,
    NoExternalNetwork = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub enum ComputeLadderLevel {
    None = 1,
    Container = 2,
    Virtualization = 3,
    DedicatedHardware = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OversightDecisionOutcome {
    Approved,
    Modified,
    Denied,
    TimedOut,
    UnreachableDenied,
    Pending,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FiveEyesControlState {
    Covered,
    Missing,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightEventInput {
    pub rule_id: String,
    pub rule_class: String,
    pub queue: String,
    pub group_name: Option<String>,
    pub group_member_count: Option<usize>,
    pub min_grade: ApprovalGrade,
    pub effective_grade: ApprovalGrade,
    pub outcome: OversightDecisionOutcome,
    pub latency_ms: u64,
    pub pending_age_seconds: u64,
    pub has_written_justification: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightAssignment {
    pub rule_class: String,
    pub group: String,
    pub attested_on: String,
    pub attested_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct QueueLatencySummary {
    pub queue: String,
    pub median_latency_ms: u64,
    pub p95_latency_ms: u64,
    pub oldest_pending_seconds: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RuleClassOversightStats {
    pub rule_class: String,
    pub decided_count: u64,
    pub override_rate_bp: u64,
    pub unreachable_deny_share_bp: u64,
    pub timeout_share_bp: u64,
    pub grade_counts: BTreeMap<String, u64>,
    pub low_grade_ask_count: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OversightQualityReport {
    pub schema: String,
    pub organisation: String,
    pub quarter: String,
    pub generated_at: Timestamp,
    pub rule_class_stats: Vec<RuleClassOversightStats>,
    pub queue_latencies: Vec<QueueLatencySummary>,
    pub oversight_assignment_coverage_bp: u64,
    pub justification_coverage_bp: u64,
    pub rubber_stamp_flagged_rules: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentLadderSnapshot {
    pub agent_type: String,
    pub group: String,
    pub network_ladder: NetworkLadderLevel,
    pub compute_ladder: ComputeLadderLevel,
    pub assurance: AssuranceLevel,
    pub identity_mode: IdentityMode,
    pub signed_receipts_enforced: bool,
    pub kill_switch_ready: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NcscContainmentReport {
    pub schema: String,
    pub organisation: String,
    pub guidance_status: String,
    pub entries: Vec<AgentLadderSnapshot>,
    pub downgrade_findings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FiveEyesReport {
    pub schema: String,
    pub organisation: String,
    pub per_agent_identity: FiveEyesControlState,
    pub short_lived_credentials: FiveEyesControlState,
    pub approval_checkpoints: FiveEyesControlState,
    pub claim_vs_observation_crosscheck_bp: u64,
    pub crosscheck_source_status: String,
}

pub fn format_utc_quarter(ts: Timestamp) -> String {
    let dt = TimeZone::UTC.to_datetime(ts);
    let q = match dt.month() {
        1..=3 => 1,
        4..=6 => 2,
        7..=9 => 3,
        _ => 4,
    };
    format!("{}-Q{q}", dt.year())
}

pub fn compute_oversight_quality_report(
    organisation: &str,
    events: &[OversightEventInput],
    assignments: &[OversightAssignment],
    expected_rule_classes: &[String],
    now: Timestamp,
) -> Result<OversightQualityReport, ComplyError> {
    if organisation.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "organisation must be non-empty".into(),
        });
    }
    let mut group_sizes: BTreeMap<String, usize> = BTreeMap::new();
    for ev in events {
        let count = ev.group_member_count.unwrap_or(0);
        if count < MIN_GROUP_SIZE_FOR_DISCLOSURE {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: "q.oversight.report".into(),
                detail: format!(
                    "P8 forbids per-approver or small-group (<{MIN_GROUP_SIZE_FOR_DISCLOSURE}) oversight reporting"
                ),
            });
        }
        let gkey = ev
            .group_name
            .as_deref()
            .map(str::trim)
            .unwrap_or("")
            .to_ascii_lowercase();
        if let Some(prev_count) = group_sizes.get(&gkey) {
            if *prev_count != count {
                return Err(ComplyError::InvalidEvidenceQuery {
                    query_id: "q.oversight.report".into(),
                    detail: "P8 rejects inconsistent group_member_count within the same group"
                        .into(),
                });
            }
        } else {
            group_sizes.insert(gkey, count);
        }
    }
    if group_sizes.len() >= 2 {
        let total_members: usize = group_sizes
            .values()
            .fold(0_usize, |acc, v| acc.saturating_add(*v));
        for count in group_sizes.values() {
            let complement = total_members.saturating_sub(*count);
            if complement > 0 && complement < MIN_GROUP_SIZE_FOR_DISCLOSURE {
                return Err(ComplyError::InvalidEvidenceQuery {
                    query_id: "q.oversight.report".into(),
                    detail: format!(
                        "P8 difference-attack guard rejects reporting when complement cohort size ({complement}) is below {MIN_GROUP_SIZE_FOR_DISCLOSURE}"
                    ),
                });
            }
        }
    }

    let mut by_class: BTreeMap<String, Vec<&OversightEventInput>> = BTreeMap::new();
    let mut by_queue: BTreeMap<String, Vec<&OversightEventInput>> = BTreeMap::new();
    let mut by_rule: BTreeMap<String, (u64, u64)> = BTreeMap::new();
    let mut high_grade_total = 0_u64;
    let mut high_grade_justified = 0_u64;

    for ev in events {
        by_class.entry(ev.rule_class.clone()).or_default().push(ev);
        by_queue.entry(ev.queue.clone()).or_default().push(ev);
        let entry = by_rule.entry(ev.rule_id.clone()).or_insert((0, 0));
        if !matches!(ev.outcome, OversightDecisionOutcome::Pending) {
            entry.0 = entry.0.saturating_add(1);
            if matches!(ev.outcome, OversightDecisionOutcome::Approved) {
                entry.1 = entry.1.saturating_add(1);
            }
        }
        if matches!(ev.effective_grade, ApprovalGrade::G2 | ApprovalGrade::G3)
            && matches!(ev.outcome, OversightDecisionOutcome::Approved)
        {
            high_grade_total = high_grade_total.saturating_add(1);
            if ev.has_written_justification {
                high_grade_justified = high_grade_justified.saturating_add(1);
            }
        }
    }

    let mut rule_class_stats = Vec::with_capacity(by_class.len());
    for (rule_class, list) in by_class {
        rule_class_stats.push(summarize_rule_class(&rule_class, &list));
    }

    let mut queue_latencies = Vec::with_capacity(by_queue.len());
    for (queue, list) in by_queue {
        queue_latencies.push(summarize_queue(&queue, &list));
    }

    let mut rubber_stamp_flagged_rules = Vec::new();
    for (rule_id, (decided, approved)) in by_rule {
        if decided >= RUBBER_STAMP_MIN_DECIDED
            && approved.saturating_mul(10_000) >= decided.saturating_mul(RUBBER_STAMP_THRESHOLD_BP)
        {
            rubber_stamp_flagged_rules.push(rule_id);
        }
    }

    let assigned_classes: BTreeSet<&str> =
        assignments.iter().map(|a| a.rule_class.as_str()).collect();
    let expected_total = u64::try_from(expected_rule_classes.len()).unwrap_or(0);
    let covered_classes = u64::try_from(
        expected_rule_classes
            .iter()
            .filter(|c| assigned_classes.contains(c.as_str()))
            .count(),
    )
    .unwrap_or(0);
    let oversight_assignment_coverage_bp = share_bp(covered_classes, expected_total);
    let justification_coverage_bp = share_bp(high_grade_justified, high_grade_total);

    Ok(OversightQualityReport {
        schema: "grdr.comply.v1alpha1".into(),
        organisation: organisation.to_owned(),
        quarter: format_utc_quarter(now),
        generated_at: now,
        rule_class_stats,
        queue_latencies,
        oversight_assignment_coverage_bp,
        justification_coverage_bp,
        rubber_stamp_flagged_rules,
    })
}

pub fn evaluate_ncsc_containment(
    organisation: &str,
    previous: &[AgentLadderSnapshot],
    current: &[AgentLadderSnapshot],
) -> NcscContainmentReport {
    let mut findings = Vec::new();
    for cur in current {
        if let Some(prev) = previous
            .iter()
            .find(|p| p.agent_type == cur.agent_type && p.group == cur.group)
        {
            if cur.network_ladder < prev.network_ladder {
                findings.push(format!(
                    "NCSC finding: network containment ladder downgraded for `{}` ({}) from {:?} to {:?}",
                    cur.agent_type, cur.group, prev.network_ladder, cur.network_ladder
                ));
            }
            if cur.compute_ladder < prev.compute_ladder {
                findings.push(format!(
                    "NCSC finding: compute containment ladder downgraded for `{}` ({}) from {:?} to {:?}",
                    cur.agent_type, cur.group, prev.compute_ladder, cur.compute_ladder
                ));
            }
        }
    }
    NcscContainmentReport {
        schema: "grdr.comply.v1alpha1".into(),
        organisation: organisation.to_owned(),
        guidance_status: "Interim NCSC guidance (recommendations use modal 'should' criteria)"
            .into(),
        entries: current.to_vec(),
        downgrade_findings: findings,
    }
}

pub fn evaluate_five_eyes_report(
    organisation: &str,
    per_agent_identity: FiveEyesControlState,
    short_lived_credentials: FiveEyesControlState,
    approval_checkpoints: FiveEyesControlState,
    claimed_actions: u64,
    crosschecked_actions: u64,
) -> FiveEyesReport {
    FiveEyesReport {
        schema: "grdr.comply.v1alpha1".into(),
        organisation: organisation.to_owned(),
        per_agent_identity,
        short_lived_credentials,
        approval_checkpoints,
        claim_vs_observation_crosscheck_bp: share_bp(crosschecked_actions, claimed_actions),
        crosscheck_source_status:
            "single-sourced (secondary summary citation pending primary PDF clause verification)"
                .into(),
    }
}

pub fn render_oversight_markdown(report: &OversightQualityReport) -> String {
    let mut out = format!(
        "# Quarterly Oversight Quality Report ({} - {})\n\n- Assignment coverage: {} bp\n- Justification coverage (>=G2): {} bp\n- Rubber-stamp flags: {}\n",
        markdown_safe(&report.organisation),
        markdown_safe(&report.quarter),
        report.oversight_assignment_coverage_bp,
        report.justification_coverage_bp,
        if report.rubber_stamp_flagged_rules.is_empty() {
            "none".to_owned()
        } else {
            markdown_safe(&report.rubber_stamp_flagged_rules.join(", "))
        }
    );
    for st in &report.rule_class_stats {
        out.push_str(&format!(
            "- `{}`: decided={}, override={} bp, unreachable_deny={} bp, timeout={} bp\n",
            markdown_safe(&st.rule_class),
            st.decided_count,
            st.override_rate_bp,
            st.unreachable_deny_share_bp,
            st.timeout_share_bp
        ));
    }
    out
}

fn summarize_rule_class(
    rule_class: &str,
    list: &[&OversightEventInput],
) -> RuleClassOversightStats {
    let mut decided = 0_u64;
    let mut overridden = 0_u64;
    let mut ask_total = 0_u64;
    let mut unreachable_denied = 0_u64;
    let mut timed_out = 0_u64;
    let mut low_grade_ask = 0_u64;
    let mut grade_counts = BTreeMap::new();

    for ev in list {
        ask_total = ask_total.saturating_add(1);
        if matches!(ev.min_grade, ApprovalGrade::G0 | ApprovalGrade::G1) {
            low_grade_ask = low_grade_ask.saturating_add(1);
        }
        let grade_key = format!("{:?}", ev.effective_grade);
        let g = grade_counts.entry(grade_key).or_insert(0_u64);
        *g = g.saturating_add(1);

        match ev.outcome {
            OversightDecisionOutcome::Approved => decided = decided.saturating_add(1),
            OversightDecisionOutcome::Modified | OversightDecisionOutcome::Denied => {
                decided = decided.saturating_add(1);
                overridden = overridden.saturating_add(1);
            }
            OversightDecisionOutcome::UnreachableDenied => {
                unreachable_denied = unreachable_denied.saturating_add(1);
            }
            OversightDecisionOutcome::TimedOut => {
                timed_out = timed_out.saturating_add(1);
            }
            OversightDecisionOutcome::Pending => {}
        }
    }

    RuleClassOversightStats {
        rule_class: rule_class.to_owned(),
        decided_count: decided,
        override_rate_bp: share_bp(overridden, decided),
        unreachable_deny_share_bp: share_bp(unreachable_denied, ask_total),
        timeout_share_bp: share_bp(timed_out, ask_total),
        grade_counts,
        low_grade_ask_count: low_grade_ask,
    }
}

fn summarize_queue(queue: &str, list: &[&OversightEventInput]) -> QueueLatencySummary {
    let mut latencies: Vec<u64> = list
        .iter()
        .filter(|e| !matches!(e.outcome, OversightDecisionOutcome::Pending))
        .map(|e| e.latency_ms)
        .collect();
    latencies.sort_unstable();
    let oldest = list
        .iter()
        .map(|e| e.pending_age_seconds)
        .max()
        .unwrap_or(0);
    let median = percentile(&latencies, 50);
    let p95 = percentile(&latencies, 95);
    QueueLatencySummary {
        queue: queue.to_owned(),
        median_latency_ms: median,
        p95_latency_ms: p95,
        oldest_pending_seconds: oldest,
    }
}

fn percentile(sorted: &[u64], pct: usize) -> u64 {
    if sorted.is_empty() {
        return 0;
    }
    let idx = sorted
        .len()
        .saturating_sub(1)
        .saturating_mul(pct)
        .checked_div(100)
        .unwrap_or(0);
    sorted.get(idx).copied().unwrap_or(0)
}

fn share_bp(num: u64, den: u64) -> u64 {
    num.saturating_mul(10_000).checked_div(den).unwrap_or(0)
}
