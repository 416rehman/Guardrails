// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::UpdateError;

pub const BPS_DENOM: u32 = 10_000;
pub const DDSKETCH_MAX_BUCKETS: usize = 512;
pub const DDSKETCH_MAX_BUCKET_INDEX: i32 = 500;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaltReason {
    CrashRateExceeded,
    CheckinLossExceeded,
    CpuBudgetExceeded,
    MemoryBudgetExceeded,
    DenyRateSpike,
    HookLatencyExceeded,
    AgentStartFailure,
    VolumeSpike,
    ManualOperatorHalt,
    ReleaseYanked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RollbackTargetKind {
    BinarySlot,
    AgentConfigJournal,
    ContentPackChannel,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RollbackDirective {
    pub target: RollbackTargetKind,
    pub reason: HaltReason,
    pub release_id: String,
    pub revert_to_generation: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutGatePolicy {
    pub min_crash_free_bps: u32,
    pub max_crash_regression_bps: u32,
    pub max_checkin_loss_bps: u32,
    pub max_cpu_increase_bps: u32,
    pub max_memory_increase_bps: u32,
    pub max_deny_rate_delta_bps: u32,
    pub max_hook_p99_us: u64,
    pub max_volume_spike_bps: u32,
    pub halt_on_agent_start_failure: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LatencyDdSketch {
    pub total_count: u64,
    pub min_us: u64,
    pub max_us: u64,
    pub buckets: BTreeMap<i32, u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortTelemetrySnapshot {
    pub baseline_crash_free_bps: u32,
    pub cohort_crash_free_bps: u32,
    pub checkin_loss_bps: u32,
    pub baseline_cpu_milli: u64,
    pub cohort_cpu_milli: u64,
    pub baseline_mem_mib: u64,
    pub cohort_mem_mib: u64,
    pub baseline_deny_bps: u32,
    pub cohort_deny_bps: u32,
    pub baseline_events_per_min: u64,
    pub cohort_events_per_min: u64,
    pub agent_start_failures: u64,
    pub hook_latency: LatencyDdSketch,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CohortGateVerdict {
    pub admitted: bool,
    pub halt_reason: Option<HaltReason>,
    pub rollback: Option<RollbackDirective>,
    pub p99_hook_us: u64,
    pub detail: String,
}

impl Default for RolloutGatePolicy {
    fn default() -> Self {
        Self {
            min_crash_free_bps: 9_990,
            max_crash_regression_bps: 5,
            max_checkin_loss_bps: 100,
            max_cpu_increase_bps: 2_500,
            max_memory_increase_bps: 2_000,
            max_deny_rate_delta_bps: 50,
            max_hook_p99_us: 5_000,
            max_volume_spike_bps: 5_000,
            halt_on_agent_start_failure: true,
        }
    }
}

impl LatencyDdSketch {
    #[must_use]
    pub fn new() -> Self {
        Self {
            total_count: 0,
            min_us: u64::MAX,
            max_us: 0,
            buckets: BTreeMap::new(),
        }
    }

    pub fn record_us(&mut self, value_us: u64) -> Result<(), UpdateError> {
        let bucket = ddsketch_bucket_index(value_us);
        if !self.buckets.contains_key(&bucket) && self.buckets.len() >= DDSKETCH_MAX_BUCKETS {
            return Err(UpdateError::MalformedMetadata(
                "DDSketch bucket cap exceeded".into(),
            ));
        }
        let entry = self.buckets.entry(bucket).or_insert(0);
        *entry = entry.saturating_add(1);
        self.total_count = self.total_count.saturating_add(1);
        self.min_us = self.min_us.min(value_us);
        self.max_us = self.max_us.max(value_us);
        Ok(())
    }

    pub fn validate(&self) -> Result<(), UpdateError> {
        if self.buckets.len() > DDSKETCH_MAX_BUCKETS {
            return Err(UpdateError::MalformedMetadata(
                "DDSketch bucket count exceeds cap".into(),
            ));
        }
        let mut sum: u64 = 0;
        for (&bucket, &count) in &self.buckets {
            if !(0..=DDSKETCH_MAX_BUCKET_INDEX).contains(&bucket) {
                return Err(UpdateError::MalformedMetadata(format!(
                    "DDSketch bucket index {bucket} out of range 0..={DDSKETCH_MAX_BUCKET_INDEX}"
                )));
            }
            sum = sum.checked_add(count).ok_or_else(|| {
                UpdateError::MalformedMetadata("DDSketch bucket sum overflow".into())
            })?;
        }
        if sum != self.total_count {
            return Err(UpdateError::MalformedMetadata(format!(
                "DDSketch total_count {} != bucket sum {sum}",
                self.total_count
            )));
        }
        Ok(())
    }

    pub fn merge(&mut self, other: &Self) -> Result<(), UpdateError> {
        self.validate()?;
        other.validate()?;
        if other.total_count == 0 {
            return Ok(());
        }
        for (&bucket, &count) in &other.buckets {
            if !self.buckets.contains_key(&bucket) && self.buckets.len() >= DDSKETCH_MAX_BUCKETS {
                return Err(UpdateError::MalformedMetadata(
                    "DDSketch merge exceeded bucket cap".into(),
                ));
            }
            let slot = self.buckets.entry(bucket).or_insert(0);
            *slot = slot.saturating_add(count);
        }
        self.total_count = self.total_count.saturating_add(other.total_count);
        self.min_us = self.min_us.min(other.min_us);
        self.max_us = self.max_us.max(other.max_us);
        Ok(())
    }

    #[must_use]
    pub fn quantile_us(&self, quantile_bps: u32) -> u64 {
        let effective_total = self
            .buckets
            .iter()
            .filter(|(k, _)| (0..=DDSKETCH_MAX_BUCKET_INDEX).contains(k))
            .fold(0u64, |acc, (_, &c)| acc.saturating_add(c));
        if effective_total == 0 {
            return 0;
        }
        let clamped_bps = u64::from(quantile_bps.min(BPS_DENOM));
        let denom = u64::from(BPS_DENOM);
        let rank = effective_total
            .saturating_mul(clamped_bps)
            .saturating_add(denom.saturating_sub(1))
            .checked_div(denom)
            .unwrap_or(effective_total);
        let mut seen: u64 = 0;
        for (&bucket, &count) in &self.buckets {
            if !(0..=DDSKETCH_MAX_BUCKET_INDEX).contains(&bucket) {
                continue;
            }
            seen = seen.saturating_add(count);
            if seen >= rank {
                return ddsketch_bucket_upper_us(bucket).min(self.max_us);
            }
        }
        self.max_us
    }
}

impl Default for LatencyDdSketch {
    fn default() -> Self {
        Self::new()
    }
}

pub(crate) fn detect_gate_breach(
    policy: &RolloutGatePolicy,
    snap: &CohortTelemetrySnapshot,
    p99_hook_us: u64,
) -> Option<(HaltReason, String)> {
    if policy.halt_on_agent_start_failure && snap.agent_start_failures > 0 {
        return Some((
            HaltReason::AgentStartFailure,
            format!(
                "{} agent-start failures observed",
                snap.agent_start_failures
            ),
        ));
    }
    if snap.cohort_crash_free_bps < policy.min_crash_free_bps
        || snap
            .baseline_crash_free_bps
            .saturating_sub(snap.cohort_crash_free_bps)
            > policy.max_crash_regression_bps
    {
        return Some((
            HaltReason::CrashRateExceeded,
            format!(
                "crash-free {} bps breached floor {} or baseline {}",
                snap.cohort_crash_free_bps, policy.min_crash_free_bps, snap.baseline_crash_free_bps
            ),
        ));
    }
    if snap.checkin_loss_bps > policy.max_checkin_loss_bps {
        return Some((
            HaltReason::CheckinLossExceeded,
            format!(
                "check-in loss {} bps > {}",
                snap.checkin_loss_bps, policy.max_checkin_loss_bps
            ),
        ));
    }
    if exceeds_increase_bps(
        snap.baseline_cpu_milli,
        snap.cohort_cpu_milli,
        policy.max_cpu_increase_bps,
    ) {
        return Some((
            HaltReason::CpuBudgetExceeded,
            format!(
                "CPU {} > baseline {}",
                snap.cohort_cpu_milli, snap.baseline_cpu_milli
            ),
        ));
    }
    if exceeds_increase_bps(
        snap.baseline_mem_mib,
        snap.cohort_mem_mib,
        policy.max_memory_increase_bps,
    ) {
        return Some((
            HaltReason::MemoryBudgetExceeded,
            format!(
                "memory {} > baseline {}",
                snap.cohort_mem_mib, snap.baseline_mem_mib
            ),
        ));
    }
    let deny_delta = snap.cohort_deny_bps.saturating_sub(snap.baseline_deny_bps);
    if deny_delta > policy.max_deny_rate_delta_bps {
        return Some((
            HaltReason::DenyRateSpike,
            format!(
                "deny delta {deny_delta} bps > {}",
                policy.max_deny_rate_delta_bps
            ),
        ));
    }
    if p99_hook_us > policy.max_hook_p99_us {
        return Some((
            HaltReason::HookLatencyExceeded,
            format!("hook p99 {p99_hook_us}us > {}us", policy.max_hook_p99_us),
        ));
    }
    if exceeds_increase_bps(
        snap.baseline_events_per_min,
        snap.cohort_events_per_min,
        policy.max_volume_spike_bps,
    ) {
        return Some((
            HaltReason::VolumeSpike,
            format!(
                "event rate {} > baseline {}",
                snap.cohort_events_per_min, snap.baseline_events_per_min
            ),
        ));
    }
    None
}

fn exceeds_increase_bps(baseline: u64, cohort: u64, max_increase_bps: u32) -> bool {
    if baseline == 0 || cohort <= baseline {
        return false;
    }
    let delta = cohort.saturating_sub(baseline);
    let max_delta = baseline
        .saturating_mul(u64::from(max_increase_bps))
        .checked_div(u64::from(BPS_DENOM))
        .unwrap_or(u64::MAX);
    delta > max_delta
}

fn ddsketch_bucket_index(value_us: u64) -> i32 {
    if value_us == 0 {
        return 0;
    }
    let mut bound: u64 = 1;
    let mut idx: i32 = 1;
    while bound < value_us && idx < 500 {
        let step = bound.checked_div(16).unwrap_or(0).max(1);
        bound = bound.saturating_add(step);
        idx = idx.saturating_add(1);
    }
    idx
}

fn ddsketch_bucket_upper_us(bucket: i32) -> u64 {
    if bucket <= 0 {
        return 0;
    }
    let clamped = bucket.clamp(0, DDSKETCH_MAX_BUCKET_INDEX);
    let mut bound: u64 = 1;
    let mut idx: i32 = 1;
    while idx < clamped {
        let step = bound.checked_div(16).unwrap_or(0).max(1);
        bound = bound.saturating_add(step);
        idx = idx.saturating_add(1);
    }
    bound
}
