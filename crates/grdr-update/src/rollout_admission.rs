// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::sha256_digest;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::rollout_sketch::BPS_DENOM;
use crate::tuf_types::YankRecord;

pub const DEFAULT_SELF_HOSTED_MIN_DELAY_HOURS: u64 = 48;
pub const DEFAULT_SELF_HOSTED_JITTER_HOURS: u64 = 24;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReleasePublishStatus {
    Draft,
    Active,
    Halted,
    Complete,
    Withdrawn,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum AdmissionDecision {
    Admitted {
        ring_index: u32,
        scheduled_at: Timestamp,
    },
    Deferred {
        ring_index: u32,
        not_before: Timestamp,
    },
    Held {
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RingDefinition {
    pub ring_index: u32,
    pub name: String,
    pub population_fraction_bps: u32,
    pub bake_hours: u64,
    pub ramp_window_secs: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedRolloutPlan {
    pub release_id: String,
    pub generation: u64,
    pub open_at: Timestamp,
    pub ramp_window_secs: u64,
    pub rate_scale_bps: u32,
    pub self_hosted_min_delay_hours: u64,
    pub self_hosted_jitter_hours: u64,
    pub active_ring_index: u32,
    pub rings: Vec<RingDefinition>,
    pub publish_status: ReleasePublishStatus,
    pub halted_reason: Option<String>,
    pub yanked: Option<YankRecord>,
}

#[must_use]
pub fn default_canary_rings() -> Vec<RingDefinition> {
    vec![
        RingDefinition {
            ring_index: 0,
            name: "ring-0-canary".into(),
            population_fraction_bps: 100,
            bake_hours: 12,
            ramp_window_secs: 3_600,
        },
        RingDefinition {
            ring_index: 1,
            name: "ring-1-early".into(),
            population_fraction_bps: 1_000,
            bake_hours: 24,
            ramp_window_secs: 14_400,
        },
        RingDefinition {
            ring_index: 2,
            name: "ring-2-broad".into(),
            population_fraction_bps: BPS_DENOM,
            bake_hours: 48,
            ramp_window_secs: 43_200,
        },
    ]
}

#[must_use]
pub fn admit_device_at(
    device_id: &str,
    plan: &SignedRolloutPlan,
    is_self_hosted: bool,
    deployment_id: &str,
    now: Timestamp,
) -> AdmissionDecision {
    match plan.publish_status {
        ReleasePublishStatus::Active | ReleasePublishStatus::Complete => {}
        ReleasePublishStatus::Draft => {
            return AdmissionDecision::Held {
                reason: "rollout plan is still draft".into(),
            };
        }
        ReleasePublishStatus::Halted => {
            return AdmissionDecision::Held {
                reason: plan
                    .halted_reason
                    .clone()
                    .unwrap_or_else(|| "rollout halted".into()),
            };
        }
        ReleasePublishStatus::Withdrawn => {
            return AdmissionDecision::Held {
                reason: "release withdrawn".into(),
            };
        }
    }
    if plan.rate_scale_bps == 0 {
        return AdmissionDecision::Held {
            reason: "rollout rate_scale paused at zero".into(),
        };
    }

    let device_bucket = deterministic_bucket_bps(device_id, &plan.release_id);
    let denom = u64::from(BPS_DENOM);
    let effective_ramp = plan
        .ramp_window_secs
        .saturating_mul(denom)
        .checked_div(u64::from(plan.rate_scale_bps))
        .unwrap_or(plan.ramp_window_secs);
    let ramp_offset_secs = effective_ramp
        .saturating_mul(u64::from(device_bucket))
        .checked_div(denom)
        .unwrap_or(0);

    let self_hosted_delay_secs = if is_self_hosted {
        let min_delay = plan.self_hosted_min_delay_hours.saturating_mul(3_600);
        let spread_mod = plan.self_hosted_jitter_hours.saturating_mul(3_600);
        let dep_spread = deterministic_u64(deployment_id, &plan.release_id)
            .checked_rem(spread_mod)
            .unwrap_or(0);
        min_delay.saturating_add(dep_spread)
    } else {
        0
    };

    let total_delay =
        i64::try_from(ramp_offset_secs.saturating_add(self_hosted_delay_secs)).unwrap_or(i64::MAX);
    let scheduled_sec = plan.open_at.as_second().saturating_add(total_delay);
    let scheduled_at = Timestamp::from_second(scheduled_sec).unwrap_or(plan.open_at);
    if now >= scheduled_at {
        AdmissionDecision::Admitted {
            ring_index: plan.active_ring_index,
            scheduled_at,
        }
    } else {
        AdmissionDecision::Deferred {
            ring_index: plan.active_ring_index,
            not_before: scheduled_at,
        }
    }
}

fn deterministic_bucket_bps(subject_id: &str, release_id: &str) -> u32 {
    let denom = u64::from(BPS_DENOM);
    let val = deterministic_u64(subject_id, release_id)
        .checked_rem(denom)
        .unwrap_or(0);
    u32::try_from(val).unwrap_or(0)
}

fn deterministic_u64(subject_id: &str, release_id: &str) -> u64 {
    let input = format!("{subject_id}:{release_id}");
    let digest = sha256_digest(input.as_bytes());
    let mut head = [0u8; 8];
    for (dst, src) in head.iter_mut().zip(digest.iter()) {
        *dst = *src;
    }
    u64::from_le_bytes(head)
}
