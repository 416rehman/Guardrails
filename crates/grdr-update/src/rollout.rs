// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::UpdateError;
pub use crate::rollout_admission::{
    AdmissionDecision, DEFAULT_SELF_HOSTED_JITTER_HOURS, DEFAULT_SELF_HOSTED_MIN_DELAY_HOURS,
    ReleasePublishStatus, RingDefinition, SignedRolloutPlan, admit_device_at, default_canary_rings,
};
use crate::rollout_sketch::{
    CohortGateVerdict, CohortTelemetrySnapshot, HaltReason, RollbackDirective, RollbackTargetKind,
    RolloutGatePolicy, detect_gate_breach,
};
use crate::tuf_types::{
    RootMetadata, SignedMetadata, TufRole, YankReason, YankRecord, verify_role_signatures,
};

const SECONDS_PER_HOUR: i64 = 3_600;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RolloutScope {
    Project,
    Deployment,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HaltRollbackStatus {
    NotRequired,
    Pending,
    Applied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorResumeStatement {
    pub release_id: String,
    pub ring_index: u32,
    pub operator_id: String,
    pub note: String,
    pub issued_at: Timestamp,
    pub expires: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "phase", rename_all = "snake_case")]
pub enum RolloutPhase {
    Draft,
    RingBaking {
        ring_index: u32,
        started_at: Timestamp,
    },
    Halted {
        ring_index: u32,
        reason: HaltReason,
        halted_at: Timestamp,
        rollback_status: HaltRollbackStatus,
    },
    Complete {
        completed_at: Timestamp,
    },
    Superseded {
        by_release_id: String,
        yanked: Option<YankRecord>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "authorization", rename_all = "snake_case")]
pub enum ResumeAuthorization {
    OperatorApproval {
        approval: SignedMetadata<OperatorResumeStatement>,
    },
    SupersedingRelease {
        new_release_id: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutCoordinator {
    pub scope: RolloutScope,
    pub release_id: String,
    pub generation: u64,
    pub baseline_generation: u64,
    pub rings: Vec<RingDefinition>,
    pub gate_policy: RolloutGatePolicy,
    pub phase: RolloutPhase,
    pub yanks: Vec<YankRecord>,
}

impl RolloutCoordinator {
    pub fn new(
        release_id: impl Into<String>,
        generation: u64,
        baseline_generation: u64,
        rings: Vec<RingDefinition>,
        gate_policy: RolloutGatePolicy,
    ) -> Result<Self, UpdateError> {
        Self::new_for_scope(
            RolloutScope::Project,
            release_id,
            generation,
            baseline_generation,
            rings,
            gate_policy,
        )
    }

    pub fn new_for_scope(
        scope: RolloutScope,
        release_id: impl Into<String>,
        generation: u64,
        baseline_generation: u64,
        rings: Vec<RingDefinition>,
        gate_policy: RolloutGatePolicy,
    ) -> Result<Self, UpdateError> {
        if rings.is_empty() {
            return Err(UpdateError::MalformedMetadata(
                "rollout coordinator requires at least one ring".into(),
            ));
        }
        Ok(Self {
            scope,
            release_id: release_id.into(),
            generation,
            baseline_generation,
            rings,
            gate_policy,
            phase: RolloutPhase::Draft,
            yanks: Vec::new(),
        })
    }

    pub fn start_ring(&mut self, ring_index: u32, now: Timestamp) -> Result<(), UpdateError> {
        match &self.phase {
            RolloutPhase::Draft | RolloutPhase::RingBaking { .. } => {}
            RolloutPhase::Halted { reason, .. } => {
                return Err(UpdateError::HaltedRelease(format!(
                    "release {} halted ({reason:?}); manual resume required",
                    self.release_id
                )));
            }
            RolloutPhase::Complete { .. } | RolloutPhase::Superseded { .. } => {
                return Err(UpdateError::InvalidSlotTransition(
                    "cannot start ring on completed or superseded rollout".into(),
                ));
            }
        }
        if !self.rings.iter().any(|r| r.ring_index == ring_index) {
            return Err(UpdateError::TargetNotFound(format!("ring {ring_index}")));
        }
        self.phase = RolloutPhase::RingBaking {
            ring_index,
            started_at: now,
        };
        Ok(())
    }

    pub fn evaluate_cohort(
        &mut self,
        snapshot: &CohortTelemetrySnapshot,
        revert_target: RollbackTargetKind,
        now: Timestamp,
    ) -> Result<CohortGateVerdict, UpdateError> {
        let current_ring = match &self.phase {
            RolloutPhase::RingBaking { ring_index, .. } => *ring_index,
            RolloutPhase::Halted { reason, .. } => {
                return Err(UpdateError::HaltedRelease(format!(
                    "rollout already halted ({reason:?})"
                )));
            }
            RolloutPhase::Superseded { .. } => {
                return Err(UpdateError::HaltedRelease("rollout superseded".into()));
            }
            RolloutPhase::Draft | RolloutPhase::Complete { .. } => {
                return Err(UpdateError::InvalidSlotTransition(
                    "rollout is not currently baking a cohort ring".into(),
                ));
            }
        };

        snapshot.hook_latency.validate()?;
        let p99_hook_us = snapshot.hook_latency.quantile_us(9_900);
        if let Some((reason, detail)) = detect_gate_breach(&self.gate_policy, snapshot, p99_hook_us)
        {
            let rollback_required = matches!(
                reason,
                HaltReason::AgentStartFailure
                    | HaltReason::CrashRateExceeded
                    | HaltReason::CheckinLossExceeded
            );
            let rollback_status = if rollback_required {
                HaltRollbackStatus::Pending
            } else {
                HaltRollbackStatus::NotRequired
            };
            self.phase = RolloutPhase::Halted {
                ring_index: current_ring,
                reason,
                halted_at: now,
                rollback_status,
            };
            let rollback = rollback_required.then(|| RollbackDirective {
                target: revert_target,
                reason,
                release_id: self.release_id.clone(),
                revert_to_generation: self.baseline_generation,
            });
            return Ok(CohortGateVerdict {
                admitted: false,
                halt_reason: Some(reason),
                rollback,
                p99_hook_us,
                detail,
            });
        }

        Ok(CohortGateVerdict {
            admitted: true,
            halt_reason: None,
            rollback: None,
            p99_hook_us,
            detail: format!("ring {current_ring} within cohort gate thresholds"),
        })
    }

    pub fn advance_ring_if_baked(&mut self, now: Timestamp) -> Result<bool, UpdateError> {
        let (current_idx, started_at) = match &self.phase {
            RolloutPhase::RingBaking {
                ring_index,
                started_at,
            } => (*ring_index, *started_at),
            _ => {
                return Err(UpdateError::InvalidSlotTransition(
                    "rollout must be in RingBaking state to advance".into(),
                ));
            }
        };
        let Some(current_def) = self.rings.iter().find(|r| r.ring_index == current_idx) else {
            return Err(UpdateError::TargetNotFound(format!("ring {current_idx}")));
        };
        let bake_secs = i64::try_from(current_def.bake_hours)
            .unwrap_or(i64::MAX)
            .saturating_mul(SECONDS_PER_HOUR);
        if now.as_second().saturating_sub(started_at.as_second()) < bake_secs {
            return Ok(false);
        }
        let next_ring = self
            .rings
            .iter()
            .filter(|r| r.ring_index > current_idx)
            .min_by_key(|r| r.ring_index);
        if let Some(next) = next_ring {
            self.phase = RolloutPhase::RingBaking {
                ring_index: next.ring_index,
                started_at: now,
            };
        } else {
            self.phase = RolloutPhase::Complete { completed_at: now };
        }
        Ok(true)
    }

    pub fn confirm_rollback_applied(&mut self) -> Result<(), UpdateError> {
        let RolloutPhase::Halted {
            rollback_status, ..
        } = &mut self.phase
        else {
            return Err(UpdateError::InvalidSlotTransition(
                "confirm_rollback_applied requires Halted rollout phase".into(),
            ));
        };
        if *rollback_status == HaltRollbackStatus::Pending {
            *rollback_status = HaltRollbackStatus::Applied;
        }
        Ok(())
    }

    pub fn resume_after_halt(
        &mut self,
        auth: ResumeAuthorization,
        authority_root: Option<&RootMetadata>,
        now: Timestamp,
    ) -> Result<(), UpdateError> {
        let RolloutPhase::Halted {
            ring_index,
            rollback_status,
            ..
        } = &self.phase
        else {
            return Err(UpdateError::InvalidSlotTransition(
                "rollout is not in Halted state".into(),
            ));
        };
        let ring = *ring_index;
        let rb_status = *rollback_status;
        match auth {
            ResumeAuthorization::OperatorApproval { approval } => {
                if self.scope == RolloutScope::Project {
                    return Err(UpdateError::UnauthorizedRoot(
                        "OperatorApproval cannot override project-scoped ring halt; issue a SupersedingRelease"
                            .into(),
                    ));
                }
                if rb_status == HaltRollbackStatus::Pending {
                    return Err(UpdateError::HaltedRelease(
                        "unresolved rollback_required halt must apply rollback before operator resume"
                            .into(),
                    ));
                }
                verify_signed_resume_approval(
                    &self.release_id,
                    ring,
                    &approval,
                    authority_root,
                    now,
                )?;
                self.phase = RolloutPhase::RingBaking {
                    ring_index: ring,
                    started_at: now,
                };
            }
            ResumeAuthorization::SupersedingRelease { new_release_id } => {
                if new_release_id.trim().is_empty() || new_release_id == self.release_id {
                    return Err(UpdateError::MalformedMetadata(
                        "superseding release id must be distinct and non-empty".into(),
                    ));
                }
                self.phase = RolloutPhase::Superseded {
                    by_release_id: new_release_id,
                    yanked: None,
                };
            }
        }
        Ok(())
    }

    pub fn yank_release(
        &mut self,
        pack_id: impl Into<String>,
        version: impl Into<String>,
        sha256: impl Into<String>,
        reason: YankReason,
        replacement: Option<(String, String)>,
        now: Timestamp,
    ) -> YankRecord {
        let (replacement_version, replacement_sha256) = match replacement {
            Some((v, s)) => (Some(v), Some(s)),
            None => (None, None),
        };
        let record = YankRecord {
            pack_id: pack_id.into(),
            version: version.into(),
            sha256: sha256.into(),
            reason,
            issued_at: now,
            replacement_version: replacement_version.clone(),
            replacement_sha256,
        };
        self.yanks.push(record.clone());
        let superseded_by = replacement_version.unwrap_or_else(|| "withdrawn".into());
        self.phase = RolloutPhase::Superseded {
            by_release_id: superseded_by,
            yanked: Some(record.clone()),
        };
        record
    }

    #[must_use]
    pub fn to_signed_plan(
        &self,
        open_at: Timestamp,
        ramp_window_secs: u64,
        rate_scale_bps: u32,
    ) -> SignedRolloutPlan {
        let (publish_status, active_ring_index, halted_reason, yanked) = match &self.phase {
            RolloutPhase::Draft => (ReleasePublishStatus::Draft, 0, None, None),
            RolloutPhase::RingBaking { ring_index, .. } => {
                (ReleasePublishStatus::Active, *ring_index, None, None)
            }
            RolloutPhase::Halted {
                ring_index, reason, ..
            } => (
                ReleasePublishStatus::Halted,
                *ring_index,
                Some(format!("{reason:?}")),
                None,
            ),
            RolloutPhase::Complete { .. } => {
                let last = self.rings.iter().map(|r| r.ring_index).max().unwrap_or(0);
                (ReleasePublishStatus::Complete, last, None, None)
            }
            RolloutPhase::Superseded { yanked, .. } => (
                ReleasePublishStatus::Withdrawn,
                0,
                Some("release yanked or superseded".into()),
                yanked.clone(),
            ),
        };
        SignedRolloutPlan {
            release_id: self.release_id.clone(),
            generation: self.generation,
            open_at,
            ramp_window_secs,
            rate_scale_bps,
            self_hosted_min_delay_hours: DEFAULT_SELF_HOSTED_MIN_DELAY_HOURS,
            self_hosted_jitter_hours: DEFAULT_SELF_HOSTED_JITTER_HOURS,
            active_ring_index,
            rings: self.rings.clone(),
            publish_status,
            halted_reason,
            yanked,
        }
    }
}

fn verify_signed_resume_approval(
    release_id: &str,
    ring_index: u32,
    approval: &SignedMetadata<OperatorResumeStatement>,
    authority_root: Option<&RootMetadata>,
    now: Timestamp,
) -> Result<(), UpdateError> {
    let Some(root) = authority_root else {
        return Err(UpdateError::UnauthorizedRoot(
            "signed operator approval requires verified authority root".into(),
        ));
    };
    if root.expires <= now {
        return Err(UpdateError::MetadataExpired {
            role: "operator_resume::root".into(),
            expired_at: root.expires.to_string(),
        });
    }
    let role = if root.roles.contains_key(&TufRole::Fleet) {
        TufRole::Fleet
    } else {
        TufRole::Rollout
    };
    verify_role_signatures(root, role, approval)?;
    let stmt = &approval.signed;
    if stmt.expires <= now {
        return Err(UpdateError::MetadataExpired {
            role: "operator_resume::approval".into(),
            expired_at: stmt.expires.to_string(),
        });
    }
    if stmt.operator_id.trim().is_empty()
        || stmt.note.trim().is_empty()
        || stmt.release_id != release_id
        || stmt.ring_index != ring_index
    {
        return Err(UpdateError::UnauthorizedRoot(
            "signed operator resume statement does not match halted release or ring".into(),
        ));
    }
    Ok(())
}
