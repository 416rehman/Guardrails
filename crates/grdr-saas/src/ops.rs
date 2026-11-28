// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::config::SaasOperationalBounds;
use crate::framing::ensure_clean_token;
use crate::{CODE_SAAS_INVALID_INPUT, CODE_SAAS_OPS_BOUND_EXCEEDED, saas_error};

const SECONDS_PER_DAY: i64 = 86_400;
const SECONDS_PER_MINUTE: i64 = 60;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RunbookActor {
    pub operator_id: String,
    pub ticket_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpsBounds {
    pub max_blast_radius_pct: u8,
    pub max_concurrent_regions: u8,
    pub cooldown_minutes: u32,
    pub min_gross_margin_bps: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChangeFreezeWindow {
    pub label: String,
    pub start_s: i64,
    pub end_s: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaintenanceStep {
    pub runbook_id: String,
    pub region: String,
    pub blast_radius_pct: u8,
    pub scheduled_at_s: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StepAuditRecord {
    pub runbook_id: String,
    pub region: String,
    pub operator_id: String,
    pub ticket_id: String,
    pub executed_at_s: i64,
    pub blast_radius_pct: u8,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct OperationsRunner {
    bounds: OpsBounds,
    freezes: Vec<ChangeFreezeWindow>,
    active_regions: BTreeSet<String>,
    cooldown_until_s: BTreeMap<String, i64>,
    audit_log: Vec<StepAuditRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum TenantLifecycleState {
    Active,
    PastDue { since_day: u16 },
    Suspended { reason: String },
    PendingErasure { delete_after: Timestamp },
    Erased,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantLifecycleRecord {
    org_id: OrgId,
    state: TenantLifecycleState,
    legal_hold_active: bool,
    updated_at: Timestamp,
}

impl OpsBounds {
    pub fn from_embedded() -> Result<Self, CodedError> {
        let embedded = SaasOperationalBounds::load_embedded()?;
        Ok(Self::from_saas_bounds(&embedded))
    }

    #[must_use]
    pub fn from_saas_bounds(bounds: &SaasOperationalBounds) -> Self {
        Self {
            max_blast_radius_pct: bounds.max_blast_radius_pct,
            max_concurrent_regions: bounds.max_concurrent_regions,
            cooldown_minutes: bounds.cooldown_minutes,
            min_gross_margin_bps: bounds.min_gross_margin_bps,
        }
    }

    pub fn validate(&self) -> Result<(), CodedError> {
        if self.max_blast_radius_pct > 100 || self.max_concurrent_regions == 0 {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "OpsBounds require max_blast_radius_pct <= 100 and max_concurrent_regions >= 1.",
                "Adjust bounds configuration in docs/ops/bounds.toml.",
            ));
        }
        Ok(())
    }
}

impl OperationsRunner {
    pub fn try_new(
        bounds: OpsBounds,
        freezes: Vec<ChangeFreezeWindow>,
    ) -> Result<Self, CodedError> {
        bounds.validate()?;
        for freeze in &freezes {
            ensure_clean_token("freeze.label", &freeze.label)?;
            if freeze.start_s > freeze.end_s {
                return Err(saas_error(
                    CODE_SAAS_INVALID_INPUT,
                    format!("Change freeze `{}` start_s exceeds end_s.", freeze.label),
                    "Ensure start_s <= end_s for every freeze window.",
                ));
            }
        }
        Ok(Self {
            bounds,
            freezes,
            active_regions: BTreeSet::new(),
            cooldown_until_s: BTreeMap::new(),
            audit_log: Vec::new(),
        })
    }

    #[must_use]
    pub fn audit_log(&self) -> &[StepAuditRecord] {
        &self.audit_log
    }

    pub fn execute_step(
        &mut self,
        actor: &RunbookActor,
        step: &MaintenanceStep,
    ) -> Result<StepAuditRecord, CodedError> {
        ensure_clean_token("actor.operator_id", &actor.operator_id)?;
        ensure_clean_token("actor.ticket_id", &actor.ticket_id)?;
        ensure_clean_token("actor.reason", &actor.reason)?;
        ensure_clean_token("step.runbook_id", &step.runbook_id)?;
        ensure_clean_token("step.region", &step.region)?;

        if step.blast_radius_pct > self.bounds.max_blast_radius_pct {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                format!(
                    "Step blast radius {}% exceeds bound {}%.",
                    step.blast_radius_pct, self.bounds.max_blast_radius_pct
                ),
                "Split rollout batches within bounds.toml limits.",
            ));
        }
        for freeze in &self.freezes {
            if step.scheduled_at_s >= freeze.start_s && step.scheduled_at_s <= freeze.end_s {
                return Err(saas_error(
                    CODE_SAAS_OPS_BOUND_EXCEEDED,
                    format!(
                        "Maintenance blocked by active change freeze `{}`.",
                        freeze.label
                    ),
                    "Reschedule outside the declared change-freeze window.",
                ));
            }
        }
        if let Some(until_s) = self.cooldown_until_s.get(&step.region)
            && step.scheduled_at_s < *until_s
        {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                format!(
                    "Region `{}` is in maintenance cooldown until epoch {until_s}.",
                    step.region
                ),
                "Wait for cooldown_minutes to elapse before starting another batch.",
            ));
        }
        let max_regions = usize::from(self.bounds.max_concurrent_regions);
        if !self.active_regions.contains(&step.region) && self.active_regions.len() >= max_regions {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                format!(
                    "Region concurrency cap ({}) reached; cannot operate on `{}` concurrently.",
                    self.bounds.max_concurrent_regions, step.region
                ),
                "Complete or release the active region window first.",
            ));
        }

        self.active_regions.insert(step.region.clone());
        let record = StepAuditRecord {
            runbook_id: step.runbook_id.clone(),
            region: step.region.clone(),
            operator_id: actor.operator_id.clone(),
            ticket_id: actor.ticket_id.clone(),
            executed_at_s: step.scheduled_at_s,
            blast_radius_pct: step.blast_radius_pct,
        };
        self.audit_log.push(record.clone());
        Ok(record)
    }

    pub fn complete_region(&mut self, region: &str, completed_at_s: i64) -> Result<(), CodedError> {
        ensure_clean_token("region", region)?;
        self.active_regions.remove(region);
        let cooldown_s = i64::from(self.bounds.cooldown_minutes)
            .checked_mul(SECONDS_PER_MINUTE)
            .ok_or_else(|| {
                saas_error(
                    CODE_SAAS_OPS_BOUND_EXCEEDED,
                    "Configured cooldown_minutes overflowed seconds conversion.",
                    "Reduce cooldown_minutes within valid i64 range.",
                )
            })?;
        let until_s = completed_at_s.checked_add(cooldown_s).ok_or_else(|| {
            saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Region cooldown watermark overflowed timestamp range.",
                "Provide a valid completion epoch.",
            )
        })?;
        self.cooldown_until_s.insert(region.to_owned(), until_s);
        Ok(())
    }
}

impl TenantLifecycleRecord {
    #[must_use]
    pub fn active(org_id: OrgId, now: Timestamp) -> Self {
        Self {
            org_id,
            state: TenantLifecycleState::Active,
            legal_hold_active: false,
            updated_at: now,
        }
    }

    #[must_use]
    pub fn org_id(&self) -> &OrgId {
        &self.org_id
    }

    #[must_use]
    pub fn state(&self) -> &TenantLifecycleState {
        &self.state
    }

    #[must_use]
    pub fn legal_hold_active(&self) -> bool {
        self.legal_hold_active
    }

    #[must_use]
    pub fn updated_at(&self) -> Timestamp {
        self.updated_at
    }

    pub fn set_legal_hold(&mut self, active: bool, now: Timestamp) -> Result<(), CodedError> {
        if matches!(self.state, TenantLifecycleState::Erased) {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Cannot change legal hold on an already erased tenant.",
                "Tenant keys have already been purged.",
            ));
        }
        self.legal_hold_active = active;
        self.updated_at = now;
        Ok(())
    }

    #[must_use]
    pub fn local_enforcement_active(&self) -> bool {
        // Endpoints remain protected during billing dunning or suspension.
        !matches!(self.state, TenantLifecycleState::Erased)
    }

    pub fn advance_dunning(
        &mut self,
        days_past_due: u16,
        now: Timestamp,
        bounds: &SaasOperationalBounds,
    ) -> Result<(), CodedError> {
        bounds.validate()?;
        if matches!(
            self.state,
            TenantLifecycleState::PendingErasure { .. } | TenantLifecycleState::Erased
        ) {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Cannot transition a pending-erasure or erased tenant via billing dunning.",
                "Use an explicit legal hold or erasure cancellation path before restoring access.",
            ));
        }
        self.updated_at = now;
        if days_past_due == 0 {
            self.state = TenantLifecycleState::Active;
        } else if days_past_due <= bounds.payment_retry_days {
            self.state = TenantLifecycleState::PastDue {
                since_day: days_past_due,
            };
        } else {
            self.state = TenantLifecycleState::Suspended {
                reason: format!("past_due_over_{}_days", bounds.payment_retry_days),
            };
        }
        Ok(())
    }

    pub fn schedule_erasure(
        &mut self,
        now: Timestamp,
        bounds: &SaasOperationalBounds,
    ) -> Result<(), CodedError> {
        bounds.validate()?;
        if self.legal_hold_active {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                format!(
                    "Cannot erase tenant `{}` while a legal hold is active.",
                    self.org_id.as_str()
                ),
                "Release legal hold under counsel sign-off before scheduling erasure.",
            ));
        }
        if matches!(
            self.state,
            TenantLifecycleState::PendingErasure { .. } | TenantLifecycleState::Erased
        ) {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Tenant is already pending erasure or erased.",
                "Avoid resetting existing erasure deadlines.",
            ));
        }
        let retention_s = bounds
            .erasure_retention_days
            .checked_mul(SECONDS_PER_DAY)
            .ok_or_else(|| {
                saas_error(
                    CODE_SAAS_OPS_BOUND_EXCEEDED,
                    "Erasure retention duration overflowed seconds conversion.",
                    "Verify erasure_cancel_window_days in contracts/limits.toml.",
                )
            })?;
        let delete_after_s = now.as_second().checked_add(retention_s).ok_or_else(|| {
            saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Erasure deadline timestamp overflowed.",
                "Verify system clock and erasure retention bounds.",
            )
        })?;
        let delete_after = Timestamp::from_second(delete_after_s).map_err(|_| {
            saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Erasure deadline exceeds valid Timestamp range.",
                "Clamp erasure_cancel_window_days within Timestamp bounds.",
            )
        })?;
        self.state = TenantLifecycleState::PendingErasure { delete_after };
        self.updated_at = now;
        Ok(())
    }

    pub fn finalize_erasure(&mut self, now: Timestamp) -> Result<(), CodedError> {
        if self.legal_hold_active {
            return Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                format!(
                    "Legal hold prevents erasure finalization for `{}`.",
                    self.org_id.as_str()
                ),
                "Preserve evidence keys until hold clears.",
            ));
        }
        match self.state {
            TenantLifecycleState::PendingErasure { delete_after } if now >= delete_after => {
                self.state = TenantLifecycleState::Erased;
                self.updated_at = now;
                Ok(())
            }
            _ => Err(saas_error(
                CODE_SAAS_OPS_BOUND_EXCEEDED,
                "Tenant erasure grace period has not elapsed.",
                "Wait until delete_after watermark before cryptographic key destruction.",
            )),
        }
    }
}
