// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Response action executor with mode ladder gating, strict verb allowlists, and fleet blast-radius circuit breakers (`D-09`, `D-55`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_model::Mode;
use grdr_schema::limits::load_embedded_limits;

pub use crate::detect::kill_switch::{
    ActiveKillEntry, ActuatorDeliveryForm, ApprovalOutcomeSignal, DeviceContainmentStage,
    GranularKillSwitchState, KillSwitchApplyRequest, KillSwitchScope, compute_preview_rollup,
};
use crate::detect::types::{
    DetectError, FindingCeiling, ResponseBinding, ResponseExecutionMode, TriggeredResponseIntent,
};

pub const DEFAULT_MAX_SHARE_BP: u16 = 500;
const ONE_HOUR_SECS: i64 = 3_600;
const MAX_BREAKER_RULES: usize = 1_024;

const RECORD_NOTIFY_VERBS: &[&str] = &["capture-evidence"];
const CONTAIN_VERBS: &[&str] = &[
    "capture-evidence",
    "deny",
    "hold-for-grant",
    "freeze-session",
    "end-session",
    "disable-artefact-by-digest",
];
const REMEDIATE_VERBS: &[&str] = &["cut-session-egress", "quarantine-config-artefact"];
const FORBIDDEN_CONTENT_VERBS: &[&str] = &[
    "restore-workspace-files",
    "revoke-brokered-leases",
    "isolate-device",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ResponseBreakerLimits {
    max_breaker_rules: usize,
    max_breaker_devices_per_rule: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ResponseBreakerState {
    Closed,
    TrippedFleetShare,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExecutedResponsePlan {
    pub intent: TriggeredResponseIntent,
    pub breaker_state: ResponseBreakerState,
}

#[derive(Debug, Clone)]
pub struct ResponsePlanRequest<'a> {
    pub rule_id: &'a str,
    pub dedup_key: &'a str,
    pub binding: &'a ResponseBinding,
    pub ceiling: FindingCeiling,
    pub pack_mode: Mode,
    pub device_id: &'a str,
    pub fleet_active_devices: usize,
    pub now_sec: i64,
    pub external_remediate_approved: bool,
}

#[derive(Debug, Clone, Default)]
pub struct ResponseExecutor {
    hourly_devices_by_rule: BTreeMap<String, BTreeMap<String, i64>>,
    max_seen_sec_by_rule: BTreeMap<String, i64>,
    pending_future_sec_by_rule: BTreeMap<String, i64>,
}

impl ResponseBreakerLimits {
    fn from_embedded() -> Result<Self, DetectError> {
        let cfg = load_embedded_limits().map_err(|err| {
            DetectError::StateRestore(format!("embedded operational limits unavailable: {err}"))
        })?;
        let max_breaker_rules = MAX_BREAKER_RULES;
        let max_breaker_devices_per_rule = cfg.broker.circuit_breaker.max_outcomes;
        if max_breaker_rules == 0 || max_breaker_devices_per_rule == 0 {
            return Err(DetectError::StateRestore(
                "response breaker limits must be positive".into(),
            ));
        }
        Ok(Self {
            max_breaker_rules,
            max_breaker_devices_per_rule,
        })
    }
}

/// Validates response binding verbs, blast-radius parameters, and ceiling compliance (`docs/design/13` s.14).
pub fn validate_response_binding(
    binding: &ResponseBinding,
    effective_ceiling: FindingCeiling,
) -> Result<(), DetectError> {
    validate_response_binding_with_legacy(binding, effective_ceiling, true)
}

pub(crate) fn validate_response_binding_with_legacy(
    binding: &ResponseBinding,
    effective_ceiling: FindingCeiling,
    enforce_ceiling_fit: bool,
) -> Result<(), DetectError> {
    if binding.max_scope.trim().is_empty()
        || binding.max_share_bp == 0
        || binding.max_share_bp > 10_000
    {
        return Err(DetectError::ResponseBreaker(format!(
            "invalid response scope `{}` or max_share_bp {}",
            binding.max_scope, binding.max_share_bp
        )));
    }
    for raw_verb in &binding.verbs {
        let verb = raw_verb.trim().to_ascii_lowercase();
        let allow_signed_sim = !enforce_ceiling_fit
            && binding.mode == ResponseExecutionMode::Simulate
            && matches!(
                verb.as_str(),
                "restore-workspace-files" | "revoke-brokered-leases"
            );
        if FORBIDDEN_CONTENT_VERBS.contains(&verb.as_str()) && !allow_signed_sim {
            return Err(breaker(&format!("response verb `{verb}` forbidden")));
        }
        if !(CONTAIN_VERBS.contains(&verb.as_str())
            || REMEDIATE_VERBS.contains(&verb.as_str())
            || allow_signed_sim)
        {
            return Err(breaker(&format!("unknown response verb `{verb}`")));
        }
        if enforce_ceiling_fit && !verb_permitted_at_ceiling(&verb, effective_ceiling) {
            return Err(breaker(&format!(
                "response verb `{verb}` exceeds `{effective_ceiling:?}`"
            )));
        }
    }
    Ok(())
}

impl ResponseExecutor {
    #[must_use]
    pub fn snapshot_devices(&self) -> BTreeMap<String, BTreeMap<String, i64>> {
        self.hourly_devices_by_rule.clone()
    }

    pub fn restore_devices(
        &mut self,
        state: &BTreeMap<String, BTreeMap<String, i64>>,
    ) -> Result<(), DetectError> {
        let limits = ResponseBreakerLimits::from_embedded()?;
        if state.len() > limits.max_breaker_rules
            || state
                .values()
                .any(|devs| devs.len() > limits.max_breaker_devices_per_rule)
        {
            return Err(DetectError::StateRestore(
                "response breaker capacity".into(),
            ));
        }
        self.hourly_devices_by_rule = state.clone();
        self.pending_future_sec_by_rule.clear();
        self.max_seen_sec_by_rule = state
            .iter()
            .filter_map(|(r, d)| d.values().copied().max().map(|m| (r.clone(), m)))
            .collect();
        Ok(())
    }

    /// Plans or executes a response binding within mode ladder, ceiling, and fleet circuit breaker.
    pub fn evaluate_binding(
        &mut self,
        req: &ResponsePlanRequest<'_>,
    ) -> Result<ExecutedResponsePlan, DetectError> {
        if req.binding.max_share_bp == 0 || req.binding.max_share_bp > 10_000 {
            return Err(breaker(&format!(
                "invalid max_share_bp {}",
                req.binding.max_share_bp
            )));
        }
        let limits = ResponseBreakerLimits::from_embedded()?;
        let sim = |m, verbs| Ok(plan(req, m, verbs, true, ResponseBreakerState::Closed));
        if req.pack_mode == Mode::Off {
            return sim(req.pack_mode, Vec::new());
        }
        let allowed = filter_verbs_by_ceiling_and_mode(
            req.binding,
            req.ceiling,
            req.pack_mode,
            req.external_remediate_approved,
        );
        if req.pack_mode != Mode::Block
            || req.binding.mode == ResponseExecutionMode::Simulate
            || allowed.is_empty()
        {
            return sim(req.pack_mode, allowed);
        }
        if !self.hourly_devices_by_rule.contains_key(req.rule_id)
            && self.hourly_devices_by_rule.len() >= limits.max_breaker_rules
            && let Some(old) = self
                .hourly_devices_by_rule
                .iter()
                .min_by_key(|(r, d)| {
                    self.max_seen_sec_by_rule
                        .get(*r)
                        .copied()
                        .or_else(|| d.values().copied().max())
                        .unwrap_or(i64::MIN)
                })
                .map(|(k, _)| k.clone())
        {
            self.hourly_devices_by_rule.remove(&old);
            self.max_seen_sec_by_rule.remove(&old);
            self.pending_future_sec_by_rule.remove(&old);
        }
        let max_seen = self
            .max_seen_sec_by_rule
            .entry(req.rule_id.to_owned())
            .or_insert(req.now_sec);
        let mut eff_now = req.now_sec;
        if req.now_sec.saturating_sub(*max_seen) > ONE_HOUR_SECS {
            if let Some(&pend) = self.pending_future_sec_by_rule.get(req.rule_id)
                && req.now_sec >= pend.saturating_sub(ONE_HOUR_SECS)
                && req.now_sec.saturating_sub(pend) <= ONE_HOUR_SECS
            {
                *max_seen = (*max_seen).max(pend.max(req.now_sec));
                self.pending_future_sec_by_rule.remove(req.rule_id);
            } else {
                self.pending_future_sec_by_rule
                    .insert(req.rule_id.to_owned(), req.now_sec);
                eff_now = *max_seen;
            }
        } else {
            self.pending_future_sec_by_rule.remove(req.rule_id);
            *max_seen = (*max_seen).max(req.now_sec);
            eff_now = eff_now.max(*max_seen);
        }
        let dev_map = self
            .hourly_devices_by_rule
            .entry(req.rule_id.to_owned())
            .or_default();
        dev_map.retain(|_, ts| *ts >= (*max_seen).saturating_sub(ONE_HOUR_SECS));
        let mut distinct: BTreeSet<&str> = dev_map.keys().map(String::as_str).collect();
        distinct.insert(req.device_id);
        let share_bp = distinct
            .len()
            .saturating_mul(10_000)
            .checked_div(req.fleet_active_devices.max(1))
            .unwrap_or(0);
        if distinct.len() > 1 && share_bp > usize::from(req.binding.max_share_bp) {
            return Ok(plan(
                req,
                Mode::Watch,
                allowed,
                true,
                ResponseBreakerState::TrippedFleetShare,
            ));
        }
        if !dev_map.contains_key(req.device_id)
            && dev_map.len() >= limits.max_breaker_devices_per_rule
            && let Some(old_dev) = dev_map
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, _)| k.clone())
        {
            dev_map.remove(&old_dev);
        }
        let prev = dev_map.get(req.device_id).copied().unwrap_or(i64::MIN);
        dev_map.insert(req.device_id.to_owned(), prev.max(eff_now));
        Ok(plan(
            req,
            Mode::Block,
            allowed,
            false,
            ResponseBreakerState::Closed,
        ))
    }
}

fn breaker(msg: &str) -> DetectError {
    DetectError::ResponseBreaker(msg.into())
}

fn plan(
    req: &ResponsePlanRequest<'_>,
    mode_applied: Mode,
    verbs: Vec<String>,
    simulated: bool,
    breaker_state: ResponseBreakerState,
) -> ExecutedResponsePlan {
    let intent = TriggeredResponseIntent {
        rule_id: req.rule_id.to_owned(),
        dedup_key: req.dedup_key.to_owned(),
        mode_applied,
        verbs,
        simulated,
    };
    ExecutedResponsePlan {
        intent,
        breaker_state,
    }
}

fn verb_permitted_at_ceiling(verb_lower: &str, ceiling: FindingCeiling) -> bool {
    if FORBIDDEN_CONTENT_VERBS.contains(&verb_lower) {
        return false;
    }
    match ceiling {
        FindingCeiling::Record | FindingCeiling::Notify => {
            RECORD_NOTIFY_VERBS.contains(&verb_lower)
        }
        FindingCeiling::Contain => CONTAIN_VERBS.contains(&verb_lower),
        FindingCeiling::Remediate => {
            CONTAIN_VERBS.contains(&verb_lower) || REMEDIATE_VERBS.contains(&verb_lower)
        }
    }
}

fn filter_verbs_by_ceiling_and_mode(
    binding: &ResponseBinding,
    ceiling: FindingCeiling,
    pack_mode: Mode,
    external_remediate_approved: bool,
) -> Vec<String> {
    if matches!(ceiling, FindingCeiling::Record | FindingCeiling::Notify) {
        return vec!["capture-evidence".into()];
    }
    if pack_mode == Mode::Ask {
        return vec!["hold-for-grant".into()];
    }
    binding
        .verbs
        .iter()
        .filter_map(|raw| {
            let verb = raw.trim().to_ascii_lowercase();
            if FORBIDDEN_CONTENT_VERBS.contains(&verb.as_str()) {
                return None;
            }
            if REMEDIATE_VERBS.contains(&verb.as_str()) {
                (ceiling == FindingCeiling::Remediate && external_remediate_approved)
                    .then_some(verb)
            } else if CONTAIN_VERBS.contains(&verb.as_str()) && ceiling >= FindingCeiling::Contain {
                Some(verb)
            } else {
                None
            }
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn forbidden_and_unapproved_remediate_verbs_are_rejected_and_filtered() {
        let forbidden = ResponseBinding {
            mode: ResponseExecutionMode::Live,
            verbs: vec!["Restore-Workspace-Files".into()],
            max_scope: "session".into(),
            max_share_bp: 500,
            opted_in_remediate: true,
        };
        assert!(validate_response_binding(&forbidden, FindingCeiling::Remediate).is_err());

        let unknown = ResponseBinding {
            mode: ResponseExecutionMode::Live,
            verbs: vec!["isolate-device".into()],
            max_scope: "session".into(),
            max_share_bp: 500,
            opted_in_remediate: false,
        };
        assert!(validate_response_binding(&unknown, FindingCeiling::Contain).is_err());

        let rem = ResponseBinding {
            mode: ResponseExecutionMode::Live,
            verbs: vec!["cut-session-egress".into(), "freeze-session".into()],
            max_scope: "session".into(),
            max_share_bp: 500,
            opted_in_remediate: true,
        };
        let mut exec = ResponseExecutor::default();
        let unapproved = exec
            .evaluate_binding(&ResponsePlanRequest {
                rule_id: "r1",
                dedup_key: "k1",
                binding: &rem,
                ceiling: FindingCeiling::Remediate,
                pack_mode: Mode::Block,
                device_id: "d1",
                fleet_active_devices: 100,
                now_sec: 1_000,
                external_remediate_approved: false,
            })
            .expect("unapproved remediate plan");
        assert_eq!(unapproved.intent.verbs, vec!["freeze-session"]);
    }

    #[test]
    fn zero_share_bp_fails_closed_and_clock_regression_preserves_hits() {
        let mut exec = ResponseExecutor::default();
        let zero_bp = ResponseBinding {
            mode: ResponseExecutionMode::Live,
            verbs: vec!["freeze-session".into()],
            max_scope: "session".into(),
            max_share_bp: 0,
            opted_in_remediate: false,
        };
        assert!(
            exec.evaluate_binding(&ResponsePlanRequest {
                rule_id: "r1",
                dedup_key: "k0",
                binding: &zero_bp,
                ceiling: FindingCeiling::Contain,
                pack_mode: Mode::Block,
                device_id: "d1",
                fleet_active_devices: 20,
                now_sec: 1_000,
                external_remediate_approved: false,
            })
            .is_err()
        );

        let valid = ResponseBinding {
            max_share_bp: 500,
            ..zero_bp
        };
        exec.evaluate_binding(&ResponsePlanRequest {
            rule_id: "r1",
            dedup_key: "k1",
            binding: &valid,
            ceiling: FindingCeiling::Contain,
            pack_mode: Mode::Block,
            device_id: "d1",
            fleet_active_devices: 20,
            now_sec: 1_500,
            external_remediate_approved: false,
        })
        .expect("future hit");
        let regressed = exec
            .evaluate_binding(&ResponsePlanRequest {
                rule_id: "r1",
                dedup_key: "k2",
                binding: &valid,
                ceiling: FindingCeiling::Contain,
                pack_mode: Mode::Block,
                device_id: "d2",
                fleet_active_devices: 20,
                now_sec: 1_400,
                external_remediate_approved: false,
            })
            .expect("out-of-order hit still sees d1");
        assert_eq!(
            regressed.breaker_state,
            ResponseBreakerState::TrippedFleetShare
        );
    }
}
