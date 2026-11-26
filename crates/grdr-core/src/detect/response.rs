// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Response action executor with mode ladder gating, strict verb allowlists, and fleet blast-radius circuit breakers (`D-09`, `D-55`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_model::Mode;

use crate::detect::types::{
    DetectError, FindingCeiling, ResponseBinding, ResponseExecutionMode, TriggeredResponseIntent,
};

pub const DEFAULT_MAX_SHARE_BP: u16 = 500;
const ONE_HOUR_SECS: i64 = 3_600;
const MAX_BREAKER_RULES: usize = 512;
const MAX_BREAKER_DEVICES_PER_RULE: usize = 2_048;

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
    if binding.max_scope.trim().is_empty() {
        return Err(DetectError::ResponseBreaker(
            "response blast_radius max_scope cannot be empty".into(),
        ));
    }
    if binding.max_share_bp == 0 || binding.max_share_bp > 10_000 {
        return Err(DetectError::ResponseBreaker(format!(
            "invalid response max_share_bp {}; expected 1..=10000",
            binding.max_share_bp
        )));
    }
    for raw_verb in &binding.verbs {
        let verb = raw_verb.trim().to_ascii_lowercase();
        let allow_signed_simulated_legacy = !enforce_ceiling_fit
            && binding.mode == ResponseExecutionMode::Simulate
            && matches!(
                verb.as_str(),
                "restore-workspace-files" | "revoke-brokered-leases"
            );
        if FORBIDDEN_CONTENT_VERBS.contains(&verb.as_str()) && !allow_signed_simulated_legacy {
            return Err(DetectError::ResponseBreaker(format!(
                "response verb `{verb}` cannot be automated from detection content"
            )));
        }
        let known = CONTAIN_VERBS.contains(&verb.as_str())
            || REMEDIATE_VERBS.contains(&verb.as_str())
            || allow_signed_simulated_legacy;
        if !known {
            return Err(DetectError::ResponseBreaker(format!(
                "unknown response verb `{verb}` outside ResponseAction allowlist"
            )));
        }
        if enforce_ceiling_fit && !verb_permitted_at_ceiling(&verb, effective_ceiling) {
            return Err(DetectError::ResponseBreaker(format!(
                "response verb `{verb}` exceeds effective rule ceiling `{effective_ceiling:?}`"
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
        if state.len() > MAX_BREAKER_RULES
            || state
                .values()
                .any(|devs| devs.len() > MAX_BREAKER_DEVICES_PER_RULE)
        {
            return Err(DetectError::StateRestore(
                "restored response breaker device map exceeds capacity bounds".into(),
            ));
        }
        self.hourly_devices_by_rule = state.clone();
        self.pending_future_sec_by_rule.clear();
        self.max_seen_sec_by_rule = state
            .iter()
            .filter_map(|(r, devs)| devs.values().copied().max().map(|m| (r.clone(), m)))
            .collect();
        Ok(())
    }

    /// Plans or executes a response binding within mode ladder, finding ceiling,
    /// external remediate approval gate, and hourly fleet share circuit breaker.
    pub fn evaluate_binding(
        &mut self,
        req: &ResponsePlanRequest<'_>,
    ) -> Result<ExecutedResponsePlan, DetectError> {
        if req.binding.max_share_bp == 0 || req.binding.max_share_bp > 10_000 {
            return Err(DetectError::ResponseBreaker(format!(
                "response max_share_bp {} is invalid (must be 1..=10000)",
                req.binding.max_share_bp
            )));
        }
        if req.pack_mode == Mode::Off {
            return Ok(ExecutedResponsePlan {
                intent: TriggeredResponseIntent {
                    rule_id: req.rule_id.to_owned(),
                    dedup_key: req.dedup_key.to_owned(),
                    mode_applied: req.pack_mode,
                    verbs: Vec::new(),
                    simulated: true,
                },
                breaker_state: ResponseBreakerState::Closed,
            });
        }

        let allowed_verbs = filter_verbs_by_ceiling_and_mode(
            req.binding,
            req.ceiling,
            req.pack_mode,
            req.external_remediate_approved,
        );
        if req.pack_mode != Mode::Block
            || req.binding.mode == ResponseExecutionMode::Simulate
            || allowed_verbs.is_empty()
        {
            return Ok(ExecutedResponsePlan {
                intent: TriggeredResponseIntent {
                    rule_id: req.rule_id.to_owned(),
                    dedup_key: req.dedup_key.to_owned(),
                    mode_applied: req.pack_mode,
                    verbs: allowed_verbs,
                    simulated: true,
                },
                breaker_state: ResponseBreakerState::Closed,
            });
        }

        if !self.hourly_devices_by_rule.contains_key(req.rule_id)
            && self.hourly_devices_by_rule.len() >= MAX_BREAKER_RULES
            && let Some(oldest_rule) = self
                .hourly_devices_by_rule
                .iter()
                .min_by_key(|(rule, devs)| {
                    self.max_seen_sec_by_rule
                        .get(*rule)
                        .copied()
                        .or_else(|| devs.values().copied().max())
                        .unwrap_or(i64::MIN)
                })
                .map(|(k, _)| k.clone())
        {
            self.hourly_devices_by_rule.remove(&oldest_rule);
            self.max_seen_sec_by_rule.remove(&oldest_rule);
            self.pending_future_sec_by_rule.remove(&oldest_rule);
        }
        let max_seen = self
            .max_seen_sec_by_rule
            .entry(req.rule_id.to_owned())
            .or_insert(req.now_sec);
        let mut effective_now = req.now_sec;
        if req.now_sec.saturating_sub(*max_seen) > ONE_HOUR_SECS {
            if let Some(&pending) = self.pending_future_sec_by_rule.get(req.rule_id)
                && req.now_sec >= pending.saturating_sub(ONE_HOUR_SECS)
                && req.now_sec.saturating_sub(pending) <= ONE_HOUR_SECS
            {
                *max_seen = (*max_seen).max(pending.max(req.now_sec));
                self.pending_future_sec_by_rule.remove(req.rule_id);
            } else {
                self.pending_future_sec_by_rule
                    .insert(req.rule_id.to_owned(), req.now_sec);
                effective_now = *max_seen;
            }
        } else {
            self.pending_future_sec_by_rule.remove(req.rule_id);
            *max_seen = (*max_seen).max(req.now_sec);
            effective_now = effective_now.max(*max_seen);
        }
        let cutoff = (*max_seen).saturating_sub(ONE_HOUR_SECS);
        let device_map = self
            .hourly_devices_by_rule
            .entry(req.rule_id.to_owned())
            .or_default();
        device_map.retain(|_, ts| *ts >= cutoff);

        let mut distinct_devices: BTreeSet<&str> = device_map.keys().map(String::as_str).collect();
        distinct_devices.insert(req.device_id);

        let fleet_denom = req.fleet_active_devices.max(1);
        let share_bp = distinct_devices
            .len()
            .saturating_mul(10_000)
            .checked_div(fleet_denom)
            .unwrap_or(0);
        let cap_bp = usize::from(req.binding.max_share_bp);

        if distinct_devices.len() > 1 && share_bp > cap_bp {
            return Ok(ExecutedResponsePlan {
                intent: TriggeredResponseIntent {
                    rule_id: req.rule_id.to_owned(),
                    dedup_key: req.dedup_key.to_owned(),
                    mode_applied: Mode::Watch,
                    verbs: allowed_verbs,
                    simulated: true,
                },
                breaker_state: ResponseBreakerState::TrippedFleetShare,
            });
        }

        if !device_map.contains_key(req.device_id)
            && device_map.len() >= MAX_BREAKER_DEVICES_PER_RULE
            && let Some((oldest_dev, _)) = device_map
                .iter()
                .min_by_key(|(_, ts)| *ts)
                .map(|(k, v)| (k.clone(), *v))
        {
            device_map.remove(&oldest_dev);
        }
        let prev = device_map.get(req.device_id).copied().unwrap_or(i64::MIN);
        device_map.insert(req.device_id.to_owned(), prev.max(effective_now));
        Ok(ExecutedResponsePlan {
            intent: TriggeredResponseIntent {
                rule_id: req.rule_id.to_owned(),
                dedup_key: req.dedup_key.to_owned(),
                mode_applied: Mode::Block,
                verbs: allowed_verbs,
                simulated: false,
            },
            breaker_state: ResponseBreakerState::Closed,
        })
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
                if ceiling == FindingCeiling::Remediate && external_remediate_approved {
                    Some(verb)
                } else {
                    None
                }
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
