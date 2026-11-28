// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Multi-vendor `VerdictProvider` fan-out engine, core pre-check, and circuit tracking (`docs/design/07`).

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use serde::{Deserialize, Serialize};

use grdr_core::session::format_session_pseudonym_sp;
use grdr_model::eval::SigningKeypair;
use grdr_model::{ActionAttempt, CodedError, Verdict};
use grdr_ports::DecisionEnginePort;
use grdr_strings::sanitize_untrusted_text;

use crate::brand::BrokerBrand;
use crate::breaker::{BreakerTracker, CircuitBreakerState};
use crate::fanout_exec::{
    execute_bounded_fanout, finalize_merged_decision, format_action_class, format_broker_notice,
};
use crate::providers::{
    MAX_PROVIDER_DEADLINE_MS, ProviderCapabilities, ProviderOnFailure, ProviderTrustModel,
};
use crate::worker_pool::BrokerWorkerPool;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderVerdictKind {
    Allow,
    Modify,
    Defer,
    StepUp,
    Deny,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderEvalRequest {
    pub request_id: String,
    pub session_id: String,
    pub action_class: String,
    pub target_preview: String,
    pub deadline_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderVerdictResponse {
    pub provider_id: String,
    pub verdict: ProviderVerdictKind,
    pub reason_code: String,
    pub reason: String,
    pub rewritten_target: Option<String>,
    pub latency_ms: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProviderEvalError {
    Timeout,
    Unavailable(String),
    MalformedResponse(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FanoutDecision {
    pub verdict: ProviderVerdictKind,
    pub winning_provider_id: Option<String>,
    pub reason_code: String,
    pub message: String,
    pub rewritten_target: Option<String>,
    pub reevaluated_after_modify: bool,
    pub diagnostics: Vec<String>,
}

pub trait VerdictProvider: Send + Sync + 'static {
    fn capabilities(&self) -> &ProviderCapabilities;
    fn evaluate(
        &self,
        request: &ProviderEvalRequest,
    ) -> Result<ProviderVerdictResponse, ProviderEvalError>;
}

pub struct HookBrokerEngine {
    providers: Vec<Arc<dyn VerdictProvider>>,
    breakers: BTreeMap<String, BreakerTracker>,
    brand: BrokerBrand,
    fanout_deadline_ms: u64,
    worker_pool: BrokerWorkerPool,
    pseudonym_key: [u8; 32],
}

impl Drop for HookBrokerEngine {
    fn drop(&mut self) {
        self.worker_pool.shutdown();
    }
}

impl ProviderVerdictKind {
    #[must_use]
    pub const fn severity_rank(self) -> u8 {
        match self {
            Self::Allow => 0,
            Self::Modify => 1,
            Self::Defer => 2,
            Self::StepUp => 3,
            Self::Deny => 4,
        }
    }

    #[must_use]
    pub fn from_model_verdict(v: Verdict) -> Self {
        match v {
            Verdict::Allow => Self::Allow,
            Verdict::Modify => Self::Modify,
            Verdict::Defer => Self::Defer,
            Verdict::StepUp => Self::StepUp,
            Verdict::Deny => Self::Deny,
        }
    }
}

impl HookBrokerEngine {
    pub fn new(
        providers: Vec<Arc<dyn VerdictProvider>>,
        brand: BrokerBrand,
    ) -> Result<Self, CodedError> {
        Self::with_deadline(providers, brand, MAX_PROVIDER_DEADLINE_MS)
    }

    pub fn with_deadline(
        mut providers: Vec<Arc<dyn VerdictProvider>>,
        brand: BrokerBrand,
        fanout_deadline_ms: u64,
    ) -> Result<Self, CodedError> {
        if fanout_deadline_ms == 0 || fanout_deadline_ms > MAX_PROVIDER_DEADLINE_MS {
            return Err(CodedError::new(
                "GRDR-BRK-0005",
                format!(
                    "fanout_deadline_ms={fanout_deadline_ms} outside 1..={MAX_PROVIDER_DEADLINE_MS}"
                ),
                "Set fanout deadline within 1..=1000ms.",
            ));
        }
        let mut modify_count: usize = 0;
        let mut seen_ids = BTreeSet::new();
        for p in &providers {
            let caps = p.capabilities();
            if caps.provider_id.trim().is_empty() {
                return Err(CodedError::new(
                    "GRDR-BRK-0005",
                    "provider_id must not be empty",
                    "Set a unique non-empty provider_id.",
                ));
            }
            if !seen_ids.insert(caps.provider_id.clone()) {
                return Err(CodedError::new(
                    "GRDR-BRK-0005",
                    format!("duplicate provider_id `{}`", caps.provider_id),
                    "Ensure every provider has a unique provider_id.",
                ));
            }
            if caps.timeout_ms == 0 || caps.timeout_ms > MAX_PROVIDER_DEADLINE_MS {
                return Err(CodedError::new(
                    "GRDR-BRK-0005",
                    format!(
                        "provider `{}` timeout_ms={} out of range",
                        caps.provider_id, caps.timeout_ms
                    ),
                    "Set provider timeout_ms within 1..=1000.",
                ));
            }
            if caps.trust_model == ProviderTrustModel::ModelBacked && caps.may_modify {
                return Err(CodedError::new(
                    "GRDR-BRK-0005",
                    format!(
                        "model_backed provider `{}` cannot hold may_modify",
                        caps.provider_id
                    ),
                    "Disable may_modify on model-backed providers.",
                ));
            }
            if caps.may_modify {
                modify_count = modify_count.saturating_add(1);
            }
        }
        if modify_count > 1 {
            return Err(CodedError::new(
                "GRDR-BRK-0006",
                "multiple providers declare may_modify=true",
                "Allow at most one active single-writer may_modify provider.",
            ));
        }
        providers.sort_by_key(|p| {
            (
                p.capabilities().priority,
                p.capabilities().provider_id.clone(),
            )
        });
        let kp = SigningKeypair::generate().map_err(|e| {
            CodedError::new(
                "GRDR-BRK-0005",
                format!("failed generating broker pseudonym key: {e}"),
                "Ensure OS CSPRNG is available.",
            )
        })?;
        let raw_sig = kp.sign_ed25519_raw(b"grdr.broker.session_pseudonym.v1");
        let mut pseudonym_key = [0u8; 32];
        if let Some(first_half) = raw_sig.get(..32) {
            pseudonym_key.copy_from_slice(first_half);
        }
        Ok(Self {
            providers,
            breakers: BTreeMap::new(),
            brand,
            fanout_deadline_ms,
            worker_pool: BrokerWorkerPool::from_limits(),
            pseudonym_key,
        })
    }

    #[must_use]
    pub fn with_pseudonym_key(mut self, pseudonym_key: [u8; 32]) -> Self {
        self.pseudonym_key = pseudonym_key;
        self
    }

    #[must_use]
    pub fn worker_pool_capacity(&self) -> usize {
        self.worker_pool.max_workers()
    }

    #[must_use]
    pub fn spawned_worker_count(&self) -> usize {
        self.worker_pool.spawned_workers()
    }

    #[must_use]
    pub fn brand(&self) -> &BrokerBrand {
        &self.brand
    }

    #[must_use]
    pub fn circuit_state(&mut self, provider_id: &str, now_ms: u64) -> CircuitBreakerState {
        self.breakers
            .entry(provider_id.to_owned())
            .or_default()
            .current_state(now_ms)
    }

    pub fn evaluate_action<E: DecisionEnginePort>(
        &mut self,
        attempt: &ActionAttempt,
        mut engine: Option<&mut E>,
        now_ms: u64,
    ) -> FanoutDecision {
        let action_class_str = format_action_class(attempt.action_class);
        let mut diagnostics: Vec<String> = Vec::new();
        let core_receipt = if let Some(eng) = engine.as_deref_mut() {
            match eng.evaluate(attempt) {
                Ok(receipt) => {
                    if receipt.verdict == Verdict::Deny {
                        let code = receipt
                            .rule_id
                            .clone()
                            .unwrap_or_else(|| "policy.deny".into());
                        let message = format_broker_notice(
                            &self.brand,
                            attempt,
                            &action_class_str,
                            ProviderVerdictKind::Deny,
                            &code,
                            &receipt.reason,
                        );
                        return FanoutDecision {
                            verdict: ProviderVerdictKind::Deny,
                            winning_provider_id: Some("grdr.core".into()),
                            reason_code: code,
                            message,
                            rewritten_target: None,
                            reevaluated_after_modify: false,
                            diagnostics,
                        };
                    }
                    Some(receipt)
                }
                Err(err) => {
                    let message = format_broker_notice(
                        &self.brand,
                        attempt,
                        &action_class_str,
                        ProviderVerdictKind::Deny,
                        "GRDR-BRK-0001",
                        &err.display_line(),
                    );
                    return FanoutDecision {
                        verdict: ProviderVerdictKind::Deny,
                        winning_provider_id: Some("grdr.core".into()),
                        reason_code: "GRDR-BRK-0001".into(),
                        message,
                        rewritten_target: None,
                        reevaluated_after_modify: false,
                        diagnostics,
                    };
                }
            }
        } else {
            None
        };

        let mut active: Vec<Arc<dyn VerdictProvider>> = Vec::new();
        let mut collected: Vec<(ProviderCapabilities, ProviderVerdictResponse)> = Vec::new();

        for provider in &self.providers {
            let caps = provider.capabilities().clone();
            if !caps.action_classes.is_empty()
                && !caps.action_classes.contains("*")
                && !caps.action_classes.contains(&action_class_str)
            {
                continue;
            }
            let state = self
                .breakers
                .entry(caps.provider_id.clone())
                .or_default()
                .current_state(now_ms);
            if matches!(state, CircuitBreakerState::Suspended { .. }) {
                diagnostics.push(format!("provider-suspended:{}", caps.provider_id));
                apply_failure_policy(&caps, "circuit suspended", &mut collected, &mut diagnostics);
                continue;
            }
            active.push(Arc::clone(provider));
        }

        let active_max_timeout_ms = active
            .iter()
            .map(|p| p.capabilities().timeout_ms)
            .max()
            .unwrap_or(0);
        let effective_deadline_ms = active_max_timeout_ms.min(self.fanout_deadline_ms);

        let session_sp = match format_session_pseudonym_sp(&attempt.session_id, &self.pseudonym_key)
        {
            Ok(sp) => sp,
            Err(err) => {
                let message = format_broker_notice(
                    &self.brand,
                    attempt,
                    &action_class_str,
                    ProviderVerdictKind::Deny,
                    "GRDR-BRK-0005",
                    &err.display_line(),
                );
                return FanoutDecision {
                    verdict: ProviderVerdictKind::Deny,
                    winning_provider_id: Some("grdr.core".into()),
                    reason_code: "GRDR-BRK-0005".into(),
                    message,
                    rewritten_target: None,
                    reevaluated_after_modify: false,
                    diagnostics,
                };
            }
        };

        let base_req = ProviderEvalRequest {
            request_id: attempt.id.clone(),
            session_id: session_sp,
            action_class: action_class_str.clone(),
            target_preview: attempt.target.clone(),
            deadline_ms: effective_deadline_ms,
        };

        let raw_results =
            execute_bounded_fanout(&self.worker_pool, &active, &base_req, effective_deadline_ms);
        for (caps, res, elapsed_ms) in raw_results {
            let effective_budget = caps.timeout_ms.min(effective_deadline_ms);
            match res {
                Ok(mut resp) => {
                    let observed_latency = resp.latency_ms.max(elapsed_ms);
                    if observed_latency > effective_budget {
                        let tracker = self.breakers.entry(caps.provider_id.clone()).or_default();
                        if let Some(evt) = tracker.record(now_ms, false) {
                            diagnostics.push(format!("{}:{}", caps.provider_id, evt));
                        }
                        diagnostics.push(format!(
                            "provider-timeout:{}:{observed_latency}ms",
                            caps.provider_id
                        ));
                        apply_failure_policy(
                            &caps,
                            "deadline exceeded",
                            &mut collected,
                            &mut diagnostics,
                        );
                    } else if let Err(malformed) =
                        normalize_provider_response(&caps, &mut resp, &mut diagnostics)
                    {
                        let tracker = self.breakers.entry(caps.provider_id.clone()).or_default();
                        if let Some(evt) = tracker.record(now_ms, false) {
                            diagnostics.push(format!("{}:{}", caps.provider_id, evt));
                        }
                        diagnostics
                            .push(format!("provider-error:{}:{malformed:?}", caps.provider_id));
                        apply_failure_policy(
                            &caps,
                            "provider response malformed",
                            &mut collected,
                            &mut diagnostics,
                        );
                    } else {
                        self.breakers
                            .entry(caps.provider_id.clone())
                            .or_default()
                            .record(now_ms, true);
                        collected.push((caps, resp));
                    }
                }
                Err(err) => {
                    let tracker = self.breakers.entry(caps.provider_id.clone()).or_default();
                    if let Some(evt) = tracker.record(now_ms, false) {
                        diagnostics.push(format!("{}:{}", caps.provider_id, evt));
                    }
                    diagnostics.push(format!("provider-error:{}:{err:?}", caps.provider_id));
                    apply_failure_policy(
                        &caps,
                        "provider evaluation failed",
                        &mut collected,
                        &mut diagnostics,
                    );
                }
            }
        }

        finalize_merged_decision(
            attempt,
            &action_class_str,
            core_receipt.as_ref(),
            &collected,
            engine,
            &self.brand,
            diagnostics,
        )
    }
}

fn apply_failure_policy(
    caps: &ProviderCapabilities,
    why: &str,
    collected: &mut Vec<(ProviderCapabilities, ProviderVerdictResponse)>,
    diagnostics: &mut Vec<String>,
) {
    let effective_policy = if caps.trust_model == ProviderTrustModel::ModelBacked {
        ProviderOnFailure::Ignore
    } else {
        caps.on_failure
    };
    match effective_policy {
        ProviderOnFailure::FailClosed => collected.push((
            caps.clone(),
            ProviderVerdictResponse {
                provider_id: caps.provider_id.clone(),
                verdict: ProviderVerdictKind::Deny,
                reason_code: format!("provider/{}/fail-closed", caps.provider_id),
                reason: format!("provider `{}` failed closed ({why})", caps.provider_id),
                rewritten_target: None,
                latency_ms: caps.timeout_ms,
            },
        )),
        ProviderOnFailure::StepUp => collected.push((
            caps.clone(),
            ProviderVerdictResponse {
                provider_id: caps.provider_id.clone(),
                verdict: ProviderVerdictKind::StepUp,
                reason_code: format!("provider/{}/step-up-on-error", caps.provider_id),
                reason: format!("provider `{}` requires step-up ({why})", caps.provider_id),
                rewritten_target: None,
                latency_ms: caps.timeout_ms,
            },
        )),
        ProviderOnFailure::Ignore => {
            diagnostics.push(format!("provider-ignored:{}:{why}", caps.provider_id));
        }
    }
}

fn normalize_provider_response(
    caps: &ProviderCapabilities,
    resp: &mut ProviderVerdictResponse,
    diagnostics: &mut Vec<String>,
) -> Result<(), ProviderEvalError> {
    if !resp.provider_id.is_empty() && resp.provider_id != caps.provider_id {
        return Err(ProviderEvalError::MalformedResponse(format!(
            "provider_id mismatch: expected `{}`",
            caps.provider_id
        )));
    }
    resp.provider_id = caps.provider_id.clone();
    resp.reason_code = sanitize_untrusted_text(&resp.reason_code);
    if let Some(ref rewritten) = resp.rewritten_target
        && rewritten.chars().any(is_control_or_bidi)
    {
        return Err(ProviderEvalError::MalformedResponse(
            "rewritten_target contains control or bidi character".into(),
        ));
    }
    if caps.trust_model == ProviderTrustModel::ModelBacked
        && resp.verdict == ProviderVerdictKind::Deny
    {
        resp.verdict = ProviderVerdictKind::StepUp;
        diagnostics.push(format!(
            "GRDR-BRK-0007:model-backed-clamped:{}",
            caps.provider_id
        ));
    }
    if resp.verdict == ProviderVerdictKind::Modify && !caps.may_modify {
        resp.verdict = ProviderVerdictKind::StepUp;
        resp.rewritten_target = None;
        diagnostics.push(format!(
            "unauthorized-modify-escalated:{}",
            caps.provider_id
        ));
    }
    Ok(())
}

fn is_control_or_bidi(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}
