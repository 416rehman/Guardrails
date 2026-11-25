// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Networkless `DetectorAdapter` port and deterministic heuristic judge implementation.

use std::collections::BTreeSet;
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::advisory::{
    AdvisoryAction, AdvisoryLabel, AdvisorySeverityCap, BoundedRiskScore, FindingCandidate,
    MAX_ADVISORY_QUOTE_BYTES, ModelAdvisorySignal, UnavailableReason, VerifiedAdvisory,
};
use crate::framing::{FramedRecord, SessionMacKey, VerifiedRecord};

pub const DEFAULT_INFER_TIMEOUT_MS: u64 = 1_500;
pub const MAX_INFER_TIMEOUT_MS: u64 = 10_000;

struct SignalPattern {
    needle: &'static str,
    label: AdvisoryLabel,
    severity: AdvisorySeverityCap,
    weight: u16,
    action: AdvisoryAction,
}

const PATTERNS: &[SignalPattern] = &[
    SignalPattern {
        needle: "ignore previous instructions",
        label: AdvisoryLabel::PromptInjectionSuspected,
        severity: AdvisorySeverityCap::High,
        weight: 160,
        action: AdvisoryAction::TightenToStepUp,
    },
    SignalPattern {
        needle: "ignore all prior instructions",
        label: AdvisoryLabel::PromptInjectionSuspected,
        severity: AdvisorySeverityCap::High,
        weight: 160,
        action: AdvisoryAction::TightenToStepUp,
    },
    SignalPattern {
        needle: "system prompt",
        label: AdvisoryLabel::PromptInjectionSuspected,
        severity: AdvisorySeverityCap::Medium,
        weight: 90,
        action: AdvisoryAction::TightenToStepUp,
    },
    SignalPattern {
        needle: "bypass guardrails",
        label: AdvisoryLabel::PolicyEvasionSuspected,
        severity: AdvisorySeverityCap::High,
        weight: 180,
        action: AdvisoryAction::EscalateFinding,
    },
    SignalPattern {
        needle: "-encodedcommand",
        label: AdvisoryLabel::PolicyEvasionSuspected,
        severity: AdvisorySeverityCap::High,
        weight: 150,
        action: AdvisoryAction::TightenToStepUp,
    },
    SignalPattern {
        needle: "begin private key",
        label: AdvisoryLabel::SecretExposureSuspected,
        severity: AdvisorySeverityCap::High,
        weight: 175,
        action: AdvisoryAction::EscalateFinding,
    },
    SignalPattern {
        needle: "sk_live_",
        label: AdvisoryLabel::SecretExposureSuspected,
        severity: AdvisorySeverityCap::High,
        weight: 140,
        action: AdvisoryAction::EscalateFinding,
    },
    SignalPattern {
        needle: "<rec id=",
        label: AdvisoryLabel::PromptInjectionSuspected,
        severity: AdvisorySeverityCap::Medium,
        weight: 110,
        action: AdvisoryAction::TightenToStepUp,
    },
];

pub type DetectFuture<'a> = Pin<Box<dyn Future<Output = ModelAdvisorySignal> + Send + 'a>>;

/// Sandboxed, networkless detector boundary (`DetectorPort`) returning P2 restrict-only signals.
pub trait DetectorAdapter: Send + Sync {
    fn adapter_id(&self) -> &'static str;
    fn inspect_verified<'a>(&'a self, record: &'a VerifiedRecord) -> DetectFuture<'a>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct HeuristicJudgeDetector;

impl DetectorAdapter for HeuristicJudgeDetector {
    fn adapter_id(&self) -> &'static str {
        "grdr-infer.heuristic-judge.v1"
    }

    fn inspect_verified<'a>(&'a self, record: &'a VerifiedRecord) -> DetectFuture<'a> {
        Box::pin(async move { analyze_verified_record(self.adapter_id(), record) })
    }
}

/// Verifies HMAC framing first, then runs detector within a bounded timeout,
/// collapsing timeouts, faults, or tampered frames to `CouldNotLook`.
pub async fn evaluate_framed_with_budget<D: DetectorAdapter>(
    detector: &D,
    mac_key: &SessionMacKey,
    expected_record_id: &str,
    framed: &FramedRecord,
    timeout_ms: u64,
) -> ModelAdvisorySignal {
    let verified = match mac_key.open_and_verify(expected_record_id, framed) {
        Ok(rec) => rec,
        Err(_) => return ModelAdvisorySignal::CouldNotLook(UnavailableReason::TamperedFrame),
    };

    let bounded_ms = timeout_ms.clamp(1, MAX_INFER_TIMEOUT_MS);
    match tokio::time::timeout(
        Duration::from_millis(bounded_ms),
        detector.inspect_verified(&verified),
    )
    .await
    {
        Ok(signal) => verify_signal_grounding(signal, &verified),
        Err(_) => ModelAdvisorySignal::CouldNotLook(UnavailableReason::Timeout),
    }
}

fn verify_signal_grounding(
    signal: ModelAdvisorySignal,
    verified: &VerifiedRecord,
) -> ModelAdvisorySignal {
    match signal {
        ModelAdvisorySignal::CouldNotLook(reason) => ModelAdvisorySignal::CouldNotLook(reason),
        ModelAdvisorySignal::Advisory(advisory) => {
            for finding in &advisory.findings {
                if finding
                    .verify_grounded(&verified.record_id, &verified.plain_text)
                    .is_err()
                {
                    return ModelAdvisorySignal::CouldNotLook(UnavailableReason::QuoteNotGrounded);
                }
            }
            ModelAdvisorySignal::Advisory(advisory)
        }
    }
}

fn analyze_verified_record(evaluator_id: &str, record: &VerifiedRecord) -> ModelAdvisorySignal {
    let lower = record.plain_text.to_ascii_lowercase();
    let mut labels = BTreeSet::new();
    let mut findings = Vec::new();
    let mut total_score: u16 = 0;
    let mut strongest_action = AdvisoryAction::NoChange;

    for pattern in PATTERNS {
        if let Some(quote) = extract_original_quote(&record.plain_text, &lower, pattern.needle) {
            labels.insert(pattern.label);
            total_score = total_score.saturating_add(pattern.weight);
            if pattern.action > strongest_action {
                strongest_action = pattern.action;
            }
            findings.push(FindingCandidate {
                record_id: record.record_id.clone(),
                label: pattern.label,
                severity: pattern.severity,
                exact_quote: quote,
                confidence_bps: 8_500,
            });
        }
    }

    ModelAdvisorySignal::Advisory(VerifiedAdvisory {
        action: strongest_action,
        risk_score: BoundedRiskScore::clamped(total_score),
        labels,
        findings,
        evaluator_id: evaluator_id.to_owned(),
    })
}

fn extract_original_quote(original: &str, lower: &str, needle: &str) -> Option<String> {
    let start = lower.find(needle)?;
    let len = needle.len().min(MAX_ADVISORY_QUOTE_BYTES);
    let end = start.checked_add(len)?;
    let slice = original.as_bytes().get(start..end)?;
    let quote = std::str::from_utf8(slice).ok()?;
    if quote.is_empty() {
        None
    } else {
        Some(quote.to_owned())
    }
}
