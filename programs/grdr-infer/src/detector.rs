// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Networkless `DetectorAdapter` port and deterministic heuristic judge implementation.

use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use crate::advisory::{
    BoundedRiskScore, FindingCandidate, MAX_ADVISORY_FINDINGS, MAX_ADVISORY_LABELS,
    ModelAdvisorySignal, UnavailableReason, VerifiedAdvisory, requires_grounded_finding,
    validate_evaluator_id,
};
use crate::confusables::is_safe_quote_char;
use crate::framing::{FramedRecord, SessionMacKey, VerifiedRecord};
use crate::normalize::score_injection;

pub const DEFAULT_INFER_TIMEOUT_MS: u64 = 1_500;
pub const MAX_INFER_TIMEOUT_MS: u64 = 10_000;

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
        let evaluator_id = self.adapter_id();
        let record_owned = record.clone();
        Box::pin(async move {
            match tokio::task::spawn_blocking(move || {
                analyze_verified_record(evaluator_id, &record_owned)
            })
            .await
            {
                Ok(signal) => signal,
                Err(_) => ModelAdvisorySignal::CouldNotLook(UnavailableReason::ModelFault),
            }
        })
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
            if !validate_evaluator_id(&advisory.evaluator_id)
                || advisory.labels.len() > MAX_ADVISORY_LABELS
                || advisory.findings.len() > MAX_ADVISORY_FINDINGS
            {
                return ModelAdvisorySignal::CouldNotLook(UnavailableReason::MalformedOutput);
            }
            if requires_grounded_finding(
                advisory.action,
                advisory.risk_score,
                advisory.labels.is_empty(),
            ) && advisory.findings.is_empty()
            {
                return ModelAdvisorySignal::CouldNotLook(UnavailableReason::QuoteNotGrounded);
            }
            for finding in &advisory.findings {
                if finding
                    .exact_quote
                    .chars()
                    .any(|ch| !is_safe_quote_char(ch))
                    || finding
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
    let report = score_injection(&record.plain_text);
    let findings = report
        .indicators
        .into_iter()
        .take(MAX_ADVISORY_FINDINGS)
        .map(|indicator| FindingCandidate {
            record_id: record.record_id.clone(),
            label: indicator.label,
            severity: indicator.severity,
            exact_quote: indicator.exact_quote,
            confidence_bps: indicator.confidence_bps,
        })
        .collect();
    let labels = report
        .labels
        .into_iter()
        .take(MAX_ADVISORY_LABELS)
        .collect();

    ModelAdvisorySignal::Advisory(VerifiedAdvisory {
        action: report.action,
        risk_score: BoundedRiskScore::clamped(report.total_weight),
        labels,
        findings,
        evaluator_id: evaluator_id.to_owned(),
    })
}
