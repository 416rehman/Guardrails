// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Two-stage Finder -> Verifier pipeline, drop/coverage accounting, and extended
//! content-sensitivity queue scoring (`docs/design/19`, `D-29`, `P2`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_model::{DataClass, FindingSeverity};

use crate::inert::{InertExplanation, render_inert_explanation};
use crate::job_frame::FramedJobRecord;
use crate::pipeline::{
    MAX_FINDER_CANDIDATES, QuoteVerifyFailure, ReviewAdvisoryAction, ReviewFindingLabel,
    VerifiedQuoteSpan, parse_restrict_only_action, prepare_verified_corpus,
    verify_and_locate_quote,
};
use crate::queue::{ReviewCandidate, ReviewSettings, compute_priority_score};
use crate::reducer::{SourceSegment, SpanOffsetMapEntry};

pub const MAX_CLAIMS_PER_FINDING: usize = 4;
const MAX_RATIONALE_CODES: usize = 16;
const MAX_SAFE_ID_LEN: usize = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum VerifierStatus {
    Confirmed,
    Refuted,
    Overstated,
    Unread,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinderClaim {
    pub record_id: String,
    pub quote: String,
    pub claimed_class: DataClass,
    #[serde(default)]
    pub start_hint: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinderStandardCandidate {
    pub standard_id: String,
    pub label: String,
    pub behaviour_severity: FindingSeverity,
    pub claims: Vec<FinderClaim>,
    pub rationale_codes: Vec<String>,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinderStageResponse {
    pub action: String,
    pub risk_score: u16,
    pub candidates: Vec<FinderStandardCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierSpanQuote {
    pub record_id: String,
    pub text: String,
    #[serde(default)]
    pub start_hint: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierCandidateVerdict {
    pub candidate_index: usize,
    pub status: VerifierStatus,
    pub spans: Vec<VerifierSpanQuote>,
    pub severity_after: FindingSeverity,
    pub explanation: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct VerifierStageResponse {
    pub decisions: Vec<VerifierCandidateVerdict>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedEvidenceSpan {
    pub record_id: String,
    pub keyed_rec_id: String,
    pub exact_quote: String,
    pub claimed_class: DataClass,
    pub span_start: u64,
    pub span_end: u64,
    pub class_commitment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedStandardFinding {
    pub standard_id: String,
    pub label: ReviewFindingLabel,
    pub status: VerifierStatus,
    pub bounded_severity: FindingSeverity,
    pub rationale_codes: Vec<String>,
    pub explanation: InertExplanation,
    pub evidence_spans: Vec<VerifiedEvidenceSpan>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct ReviewCoverage {
    pub records_inspected: usize,
    pub candidates_received: usize,
    pub verified_confirmed: usize,
    pub verified_overstated: usize,
    pub rejected_refuted: usize,
    pub marked_unread: usize,
    pub dropped_missing_record: usize,
    pub dropped_quote_mismatch: usize,
    pub dropped_commitment_mismatch: usize,
    pub dropped_policy_only: usize,
    pub dropped_exceeded_claims: usize,
    pub dropped_invalid_label: usize,
    pub could_not_look: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TwoStageReviewOutcome {
    pub action: ReviewAdvisoryAction,
    pub bounded_risk_score: u16,
    pub findings: Vec<VerifiedStandardFinding>,
    pub coverage: ReviewCoverage,
    pub could_not_look_reason: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExtendedReviewFlag {
    ContentSensitivity,
    UntrustedSink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ModelAdvisoryTier {
    None,
    Low,
    MediumOrAbove,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedReviewSignals {
    pub flags: BTreeSet<ExtendedReviewFlag>,
    pub deterministic_findings_count: usize,
    pub model_advisory: ModelAdvisoryTier,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ExtendedReviewSettings {
    pub base: ReviewSettings,
    pub weight_content_sensitivity: u16,
    pub weight_untrusted_sink: u16,
}

pub struct TwoStageReviewRequest<'a> {
    pub job_mac_key: &'a [u8; 32],
    pub class_salt: &'a [u8; 32],
    pub expected_job_id: &'a str,
    pub transcript_partial: bool,
    pub framed_records: &'a [FramedJobRecord],
    pub source_segments: &'a [SourceSegment],
    pub offset_map: &'a [SpanOffsetMapEntry],
    pub finder: &'a FinderStageResponse,
    pub verifier: &'a VerifierStageResponse,
}

impl Default for ExtendedReviewSettings {
    fn default() -> Self {
        Self {
            base: ReviewSettings::default(),
            weight_content_sensitivity: 30,
            weight_untrusted_sink: 45,
        }
    }
}

/// Executes full two-stage Finder -> QuoteCheck -> Verifier -> SpanBind review (`docs/design/19`).
#[must_use]
pub fn run_two_stage_review(req: &TwoStageReviewRequest<'_>) -> TwoStageReviewOutcome {
    let mut coverage = ReviewCoverage {
        records_inspected: req.framed_records.len(),
        candidates_received: req.finder.candidates.len(),
        ..ReviewCoverage::default()
    };

    if req.finder.candidates.len() > MAX_FINDER_CANDIDATES {
        return abort_with_could_not_look(
            coverage,
            "Finder candidate count exceeded MAX_FINDER_CANDIDATES",
        );
    }
    if req.verifier.decisions.len() > MAX_FINDER_CANDIDATES {
        return abort_with_could_not_look(
            coverage,
            "Verifier decision count exceeded MAX_FINDER_CANDIDATES",
        );
    }
    let mut verdict_by_idx: BTreeMap<usize, &VerifierCandidateVerdict> = BTreeMap::new();
    for decision in &req.verifier.decisions {
        if verdict_by_idx
            .insert(decision.candidate_index, decision)
            .is_some()
        {
            return abort_with_could_not_look(
                coverage,
                "duplicate or conflicting Verifier candidate_index rejected",
            );
        }
    }

    let Some(action) = parse_restrict_only_action(&req.finder.action) else {
        return abort_with_could_not_look(
            coverage,
            "permissive or invalid Finder advisory action rejected",
        );
    };

    if req.transcript_partial && action == ReviewAdvisoryAction::NoChange {
        return abort_with_could_not_look(
            coverage,
            "partial or elided transcript cannot certify NoChange",
        );
    }

    let corpus = match prepare_verified_corpus(
        req.job_mac_key,
        req.class_salt,
        req.expected_job_id,
        req.transcript_partial,
        req.framed_records,
        req.source_segments,
        req.offset_map,
    ) {
        Ok(c) => c,
        Err((code, msg)) => return abort_with_could_not_look(coverage, &format!("{code}: {msg}")),
    };

    let mut out_findings = Vec::new();
    for (idx, candidate) in req.finder.candidates.iter().enumerate() {
        let Some(label) = ReviewFindingLabel::parse_strict(&candidate.label) else {
            coverage.dropped_invalid_label = coverage.dropped_invalid_label.saturating_add(1);
            continue;
        };
        if !is_safe_ascii_id(&candidate.standard_id) {
            coverage.dropped_invalid_label = coverage.dropped_invalid_label.saturating_add(1);
            continue;
        }
        if candidate.claims.is_empty() || candidate.claims.len() > MAX_CLAIMS_PER_FINDING {
            coverage.dropped_exceeded_claims = coverage.dropped_exceeded_claims.saturating_add(1);
            continue;
        }
        let finder_cap_sev = cap_model_severity(candidate.behaviour_severity);

        let mut candidate_failed_claim = false;
        let mut saw_elision_in_claim = req.transcript_partial;
        let mut finder_verified_any = false;

        for claim in &candidate.claims {
            match verify_and_locate_quote(
                &corpus,
                &claim.record_id,
                &claim.quote,
                claim.claimed_class,
                claim.start_hint,
            ) {
                Ok(span) => {
                    saw_elision_in_claim = saw_elision_in_claim || span.record_was_elided;
                    finder_verified_any = true;
                }
                Err((reason, _, _)) => {
                    record_drop_reason(&mut coverage, reason);
                    candidate_failed_claim = true;
                }
            }
        }
        if candidate_failed_claim || !finder_verified_any {
            continue;
        }

        let Some(&verdict) = verdict_by_idx.get(&idx) else {
            coverage.marked_unread = coverage.marked_unread.saturating_add(1);
            continue;
        };

        if verdict.status == VerifierStatus::Refuted {
            coverage.rejected_refuted = coverage.rejected_refuted.saturating_add(1);
            continue;
        }

        let mut verified_spans = Vec::new();
        for vspan in &verdict.spans {
            let Some(matching_class) = candidate
                .claims
                .iter()
                .find(|c| c.record_id == vspan.record_id)
                .map(|c| c.claimed_class)
            else {
                coverage.dropped_missing_record = coverage.dropped_missing_record.saturating_add(1);
                continue;
            };
            match verify_and_locate_quote(
                &corpus,
                &vspan.record_id,
                &vspan.text,
                matching_class,
                vspan.start_hint,
            ) {
                Ok(span) => {
                    saw_elision_in_claim = saw_elision_in_claim || span.record_was_elided;
                    verified_spans.push(to_evidence_span(span));
                }
                Err((reason, _, _)) => {
                    record_drop_reason(&mut coverage, reason);
                }
            }
        }

        if verified_spans.is_empty() {
            coverage.dropped_quote_mismatch = coverage.dropped_quote_mismatch.saturating_add(1);
            continue;
        }

        let effective_status = if saw_elision_in_claim
            && matches!(
                verdict.status,
                VerifierStatus::Confirmed | VerifierStatus::Overstated
            ) {
            VerifierStatus::Unread
        } else {
            verdict.status
        };

        match effective_status {
            VerifierStatus::Confirmed => {
                coverage.verified_confirmed = coverage.verified_confirmed.saturating_add(1);
            }
            VerifierStatus::Overstated => {
                coverage.verified_overstated = coverage.verified_overstated.saturating_add(1);
            }
            VerifierStatus::Unread => {
                coverage.marked_unread = coverage.marked_unread.saturating_add(1);
                continue;
            }
            VerifierStatus::Refuted => {
                coverage.rejected_refuted = coverage.rejected_refuted.saturating_add(1);
                continue;
            }
        }

        let safe_rationale_codes: Vec<String> = candidate
            .rationale_codes
            .iter()
            .filter(|code| is_safe_ascii_id(code))
            .take(MAX_RATIONALE_CODES)
            .cloned()
            .collect();

        let bounded_sev = min_severity(cap_model_severity(verdict.severity_after), finder_cap_sev);
        let inert_text = if verdict.explanation.trim().is_empty() {
            render_inert_explanation(&candidate.explanation)
        } else {
            render_inert_explanation(&verdict.explanation)
        };

        out_findings.push(VerifiedStandardFinding {
            standard_id: candidate.standard_id.clone(),
            label,
            status: effective_status,
            bounded_severity: bounded_sev,
            rationale_codes: safe_rationale_codes,
            explanation: inert_text,
            evidence_spans: verified_spans,
        });
    }

    let has_substantive_finding = out_findings.iter().any(|f| {
        matches!(
            f.status,
            VerifierStatus::Confirmed | VerifierStatus::Overstated
        )
    });
    if !has_substantive_finding
        && (action != ReviewAdvisoryAction::NoChange || req.finder.risk_score > 0)
    {
        return abort_with_could_not_look(
            coverage,
            "non-zero advisory action or risk requires at least one Confirmed or Overstated finding",
        );
    }

    TwoStageReviewOutcome {
        action,
        bounded_risk_score: req.finder.risk_score.min(250),
        findings: out_findings,
        coverage,
        could_not_look_reason: None,
    }
}

/// Computes doc 18 + doc 19 queue score where deterministic findings and content/sink
/// terms additively increase review priority and model findings never suppress priority.
#[must_use]
pub fn compute_extended_queue_score(
    cand: &ReviewCandidate,
    ext: &ExtendedReviewSignals,
    settings: &ExtendedReviewSettings,
) -> u16 {
    let mut score = compute_priority_score(cand, &settings.base);
    if ext.flags.contains(&ExtendedReviewFlag::ContentSensitivity) {
        score = score.saturating_add(settings.weight_content_sensitivity);
    }
    if ext.flags.contains(&ExtendedReviewFlag::UntrustedSink) {
        score = score.saturating_add(settings.weight_untrusted_sink);
    }
    if ext.deterministic_findings_count > 0 {
        score = score.saturating_add(100);
    }
    if ext.model_advisory == ModelAdvisoryTier::MediumOrAbove {
        score = score.saturating_add(40);
    }
    score
}

fn is_safe_ascii_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_SAFE_ID_LEN
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}

fn to_evidence_span(span: VerifiedQuoteSpan) -> VerifiedEvidenceSpan {
    VerifiedEvidenceSpan {
        record_id: span.record_id,
        keyed_rec_id: span.keyed_rec_id,
        exact_quote: span.exact_quote,
        claimed_class: span.claimed_class,
        span_start: span.span_start,
        span_end: span.span_end,
        class_commitment_sha256: span.class_commitment_sha256,
    }
}

fn abort_with_could_not_look(mut coverage: ReviewCoverage, reason: &str) -> TwoStageReviewOutcome {
    coverage.could_not_look = true;
    TwoStageReviewOutcome {
        action: ReviewAdvisoryAction::NoChange,
        bounded_risk_score: 0,
        findings: Vec::new(),
        coverage,
        could_not_look_reason: Some(reason.to_owned()),
    }
}

fn record_drop_reason(coverage: &mut ReviewCoverage, reason: QuoteVerifyFailure) {
    match reason {
        QuoteVerifyFailure::MissingRecord => {
            coverage.dropped_missing_record = coverage.dropped_missing_record.saturating_add(1);
        }
        QuoteVerifyFailure::PolicyOnly => {
            coverage.dropped_policy_only = coverage.dropped_policy_only.saturating_add(1);
        }
        QuoteVerifyFailure::QuoteMismatch => {
            coverage.dropped_quote_mismatch = coverage.dropped_quote_mismatch.saturating_add(1);
        }
        QuoteVerifyFailure::CommitmentOrSpanMismatch => {
            coverage.dropped_commitment_mismatch =
                coverage.dropped_commitment_mismatch.saturating_add(1);
        }
    }
}

fn cap_model_severity(sev: FindingSeverity) -> FindingSeverity {
    match sev {
        FindingSeverity::Critical => FindingSeverity::High,
        other => other,
    }
}

fn min_severity(a: FindingSeverity, b: FindingSeverity) -> FindingSeverity {
    if severity_rank(a) <= severity_rank(b) {
        a
    } else {
        b
    }
}

fn severity_rank(sev: FindingSeverity) -> u8 {
    match sev {
        FindingSeverity::Low => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::High => 3,
        FindingSeverity::Critical => 4,
    }
}
