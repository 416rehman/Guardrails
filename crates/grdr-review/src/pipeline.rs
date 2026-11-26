// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Per-job `QuoteCheck`, salted `SpanBind`, and P2 restrict-only Verifier (`docs/design/19`, `D-29`).

use std::collections::{BTreeMap, BTreeSet};

use serde::{Deserialize, Serialize};

use grdr_crypto::constant_time_eq;
use grdr_model::DataClass;

pub use crate::job_frame::{
    CODE_REV_FRAMING_INVALID, FramedJobRecord, seal_job_record, seal_job_record_with_commitment,
    seal_reduced_transcript, verify_job_record,
};
pub use crate::reducer::{
    ELISION_MARKER, MAX_REDUCED_TOKENS, ReducedTranscript, ReviewRecordKind, SourceSegment,
    SpanOffsetMapEntry, reduce_for_review, salted_class_commitment,
};
use crate::span_bind::{
    locate_verified_span, map_reduced_span_to_source, normalize_for_quotecheck,
    validate_offset_map, verify_decoded_against_offset_map,
};

pub const CODE_REV_QUOTE_CHECK_FAILED: &str = "GRDR-REV-0005";
pub const CODE_REV_SPAN_BIND_FAILED: &str = "GRDR-REV-0006";

pub const MIN_QUOTE_CHARS: usize = 12;
pub const MAX_QUOTE_CHARS: usize = 300;
pub const MAX_RAW_QUOTE_BYTES: usize = 2_048;
pub const MAX_FINDER_CANDIDATES: usize = 16;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewAdvisoryAction {
    NoChange,
    AddAdvisoryLabel,
    RaiseReviewPriority,
    EscalateFinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewFindingLabel {
    PromptInjectionSuspected,
    SecretExposureSuspected,
    PolicyEvasionSuspected,
    CredentialHarvesting,
    MonitoringTamper,
    DataOverCollection,
    UnsanctionedAction,
    SemanticIntentDrift,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinderFindingCandidate {
    pub record_id: String,
    pub label: String,
    pub exact_quote: String,
    pub claimed_class: DataClass,
    #[serde(default)]
    pub start_hint: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FinderRawResponse {
    pub action: String,
    pub risk_score: u16,
    pub findings: Vec<FinderFindingCandidate>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedFinding {
    pub record_id: String,
    pub keyed_rec_id: String,
    pub label: ReviewFindingLabel,
    pub exact_quote: String,
    pub claimed_class: DataClass,
    pub span_start: u64,
    pub span_end: u64,
    pub class_commitment_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifiedFinderOutcome {
    pub action: ReviewAdvisoryAction,
    pub bounded_risk_score: u16,
    pub verified_findings: Vec<VerifiedFinding>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum ReviewPipelineOutcome {
    Verified(VerifiedFinderOutcome),
    CouldNotLook { reason: String },
}

impl ReviewFindingLabel {
    #[must_use]
    pub fn parse_strict(raw: &str) -> Option<Self> {
        match raw {
            "prompt_injection_suspected" => Some(Self::PromptInjectionSuspected),
            "secret_exposure_suspected" => Some(Self::SecretExposureSuspected),
            "policy_evasion_suspected" => Some(Self::PolicyEvasionSuspected),
            "credential_harvesting" => Some(Self::CredentialHarvesting),
            "monitoring_tamper" => Some(Self::MonitoringTamper),
            "data_over_collection" => Some(Self::DataOverCollection),
            "unsanctioned_action" => Some(Self::UnsanctionedAction),
            "semantic_intent_drift" => Some(Self::SemanticIntentDrift),
            _ => None,
        }
    }
}

/// Runs Finder `QuoteCheck`, salted `SpanBind` commitment verification, and P2 Verifier
/// over full (unreduced) source segments.
#[must_use]
pub fn run_finder_verifier(
    job_mac_key: &[u8; 32],
    class_salt: &[u8; 32],
    expected_job_id: &str,
    transcript_partial: bool,
    framed_records: &[FramedJobRecord],
    source_segments: &[SourceSegment],
    raw_finder: &FinderRawResponse,
) -> ReviewPipelineOutcome {
    run_finder_verifier_with_offset_map(
        job_mac_key,
        class_salt,
        expected_job_id,
        transcript_partial,
        framed_records,
        source_segments,
        &[],
        raw_finder,
    )
}

/// Runs Finder `QuoteCheck`, salted `SpanBind` commitment verification with optional
/// `ReducedTranscript::offset_map` mapping, and P2 Verifier.
#[must_use]
#[allow(clippy::too_many_arguments)]
pub fn run_finder_verifier_with_offset_map(
    job_mac_key: &[u8; 32],
    class_salt: &[u8; 32],
    expected_job_id: &str,
    transcript_partial: bool,
    framed_records: &[FramedJobRecord],
    source_segments: &[SourceSegment],
    offset_map: &[SpanOffsetMapEntry],
    raw_finder: &FinderRawResponse,
) -> ReviewPipelineOutcome {
    let Some(action) = parse_restrict_only_action(&raw_finder.action) else {
        return could_not_look(
            CODE_REV_FRAMING_INVALID,
            "permissive or invalid P2 action rejected",
        );
    };
    if raw_finder.findings.len() > MAX_FINDER_CANDIDATES {
        return could_not_look(
            CODE_REV_QUOTE_CHECK_FAILED,
            "candidate findings exceed bound",
        );
    }

    let mut source_by_id: BTreeMap<&str, &SourceSegment> = BTreeMap::new();
    for seg in source_segments {
        if source_by_id.insert(seg.record_id.as_str(), seg).is_some() {
            return could_not_look(CODE_REV_FRAMING_INVALID, "duplicate source record_id");
        }
    }
    if !transcript_partial && framed_records.len() != source_segments.len() {
        return could_not_look(
            CODE_REV_FRAMING_INVALID,
            "full transcript framed record count mismatch",
        );
    }

    let grouped_offsets = if offset_map.is_empty() {
        None
    } else {
        let Ok(map) = validate_offset_map(offset_map, &source_by_id, class_salt) else {
            return could_not_look(
                CODE_REV_SPAN_BIND_FAILED,
                "reduced transcript offset_map verification failed",
            );
        };
        Some(map)
    };

    let mut seen_ids = BTreeSet::new();
    let mut framed_by_tag: BTreeMap<&str, (&FramedJobRecord, String)> = BTreeMap::new();
    for f in framed_records {
        let Ok(decoded_text) = verify_job_record(job_mac_key, expected_job_id, f) else {
            return could_not_look(CODE_REV_FRAMING_INVALID, "job frame verification failed");
        };
        if framed_by_tag.contains_key(f.keyed_rec_id.as_str())
            || !seen_ids.insert(f.record_id.as_str())
        {
            return could_not_look(
                CODE_REV_FRAMING_INVALID,
                "duplicate framed record identifier",
            );
        }
        let Some(src) = source_by_id.get(f.record_id.as_str()) else {
            return could_not_look(
                CODE_REV_FRAMING_INVALID,
                "framed record missing source segment",
            );
        };
        if src.data_class != f.data_class || src.kind != f.kind {
            return could_not_look(
                CODE_REV_SPAN_BIND_FAILED,
                "framed content or class mismatch",
            );
        }
        let expected_commit =
            salted_class_commitment(class_salt, &src.record_id, src.data_class, &src.text);
        if !constant_time_eq(
            expected_commit.as_bytes(),
            f.class_commitment_sha256.as_bytes(),
        ) {
            return could_not_look(
                CODE_REV_SPAN_BIND_FAILED,
                "sensor class commitment mismatch",
            );
        }
        if let Some(ref map) = grouped_offsets {
            let Some(entries) = map.get(f.record_id.as_str()) else {
                return could_not_look(
                    CODE_REV_SPAN_BIND_FAILED,
                    "reduced framed record missing offset_map entries",
                );
            };
            if !verify_decoded_against_offset_map(
                &decoded_text,
                &src.text,
                entries,
                transcript_partial,
            ) {
                return could_not_look(
                    CODE_REV_SPAN_BIND_FAILED,
                    "reduced record text diverges from offset_map or source",
                );
            }
        } else if decoded_text != src.text {
            return could_not_look(
                CODE_REV_SPAN_BIND_FAILED,
                "framed content or class mismatch",
            );
        }
        framed_by_tag.insert(f.keyed_rec_id.as_str(), (f, decoded_text));
    }

    if transcript_partial && action == ReviewAdvisoryAction::NoChange {
        return could_not_look(
            CODE_REV_QUOTE_CHECK_FAILED,
            "partial transcript cannot be verified as no_change",
        );
    }

    if (action != ReviewAdvisoryAction::NoChange || raw_finder.risk_score > 0)
        && raw_finder.findings.is_empty()
    {
        return could_not_look(
            CODE_REV_QUOTE_CHECK_FAILED,
            "non-trivial action or score requires grounded findings",
        );
    }

    let mut verified_findings = Vec::with_capacity(raw_finder.findings.len());
    for candidate in &raw_finder.findings {
        let Some(label) = ReviewFindingLabel::parse_strict(&candidate.label) else {
            return could_not_look(
                CODE_REV_QUOTE_CHECK_FAILED,
                "unknown advisory label rejected",
            );
        };
        let Some(&(framed, ref decoded_text)) = framed_by_tag.get(candidate.record_id.as_str())
        else {
            return could_not_look(CODE_REV_QUOTE_CHECK_FAILED, "unknown or unframed record_id");
        };
        let Some(src) = source_by_id.get(framed.record_id.as_str()) else {
            return could_not_look(CODE_REV_QUOTE_CHECK_FAILED, "source record missing");
        };
        if src.kind == ReviewRecordKind::Policy {
            return could_not_look(
                CODE_REV_QUOTE_CHECK_FAILED,
                "findings cannot cite trusted policy records",
            );
        }
        if candidate.exact_quote.is_empty() || candidate.exact_quote.len() > MAX_RAW_QUOTE_BYTES {
            return could_not_look(
                CODE_REV_QUOTE_CHECK_FAILED,
                "raw quote byte length outside 1..=2048 bound",
            );
        }

        let norm_quote = normalize_for_quotecheck(&candidate.exact_quote);
        let q_chars = norm_quote.chars().count();
        if !(MIN_QUOTE_CHARS..=MAX_QUOTE_CHARS).contains(&q_chars) {
            return could_not_look(
                CODE_REV_QUOTE_CHECK_FAILED,
                "quote length outside 12..=300 char bound",
            );
        }
        if candidate.claimed_class != framed.data_class {
            return could_not_look(CODE_REV_SPAN_BIND_FAILED, "claimed data_class mismatch");
        }
        let Some((red_start, red_end)) = locate_verified_span(
            decoded_text,
            &candidate.exact_quote,
            &norm_quote,
            candidate.start_hint,
        ) else {
            return could_not_look(
                CODE_REV_SPAN_BIND_FAILED,
                "span could not be uniquely located in source record",
            );
        };
        if red_end.saturating_sub(red_start) > MAX_RAW_QUOTE_BYTES {
            return could_not_look(
                CODE_REV_QUOTE_CHECK_FAILED,
                "located span exceeds maximum quote byte bound",
            );
        }

        let (span_start, span_end) = if let Some(ref map) = grouped_offsets {
            let Some(entries) = map.get(framed.record_id.as_str()) else {
                return could_not_look(CODE_REV_SPAN_BIND_FAILED, "missing record offset entries");
            };
            let Some(mapped) = map_reduced_span_to_source(entries, red_start, red_end) else {
                return could_not_look(
                    CODE_REV_SPAN_BIND_FAILED,
                    "span overlaps elision marker or unmapped region",
                );
            };
            mapped
        } else {
            (red_start, red_end)
        };

        let Some(verified_slice) = src.text.get(span_start..span_end) else {
            return could_not_look(
                CODE_REV_SPAN_BIND_FAILED,
                "mapped source span out of bounds",
            );
        };
        if decoded_text.get(red_start..red_end) != Some(verified_slice) {
            return could_not_look(CODE_REV_SPAN_BIND_FAILED, "mapped source slice mismatch");
        }

        verified_findings.push(VerifiedFinding {
            record_id: framed.record_id.clone(),
            keyed_rec_id: framed.keyed_rec_id.clone(),
            label,
            exact_quote: verified_slice.to_owned(),
            claimed_class: framed.data_class,
            span_start: u64::try_from(span_start).unwrap_or(u64::MAX),
            span_end: u64::try_from(span_end).unwrap_or(u64::MAX),
            class_commitment_sha256: framed.class_commitment_sha256.clone(),
        });
    }

    ReviewPipelineOutcome::Verified(VerifiedFinderOutcome {
        action,
        bounded_risk_score: raw_finder.risk_score.min(250),
        verified_findings,
    })
}

fn could_not_look(code: &str, safe_msg: &str) -> ReviewPipelineOutcome {
    ReviewPipelineOutcome::CouldNotLook {
        reason: format!("{code}: {safe_msg}"),
    }
}

fn parse_restrict_only_action(raw: &str) -> Option<ReviewAdvisoryAction> {
    match raw {
        "no_change" => Some(ReviewAdvisoryAction::NoChange),
        "add_advisory_label" => Some(ReviewAdvisoryAction::AddAdvisoryLabel),
        "raise_review_priority" => Some(ReviewAdvisoryAction::RaiseReviewPriority),
        "escalate_finding" => Some(ReviewAdvisoryAction::EscalateFinding),
        _ => None,
    }
}
