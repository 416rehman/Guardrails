// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Deterministic review queue scoring, unbiased HMAC lineage sampling, judge canaries,
//! and `llm.tokens` usage metering (`docs/design/19`, `D-29`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use grdr_crypto::domain_hmac_sha256;
use grdr_model::{CodedError, FindingSeverity};

pub const CODE_REV_CANARY_FAILED: &str = "GRDR-REV-0008";
pub const CODE_REV_TOKEN_BUDGET_EXCEEDED: &str = "GRDR-REV-0009";
pub const DEFAULT_SAMPLE_RATE_BP: u16 = 20;
const SAMPLE_DOMAIN: &str = "grdr.review.lineage-sample.v1";
const REJECTION_LIMIT_U16: u16 = 60_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateSignal {
    TaintExfil,
    MalformedExec,
    NovelHostHit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewSettings {
    pub weight_finding_severity: u16,
    pub weight_taint_exfil: u16,
    pub weight_malformed_exec: u16,
    pub weight_novel_host: u16,
    pub sample_rate_bp: u16,
    pub max_token_budget: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum QueueReason {
    HighPriorityScore,
    HmacLineageSample,
    JudgeCanary,
    SkippedBelowThreshold,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewCandidate {
    pub session_id: String,
    pub root_session_id: String,
    pub max_severity: Option<FindingSeverity>,
    pub signals: BTreeSet<CandidateSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PriorityDecision {
    pub score: u16,
    pub enqueue: bool,
    pub reason: QueueReason,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JudgeCanaryCase {
    pub canary_id: String,
    pub input_text: String,
    pub expected_label: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryCheckStatus {
    Passed,
    RecallMissed,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct TokenBudgetTracker {
    pub prompt_tokens: u64,
    pub completion_tokens: u64,
    pub cached_tokens: u64,
}

impl Default for ReviewSettings {
    fn default() -> Self {
        Self {
            weight_finding_severity: 40,
            weight_taint_exfil: 60,
            weight_malformed_exec: 50,
            weight_novel_host: 25,
            sample_rate_bp: DEFAULT_SAMPLE_RATE_BP,
            max_token_budget: 500_000,
        }
    }
}

/// Deterministic queue priority scoring without runtime RNG (`docs/design/19`).
#[must_use]
pub fn compute_priority_score(cand: &ReviewCandidate, settings: &ReviewSettings) -> u16 {
    let mut score: u16 = 0;
    let sev_mult = match cand.max_severity {
        Some(FindingSeverity::Critical) => 4_u16,
        Some(FindingSeverity::High) => 3_u16,
        Some(FindingSeverity::Medium) => 2_u16,
        Some(FindingSeverity::Low) => 1_u16,
        None => 0_u16,
    };
    score = score.saturating_add(settings.weight_finding_severity.saturating_mul(sev_mult));
    if cand.signals.contains(&CandidateSignal::TaintExfil) {
        score = score.saturating_add(settings.weight_taint_exfil);
    }
    if cand.signals.contains(&CandidateSignal::MalformedExec) {
        score = score.saturating_add(settings.weight_malformed_exec);
    }
    if cand.signals.contains(&CandidateSignal::NovelHostHit) {
        score = score.saturating_add(settings.weight_novel_host);
    }
    score
}

/// Deterministic unbiased keyed HMAC-SHA256 lineage sampling (default `20 bp` = `0.2%`).
#[must_use]
pub fn should_sample_lineage(sample_key: &[u8; 32], root_session_id: &str, rate_bp: u16) -> bool {
    if rate_bp == 0 {
        return false;
    }
    if rate_bp >= 10_000 {
        return true;
    }
    let tag = domain_hmac_sha256(sample_key, SAMPLE_DOMAIN, root_session_id.as_bytes());
    for &[lo, hi] in tag.as_chunks::<2>().0 {
        let val = u16::from_le_bytes([lo, hi]);
        if val < REJECTION_LIMIT_U16 {
            return (val % 10_000) < rate_bp;
        }
    }
    let word = u64::from_le_bytes([
        *tag.first().unwrap_or(&0),
        *tag.get(1).unwrap_or(&0),
        *tag.get(2).unwrap_or(&0),
        *tag.get(3).unwrap_or(&0),
        *tag.get(4).unwrap_or(&0),
        *tag.get(5).unwrap_or(&0),
        *tag.get(6).unwrap_or(&0),
        *tag.get(7).unwrap_or(&0),
    ]);
    let scaled = (u128::from(word).saturating_mul(10_000)) >> 64;
    scaled < u128::from(rate_bp)
}

#[must_use]
pub fn evaluate_queue_admission(
    cand: &ReviewCandidate,
    settings: &ReviewSettings,
    sample_key: &[u8; 32],
    priority_threshold: u16,
) -> PriorityDecision {
    let score = compute_priority_score(cand, settings);
    if score >= priority_threshold {
        return PriorityDecision {
            score,
            enqueue: true,
            reason: QueueReason::HighPriorityScore,
        };
    }
    if should_sample_lineage(sample_key, &cand.root_session_id, settings.sample_rate_bp) {
        return PriorityDecision {
            score,
            enqueue: true,
            reason: QueueReason::HmacLineageSample,
        };
    }
    PriorityDecision {
        score,
        enqueue: false,
        reason: QueueReason::SkippedBelowThreshold,
    }
}

pub fn verify_judge_canary(
    canary: &JudgeCanaryCase,
    observed_labels: &[String],
) -> Result<CanaryCheckStatus, CodedError> {
    if observed_labels.iter().any(|l| l == &canary.expected_label) {
        Ok(CanaryCheckStatus::Passed)
    } else {
        Err(CodedError::new(
            CODE_REV_CANARY_FAILED,
            format!(
                "judge canary `{}` missed expected label `{}`",
                canary.canary_id, canary.expected_label
            ),
            "Mark judge pipeline degraded and avoid relying on recall.",
        ))
    }
}

impl TokenBudgetTracker {
    #[must_use]
    pub const fn total_tokens(&self) -> u64 {
        self.prompt_tokens
            .saturating_add(self.completion_tokens)
            .saturating_add(self.cached_tokens)
    }

    pub fn record_usage(
        &mut self,
        prompt: u64,
        completion: u64,
        cached: u64,
        budget_limit: u64,
    ) -> Result<(), CodedError> {
        let next_total = self
            .prompt_tokens
            .checked_add(self.completion_tokens)
            .and_then(|t| t.checked_add(self.cached_tokens))
            .and_then(|t| t.checked_add(prompt))
            .and_then(|t| t.checked_add(completion))
            .and_then(|t| t.checked_add(cached))
            .ok_or_else(|| {
                CodedError::new(
                    CODE_REV_TOKEN_BUDGET_EXCEEDED,
                    "review llm.tokens budget counter overflowed",
                    "Collapse queued LLM review calls to could_not_look when budget exhausted.",
                )
            })?;
        if next_total > budget_limit {
            return Err(CodedError::new(
                CODE_REV_TOKEN_BUDGET_EXCEEDED,
                format!("review llm.tokens budget exceeded ({next_total} > {budget_limit})"),
                "Collapse queued LLM review calls to could_not_look when budget exhausted.",
            ));
        }
        self.prompt_tokens = self.prompt_tokens.checked_add(prompt).ok_or_else(|| {
            CodedError::new(
                CODE_REV_TOKEN_BUDGET_EXCEEDED,
                "review prompt_tokens counter overflowed",
                "Collapse queued LLM review calls to could_not_look when budget exhausted.",
            )
        })?;
        self.completion_tokens =
            self.completion_tokens
                .checked_add(completion)
                .ok_or_else(|| {
                    CodedError::new(
                        CODE_REV_TOKEN_BUDGET_EXCEEDED,
                        "review completion_tokens counter overflowed",
                        "Collapse queued LLM review calls to could_not_look when budget exhausted.",
                    )
                })?;
        self.cached_tokens = self.cached_tokens.checked_add(cached).ok_or_else(|| {
            CodedError::new(
                CODE_REV_TOKEN_BUDGET_EXCEEDED,
                "review cached_tokens counter overflowed",
                "Collapse queued LLM review calls to could_not_look when budget exhausted.",
            )
        })?;
        Ok(())
    }
}
