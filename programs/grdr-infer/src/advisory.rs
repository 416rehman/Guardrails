// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Restrict-only P2 advisory output types.
//!
//! By type construction, `grdr-infer` cannot represent `Allow`, `Grant`,
//! `Suppress`, `Clear`, `Modify`, or rule-bypass outcomes.

use std::collections::BTreeSet;

use serde::{Deserialize, Deserializer, Serialize};

use grdr_model::FindingSeverity;

use crate::InferError;

pub const MAX_BOUNDED_RISK_SCORE: u16 = 250;
pub const MAX_ADVISORY_QUOTE_BYTES: usize = 512;

/// Closed restrict-only advisory actions.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryAction {
    NoChange,
    TightenToStepUp,
    EscalateFinding,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisorySeverityCap {
    Info,
    Low,
    Medium,
    High,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AdvisoryLabel {
    PromptInjectionSuspected,
    SecretExposureSuspected,
    PolicyEvasionSuspected,
    AnomalousToolSequence,
    SemanticIntentDrift,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnavailableReason {
    Timeout,
    ModelFault,
    MalformedOutput,
    TamperedFrame,
    QuoteNotGrounded,
    PermissiveOutputRejected,
}

/// Risk contribution bounded at `<= 250` on the total risk scale.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub struct BoundedRiskScore(u16);

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FindingCandidate {
    pub record_id: String,
    pub label: AdvisoryLabel,
    pub severity: AdvisorySeverityCap,
    pub exact_quote: String,
    pub confidence_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct VerifiedAdvisory {
    pub action: AdvisoryAction,
    pub risk_score: BoundedRiskScore,
    pub labels: BTreeSet<AdvisoryLabel>,
    pub findings: Vec<FindingCandidate>,
    pub evaluator_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", content = "detail", rename_all = "snake_case")]
pub enum ModelAdvisorySignal {
    Advisory(VerifiedAdvisory),
    CouldNotLook(UnavailableReason),
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RawJudgeResponse {
    pub action: String,
    pub risk_score: u16,
    #[serde(default)]
    pub labels: Vec<AdvisoryLabel>,
    #[serde(default)]
    pub findings: Vec<FindingCandidate>,
    pub evaluator_id: String,
}

impl<'de> Deserialize<'de> for BoundedRiskScore {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = u16::deserialize(deserializer)?;
        Self::try_new(raw).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for AdvisoryAction {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = String::deserialize(deserializer)?;
        Self::parse_strict(&raw).map_err(serde::de::Error::custom)
    }
}

impl<'de> Deserialize<'de> for VerifiedAdvisory {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct WireVerified {
            action: AdvisoryAction,
            risk_score: BoundedRiskScore,
            labels: BTreeSet<AdvisoryLabel>,
            findings: Vec<FindingCandidate>,
            evaluator_id: String,
        }

        let wire = WireVerified::deserialize(deserializer)?;
        if wire.evaluator_id.trim().is_empty() {
            return Err(serde::de::Error::custom("evaluator_id cannot be empty"));
        }
        for candidate in &wire.findings {
            if candidate.record_id.trim().is_empty()
                || candidate.exact_quote.is_empty()
                || candidate.exact_quote.len() > MAX_ADVISORY_QUOTE_BYTES
                || candidate.confidence_bps > 10_000
            {
                return Err(serde::de::Error::custom(
                    "invalid FindingCandidate field bounds in VerifiedAdvisory",
                ));
            }
        }
        Ok(Self {
            action: wire.action,
            risk_score: wire.risk_score,
            labels: wire.labels,
            findings: wire.findings,
            evaluator_id: wire.evaluator_id,
        })
    }
}

impl BoundedRiskScore {
    #[must_use]
    pub const fn clamped(raw: u16) -> Self {
        if raw > MAX_BOUNDED_RISK_SCORE {
            Self(MAX_BOUNDED_RISK_SCORE)
        } else {
            Self(raw)
        }
    }

    pub fn try_new(raw: u16) -> Result<Self, InferError> {
        if raw > MAX_BOUNDED_RISK_SCORE {
            return Err(InferError::InvalidInput(format!(
                "risk score {raw} exceeds P2 bound {MAX_BOUNDED_RISK_SCORE}"
            )));
        }
        Ok(Self(raw))
    }

    #[must_use]
    pub const fn get(self) -> u16 {
        self.0
    }
}

impl AdvisoryAction {
    pub fn parse_strict(raw: &str) -> Result<Self, InferError> {
        let normalized = raw.trim().to_ascii_lowercase();
        match normalized.as_str() {
            "no_change" => Ok(Self::NoChange),
            "tighten_to_step_up" => Ok(Self::TightenToStepUp),
            "escalate_finding" => Ok(Self::EscalateFinding),
            other => Err(InferError::PermissiveOutputRejected(other.to_owned())),
        }
    }
}

impl AdvisorySeverityCap {
    #[must_use]
    pub const fn into_finding_severity(self) -> FindingSeverity {
        match self {
            Self::Info | Self::Low => FindingSeverity::Low,
            Self::Medium => FindingSeverity::Medium,
            Self::High => FindingSeverity::High,
        }
    }
}

impl FindingCandidate {
    /// Verifies that `exact_quote` is non-empty, within bounds, and grounded inside `verified_text`.
    pub fn verify_grounded(
        &self,
        expected_record_id: &str,
        verified_text: &str,
    ) -> Result<(), InferError> {
        if self.record_id != expected_record_id {
            return Err(InferError::UngroundedQuote(format!(
                "record_id mismatch: expected `{expected_record_id}`, got `{}`",
                self.record_id
            )));
        }
        if self.exact_quote.is_empty() || self.exact_quote.len() > MAX_ADVISORY_QUOTE_BYTES {
            return Err(InferError::UngroundedQuote(
                "exact_quote must be non-empty and within byte bound".into(),
            ));
        }
        if self.confidence_bps > 10_000 {
            return Err(InferError::InvalidInput(format!(
                "confidence_bps {} exceeds 10000",
                self.confidence_bps
            )));
        }
        if !verified_text.contains(&self.exact_quote) {
            return Err(InferError::UngroundedQuote(
                "quote text does not appear verbatim in verified record".into(),
            ));
        }
        Ok(())
    }
}

pub fn parse_raw_judge_json(
    raw_json: &str,
    expected_record_id: &str,
    verified_text: &str,
) -> ModelAdvisorySignal {
    let parsed: RawJudgeResponse = match serde_json::from_str(raw_json) {
        Ok(val) => val,
        Err(_) => return ModelAdvisorySignal::CouldNotLook(UnavailableReason::MalformedOutput),
    };

    let action = match AdvisoryAction::parse_strict(&parsed.action) {
        Ok(act) => act,
        Err(_) => {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::PermissiveOutputRejected);
        }
    };

    if parsed.evaluator_id.trim().is_empty() {
        return ModelAdvisorySignal::CouldNotLook(UnavailableReason::MalformedOutput);
    }

    for candidate in &parsed.findings {
        if candidate
            .verify_grounded(expected_record_id, verified_text)
            .is_err()
        {
            return ModelAdvisorySignal::CouldNotLook(UnavailableReason::QuoteNotGrounded);
        }
    }

    let labels: BTreeSet<AdvisoryLabel> = parsed.labels.into_iter().collect();
    ModelAdvisorySignal::Advisory(VerifiedAdvisory {
        action,
        risk_score: BoundedRiskScore::clamped(parsed.risk_score),
        labels,
        findings: parsed.findings,
        evaluator_id: parsed.evaluator_id,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_permissive_judge_outputs_and_caps_risk_score() {
        for forbidden in [
            "allow",
            "grant",
            "suppress",
            "clear",
            "modify",
            "declassify",
            "Allow",
        ] {
            let payload = serde_json::json!({
                "action": forbidden,
                "risk_score": 10,
                "labels": [],
                "findings": [],
                "evaluator_id": "judge-local"
            })
            .to_string();
            assert_eq!(
                parse_raw_judge_json(&payload, "rec-1", "hello"),
                ModelAdvisorySignal::CouldNotLook(UnavailableReason::PermissiveOutputRejected)
            );
        }

        let clamped = BoundedRiskScore::clamped(999);
        assert_eq!(clamped.get(), MAX_BOUNDED_RISK_SCORE);
        assert!(BoundedRiskScore::try_new(251).is_err());
    }
}
