// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Prompt/model/review-settings packs, org escalation standards, judge canary isolation,
//! never-model-dependent lints, and per-bucket token budgets (`docs/design/19`).

use std::collections::{BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use grdr_crypto::{encode_lower_hex, sha256_digest};
use grdr_model::{CodedError, FindingSeverity};

use crate::inert::{render_inert_explanation, render_inert_with_limit};
pub use crate::packs_budget::{
    ASSISTANTS_BUDGET_SHARE_PCT, AUTHORING_BUDGET_SHARE_PCT, BudgetBucket, REVIEW_BUDGET_SHARE_PCT,
    TokenAllocationLedger,
};
use crate::pipeline::{ReviewFindingLabel, parse_restrict_only_action};
use crate::queue::CODE_REV_CANARY_FAILED;

pub const CODE_REV_PACK_INVALID: &str = "GRDR-REV-0001";
pub const MAX_ESCALATION_STANDARDS: usize = 20;
pub const MAX_STANDARD_GUIDANCE_CHARS: usize = 600;
pub const MAX_CANARY_WINDOW: usize = 50;
const MAX_STANDARD_ID_LEN: usize = 64;

const NEVER_MODEL_DEPENDENT_CLASSES: &[&str] = &[
    "egress",
    "protected-path",
    "agent-config",
    "credential",
    "kill-switch",
    "failure-mode",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PromptPackKind {
    Prompt,
    Model,
    ReviewSettings,
    EscalationStandards,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuleEvaluationKey {
    Deterministic,
    Heuristic,
    Model,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PolicyRuleSourceCheck {
    pub rule_id: String,
    pub rule_class: String,
    pub evaluation_keys: Vec<RuleEvaluationKey>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationStandard {
    pub standard_id: String,
    pub title: String,
    pub guidance: String,
    pub max_severity: FindingSeverity,
    pub canary_expected_label: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationAuditEvent {
    pub event_kind: String,
    pub actor_id: String,
    pub prev_digest_sha256: String,
    pub next_digest_sha256: String,
    pub standards_count: usize,
    pub canary_recall_bps: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EscalationStandardSet {
    pub standards: Vec<EscalationStandard>,
    pub digest_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum PromptRolloutState {
    Shadow,
    Active,
    PackHalted { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PromptPackSpec {
    pub pack_id: String,
    pub version: String,
    pub kind: PromptPackKind,
    pub content_digest_sha256: String,
    pub allowed_advisory_actions: Vec<String>,
    pub rollout_state: PromptRolloutState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelPackSpec {
    pub pack_id: String,
    pub pinned_model_digest_sha256: String,
    pub backend_endpoint: String,
    pub zero_widening_verified: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CanaryProbeObservation {
    pub canary_id: String,
    pub lineage_id: String,
    pub passed: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewHealthState {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CanaryHealthMonitor {
    window: VecDeque<bool>,
    canary_lineages: BTreeSet<String>,
}

fn pack_err(code: &'static str, msg: impl Into<String>, fix: &'static str) -> CodedError {
    CodedError::new(code, msg, fix)
}

impl EscalationStandardSet {
    /// Validates count (`<= 20`), guidance bounds (`<= 600` chars), inert sanitization,
    /// and deterministic digest computation (`AI-15`).
    pub fn validate_and_build(standards: Vec<EscalationStandard>) -> Result<Self, CodedError> {
        if standards.is_empty() || standards.len() > MAX_ESCALATION_STANDARDS {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                format!(
                    "escalation standards count {} out of 1..={MAX_ESCALATION_STANDARDS}",
                    standards.len()
                ),
                "Keep between 1 and 20 escalation standards per organisation.",
            ));
        }
        let mut seen = BTreeSet::new();
        let mut sanitized = Vec::with_capacity(standards.len());
        for std_item in standards {
            if !is_safe_ascii_id(&std_item.standard_id)
                || !seen.insert(std_item.standard_id.clone())
            {
                return Err(pack_err(
                    CODE_REV_PACK_INVALID,
                    format!(
                        "invalid or duplicate escalation standard `{}`",
                        std_item.standard_id
                    ),
                    "Provide unique 1..=64-byte ASCII identifiers (`[A-Za-z0-9._-]`).",
                ));
            }
            if ReviewFindingLabel::parse_strict(&std_item.canary_expected_label).is_none() {
                return Err(pack_err(
                    CODE_REV_PACK_INVALID,
                    format!(
                        "escalation standard `{}` has invalid canary_expected_label",
                        std_item.standard_id
                    ),
                    "Use a closed ReviewFindingLabel variant for canary_expected_label.",
                ));
            }
            let inert_guidance =
                render_inert_with_limit(&std_item.guidance, MAX_STANDARD_GUIDANCE_CHARS);
            if inert_guidance.text.is_empty()
                || std_item.guidance.chars().count() > MAX_STANDARD_GUIDANCE_CHARS
            {
                return Err(pack_err(
                    CODE_REV_PACK_INVALID,
                    format!(
                        "escalation standard `{}` guidance invalid or > {MAX_STANDARD_GUIDANCE_CHARS} chars",
                        std_item.standard_id
                    ),
                    "Trim and sanitize guidance text within 600 chars.",
                ));
            }
            let inert_title = render_inert_explanation(&std_item.title);
            let max_severity = match std_item.max_severity {
                FindingSeverity::Critical => FindingSeverity::High,
                other => other,
            };
            sanitized.push(EscalationStandard {
                standard_id: std_item.standard_id,
                title: inert_title.text,
                guidance: inert_guidance.text,
                max_severity,
                canary_expected_label: std_item.canary_expected_label,
            });
        }
        let payload = serde_json::to_vec(&sanitized).map_err(|e| {
            pack_err(
                CODE_REV_PACK_INVALID,
                format!("canonicalize standards: {e}"),
                "Check fields.",
            )
        })?;
        let digest_sha256 = encode_lower_hex(&sha256_digest(&payload));
        Ok(Self {
            standards: sanitized,
            digest_sha256,
        })
    }
}

impl ModelPackSpec {
    /// Rejects non-HTTPS endpoints, unpinned aliases, and untrusted widening flags (`AI-11`).
    pub fn validate(&self) -> Result<(), CodedError> {
        let endpoint = self.backend_endpoint.trim();
        let https_host = endpoint.strip_prefix("https://").unwrap_or("");
        if endpoint.is_empty()
            || https_host.is_empty()
            || !endpoint.starts_with("https://")
            || https_host.chars().any(char::is_whitespace)
            || https_host.contains('@')
        {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                "model backend endpoint must be a valid https:// TLS URL",
                "Configure an explicit https:// pinned model backend endpoint.",
            ));
        }
        if !is_sha256_hex(&self.pinned_model_digest_sha256) {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                "model pack requires 64-hex pinned SHA-256 model digest (no floating aliases)",
                "Pin exact model artifact SHA-256 digest before selection.",
            ));
        }
        if !self.zero_widening_verified {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                "model pack has not passed P2 zero-widening conformance check",
                "Run model conformance kit before enabling.",
            ));
        }
        Ok(())
    }
}

impl PromptPackSpec {
    /// Rejects invalid digests or prompt packs whose outputs escape the closed restrict-only action list (`P2`).
    pub fn validate(&self) -> Result<(), CodedError> {
        if !is_sha256_hex(&self.content_digest_sha256) {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                "prompt pack digest must be 64-hex SHA-256",
                "Provide valid 64-hex SHA-256 digest for prompt pack.",
            ));
        }
        if self.allowed_advisory_actions.is_empty() {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                "prompt pack requires at least one closed advisory action",
                "Specify allowed_advisory_actions from ReviewAdvisoryAction variants.",
            ));
        }
        for action in &self.allowed_advisory_actions {
            if parse_restrict_only_action(action.trim()).is_none() {
                return Err(pack_err(
                    CODE_REV_PACK_INVALID,
                    format!(
                        "prompt pack closed output list includes unknown or permissive action `{action}`"
                    ),
                    "Use strictly restrict-only ReviewAdvisoryAction values.",
                ));
            }
        }
        Ok(())
    }

    pub fn evaluate_shadow_regression(&mut self, recall_bps: u16, floor_bps: u16) -> bool {
        if recall_bps < floor_bps {
            self.rollout_state = PromptRolloutState::PackHalted {
                reason: format!("shadow recall {recall_bps} bps fell below {floor_bps} bps"),
            };
            return false;
        }
        true
    }

    /// Resumes halted prompt pack only when currently `PackHalted` and signed off (`AI-25`).
    pub fn resume_with_operator_decision(
        &mut self,
        operator_id: &str,
        recorded_decision_id: &str,
    ) -> Result<(), CodedError> {
        if !matches!(self.rollout_state, PromptRolloutState::PackHalted { .. }) {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                "only a PackHalted prompt pack can be resumed",
                "Evaluate rollout state before resuming.",
            ));
        }
        if operator_id.trim().is_empty() || recorded_decision_id.trim().is_empty() {
            return Err(pack_err(
                CODE_REV_PACK_INVALID,
                "resuming halted prompt pack requires non-empty operator_id and decision record",
                "Record explicit operator decision before resuming.",
            ));
        }
        self.rollout_state = PromptRolloutState::Active;
        Ok(())
    }
}

impl CanaryHealthMonitor {
    pub fn register_canary_lineage(&mut self, lineage_id: &str) {
        self.canary_lineages.insert(lineage_id.to_owned());
    }

    #[must_use]
    pub fn is_canary_lineage(&self, lineage_id: &str) -> bool {
        self.canary_lineages.contains(lineage_id)
    }

    pub fn record_probe(
        &mut self,
        obs: CanaryProbeObservation,
        min_recall_bps: u16,
    ) -> ReviewHealthState {
        self.canary_lineages.insert(obs.lineage_id);
        if self.window.len() >= MAX_CANARY_WINDOW {
            self.window.pop_front();
        }
        self.window.push_back(obs.passed);
        if self.window.is_empty() {
            return ReviewHealthState::Healthy;
        }
        let passed_count = self.window.iter().filter(|ok| **ok).count();
        let bps = passed_count
            .saturating_mul(10_000)
            .checked_div(self.window.len())
            .unwrap_or(0);
        if bps < usize::from(min_recall_bps) {
            ReviewHealthState::Degraded
        } else {
            ReviewHealthState::Healthy
        }
    }

    #[must_use]
    pub fn isolate_customer_lineages(&self, candidate_lineages: &[String]) -> Vec<String> {
        candidate_lineages
            .iter()
            .filter(|id| !self.is_canary_lineage(id))
            .cloned()
            .collect()
    }
}

pub fn validate_rule_never_model_dependent(rule: &PolicyRuleSourceCheck) -> Result<(), CodedError> {
    let class_norm = rule.rule_class.trim().to_ascii_lowercase();
    if NEVER_MODEL_DEPENDENT_CLASSES.contains(&class_norm.as_str())
        && rule
            .evaluation_keys
            .iter()
            .any(|k| matches!(k, RuleEvaluationKey::Heuristic | RuleEvaluationKey::Model))
    {
        return Err(pack_err(
            CODE_REV_PACK_INVALID,
            format!(
                "rule `{}` in class `{}` cannot use heuristic or model keys",
                rule.rule_id, rule.rule_class
            ),
            "Move the rule to deterministic predicates only.",
        ));
    }
    Ok(())
}

pub fn activate_escalation_standards(
    previous: Option<&EscalationStandardSet>,
    actor_id: &str,
    proposed: Vec<EscalationStandard>,
    canary_observations: &[CanaryProbeObservation],
    min_recall_bps: u16,
) -> Result<(EscalationStandardSet, EscalationAuditEvent), CodedError> {
    if actor_id.trim().is_empty() {
        return Err(pack_err(
            CODE_REV_PACK_INVALID,
            "escalation standard update requires authenticated actor_id",
            "Authenticate operator session before changing standards.",
        ));
    }
    let next = EscalationStandardSet::validate_and_build(proposed)?;
    let recall_bps = evaluate_canary_recall_bps(canary_observations);
    if recall_bps < min_recall_bps {
        return Err(pack_err(
            CODE_REV_CANARY_FAILED,
            format!("escalation canary recall {recall_bps} bps below floor {min_recall_bps} bps"),
            "Fix failing canary coverage before activating escalation standard edits.",
        ));
    }
    let audit = EscalationAuditEvent {
        event_kind: "audit.admin".into(),
        actor_id: actor_id.to_owned(),
        prev_digest_sha256: previous
            .map(|p| p.digest_sha256.clone())
            .unwrap_or_else(|| "none".into()),
        next_digest_sha256: next.digest_sha256.clone(),
        standards_count: next.standards.len(),
        canary_recall_bps: recall_bps,
    };
    Ok((next, audit))
}

fn evaluate_canary_recall_bps(observations: &[CanaryProbeObservation]) -> u16 {
    if observations.is_empty() {
        return 0;
    }
    let passed = observations.iter().filter(|o| o.passed).count();
    let bps = passed
        .saturating_mul(10_000)
        .checked_div(observations.len())
        .unwrap_or(0);
    u16::try_from(bps).unwrap_or(10_000)
}

fn is_sha256_hex(raw: &str) -> bool {
    raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit())
}

fn is_safe_ascii_id(raw: &str) -> bool {
    !raw.is_empty()
        && raw.len() <= MAX_STANDARD_ID_LEN
        && raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-'))
}
