// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::sha256_hex;
use grdr_model::AssuranceLevel;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::IntegrationError;
use crate::saas::sanitize_inert_text;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct GrcLimits {
    pub max_artifact_refs: usize,
    pub max_id_chars: usize,
    pub max_summary_chars: usize,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrcTarget {
    CisoAssistant,
    Probo,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrcControlStatus {
    Active,
    InProgress,
    Planned,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrcEvidenceInput {
    pub organization_id: String,
    pub control_id: String,
    pub framework: String,
    pub control_title: String,
    pub summary: String,
    pub assurance_level: AssuranceLevel,
    pub finding_count: u64,
    pub blocked_count: u64,
    pub evidence_digest: String,
    pub collected_at: Timestamp,
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CisoAssistantEvidencePayload {
    pub external_id: String,
    pub applied_control_id: String,
    pub name: String,
    pub description: String,
    pub status: GrcControlStatus,
    pub collected_at: Timestamp,
    pub assurance_level: AssuranceLevel,
    pub evidence_sha256: String,
    pub tags: Vec<String>,
    pub attachment_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProboEvidencePayload {
    pub control_id: String,
    pub framework: String,
    pub title: String,
    pub compliance_status: GrcControlStatus,
    pub collected_at: Timestamp,
    pub sha256: String,
    pub source: String,
    pub summary: String,
    pub finding_count: u64,
    pub blocked_count: u64,
    pub artifact_refs: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "target", content = "body", rename_all = "snake_case")]
pub enum GrcPushPayload {
    CisoAssistant(CisoAssistantEvidencePayload),
    Probo(ProboEvidencePayload),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrcPushEnvelope {
    pub target: GrcTarget,
    pub dedup_key: String,
    pub organization_id: String,
    pub collected_at: Timestamp,
    pub payload: GrcPushPayload,
}

impl Default for GrcLimits {
    fn default() -> Self {
        Self {
            max_artifact_refs: 64,
            max_id_chars: 128,
            max_summary_chars: 512,
        }
    }
}

pub fn build_grc_evidence_push(
    target: GrcTarget,
    input: &GrcEvidenceInput,
) -> Result<GrcPushEnvelope, IntegrationError> {
    build_grc_evidence_push_with_limits(target, input, GrcLimits::default())
}

pub fn build_grc_evidence_push_with_limits(
    target: GrcTarget,
    input: &GrcEvidenceInput,
    limits: GrcLimits,
) -> Result<GrcPushEnvelope, IntegrationError> {
    validate_grc_identifier(
        "organization_id",
        &input.organization_id,
        limits.max_id_chars,
    )?;
    validate_grc_identifier("control_id", &input.control_id, limits.max_id_chars)?;
    validate_grc_identifier(
        "evidence_digest",
        &input.evidence_digest,
        limits.max_id_chars,
    )?;
    if input.artifact_refs.len() > limits.max_artifact_refs {
        return Err(IntegrationError::InvalidGrcInput(format!(
            "artifact_refs count {} exceeds limit {}",
            input.artifact_refs.len(),
            limits.max_artifact_refs
        )));
    }

    let safe_title = sanitize_inert_text(&input.control_title, limits.max_summary_chars);
    let safe_summary = sanitize_inert_text(&input.summary, limits.max_summary_chars);
    let safe_framework = sanitize_inert_text(&input.framework, 64);
    let safe_refs: Vec<String> = input
        .artifact_refs
        .iter()
        .map(|r| sanitize_inert_text(r, 256))
        .collect();

    let status = match input.assurance_level {
        AssuranceLevel::Al3Contained | AssuranceLevel::Al4Enforced => GrcControlStatus::Active,
        AssuranceLevel::Al2Guided | AssuranceLevel::Al1Observed => GrcControlStatus::InProgress,
        AssuranceLevel::Al0Inventoried => GrcControlStatus::Planned,
    };

    let target_slug = match target {
        GrcTarget::CisoAssistant => "ciso_assistant",
        GrcTarget::Probo => "probo",
    };
    let dedup_key = format!(
        "grc:{target_slug}:{}:{}:{}",
        input.organization_id,
        input.control_id,
        sha256_hex(input.evidence_digest.as_bytes())
    );

    let payload = match target {
        GrcTarget::CisoAssistant => GrcPushPayload::CisoAssistant(CisoAssistantEvidencePayload {
            external_id: dedup_key.clone(),
            applied_control_id: input.control_id.clone(),
            name: safe_title,
            description: safe_summary,
            status,
            collected_at: input.collected_at,
            assurance_level: input.assurance_level,
            evidence_sha256: input.evidence_digest.clone(),
            tags: vec![safe_framework, input.assurance_level.label().to_owned()],
            attachment_refs: safe_refs,
        }),
        GrcTarget::Probo => GrcPushPayload::Probo(ProboEvidencePayload {
            control_id: input.control_id.clone(),
            framework: safe_framework,
            title: safe_title,
            compliance_status: status,
            collected_at: input.collected_at,
            sha256: input.evidence_digest.clone(),
            source: "guardrails-adr".to_owned(),
            summary: safe_summary,
            finding_count: input.finding_count,
            blocked_count: input.blocked_count,
            artifact_refs: safe_refs,
        }),
    };

    Ok(GrcPushEnvelope {
        target,
        dedup_key,
        organization_id: input.organization_id.clone(),
        collected_at: input.collected_at,
        payload,
    })
}

fn validate_grc_identifier(
    field: &str,
    value: &str,
    max_chars: usize,
) -> Result<(), IntegrationError> {
    if value.is_empty()
        || value.chars().count() > max_chars
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(IntegrationError::InvalidGrcInput(format!(
            "{field} must be non-empty, <= {max_chars} chars, and contain only ASCII [A-Za-z0-9._-]"
        )));
    }
    Ok(())
}
