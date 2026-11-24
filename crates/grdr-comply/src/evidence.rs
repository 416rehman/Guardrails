// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Evidence query validation, signed EvidenceItem evaluation, and lag -> NotEvaluable (`P9`).

use std::collections::BTreeMap;

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_model::{SignatureStatus, TrustedKeyInfo};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ComplyError;
use crate::registry::CapabilityRegistry;

const MAX_SAMPLE_IDS: usize = 20;
const DOMAIN_EVIDENCE_ITEM: &str = "compliance_evidence_item";
const PRINCIPAL_GROUP_BY_FIELDS: &[&str] = &[
    "user_id",
    "user_display",
    "principal",
    "pseudonym",
    "pseudonym_id",
    "actor",
    "subject",
    "subject_ref",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDataClass {
    Public,
    Identifier,
    Structural,
    Derived,
    Content,
    Secret,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum EvidenceResult {
    Met,
    Partial,
    NotMet,
    NotEvaluable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FieldRead {
    pub field_path: String,
    pub data_class: EvidenceDataClass,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceQuery {
    pub id: String,
    pub version: String,
    pub capability: String,
    pub reads: Vec<FieldRead>,
    pub max_class: EvidenceDataClass,
    pub group_by: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidencePipelineInput {
    pub organisation: String,
    pub period_start: Timestamp,
    pub period_end: Timestamp,
    pub pipeline_lag_seconds: u64,
    pub max_lag_seconds: u64,
    pub total_observations: u64,
    pub covered_observations: u64,
    pub sample_ids: Vec<String>,
    pub query_digest: String,
    pub pack_digest: String,
    pub schema_rev: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EvidenceItem {
    pub id: String,
    pub organisation: String,
    pub capability: String,
    pub control_refs: Vec<String>,
    pub period_start: Timestamp,
    pub period_end: Timestamp,
    pub result: EvidenceResult,
    pub metrics: BTreeMap<String, i64>,
    pub sample_ids: Vec<String>,
    pub query_digest: String,
    pub pack_digest: String,
    pub schema_rev: String,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Serialize)]
struct CanonicalEvidencePayload<'a> {
    id: &'a str,
    organisation: &'a str,
    capability: &'a str,
    control_refs: &'a [String],
    period_start: Timestamp,
    period_end: Timestamp,
    result: EvidenceResult,
    metrics: &'a BTreeMap<String, i64>,
    sample_ids: &'a [String],
    query_digest: &'a str,
    pack_digest: &'a str,
    schema_rev: &'a str,
}

pub fn validate_evidence_query(query: &EvidenceQuery) -> Result<(), ComplyError> {
    if query.max_class > EvidenceDataClass::Derived {
        return Err(ComplyError::InvalidEvidenceQuery {
            query_id: query.id.clone(),
            detail: "evidence query `max_class` cannot exceed `derived`".into(),
        });
    }

    for read in &query.reads {
        if read.data_class > EvidenceDataClass::Derived {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: query.id.clone(),
                detail: format!("read field `{}` has class above `derived`", read.field_path),
            });
        }
        if read.data_class > query.max_class {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: query.id.clone(),
                detail: format!("read field `{}` exceeds query `max_class`", read.field_path),
            });
        }
    }

    for grp in &query.group_by {
        let norm = grp.trim().to_ascii_lowercase();
        if PRINCIPAL_GROUP_BY_FIELDS.iter().any(|p| norm == *p) {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: query.id.clone(),
                detail: format!("evidence query forbids principal `group_by` field `{grp}`"),
            });
        }
    }

    Ok(())
}

pub fn evaluate_evidence_item(
    query: &EvidenceQuery,
    input: &EvidencePipelineInput,
    registry: &CapabilityRegistry,
    keypair: &SigningKeypair,
) -> Result<EvidenceItem, ComplyError> {
    validate_evidence_query(query)?;
    let _cap = registry.capability(&query.capability)?;

    let control_refs: Vec<String> = registry
        .controls_for_capability(&query.capability)
        .into_iter()
        .map(|(fw, ctrl)| format!("{fw}:{ctrl}"))
        .collect();

    let result = if input.pipeline_lag_seconds > input.max_lag_seconds {
        EvidenceResult::NotEvaluable
    } else if input.total_observations == 0 || input.covered_observations == 0 {
        EvidenceResult::NotMet
    } else if input.covered_observations >= input.total_observations {
        EvidenceResult::Met
    } else {
        EvidenceResult::Partial
    };

    let mut metrics = BTreeMap::new();
    metrics.insert(
        "total_observations".into(),
        i64::try_from(input.total_observations).unwrap_or(i64::MAX),
    );
    metrics.insert(
        "covered_observations".into(),
        i64::try_from(input.covered_observations).unwrap_or(i64::MAX),
    );
    metrics.insert(
        "pipeline_lag_seconds".into(),
        i64::try_from(input.pipeline_lag_seconds).unwrap_or(i64::MAX),
    );

    let sample_ids: Vec<String> = input
        .sample_ids
        .iter()
        .take(MAX_SAMPLE_IDS)
        .cloned()
        .collect();

    let mut item = EvidenceItem {
        id: format!("evi_{}", Uuid::now_v7().simple()),
        organisation: input.organisation.clone(),
        capability: query.capability.clone(),
        control_refs,
        period_start: input.period_start,
        period_end: input.period_end,
        result,
        metrics,
        sample_ids,
        query_digest: input.query_digest.clone(),
        pack_digest: input.pack_digest.clone(),
        schema_rev: input.schema_rev.clone(),
        key_id: None,
        signature: None,
    };

    sign_evidence_item(keypair, &mut item)?;
    Ok(item)
}

pub fn sign_evidence_item(
    keypair: &SigningKeypair,
    item: &mut EvidenceItem,
) -> Result<(), ComplyError> {
    let payload = canonical_evidence_bytes(item)?;
    item.key_id = Some(keypair.key_id().to_owned());
    item.signature = Some(keypair.sign_bytes(DOMAIN_EVIDENCE_ITEM, &payload));
    Ok(())
}

pub fn verify_evidence_item(item: &EvidenceItem, keys: &[TrustedKeyInfo]) -> SignatureStatus {
    let (Some(kid), Some(sig)) = (item.key_id.as_deref(), item.signature.as_deref()) else {
        return SignatureStatus::Unsigned;
    };
    let Some(trusted) = keys.iter().find(|k| k.key_id == kid) else {
        return SignatureStatus::Invalid;
    };
    let Ok(payload) = canonical_evidence_bytes(item) else {
        return SignatureStatus::Invalid;
    };
    match verify_bytes(&trusted.public_key_b64, DOMAIN_EVIDENCE_ITEM, &payload, sig) {
        Ok(()) => SignatureStatus::Verified,
        Err(_) => SignatureStatus::Invalid,
    }
}

pub fn canonical_evidence_bytes(item: &EvidenceItem) -> Result<Vec<u8>, ComplyError> {
    let canonical = CanonicalEvidencePayload {
        id: &item.id,
        organisation: &item.organisation,
        capability: &item.capability,
        control_refs: &item.control_refs,
        period_start: item.period_start,
        period_end: item.period_end,
        result: item.result,
        metrics: &item.metrics,
        sample_ids: &item.sample_ids,
        query_digest: &item.query_digest,
        pack_digest: &item.pack_digest,
        schema_rev: &item.schema_rev,
    };
    serde_json::to_vec(&canonical).map_err(|e| ComplyError::Serialization {
        detail: e.to_string(),
    })
}
