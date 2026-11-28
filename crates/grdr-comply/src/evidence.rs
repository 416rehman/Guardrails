// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Evidence query validation, signed EvidenceItem evaluation, and lag -> NotEvaluable (`P9`).

use std::collections::BTreeMap;

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_model::{SignatureStatus, TrustedKeyInfo};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::registry::CapabilityRegistry;
use crate::{ComplyError, deterministic_prefixed_id};

const MAX_SAMPLE_IDS: usize = 20;
const DOMAIN_EVIDENCE_ITEM: &str = "compliance_evidence_item";
const ALLOWED_GROUP_BY_DIMENSIONS: &[&str] = &[
    "capability",
    "action_class",
    "rule_id",
    "rule_class",
    "control_point",
    "verdict",
    "period",
    "organisation",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceDataClass {
    Structural,
    Derived,
    Identifier,
    Content,
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
    if query.id.trim().is_empty()
        || query.version.trim().is_empty()
        || query.capability.trim().is_empty()
    {
        return Err(ComplyError::InvalidEvidenceQuery {
            query_id: query.id.clone(),
            detail: "evidence query `id`, `version`, and `capability` must not be empty".into(),
        });
    }
    if query.max_class > EvidenceDataClass::Derived {
        return Err(ComplyError::InvalidEvidenceQuery {
            query_id: query.id.clone(),
            detail: "evidence query `max_class` cannot exceed `derived`".into(),
        });
    }

    for read in &query.reads {
        if read.field_path.trim().is_empty() {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: query.id.clone(),
                detail: "read `field_path` must not be empty".into(),
            });
        }
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
        if !ALLOWED_GROUP_BY_DIMENSIONS.contains(&norm.as_str()) {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: query.id.clone(),
                detail: format!(
                    "evidence query rejects disallowed or principal `group_by` dimension `{grp}`"
                ),
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
    registry.capability(&query.capability)?;

    if input.organisation.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "organisation must not be empty".into(),
        });
    }
    if input.period_end < input.period_start {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "period_end must be greater than or equal to period_start".into(),
        });
    }
    if input.covered_observations > input.total_observations {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "covered_observations cannot exceed total_observations".into(),
        });
    }

    let total_i64 =
        i64::try_from(input.total_observations).map_err(|_| ComplyError::InvalidEvidenceInput {
            detail: "total_observations exceeds signed 64-bit range".into(),
        })?;
    let covered_i64 = i64::try_from(input.covered_observations).map_err(|_| {
        ComplyError::InvalidEvidenceInput {
            detail: "covered_observations exceeds signed 64-bit range".into(),
        }
    })?;
    let lag_i64 = i64::try_from(input.pipeline_lag_seconds).map_err(|_| {
        ComplyError::InvalidEvidenceInput {
            detail: "pipeline_lag_seconds exceeds signed 64-bit range".into(),
        }
    })?;

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
    metrics.insert("total_observations".into(), total_i64);
    metrics.insert("covered_observations".into(), covered_i64);
    metrics.insert("pipeline_lag_seconds".into(), lag_i64);

    let sample_ids: Vec<String> = input
        .sample_ids
        .iter()
        .take(MAX_SAMPLE_IDS)
        .cloned()
        .collect();

    let seed = format!(
        "{}:{}:{}:{}:{}:{}:{}",
        input.organisation,
        query.id,
        query.capability,
        input.period_start,
        input.period_end,
        input.query_digest,
        input.pack_digest
    );

    let mut item = EvidenceItem {
        id: deterministic_prefixed_id("evi", &seed),
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

#[cfg(test)]
mod tests {
    use super::{EvidenceDataClass, EvidenceQuery, FieldRead, validate_evidence_query};

    #[test]
    fn evidence_data_class_is_four_canonical_p8_tiers() {
        assert!(EvidenceDataClass::Structural < EvidenceDataClass::Derived);
        assert!(EvidenceDataClass::Derived < EvidenceDataClass::Identifier);
        assert!(EvidenceDataClass::Identifier < EvidenceDataClass::Content);

        let parsed: EvidenceDataClass =
            serde_json::from_str("\"derived\"").expect("derived class parses");
        assert_eq!(parsed, EvidenceDataClass::Derived);
        assert!(serde_json::from_str::<EvidenceDataClass>("\"public\"").is_err());
        assert!(serde_json::from_str::<EvidenceDataClass>("\"secret\"").is_err());

        let identifier_query = EvidenceQuery {
            id: "q.test.identifier".into(),
            version: "1.0.0".into(),
            capability: "cap.inventory.agents".into(),
            reads: vec![FieldRead {
                field_path: "session.user_id".into(),
                data_class: EvidenceDataClass::Identifier,
            }],
            max_class: EvidenceDataClass::Derived,
            group_by: vec!["capability".into()],
        };
        assert!(validate_evidence_query(&identifier_query).is_err());
    }
}
