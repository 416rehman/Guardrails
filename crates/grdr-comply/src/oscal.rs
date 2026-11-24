// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! OSCAL 1.2.3 Component Definition, Assessment Results, CSV/Markdown, and offline bundle.

use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::{SignatureStatus, TrustedKeyInfo};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::ComplyError;
use crate::evidence::{
    EvidenceItem, EvidenceResult, canonical_evidence_bytes, verify_evidence_item,
};
use crate::registry::CapabilityRegistry;

pub const OSCAL_VERSION: &str = "1.2.3";
const OFFLINE_BUNDLE_VERSION: u32 = 1;
const DOMAIN_OFFLINE_BUNDLE: &str = "compliance_offline_bundle";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalMetadata {
    pub title: String,
    #[serde(rename = "last-modified")]
    pub last_modified: Timestamp,
    pub version: String,
    #[serde(rename = "oscal-version")]
    pub oscal_version: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalImplementedRequirement {
    pub uuid: String,
    #[serde(rename = "control-id")]
    pub control_id: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalControlImplementation {
    pub uuid: String,
    pub source: String,
    pub description: String,
    #[serde(rename = "implemented-requirements")]
    pub implemented_requirements: Vec<OscalImplementedRequirement>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalComponent {
    pub uuid: String,
    #[serde(rename = "type")]
    pub component_type: String,
    pub title: String,
    pub description: String,
    #[serde(rename = "control-implementations")]
    pub control_implementations: Vec<OscalControlImplementation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalComponentDefinitionBody {
    pub uuid: String,
    pub metadata: OscalMetadata,
    pub components: Vec<OscalComponent>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalComponentDefinitionDoc {
    #[serde(rename = "component-definition")]
    pub component_definition: OscalComponentDefinitionBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalObservation {
    pub uuid: String,
    pub description: String,
    pub collected: Timestamp,
    #[serde(rename = "subject-references")]
    pub subject_references: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalAssessmentResultEntry {
    pub uuid: String,
    pub title: String,
    pub description: String,
    pub start: Timestamp,
    pub end: Timestamp,
    pub observations: Vec<OscalObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalAssessmentResultsBody {
    pub uuid: String,
    pub metadata: OscalMetadata,
    pub results: Vec<OscalAssessmentResultEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OscalAssessmentResultsDoc {
    #[serde(rename = "assessment-results")]
    pub assessment_results: OscalAssessmentResultsBody,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ItemInclusionProof {
    pub item_id: String,
    pub item_digest_sha256: String,
    pub prev_chain_digest: String,
    pub chain_digest: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OfflineEvidenceBundle {
    pub bundle_version: u32,
    pub deployment_fingerprint: String,
    pub organisation: String,
    pub exported_at: Timestamp,
    pub assessment_results: OscalAssessmentResultsDoc,
    pub items: Vec<EvidenceItem>,
    pub trusted_keys: Vec<TrustedKeyInfo>,
    pub checkpoint_root: String,
    pub inclusion_proofs: Vec<ItemInclusionProof>,
    pub bundle_key_id: String,
    pub bundle_signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BundleVerificationReport {
    pub deployment_fingerprint: String,
    pub verified_items: usize,
    pub checkpoint_root: String,
    pub oscal_version: String,
}

#[derive(Serialize)]
struct CanonicalBundlePayload<'a> {
    bundle_version: u32,
    deployment_fingerprint: &'a str,
    organisation: &'a str,
    exported_at: Timestamp,
    checkpoint_root: &'a str,
    item_ids: Vec<&'a str>,
}

pub fn export_component_definition(
    registry: &CapabilityRegistry,
    title: &str,
    version: &str,
    now: Timestamp,
) -> OscalComponentDefinitionDoc {
    let mut implementations = Vec::with_capacity(registry.frameworks.len());
    for (fw_id, fw) in &registry.frameworks {
        let mut reqs = Vec::new();
        for cw in registry
            .crosswalks
            .iter()
            .filter(|c| c.framework_id == *fw_id)
        {
            reqs.push(OscalImplementedRequirement {
                uuid: deterministic_uuid(&format!(
                    "req:{fw_id}:{}:{}",
                    cw.control_id, cw.capability
                )),
                control_id: cw.control_id.clone(),
                description: format!("{} ({:?}): {}", cw.capability, cw.relation, cw.note),
            });
        }
        implementations.push(OscalControlImplementation {
            uuid: deterministic_uuid(&format!("impl:{fw_id}")),
            source: format!("urn:grdr:framework:{fw_id}@{}", fw.version),
            description: fw.title.clone(),
            implemented_requirements: reqs,
        });
    }

    OscalComponentDefinitionDoc {
        component_definition: OscalComponentDefinitionBody {
            uuid: deterministic_uuid(&format!("compdef:{title}:{version}")),
            metadata: OscalMetadata {
                title: title.to_owned(),
                last_modified: now,
                version: version.to_owned(),
                oscal_version: OSCAL_VERSION.to_owned(),
            },
            components: vec![OscalComponent {
                uuid: deterministic_uuid("component:guardrails-adr"),
                component_type: "software".to_owned(),
                title: "Guardrails ADR".to_owned(),
                description: "Open-source agent detection and response platform".to_owned(),
                control_implementations: implementations,
            }],
        },
    }
}

pub fn export_assessment_results(
    organisation: &str,
    items: &[EvidenceItem],
    now: Timestamp,
) -> Result<OscalAssessmentResultsDoc, ComplyError> {
    let mut observations = Vec::with_capacity(items.len());
    let mut start = now;
    let mut end = now;

    for (idx, item) in items.iter().enumerate() {
        if idx == 0 || item.period_start < start {
            start = item.period_start;
        }
        if idx == 0 || item.period_end > end {
            end = item.period_end;
        }
        observations.push(OscalObservation {
            uuid: deterministic_uuid(&format!("obs:{}", item.id)),
            description: format!(
                "Capability `{}` evaluated as {:?} for controls [{}]",
                item.capability,
                item.result,
                item.control_refs.join(", ")
            ),
            collected: item.period_end,
            subject_references: item.sample_ids.clone(),
        });
    }

    Ok(OscalAssessmentResultsDoc {
        assessment_results: OscalAssessmentResultsBody {
            uuid: deterministic_uuid(&format!("ar:{organisation}:{now}")),
            metadata: OscalMetadata {
                title: format!("Guardrails ADR Assessment Results ({organisation})"),
                last_modified: now,
                version: "1.0.0".to_owned(),
                oscal_version: OSCAL_VERSION.to_owned(),
            },
            results: vec![OscalAssessmentResultEntry {
                uuid: deterministic_uuid(&format!("res:{organisation}:{start}:{end}")),
                title: "Computed Compliance Evidence Period".to_owned(),
                description: "Metadata and sample identifier observations only".to_owned(),
                start,
                end,
                observations,
            }],
        },
    })
}

pub fn export_evidence_csv(items: &[EvidenceItem]) -> String {
    let mut out = String::from(
        "item_id,organisation,capability,result,period_start,period_end,sample_count,controls\n",
    );
    for item in items {
        let result_label = match item.result {
            EvidenceResult::Met => "met",
            EvidenceResult::Partial => "partial",
            EvidenceResult::NotMet => "not-met",
            EvidenceResult::NotEvaluable => "not-evaluable",
        };
        let line = format!(
            "{},{},{},{},{},{},{},\"{}\"\n",
            csv_safe(&item.id),
            csv_safe(&item.organisation),
            csv_safe(&item.capability),
            result_label,
            item.period_start,
            item.period_end,
            item.sample_ids.len(),
            csv_safe(&item.control_refs.join(";"))
        );
        out.push_str(&line);
    }
    out
}

pub fn export_evidence_markdown(organisation: &str, items: &[EvidenceItem]) -> String {
    let mut out = format!(
        "# Compliance Evidence Report ({organisation})\n\n| Item | Capability | Result | Samples | Controls |\n|---|---|---|---|---|\n"
    );
    for item in items {
        out.push_str(&format!(
            "| `{}` | `{}` | `{:?}` | {} | {} |\n",
            item.id,
            item.capability,
            item.result,
            item.sample_ids.len(),
            item.control_refs.join(", ")
        ));
    }
    out
}

pub fn export_offline_bundle(
    keypair: &SigningKeypair,
    organisation: &str,
    deployment_fingerprint: &str,
    items: &[EvidenceItem],
    now: Timestamp,
) -> Result<OfflineEvidenceBundle, ComplyError> {
    let assessment_results = export_assessment_results(organisation, items, now)?;
    let (checkpoint_root, inclusion_proofs) = build_inclusion_chain(items)?;
    let item_ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
    let payload = serde_json::to_vec(&CanonicalBundlePayload {
        bundle_version: OFFLINE_BUNDLE_VERSION,
        deployment_fingerprint,
        organisation,
        exported_at: now,
        checkpoint_root: &checkpoint_root,
        item_ids,
    })
    .map_err(|e| ComplyError::Serialization {
        detail: e.to_string(),
    })?;
    let bundle_signature = keypair.sign_bytes(DOMAIN_OFFLINE_BUNDLE, &payload);

    Ok(OfflineEvidenceBundle {
        bundle_version: OFFLINE_BUNDLE_VERSION,
        deployment_fingerprint: deployment_fingerprint.to_owned(),
        organisation: organisation.to_owned(),
        exported_at: now,
        assessment_results,
        items: items.to_vec(),
        trusted_keys: vec![keypair.public_info()],
        checkpoint_root,
        inclusion_proofs,
        bundle_key_id: keypair.key_id().to_owned(),
        bundle_signature,
    })
}

pub fn verify_evidence_bundle(
    bundle: &OfflineEvidenceBundle,
    expected_fingerprint: &str,
) -> Result<BundleVerificationReport, ComplyError> {
    if bundle.deployment_fingerprint != expected_fingerprint {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "deployment fingerprint mismatch: expected `{expected_fingerprint}`, got `{}`",
                bundle.deployment_fingerprint
            ),
        });
    }
    if bundle
        .assessment_results
        .assessment_results
        .metadata
        .oscal_version
        != OSCAL_VERSION
    {
        return Err(ComplyError::VerificationFailed {
            detail: "OSCAL version mismatch in offline bundle".into(),
        });
    }

    let key = bundle
        .trusted_keys
        .iter()
        .find(|k| k.key_id == bundle.bundle_key_id)
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: "bundle signing key missing from trusted_keys".into(),
        })?;

    let item_ids: Vec<&str> = bundle.items.iter().map(|i| i.id.as_str()).collect();
    let payload = serde_json::to_vec(&CanonicalBundlePayload {
        bundle_version: bundle.bundle_version,
        deployment_fingerprint: &bundle.deployment_fingerprint,
        organisation: &bundle.organisation,
        exported_at: bundle.exported_at,
        checkpoint_root: &bundle.checkpoint_root,
        item_ids,
    })
    .map_err(|e| ComplyError::Serialization {
        detail: e.to_string(),
    })?;

    verify_bytes(
        &key.public_key_b64,
        DOMAIN_OFFLINE_BUNDLE,
        &payload,
        &bundle.bundle_signature,
    )
    .map_err(|e| ComplyError::VerificationFailed {
        detail: format!("bundle signature invalid: {e}"),
    })?;

    if bundle.items.len() != bundle.inclusion_proofs.len() {
        return Err(ComplyError::VerificationFailed {
            detail: "inclusion proof count does not match evidence items".into(),
        });
    }

    let (recomputed_root, expected_proofs) = build_inclusion_chain(&bundle.items)?;
    if recomputed_root != bundle.checkpoint_root {
        return Err(ComplyError::VerificationFailed {
            detail: "checkpoint root mismatch against evidence items".into(),
        });
    }

    for (idx, item) in bundle.items.iter().enumerate() {
        if verify_evidence_item(item, &bundle.trusted_keys) != SignatureStatus::Verified {
            return Err(ComplyError::VerificationFailed {
                detail: format!("evidence item `{}` failed Ed25519 verification", item.id),
            });
        }
        let given = bundle.inclusion_proofs.get(idx);
        let expected = expected_proofs.get(idx);
        if given != expected {
            return Err(ComplyError::VerificationFailed {
                detail: format!("inclusion proof mismatch for `{}`", item.id),
            });
        }
    }

    Ok(BundleVerificationReport {
        deployment_fingerprint: bundle.deployment_fingerprint.clone(),
        verified_items: bundle.items.len(),
        checkpoint_root: bundle.checkpoint_root.clone(),
        oscal_version: OSCAL_VERSION.to_owned(),
    })
}

fn build_inclusion_chain(
    items: &[EvidenceItem],
) -> Result<(String, Vec<ItemInclusionProof>), ComplyError> {
    let mut prev = "0".repeat(64);
    let mut proofs = Vec::with_capacity(items.len());
    for item in items {
        let canonical = canonical_evidence_bytes(item)?;
        let item_digest = sha256_hex(&canonical);
        let chain_input = format!("{prev}:{item_digest}");
        let chain_digest = sha256_hex(chain_input.as_bytes());
        proofs.push(ItemInclusionProof {
            item_id: item.id.clone(),
            item_digest_sha256: item_digest,
            prev_chain_digest: prev,
            chain_digest: chain_digest.clone(),
        });
        prev = chain_digest;
    }
    Ok((prev, proofs))
}

fn deterministic_uuid(seed: &str) -> String {
    let hex = sha256_hex(seed.as_bytes());
    let slice = hex.get(0..32).unwrap_or("00000000000000000000000000000000");
    let raw = u128::from_str_radix(slice, 16).unwrap_or(0);
    Uuid::from_u128(raw).hyphenated().to_string()
}

fn csv_safe(raw: &str) -> String {
    raw.replace('"', "\"\"").replace(['\n', '\r'], " ")
}
