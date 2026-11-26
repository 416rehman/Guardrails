// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! OSCAL 1.2.3 Component Definition, Assessment Results, CSV/Markdown, and offline bundle.

use std::collections::BTreeSet;

use grdr_crypto::{SigningKeypair, sha256_hex, verify_bytes};
use grdr_model::{SignatureStatus, SigningKeypairExt as _, TrustedKeyInfo};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::evidence::{
    EvidenceItem, EvidenceResult, canonical_evidence_bytes, verify_evidence_item,
};
use crate::registry::CapabilityRegistry;
use crate::{ComplyError, deterministic_uuid_string, markdown_safe};

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
    pub root_key: TrustedKeyInfo,
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
    root_key: &'a TrustedKeyInfo,
    trusted_keys_sha256: &'a str,
    assessment_results_sha256: &'a str,
    inclusion_proofs_sha256: &'a str,
    item_ids: Vec<&'a str>,
}

pub fn deployment_fingerprint(root_key: &TrustedKeyInfo) -> String {
    let material = format!(
        "grdr.deployment.root.v1:{}:{}",
        root_key.key_id, root_key.public_key_b64
    );
    format!("fp_{}", sha256_hex(material.as_bytes()))
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
                uuid: deterministic_uuid_string(&format!(
                    "req:{fw_id}:{}:{}",
                    cw.control_id, cw.capability
                )),
                control_id: cw.control_id.clone(),
                description: format!("{} ({:?}): {}", cw.capability, cw.relation, cw.note),
            });
        }
        implementations.push(OscalControlImplementation {
            uuid: deterministic_uuid_string(&format!("impl:{fw_id}")),
            source: format!("urn:grdr:framework:{fw_id}@{}", fw.version),
            description: fw.title.clone(),
            implemented_requirements: reqs,
        });
    }

    OscalComponentDefinitionDoc {
        component_definition: OscalComponentDefinitionBody {
            uuid: deterministic_uuid_string(&format!("compdef:{title}:{version}")),
            metadata: OscalMetadata {
                title: title.to_owned(),
                last_modified: now,
                version: version.to_owned(),
                oscal_version: OSCAL_VERSION.to_owned(),
            },
            components: vec![OscalComponent {
                uuid: deterministic_uuid_string("component:guardrails-adr"),
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
            uuid: deterministic_uuid_string(&format!("obs:{}", item.id)),
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
            uuid: deterministic_uuid_string(&format!("ar:{organisation}:{now}")),
            metadata: OscalMetadata {
                title: format!("Guardrails ADR Assessment Results ({organisation})"),
                last_modified: now,
                version: "1.0.0".to_owned(),
                oscal_version: OSCAL_VERSION.to_owned(),
            },
            results: vec![OscalAssessmentResultEntry {
                uuid: deterministic_uuid_string(&format!("res:{organisation}:{start}:{end}")),
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
            "\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",\"{}\",{},\"{}\"\n",
            csv_safe(&item.id),
            csv_safe(&item.organisation),
            csv_safe(&item.capability),
            csv_safe(result_label),
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
        "# Compliance Evidence Report ({})\n\n| Item | Capability | Result | Samples | Controls |\n|---|---|---|---|---|\n",
        markdown_safe(organisation)
    );
    for item in items {
        out.push_str(&format!(
            "| `{}` | `{}` | `{:?}` | {} | {} |\n",
            markdown_safe(&item.id),
            markdown_safe(&item.capability),
            item.result,
            item.sample_ids.len(),
            markdown_safe(&item.control_refs.join(", "))
        ));
    }
    out
}

pub fn export_offline_bundle(
    keypair: &SigningKeypair,
    organisation: &str,
    items: &[EvidenceItem],
    now: Timestamp,
) -> Result<OfflineEvidenceBundle, ComplyError> {
    let root_key = keypair.public_info();
    let fingerprint = deployment_fingerprint(&root_key);
    let trusted_keys = vec![root_key.clone()];
    let assessment_results = export_assessment_results(organisation, items, now)?;
    let (checkpoint_root, inclusion_proofs) = build_inclusion_chain(items)?;
    let payload = serialize_bundle_payload(
        OFFLINE_BUNDLE_VERSION,
        &fingerprint,
        organisation,
        now,
        &checkpoint_root,
        &root_key,
        &trusted_keys,
        &assessment_results,
        &inclusion_proofs,
        items,
    )?;
    let bundle_signature = keypair.sign_bytes(DOMAIN_OFFLINE_BUNDLE, &payload);

    Ok(OfflineEvidenceBundle {
        bundle_version: OFFLINE_BUNDLE_VERSION,
        deployment_fingerprint: fingerprint,
        organisation: organisation.to_owned(),
        exported_at: now,
        root_key,
        assessment_results,
        items: items.to_vec(),
        trusted_keys,
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
    if bundle.bundle_version != OFFLINE_BUNDLE_VERSION {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "unsupported offline bundle version {}",
                bundle.bundle_version
            ),
        });
    }
    let derived_root_fp = deployment_fingerprint(&bundle.root_key);
    if derived_root_fp != expected_fingerprint
        || bundle.deployment_fingerprint != expected_fingerprint
    {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "deployment fingerprint mismatch: expected `{expected_fingerprint}`, got `{}` (root key `{derived_root_fp}`)",
                bundle.deployment_fingerprint
            ),
        });
    }
    if bundle.bundle_key_id != bundle.root_key.key_id
        || !bundle.trusted_keys.contains(&bundle.root_key)
    {
        return Err(ComplyError::VerificationFailed {
            detail: "bundle signing key must match attested deployment root key".into(),
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

    let payload = serialize_bundle_payload(
        bundle.bundle_version,
        &bundle.deployment_fingerprint,
        &bundle.organisation,
        bundle.exported_at,
        &bundle.checkpoint_root,
        &bundle.root_key,
        &bundle.trusted_keys,
        &bundle.assessment_results,
        &bundle.inclusion_proofs,
        &bundle.items,
    )?;

    verify_bytes(
        &bundle.root_key.public_key_b64,
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

    let expected_ar =
        export_assessment_results(&bundle.organisation, &bundle.items, bundle.exported_at)?;
    if bundle.assessment_results != expected_ar {
        return Err(ComplyError::VerificationFailed {
            detail: "OSCAL assessment results do not match signed evidence items".into(),
        });
    }

    let (recomputed_root, expected_proofs) = build_inclusion_chain(&bundle.items)?;
    if recomputed_root != bundle.checkpoint_root {
        return Err(ComplyError::VerificationFailed {
            detail: "checkpoint root mismatch against evidence items".into(),
        });
    }

    let mut seen_ids = BTreeSet::new();
    for (idx, item) in bundle.items.iter().enumerate() {
        if !seen_ids.insert(item.id.as_str()) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate evidence item id `{}`", item.id),
            });
        }
        if item.organisation != bundle.organisation {
            return Err(ComplyError::VerificationFailed {
                detail: format!(
                    "evidence item `{}` organisation `{}` mismatches bundle `{}`",
                    item.id, item.organisation, bundle.organisation
                ),
            });
        }
        if verify_evidence_item(item, &bundle.trusted_keys) != SignatureStatus::Verified {
            return Err(ComplyError::VerificationFailed {
                detail: format!("evidence item `{}` failed Ed25519 verification", item.id),
            });
        }
        if bundle.inclusion_proofs.get(idx) != expected_proofs.get(idx) {
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

#[allow(clippy::too_many_arguments)]
fn serialize_bundle_payload(
    bundle_version: u32,
    deployment_fingerprint: &str,
    organisation: &str,
    exported_at: Timestamp,
    checkpoint_root: &str,
    root_key: &TrustedKeyInfo,
    trusted_keys: &[TrustedKeyInfo],
    assessment_results: &OscalAssessmentResultsDoc,
    inclusion_proofs: &[ItemInclusionProof],
    items: &[EvidenceItem],
) -> Result<Vec<u8>, ComplyError> {
    let trusted_keys_sha256 = sha256_json(trusted_keys)?;
    let assessment_results_sha256 = sha256_json(assessment_results)?;
    let inclusion_proofs_sha256 = sha256_json(inclusion_proofs)?;
    let item_ids: Vec<&str> = items.iter().map(|i| i.id.as_str()).collect();
    serde_json::to_vec(&CanonicalBundlePayload {
        bundle_version,
        deployment_fingerprint,
        organisation,
        exported_at,
        checkpoint_root,
        root_key,
        trusted_keys_sha256: &trusted_keys_sha256,
        assessment_results_sha256: &assessment_results_sha256,
        inclusion_proofs_sha256: &inclusion_proofs_sha256,
        item_ids,
    })
    .map_err(|e| ComplyError::Serialization {
        detail: e.to_string(),
    })
}

fn sha256_json<T: Serialize + ?Sized>(val: &T) -> Result<String, ComplyError> {
    let bytes = serde_json::to_vec(val).map_err(|e| ComplyError::Serialization {
        detail: e.to_string(),
    })?;
    Ok(sha256_hex(&bytes))
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

fn csv_safe(raw: &str) -> String {
    let single_line = raw.replace(['\n', '\r'], " ");
    let trimmed = single_line.trim_start();
    let formula_prefix =
        single_line.starts_with('\t') || trimmed.starts_with(['=', '+', '-', '@', '\t']);
    let neutralized = if formula_prefix {
        format!("'{single_line}")
    } else {
        single_line
    };
    neutralized.replace('"', "\"\"")
}
