// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Verified YAML compliance pack loader (`packs/compliance/`) and shared YAML extractors (`P14`).

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_model::AssuranceLevel;
use jiff::Timestamp;

use crate::ComplyError;
use crate::evidence::EvidenceQuery;
use crate::pack_toml::{
    CompliancePackManifest, SignerTrustStatus, TrustedRootEntry, parse_trust_roots_toml,
};
use crate::pack_verify::{
    VerifiedPackBundle, load_trust_roots_from_path, verify_signed_bytes_bundle, verify_signed_dir,
};
use crate::registry::{
    CapabilityRecord, CapabilityRegistry, ControlEntry, CrosswalkEntry, CrosswalkRelation,
    FrameworkCatalogue, Responsibility,
};

const MAX_PARAPHRASE_WORDS: usize = 20;
const COMPLIANCE_PACK_ID: &str = "grdr.compliance";
const EMBEDDED_MIN_PACK_VERSION: &str = "1.0.0";

const EMBEDDED_TRUST_ROOTS_TOML: &str = include_str!("../../../packs/trust-roots.toml");
const EMBEDDED_PACK_TOML: &str = include_str!("../../../packs/compliance/pack.toml");
const EMBEDDED_SIGNATURE_JSON: &str = include_str!("../../../packs/compliance/signature.json");
const EMBEDDED_CAPABILITIES_YAML: &str =
    include_str!("../../../packs/compliance/controls/capabilities.yaml");
const EMBEDDED_FRAMEWORKS_YAML: &str =
    include_str!("../../../packs/compliance/controls/frameworks.yaml");
const EMBEDDED_CROSSWALKS_YAML: &str =
    include_str!("../../../packs/compliance/controls/crosswalks.yaml");

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LoadedCompliancePack {
    pub manifest: CompliancePackManifest,
    pub registry: CapabilityRegistry,
    pub digest_sha256: String,
    pub signer_ref: String,
}

pub fn load_embedded_compliance_pack() -> Result<LoadedCompliancePack, ComplyError> {
    let trust_roots = parse_trust_roots_toml(EMBEDDED_TRUST_ROOTS_TOML)?;
    let verified = verify_signed_bytes_bundle(
        COMPLIANCE_PACK_ID,
        EMBEDDED_SIGNATURE_JSON,
        &trust_roots,
        Some(EMBEDDED_MIN_PACK_VERSION),
        &[
            (
                "controls/capabilities.yaml",
                EMBEDDED_CAPABILITIES_YAML.as_bytes(),
            ),
            (
                "controls/crosswalks.yaml",
                EMBEDDED_CROSSWALKS_YAML.as_bytes(),
            ),
            (
                "controls/frameworks.yaml",
                EMBEDDED_FRAMEWORKS_YAML.as_bytes(),
            ),
            ("pack.toml", EMBEDDED_PACK_TOML.as_bytes()),
        ],
        Timestamp::now(),
    )?;
    build_loaded_from_verified(verified)
}

pub fn load_compliance_pack_from_dir(
    pack_dir: &Path,
    trust_roots_path: Option<&Path>,
) -> Result<LoadedCompliancePack, ComplyError> {
    let (roots, floor) = match trust_roots_path {
        Some(path) => (load_trust_roots_from_path(path)?, None),
        None => (
            parse_trust_roots_toml(EMBEDDED_TRUST_ROOTS_TOML)?,
            Some(EMBEDDED_MIN_PACK_VERSION),
        ),
    };
    let verified = verify_signed_dir(
        pack_dir,
        COMPLIANCE_PACK_ID,
        &roots,
        floor,
        Timestamp::now(),
    )?;
    build_loaded_from_verified(verified)
}

pub fn load_compliance_pack_with_trusted(
    pack_dir: &Path,
    trusted_verifiers: &[(&str, &str)],
) -> Result<LoadedCompliancePack, ComplyError> {
    let roots: Vec<TrustedRootEntry> = trusted_verifiers
        .iter()
        .map(|(signer_ref, verifier_ed25519_b64)| TrustedRootEntry {
            signer_ref: (*signer_ref).to_owned(),
            verifier_ed25519_b64: (*verifier_ed25519_b64).to_owned(),
            status: SignerTrustStatus::Active,
            min_version: None,
            expires_at: None,
        })
        .collect();
    let verified = verify_signed_dir(pack_dir, COMPLIANCE_PACK_ID, &roots, None, Timestamp::now())?;
    build_loaded_from_verified(verified)
}

fn build_loaded_from_verified(
    verified: VerifiedPackBundle,
) -> Result<LoadedCompliancePack, ComplyError> {
    let caps_raw = verified_utf8_file(&verified, "controls/capabilities.yaml")?;
    let fws_raw = verified_utf8_file(&verified, "controls/frameworks.yaml")?;
    let cw_raw = verified_utf8_file(&verified, "controls/crosswalks.yaml")?;
    let registry = parse_registry_from_yaml(caps_raw, fws_raw, cw_raw)?;
    Ok(LoadedCompliancePack {
        manifest: verified.manifest,
        registry,
        digest_sha256: verified.sig.manifest_sha256,
        signer_ref: verified.sig.signer_ref,
    })
}

fn verified_utf8_file<'a>(
    verified: &'a VerifiedPackBundle,
    rel_path: &str,
) -> Result<&'a str, ComplyError> {
    let raw = verified
        .files
        .get(rel_path)
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("verified compliance pack missing `{rel_path}`"),
        })?;
    std::str::from_utf8(raw).map_err(|e| ComplyError::VerificationFailed {
        detail: format!("non-UTF8 compliance file `{rel_path}`: {e}"),
    })
}

pub fn parse_registry_from_yaml(
    capabilities_yaml: &str,
    frameworks_yaml: &str,
    crosswalks_yaml: &str,
) -> Result<CapabilityRegistry, ComplyError> {
    let caps = parse_capabilities_yaml(capabilities_yaml)?;
    let frameworks = parse_frameworks_yaml(frameworks_yaml)?;
    let crosswalks = parse_crosswalks_yaml(crosswalks_yaml, &caps, &frameworks)?;
    Ok(CapabilityRegistry {
        capabilities: caps,
        frameworks,
        crosswalks,
    })
}

pub(crate) fn default_pack_evidence_queries() -> Result<Vec<EvidenceQuery>, ComplyError> {
    load_embedded_compliance_pack().map(|pack| pack.manifest.evidence_queries)
}

pub(crate) fn default_pack_digest_sha256() -> Result<String, ComplyError> {
    load_embedded_compliance_pack().map(|pack| pack.digest_sha256)
}

pub(crate) fn load_yaml_checked(raw: &str, label: &str) -> Result<YamlValue, ComplyError> {
    if raw.contains('\u{2014}') {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{label}` contains forbidden em dash"),
        });
    }
    parse_yaml(raw).map_err(|e| ComplyError::Serialization {
        detail: format!("invalid compliance YAML `{label}`: {e}"),
    })
}

pub(crate) fn yaml_req_str<'a>(
    val: &'a YamlValue,
    key: &str,
    ctx: &str,
) -> Result<&'a str, ComplyError> {
    val.get(key)
        .and_then(YamlValue::as_str)
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| ComplyError::Serialization {
            detail: format!("missing non-empty `{key}` in {ctx}"),
        })
}

pub(crate) fn yaml_req_seq<'a>(
    val: &'a YamlValue,
    key: &str,
    ctx: &str,
) -> Result<&'a [YamlValue], ComplyError> {
    val.get(key)
        .and_then(YamlValue::as_seq)
        .ok_or_else(|| ComplyError::Serialization {
            detail: format!("missing sequence `{key}` in {ctx}"),
        })
}

pub(crate) fn yaml_req_u32(val: &YamlValue, key: &str, ctx: &str) -> Result<u32, ComplyError> {
    let raw =
        val.get(key)
            .and_then(YamlValue::as_i64)
            .ok_or_else(|| ComplyError::Serialization {
                detail: format!("missing integer `{key}` in {ctx}"),
            })?;
    u32::try_from(raw).map_err(|_| ComplyError::Serialization {
        detail: format!("integer `{key}` out of u32 range in {ctx}"),
    })
}

pub(crate) fn yaml_req_bool(val: &YamlValue, key: &str, ctx: &str) -> Result<bool, ComplyError> {
    val.get(key)
        .and_then(YamlValue::as_bool)
        .ok_or_else(|| ComplyError::Serialization {
            detail: format!("missing boolean `{key}` in {ctx}"),
        })
}

pub(crate) fn yaml_req_str_list(
    val: &YamlValue,
    key: &str,
    ctx: &str,
) -> Result<Vec<String>, ComplyError> {
    let seq = yaml_req_seq(val, key, ctx)?;
    let mut out = Vec::with_capacity(seq.len());
    for item in seq {
        let s = item
            .as_str()
            .map(str::trim)
            .filter(|v| !v.is_empty())
            .ok_or_else(|| ComplyError::Serialization {
                detail: format!("non-string entry in `{key}` in {ctx}"),
            })?;
        out.push(s.to_owned());
    }
    Ok(out)
}

fn parse_capabilities_yaml(raw: &str) -> Result<BTreeMap<String, CapabilityRecord>, ComplyError> {
    let doc = load_yaml_checked(raw, "capabilities.yaml")?;
    validate_yaml_pack_header(&doc, "capabilities.yaml")?;
    let items = yaml_req_seq(&doc, "capabilities", "capabilities.yaml")?;
    let mut caps = BTreeMap::new();
    for item in items {
        let id = yaml_req_str(item, "id", "capabilities.yaml")?.to_owned();
        if caps.contains_key(&id) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate capability `{id}` in capabilities.yaml"),
            });
        }
        let statement = yaml_req_str(item, "statement", &id)?.to_owned();
        let decisions = yaml_req_str_list(item, "decisions", &id)?;
        let requires = yaml_req_str_list(item, "requires", &id)?;
        let assurance_str = yaml_req_str(item, "assurance_requirement", &id)?;
        let assurance_requirement = parse_assurance_level(assurance_str, &id)?;
        let evidence_query = yaml_req_str(item, "evidence_query", &id)?.to_owned();
        let resp_str = yaml_req_str(item, "responsibility", &id)?;
        let responsibility = match resp_str {
            "product" => Responsibility::Product,
            "operator" => Responsibility::Operator,
            "customer" => Responsibility::Customer,
            other => {
                return Err(ComplyError::Serialization {
                    detail: format!("unknown responsibility `{other}` for `{id}`"),
                });
            }
        };
        caps.insert(
            id.clone(),
            CapabilityRecord {
                id,
                statement,
                decisions,
                requires,
                assurance_requirement,
                evidence_query,
                responsibility,
            },
        );
    }
    if caps.is_empty() {
        return Err(ComplyError::VerificationFailed {
            detail: "capabilities.yaml contains no capabilities".into(),
        });
    }
    Ok(caps)
}

fn parse_frameworks_yaml(raw: &str) -> Result<BTreeMap<String, FrameworkCatalogue>, ComplyError> {
    let doc = load_yaml_checked(raw, "frameworks.yaml")?;
    validate_yaml_pack_header(&doc, "frameworks.yaml")?;
    let items = yaml_req_seq(&doc, "frameworks", "frameworks.yaml")?;
    let mut out = BTreeMap::new();
    for fw in items {
        let doc_id = yaml_req_str(fw, "doc_id", "frameworks.yaml")?.to_owned();
        if out.contains_key(&doc_id) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate framework `{doc_id}` in frameworks.yaml"),
            });
        }
        let title = yaml_req_str(fw, "title", &doc_id)?.to_owned();
        let version = yaml_req_str(fw, "version", &doc_id)?.to_owned();
        let ctrl_nodes = yaml_req_seq(fw, "controls", &doc_id)?;
        if ctrl_nodes.is_empty() {
            return Err(ComplyError::VerificationFailed {
                detail: format!("framework `{doc_id}` defines zero controls"),
            });
        }
        let mut seen_ctrls = BTreeSet::new();
        let mut controls = Vec::with_capacity(ctrl_nodes.len());
        for node in ctrl_nodes {
            let control_id = yaml_req_str(node, "control_id", &doc_id)?.to_owned();
            if !seen_ctrls.insert(control_id.clone()) {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("duplicate control `{control_id}` in framework `{doc_id}`"),
                });
            }
            let paraphrase = yaml_req_str(node, "paraphrase", &control_id)?.to_owned();
            if paraphrase.split_whitespace().count() > MAX_PARAPHRASE_WORDS {
                return Err(ComplyError::VerificationFailed {
                    detail: format!(
                        "control `{control_id}` paraphrase exceeds {MAX_PARAPHRASE_WORDS} words"
                    ),
                });
            }
            controls.push(ControlEntry {
                control_id,
                paraphrase,
            });
        }
        out.insert(
            doc_id.clone(),
            FrameworkCatalogue {
                doc_id,
                title,
                version,
                controls,
            },
        );
    }
    if out.is_empty() {
        return Err(ComplyError::VerificationFailed {
            detail: "frameworks.yaml contains no frameworks".into(),
        });
    }
    Ok(out)
}

fn parse_crosswalks_yaml(
    raw: &str,
    caps: &BTreeMap<String, CapabilityRecord>,
    frameworks: &BTreeMap<String, FrameworkCatalogue>,
) -> Result<Vec<CrosswalkEntry>, ComplyError> {
    let doc = load_yaml_checked(raw, "crosswalks.yaml")?;
    validate_yaml_pack_header(&doc, "crosswalks.yaml")?;
    let items = yaml_req_seq(&doc, "crosswalks", "crosswalks.yaml")?;
    let mut out = Vec::with_capacity(items.len());
    for node in items {
        let capability = yaml_req_str(node, "capability", "crosswalks.yaml")?.to_owned();
        if !caps.contains_key(&capability) {
            return Err(ComplyError::UnknownCapability(capability));
        }
        let framework_id = yaml_req_str(node, "framework_id", "crosswalks.yaml")?.to_owned();
        let fw = frameworks
            .get(&framework_id)
            .ok_or_else(|| ComplyError::UnknownFramework(framework_id.clone()))?;
        let control_id = yaml_req_str(node, "control_id", "crosswalks.yaml")?.to_owned();
        if !fw.controls.iter().any(|c| c.control_id == control_id) {
            return Err(ComplyError::VerificationFailed {
                detail: format!(
                    "crosswalk cites unknown control `{control_id}` in `{framework_id}`"
                ),
            });
        }
        let rel_str = yaml_req_str(node, "relation", &control_id)?;
        let relation = match rel_str {
            "satisfies" => CrosswalkRelation::Satisfies,
            "supports" => CrosswalkRelation::Supports,
            "evidence-for" => CrosswalkRelation::EvidenceFor,
            other => {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("unknown crosswalk relation `{other}`"),
                });
            }
        };
        let note = yaml_req_str(node, "note", &control_id)?.to_owned();
        out.push(CrosswalkEntry {
            capability,
            framework_id,
            control_id,
            relation,
            note,
        });
    }
    Ok(out)
}

fn validate_yaml_pack_header(doc: &YamlValue, label: &str) -> Result<(), ComplyError> {
    let pack_id = yaml_req_str(doc, "pack_id", label)?;
    if pack_id != COMPLIANCE_PACK_ID {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{label}` unexpected pack_id `{pack_id}`"),
        });
    }
    Ok(())
}

fn parse_assurance_level(raw: &str, ctx: &str) -> Result<AssuranceLevel, ComplyError> {
    match raw {
        "al0-inventoried" => Ok(AssuranceLevel::Al0Inventoried),
        "al1-observed" => Ok(AssuranceLevel::Al1Observed),
        "al2-guided" => Ok(AssuranceLevel::Al2Guided),
        "al3-contained" => Ok(AssuranceLevel::Al3Contained),
        "al4-enforced" => Ok(AssuranceLevel::Al4Enforced),
        other => Err(ComplyError::Serialization {
            detail: format!("unknown assurance_requirement `{other}` for `{ctx}`"),
        }),
    }
}
