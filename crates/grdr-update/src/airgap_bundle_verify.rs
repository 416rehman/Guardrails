// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::UpdateError;
use crate::dsse::{DsseEnvelope, verify_dsse_envelope};
use crate::tuf::UpdateTrust;
use crate::tuf_types::canonical_sha256;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutHaltEntry {
    pub pack_id: String,
    pub version: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapBundleEntry {
    pub path: String,
    pub pack_id: String,
    pub version: String,
    pub sha256: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapBundleManifest {
    pub bundle_id: String,
    pub bundle_version: String,
    pub created_at: Timestamp,
    pub entries: Vec<AirgapBundleEntry>,
    pub halted_releases: Vec<RolloutHaltEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapArtifact {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "approval", rename_all = "snake_case")]
pub enum BundleApprovalState {
    AwaitingTermsAcceptance,
    TermsAccepted {
        operator_id: String,
        accepted_at: Timestamp,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapVerificationOutcome {
    pub bundle_id: String,
    pub bundle_version: String,
    pub verified_entries: usize,
    pub operator_id: String,
}

pub fn verify_airgap_bundle(
    trust: &UpdateTrust,
    bundle_envelope: &DsseEnvelope,
    artifacts: &[AirgapArtifact],
    approval: &BundleApprovalState,
    external_halts: &[RolloutHaltEntry],
    now: Timestamp,
) -> Result<AirgapVerificationOutcome, UpdateError> {
    let BundleApprovalState::TermsAccepted { operator_id, .. } = approval else {
        return Err(UpdateError::TermsNotAccepted);
    };

    if trust.project_root_expires() <= now {
        return Err(UpdateError::MetadataExpired {
            role: "project_root".into(),
            expired_at: trust.project_root_expires().to_string(),
        });
    }

    let mut artifact_map: BTreeMap<&str, &[u8]> = BTreeMap::new();
    for item in artifacts {
        validate_relative_bundle_path(&item.path)?;
        if artifact_map
            .insert(item.path.as_str(), item.bytes.as_slice())
            .is_some()
        {
            return Err(UpdateError::MalformedMetadata(format!(
                "duplicate artifact path `{}` in air-gap bundle",
                item.path
            )));
        }
    }

    let payload_bytes = verify_airgap_envelope_role(trust, bundle_envelope, artifacts)?;

    let manifest: AirgapBundleManifest = serde_json::from_slice(&payload_bytes).map_err(|e| {
        UpdateError::MalformedMetadata(format!("invalid airgap bundle manifest JSON: {e}"))
    })?;

    if manifest.entries.is_empty() {
        return Err(UpdateError::MalformedMetadata(
            "airgap bundle manifest has no entries".into(),
        ));
    }

    let mut seen_manifest_paths = BTreeSet::new();
    for entry in &manifest.entries {
        validate_relative_bundle_path(&entry.path)?;
        if !seen_manifest_paths.insert(entry.path.as_str()) {
            return Err(UpdateError::MalformedMetadata(format!(
                "duplicate manifest entry path `{}`",
                entry.path
            )));
        }

        if let Some(halt) = manifest
            .halted_releases
            .iter()
            .chain(external_halts.iter())
            .find(|h| h.pack_id == entry.pack_id && h.version == entry.version)
        {
            return Err(UpdateError::HaltedRelease(format!(
                "{}@{} ({})",
                halt.pack_id, halt.version, halt.reason
            )));
        }

        let Some(raw) = artifact_map.get(entry.path.as_str()) else {
            return Err(UpdateError::ArtifactIntegrity {
                target: entry.path.clone(),
                detail: "artifact missing from air-gap bundle".into(),
            });
        };

        let actual_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if actual_len != entry.length {
            return Err(UpdateError::ArtifactIntegrity {
                target: entry.path.clone(),
                detail: format!("length {actual_len} != expected {}", entry.length),
            });
        }

        let actual_sha = canonical_sha256(raw);
        if actual_sha != entry.sha256 {
            return Err(UpdateError::ArtifactIntegrity {
                target: entry.path.clone(),
                detail: format!("sha256 {actual_sha} != expected {}", entry.sha256),
            });
        }
    }

    if artifact_map.len() != seen_manifest_paths.len() {
        return Err(UpdateError::ArtifactIntegrity {
            target: manifest.bundle_id,
            detail: "air-gap bundle contains unmanifested artifacts".into(),
        });
    }

    Ok(AirgapVerificationOutcome {
        bundle_id: manifest.bundle_id,
        bundle_version: manifest.bundle_version,
        verified_entries: manifest.entries.len(),
        operator_id: operator_id.clone(),
    })
}

fn verify_airgap_envelope_role(
    trust: &UpdateTrust,
    bundle_envelope: &DsseEnvelope,
    artifacts: &[AirgapArtifact],
) -> Result<Vec<u8>, UpdateError> {
    let has_non_content = artifacts
        .iter()
        .any(|a| !is_content_only_companion_path(&a.path));

    let (bin_keys, bin_threshold) = trust.project_binaries_role_keys()?;
    if bin_threshold < 2 {
        return Err(UpdateError::UnauthorizedRoot(
            "project root TufRole::Binaries must enforce threshold >= 2".into(),
        ));
    }
    if let Ok(payload_bytes) = verify_dsse_envelope(bundle_envelope, &bin_keys, bin_threshold) {
        return Ok(payload_bytes);
    }
    if has_non_content {
        return Err(UpdateError::InvalidSignature(
            "airgap bundle carrying binaries/images/packages/charts requires 2-of-2 TufRole::Binaries signatures"
                .into(),
        ));
    }

    let (content_keys, content_threshold) = trust.project_content_role_keys()?;
    let payload_bytes = verify_dsse_envelope(bundle_envelope, &content_keys, content_threshold)?;
    let manifest: AirgapBundleManifest = serde_json::from_slice(&payload_bytes).map_err(|e| {
        UpdateError::MalformedMetadata(format!("invalid airgap bundle manifest JSON: {e}"))
    })?;
    if manifest
        .entries
        .iter()
        .any(|e| !is_content_only_companion_path(&e.path))
        || extended_meta_contains_non_content(artifacts)
    {
        return Err(UpdateError::UnauthorizedRoot(
            "TufRole::Content cannot authorize binaries, images, charts, packages, terraform, or models"
                .into(),
        ));
    }
    Ok(payload_bytes)
}

fn is_content_only_companion_path(path: &str) -> bool {
    path.starts_with("packs/")
        || path.starts_with("content/")
        || path.starts_with("docs/")
        || path.starts_with("sbom/")
        || path.starts_with("vex/")
        || path.starts_with("csaf/")
        || path.starts_with("sources/")
        || matches!(
            path,
            "oci-layout"
                | "THIRD-PARTY-NOTICES"
                | "terms.txt"
                | "meta/bundle-extended.json"
                | "meta/upgrade-path.json"
                | "meta/yanks.json"
                | "meta/dependencies.lock.json"
                | "meta/rollout.json"
        )
}

fn extended_meta_contains_non_content(artifacts: &[AirgapArtifact]) -> bool {
    let Some(ext) = artifacts
        .iter()
        .find(|a| a.path == "meta/bundle-extended.json")
    else {
        return false;
    };
    let Ok(val) = serde_json::from_slice::<serde_json::Value>(&ext.bytes) else {
        return true;
    };
    val.get("included_classes")
        .and_then(|c| c.as_array())
        .is_none_or(|arr| {
            arr.iter().any(|v| {
                matches!(
                    v.as_str(),
                    Some(
                        "binaries"
                            | "images"
                            | "charts"
                            | "apt_packages"
                            | "rpm_packages"
                            | "terraform"
                            | "models"
                    )
                )
            })
        })
}

fn validate_relative_bundle_path(path: &str) -> Result<(), UpdateError> {
    if path.is_empty()
        || path.starts_with('/')
        || path.contains('\\')
        || path.contains(':')
        || path.chars().any(char::is_control)
    {
        return Err(UpdateError::MalformedMetadata(format!(
            "invalid air-gap bundle path `{path}`"
        )));
    }
    for segment in path.split('/') {
        if segment.is_empty() || segment == "." || segment == ".." {
            return Err(UpdateError::MalformedMetadata(format!(
                "path traversal or empty segment in air-gap bundle path `{path}`"
            )));
        }
    }
    Ok(())
}
