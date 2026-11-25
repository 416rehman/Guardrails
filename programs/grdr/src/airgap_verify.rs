// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap tar verification, OCI index validation, and symlink-safe atomic extraction.

use std::fs;
use std::path::Path;

use grdr_update::{
    AirgapArtifact, AirgapVerificationOutcome, DsseEnvelope, RootMetadata, SignedMetadata,
    UpdateError, canonical_sha256,
};

use crate::airgap::AirgapCliError;
use crate::airgap_bundle::{
    AIRGAP_PAYLOAD_TYPE, OCI_LAYOUT_BYTES, PATH_INDEX_JSON, PATH_MANIFEST_DSSE, PATH_MANIFEST_JSON,
    PATH_NOTICES, PATH_OCI_LAYOUT, PATH_PROJECT_ROOT, PATH_TERMS, root_fingerprint,
};
use crate::fs_safe::{
    atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular,
    reject_symlinks_on_existing_prefixes,
};
use crate::tar_archive::{read_tar_file, validate_archive_rel_path};

const MAX_ROOT_METADATA_BYTES: u64 = 1024 * 1024;
const PINNED_ROOT_FILE: &str = "project-root.json";

pub struct ParsedTarBundle {
    pub embedded_root: Option<SignedMetadata<RootMetadata>>,
    pub envelope: DsseEnvelope,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: String,
    pub index_bytes: Vec<u8>,
    pub artifacts: Vec<AirgapArtifact>,
}

pub fn load_parsed_tar_bundle(bundle_path: &Path) -> Result<ParsedTarBundle, AirgapCliError> {
    let entries =
        read_tar_file(bundle_path).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    let mut root_bytes: Option<Vec<u8>> = None;
    let mut dsse_bytes: Option<Vec<u8>> = None;
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut index_bytes: Option<Vec<u8>> = None;
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut artifacts = Vec::new();

    for entry in entries {
        match entry.path.as_str() {
            PATH_PROJECT_ROOT => root_bytes = Some(entry.bytes),
            PATH_MANIFEST_DSSE => dsse_bytes = Some(entry.bytes),
            PATH_MANIFEST_JSON => manifest_bytes = Some(entry.bytes),
            PATH_INDEX_JSON => index_bytes = Some(entry.bytes),
            p if p.starts_with("blobs/sha256/") => {
                let hex_part = p.strip_prefix("blobs/sha256/").unwrap_or("").to_owned();
                blobs.push((hex_part, entry.bytes));
            }
            _ => artifacts.push(AirgapArtifact {
                path: entry.path,
                bytes: entry.bytes,
            }),
        }
    }

    let raw_dsse = dsse_bytes.ok_or_else(|| {
        UpdateError::MalformedMetadata("missing meta/airgap-manifest.dsse.json".into())
    })?;
    let envelope: DsseEnvelope = serde_json::from_slice(&raw_dsse)
        .map_err(|e| UpdateError::MalformedMetadata(e.to_string()))?;
    let raw_manifest = manifest_bytes.ok_or_else(|| {
        UpdateError::MalformedMetadata("missing meta/airgap-manifest.json".into())
    })?;
    let manifest_sha256 = canonical_sha256(&raw_manifest);
    if blobs.len() != 1 {
        return Err(UpdateError::ArtifactIntegrity {
            target: "blobs/sha256".into(),
            detail: "expected exact single OCI manifest blob without unmanifested extras".into(),
        }
        .into());
    }
    if let Some((blob_hex, blob_bytes)) = blobs.first()
        && (*blob_hex != manifest_sha256
            || canonical_sha256(blob_bytes) != manifest_sha256
            || *blob_bytes != raw_manifest)
    {
        return Err(UpdateError::ArtifactIntegrity {
            target: format!("blobs/sha256/{blob_hex}"),
            detail: "OCI blob digest or bytes diverge from manifest".into(),
        }
        .into());
    }
    let idx_raw =
        index_bytes.ok_or_else(|| UpdateError::MalformedMetadata("missing index.json".into()))?;
    let embedded_root = match root_bytes {
        Some(raw) => Some(
            serde_json::from_slice::<SignedMetadata<RootMetadata>>(&raw)
                .map_err(|e| UpdateError::MalformedMetadata(e.to_string()))?,
        ),
        None => None,
    };

    Ok(ParsedTarBundle {
        embedded_root,
        envelope,
        manifest_bytes: raw_manifest,
        manifest_sha256,
        index_bytes: idx_raw,
        artifacts,
    })
}

pub fn resolve_trust_anchor(
    override_root: Option<&Path>,
    state_dir: Option<&Path>,
    expected_fingerprint: Option<&str>,
    parsed: &ParsedTarBundle,
) -> Result<SignedMetadata<RootMetadata>, AirgapCliError> {
    if let Some(root_path) = override_root {
        return read_root_metadata_file(root_path);
    }
    if let Some(dir) = state_dir {
        let pinned = dir.join(PINNED_ROOT_FILE);
        if fs::symlink_metadata(&pinned).is_ok() {
            return read_root_metadata_file(&pinned);
        }
    }
    let Some(expected_fp) = expected_fingerprint else {
        return Err(UpdateError::UnauthorizedRoot(
            "no trust anchor provided: supply --root, an initialized --state-dir/project-root.json, or --expected-fingerprint verified via --print-root".into(),
        )
        .into());
    };
    let embedded = parsed.embedded_root.clone().ok_or_else(|| {
        UpdateError::MalformedMetadata("missing meta/project-root.json in bundle".into())
    })?;
    let actual_fp = root_fingerprint(&embedded.signed)?;
    if actual_fp != expected_fp {
        return Err(UpdateError::UnauthorizedRoot(format!(
            "project root fingerprint `{actual_fp}` != expected `{expected_fp}`"
        ))
        .into());
    }
    Ok(embedded)
}

pub fn read_root_metadata_file(
    path: &Path,
) -> Result<SignedMetadata<RootMetadata>, AirgapCliError> {
    let raw = read_bounded_regular(path, MAX_ROOT_METADATA_BYTES)
        .map_err(|e| io_err(path, &e.to_string()))?;
    serde_json::from_slice(&raw)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid root metadata: {e}")).into())
}

pub fn verify_required_bundle_envelope(
    parsed: &ParsedTarBundle,
    outcome: &AirgapVerificationOutcome,
    actual_root_fp: &str,
) -> Result<(), AirgapCliError> {
    let mut has_oci = false;
    let mut has_notices = false;
    let mut has_terms = false;
    for item in &parsed.artifacts {
        match item.path.as_str() {
            PATH_OCI_LAYOUT => {
                if item.bytes != OCI_LAYOUT_BYTES {
                    return Err(UpdateError::ArtifactIntegrity {
                        target: PATH_OCI_LAYOUT.into(),
                        detail: "unexpected oci-layout descriptor".into(),
                    }
                    .into());
                }
                has_oci = true;
            }
            PATH_NOTICES => has_notices = true,
            PATH_TERMS => has_terms = true,
            _ => {}
        }
    }
    if !has_oci || !has_notices || !has_terms {
        return Err(UpdateError::MalformedMetadata(
            "bundle missing signed oci-layout, THIRD-PARTY-NOTICES, or terms.txt entry".into(),
        )
        .into());
    }

    let index: serde_json::Value = serde_json::from_slice(&parsed.index_bytes)
        .map_err(|e| UpdateError::MalformedMetadata(format!("malformed index.json: {e}")))?;
    let manifests = index
        .get("manifests")
        .and_then(|v| v.as_array())
        .ok_or_else(|| {
            UpdateError::MalformedMetadata("index.json missing manifests array".into())
        })?;
    if index.get("schemaVersion").and_then(|v| v.as_u64()) != Some(2) || manifests.len() != 1 {
        return Err(UpdateError::MalformedMetadata(
            "index.json must be schemaVersion 2 with exactly 1 manifest".into(),
        )
        .into());
    }
    let desc = manifests.first().ok_or_else(|| {
        UpdateError::MalformedMetadata("index.json manifest descriptor missing".into())
    })?;
    let expected_digest = format!("sha256:{}", parsed.manifest_sha256);
    if desc.get("mediaType").and_then(|v| v.as_str()) != Some(AIRGAP_PAYLOAD_TYPE)
        || desc.get("digest").and_then(|v| v.as_str()) != Some(expected_digest.as_str())
        || desc.get("size").and_then(|v| v.as_u64())
            != u64::try_from(parsed.manifest_bytes.len()).ok()
    {
        return Err(UpdateError::ArtifactIntegrity {
            target: PATH_INDEX_JSON.into(),
            detail: "index.json manifest descriptor does not match signed manifest".into(),
        }
        .into());
    }
    let annotations = desc
        .get("annotations")
        .and_then(|v| v.as_object())
        .ok_or_else(|| UpdateError::MalformedMetadata("index.json missing annotations".into()))?;
    if annotations
        .get("org.guardrails.airgap.bundle_id")
        .and_then(|v| v.as_str())
        != Some(outcome.bundle_id.as_str())
        || annotations
            .get("org.guardrails.airgap.bundle_version")
            .and_then(|v| v.as_str())
            != Some(outcome.bundle_version.as_str())
        || annotations
            .get("org.guardrails.airgap.root_fingerprint")
            .and_then(|v| v.as_str())
            != Some(actual_root_fp)
    {
        return Err(UpdateError::ArtifactIntegrity {
            target: PATH_INDEX_JSON.into(),
            detail: "index.json annotations diverge from verified manifest or root".into(),
        }
        .into());
    }
    Ok(())
}

pub fn extract_verified_artifacts(
    dest: &Path,
    artifacts: &[AirgapArtifact],
) -> Result<(), AirgapCliError> {
    ensure_safe_dir_all(dest, false).map_err(|e| io_err(dest, &e.to_string()))?;
    let mut staged_targets = Vec::with_capacity(artifacts.len());
    for item in artifacts {
        validate_archive_rel_path(&item.path)
            .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
        let target = item
            .path
            .split('/')
            .fold(dest.to_path_buf(), |acc, s| acc.join(s));
        reject_symlinks_on_existing_prefixes(&target)
            .map_err(|e| io_err(&target, &e.to_string()))?;
        staged_targets.push((target, &item.bytes));
    }
    for (target, bytes) in staged_targets {
        atomic_write_bytes(&target, bytes, false).map_err(|e| io_err(&target, &e.to_string()))?;
    }
    Ok(())
}

fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
