// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap tar verification, OCI index validation, delta/split validation, and atomic extraction.

use std::path::Path;

use grdr_update::{
    AirgapArtifact, AirgapBundleManifest, AirgapVerificationOutcome, DsseEnvelope, RootMetadata,
    SignedMetadata, SnapshotMetadata, TargetsMetadata, TimestampMetadata, UpdateError, YankRecord,
    canonical_sha256,
};

use crate::airgap::AirgapCliError;
use crate::airgap::airgap_policy::{
    BundleTransferKind, ExtendedBundleDescriptor, PATH_BUNDLE_EXTENDED, reassemble_verified_parts,
};
use crate::airgap::airgap_state::check_yank_slice;
use crate::airgap_bundle::{
    AIRGAP_PAYLOAD_TYPE, OCI_LAYOUT_BYTES, PATH_INDEX_JSON, PATH_MANIFEST_DSSE, PATH_MANIFEST_JSON,
    PATH_NOTICES, PATH_OCI_LAYOUT, PATH_PROJECT_ROOT, PATH_TERMS, PATH_TUF_SNAPSHOT,
    PATH_TUF_TARGETS, PATH_TUF_TIMESTAMP, root_fingerprint,
};
use crate::fs_safe::{
    atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular,
    reject_symlinks_on_existing_prefixes,
};
use crate::tar_archive::{decode_tar, read_tar_file, validate_archive_rel_path};

const MAX_ROOT_METADATA_BYTES: u64 = 1024 * 1024;

pub struct ParsedTarBundle {
    pub embedded_root: Option<SignedMetadata<RootMetadata>>,
    pub tuf_timestamp: Option<SignedMetadata<TimestampMetadata>>,
    pub tuf_snapshot: Option<SignedMetadata<SnapshotMetadata>>,
    pub tuf_targets: Option<SignedMetadata<TargetsMetadata>>,
    pub envelope: DsseEnvelope,
    pub manifest: AirgapBundleManifest,
    pub manifest_bytes: Vec<u8>,
    pub manifest_sha256: String,
    pub index_bytes: Vec<u8>,
    pub artifacts: Vec<AirgapArtifact>,
}

pub fn load_parsed_tar_bundle(bundle_path: &Path) -> Result<ParsedTarBundle, AirgapCliError> {
    let is_parts_manifest = bundle_path
        .file_name()
        .and_then(|n| n.to_str())
        .is_some_and(|n| n.ends_with(".parts.json"));
    let entries = if is_parts_manifest {
        let reassembled = reassemble_verified_parts(bundle_path)?;
        decode_tar(&reassembled).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?
    } else {
        read_tar_file(bundle_path).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?
    };

    let mut root_bytes: Option<Vec<u8>> = None;
    let mut ts_bytes: Option<Vec<u8>> = None;
    let mut snap_bytes: Option<Vec<u8>> = None;
    let mut targets_bytes: Option<Vec<u8>> = None;
    let mut dsse_bytes: Option<Vec<u8>> = None;
    let mut manifest_bytes: Option<Vec<u8>> = None;
    let mut index_bytes: Option<Vec<u8>> = None;
    let mut blobs: Vec<(String, Vec<u8>)> = Vec::new();
    let mut artifacts = Vec::new();

    for entry in entries {
        match entry.path.as_str() {
            PATH_PROJECT_ROOT => root_bytes = Some(entry.bytes),
            PATH_TUF_TIMESTAMP => ts_bytes = Some(entry.bytes),
            PATH_TUF_SNAPSHOT => snap_bytes = Some(entry.bytes),
            PATH_TUF_TARGETS => targets_bytes = Some(entry.bytes),
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
    let manifest: AirgapBundleManifest = serde_json::from_slice(&raw_manifest)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid manifest JSON: {e}")))?;
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

    Ok(ParsedTarBundle {
        embedded_root: parse_opt_json(root_bytes, "project-root.json")?,
        tuf_timestamp: parse_opt_json(ts_bytes, "timestamp.json")?,
        tuf_snapshot: parse_opt_json(snap_bytes, "snapshot.json")?,
        tuf_targets: parse_opt_json(targets_bytes, "targets.json")?,
        envelope,
        manifest,
        manifest_bytes: raw_manifest,
        manifest_sha256,
        index_bytes: idx_raw,
        artifacts,
    })
}

fn parse_opt_json<T: serde::de::DeserializeOwned>(
    raw: Option<Vec<u8>>,
    label: &str,
) -> Result<Option<T>, AirgapCliError> {
    match raw {
        Some(bytes) => serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|e| UpdateError::MalformedMetadata(format!("invalid {label}: {e}")).into()),
        None => Ok(None),
    }
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
    let expected_ann_fp = match parsed.embedded_root.as_ref() {
        Some(emb) => root_fingerprint(&emb.signed)?,
        None => actual_root_fp.to_owned(),
    };
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
            != Some(expected_ann_fp.as_str())
    {
        return Err(UpdateError::ArtifactIntegrity {
            target: PATH_INDEX_JSON.into(),
            detail: "index.json annotations diverge from verified manifest or root".into(),
        }
        .into());
    }
    Ok(())
}

pub fn verify_extended_bundle_rules(
    parsed: &ParsedTarBundle,
    outcome: &AirgapVerificationOutcome,
    installed_base_sha256: Option<&str>,
    external_yanks: &[YankRecord],
) -> Result<Option<ExtendedBundleDescriptor>, AirgapCliError> {
    check_yank_slice(
        external_yanks,
        outcome,
        &parsed.manifest_sha256,
        &parsed.manifest.entries,
    )?;

    let Some(ext_item) = parsed
        .artifacts
        .iter()
        .find(|a| a.path == PATH_BUNDLE_EXTENDED)
    else {
        return Ok(None);
    };

    let ext: ExtendedBundleDescriptor = serde_json::from_slice(&ext_item.bytes).map_err(|e| {
        UpdateError::MalformedMetadata(format!("invalid bundle-extended JSON: {e}"))
    })?;

    if let BundleTransferKind::Delta {
        base_version,
        base_manifest_sha256,
    } = &ext.bundle_kind
    {
        match installed_base_sha256 {
            Some(installed) if installed == base_manifest_sha256 => {}
            other => {
                return Err(UpdateError::ArtifactIntegrity {
                    target: format!("delta-base@{base_version}"),
                    detail: format!(
                        "missing required delta base `{base_version}` (expected sha256:{base_manifest_sha256}, installed:{other:?})"
                    ),
                }
                .into());
            }
        }
    }

    check_yank_slice(
        &ext.yanked_releases,
        outcome,
        &parsed.manifest_sha256,
        &parsed.manifest.entries,
    )?;

    Ok(Some(ext))
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
