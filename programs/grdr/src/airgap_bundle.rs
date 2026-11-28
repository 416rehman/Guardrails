// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap OCI-layout / POSIX tar bundle construction helpers.

use std::collections::BTreeSet;
use std::path::Path;

use grdr_update::{
    AirgapArtifact, AirgapBundleEntry, AirgapBundleManifest, RolloutHaltEntry, YankRecord,
    canonical_sha256, sign_dsse_envelope,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
pub use crate::airgap::airgap_bundle_tuf::root_fingerprint;
use crate::airgap::airgap_bundle_tuf::{
    build_project_root_metadata, build_signed_tuf_chain, resolve_signing_pair,
};
use crate::airgap::airgap_policy::{
    ArtefactClass, BundleTransferKind, DependenciesLockFile, ExtendedBundleDescriptor,
    MAX_ASSET_FILE_BYTES, PATH_BUNDLE_EXTENDED, PATH_DEPS_LOCK, PATH_RELEASE_MANIFEST,
    PATH_ROLLOUT_JSON, PATH_TRUSTED_ROOT, PATH_UPGRADE_PATH, PATH_YANKS_JSON, UpgradePathMetadata,
    collect_scoped_files, split_archive_to_parts, validate_dependencies_and_generate_notices,
    validate_real_dir,
};
use crate::fs_safe::{atomic_write_bytes, read_bounded_regular};
use crate::tar_archive::{TarEntry, encode_tar};

pub const PATH_OCI_LAYOUT: &str = "oci-layout";
pub const PATH_INDEX_JSON: &str = "index.json";
pub const PATH_MANIFEST_JSON: &str = "meta/airgap-manifest.json";
pub const PATH_MANIFEST_DSSE: &str = "meta/airgap-manifest.dsse.json";
pub const PATH_PROJECT_ROOT: &str = "meta/project-root.json";
pub const PATH_TUF_TIMESTAMP: &str = "meta/tuf/timestamp.json";
pub const PATH_TUF_SNAPSHOT: &str = "meta/tuf/snapshot.json";
pub const PATH_TUF_TARGETS: &str = "meta/tuf/targets.json";
pub const PATH_NOTICES: &str = "THIRD-PARTY-NOTICES";
pub const PATH_TERMS: &str = "terms.txt";
pub const AIRGAP_PAYLOAD_TYPE: &str = "application/vnd.grdr.airgap-manifest+json";
pub const OCI_LAYOUT_BYTES: &[u8] = br#"{"imageLayoutVersion":"1.0.0"}"#;
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone)]
pub struct AirgapBuildRequest<'a> {
    pub packs_dir: &'a Path,
    pub out: &'a Path,
    pub bundle_id: &'a str,
    pub version: &'a str,
    pub expires_days: i64,
    pub halted_releases: &'a [RolloutHaltEntry],
    pub key_dir: Option<&'a Path>,
    pub allow_ephemeral_dev_keys: bool,
}

#[derive(Debug, Clone)]
pub struct AirgapFullBuildRequest<'a> {
    pub base: AirgapBuildRequest<'a>,
    pub binaries_dir: Option<&'a Path>,
    pub images_dir: Option<&'a Path>,
    pub charts_dir: Option<&'a Path>,
    pub apt_dir: Option<&'a Path>,
    pub rpm_dir: Option<&'a Path>,
    pub docs_dir: Option<&'a Path>,
    pub terraform_dir: Option<&'a Path>,
    pub models_dir: Option<&'a Path>,
    pub csaf_dir: Option<&'a Path>,
    pub sources_dir: Option<&'a Path>,
    pub sbom_path: Option<&'a Path>,
    pub vex_path: Option<&'a Path>,
    pub dependencies_lock_path: Option<&'a Path>,
    pub release_manifest_path: Option<&'a Path>,
    pub trusted_root_path: Option<&'a Path>,
    pub rollout_path: Option<&'a Path>,
    pub platforms: &'a [String],
    pub delta_from_version: Option<&'a str>,
    pub delta_from_manifest_sha256: Option<&'a str>,
    pub minimum_base_version: Option<&'a str>,
    pub yanked_releases: &'a [YankRecord],
    pub split_bytes: Option<u64>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapBuildSummary {
    pub bundle_id: String,
    pub bundle_version: String,
    pub root_fingerprint: String,
    pub manifest_sha256: String,
    pub entries_count: usize,
    pub out: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parts_manifest: Option<String>,
    pub parts_count: usize,
}

pub fn build_full_airgap_tar(
    req: &AirgapFullBuildRequest<'_>,
) -> Result<AirgapBuildSummary, AirgapCliError> {
    let base = &req.base;
    validate_real_dir(base.packs_dir, "packs_dir")?;

    let mut files = Vec::new();
    let mut classes = BTreeSet::from([ArtefactClass::Packs, ArtefactClass::TufMetadata]);
    collect_scoped_files(
        base.packs_dir,
        base.packs_dir,
        "packs",
        req.platforms,
        &mut files,
        0,
    )?;

    let optional_dirs: [(&str, Option<&Path>, ArtefactClass); 10] = [
        ("binaries", req.binaries_dir, ArtefactClass::Binaries),
        ("images", req.images_dir, ArtefactClass::Images),
        ("charts", req.charts_dir, ArtefactClass::Charts),
        ("packages/apt", req.apt_dir, ArtefactClass::AptPackages),
        ("packages/rpm", req.rpm_dir, ArtefactClass::RpmPackages),
        ("docs", req.docs_dir, ArtefactClass::Docs),
        ("terraform", req.terraform_dir, ArtefactClass::Terraform),
        ("models", req.models_dir, ArtefactClass::Models),
        ("csaf", req.csaf_dir, ArtefactClass::Csaf),
        ("sources", req.sources_dir, ArtefactClass::Sources),
    ];
    let mut has_extended = !req.platforms.is_empty()
        || !req.yanked_releases.is_empty()
        || req.delta_from_manifest_sha256.is_some();

    for (prefix, maybe_dir, class) in optional_dirs {
        if let Some(dir) = maybe_dir {
            validate_real_dir(dir, prefix)?;
            let before = files.len();
            collect_scoped_files(dir, dir, prefix, req.platforms, &mut files, 0)?;
            if files.len() > before {
                classes.insert(class);
                has_extended = true;
            }
        }
    }

    let optional_files: [(&str, Option<&Path>, ArtefactClass); 6] = [
        ("sbom/cyclonedx.json", req.sbom_path, ArtefactClass::Sbom),
        ("vex/openvex.json", req.vex_path, ArtefactClass::Vex),
        (
            PATH_DEPS_LOCK,
            req.dependencies_lock_path,
            ArtefactClass::TufMetadata,
        ),
        (
            PATH_RELEASE_MANIFEST,
            req.release_manifest_path,
            ArtefactClass::TufMetadata,
        ),
        (
            PATH_TRUSTED_ROOT,
            req.trusted_root_path,
            ArtefactClass::TufMetadata,
        ),
        (
            PATH_ROLLOUT_JSON,
            req.rollout_path,
            ArtefactClass::TufMetadata,
        ),
    ];
    for (target_path, maybe_file, class) in optional_files {
        if let Some(src) = maybe_file {
            let bytes = read_bounded_regular(src, MAX_ASSET_FILE_BYTES)
                .map_err(|e| io_err(src, &e.to_string()))?;
            files.push(AirgapArtifact {
                path: target_path.into(),
                bytes,
            });
            classes.insert(class);
            has_extended = true;
        }
    }

    if files.is_empty() {
        return Err(AirgapCliError::InvalidInput(
            "no pack files found to bundle".into(),
        ));
    }

    let (notices_txt, terms_txt) = resolve_notices_and_terms(req, &files)?;
    let notices_sha = canonical_sha256(notices_txt.as_bytes());
    let terms_sha = canonical_sha256(terms_txt.as_bytes());

    files.extend([
        AirgapArtifact {
            path: PATH_OCI_LAYOUT.into(),
            bytes: OCI_LAYOUT_BYTES.to_vec(),
        },
        AirgapArtifact {
            path: PATH_NOTICES.into(),
            bytes: notices_txt.into_bytes(),
        },
        AirgapArtifact {
            path: PATH_TERMS.into(),
            bytes: terms_txt.into_bytes(),
        },
    ]);
    if has_extended {
        append_extended_meta(req, classes, notices_sha, terms_sha, &mut files)?;
    }
    files.sort_by(|a, b| a.path.cmp(&b.path));

    let (signer_a, signer_b) = resolve_signing_pair(base.key_dir, base.allow_ephemeral_dev_keys)?;
    let now = Timestamp::now();
    let expires = Timestamp::from_second(
        now.as_second()
            .saturating_add(base.expires_days.max(1).saturating_mul(SECONDS_PER_DAY)),
    )
    .unwrap_or(now);

    let root_meta = build_project_root_metadata(&signer_a, &signer_b, expires)?;
    let root_fp = root_fingerprint(&root_meta.signed)?;
    let root_json = serde_json::to_vec_pretty(&root_meta).map_err(bad_input)?;

    let mut manifest_entries = Vec::with_capacity(files.len());
    let mut tar_entries = Vec::new();
    for item in &files {
        let (pack_id, pack_ver) = infer_pack_id_and_version(&item.path, base.version);
        manifest_entries.push(AirgapBundleEntry {
            path: item.path.clone(),
            pack_id,
            version: pack_ver,
            sha256: canonical_sha256(&item.bytes),
            length: u64::try_from(item.bytes.len()).unwrap_or(u64::MAX),
        });
        tar_entries.push(TarEntry {
            path: item.path.clone(),
            bytes: item.bytes.clone(),
        });
    }

    let manifest = AirgapBundleManifest {
        bundle_id: base.bundle_id.to_owned(),
        bundle_version: base.version.to_owned(),
        created_at: now,
        entries: manifest_entries,
        halted_releases: base.halted_releases.to_vec(),
    };
    let manifest_bytes = serde_json::to_vec_pretty(&manifest).map_err(bad_input)?;
    let manifest_sha = canonical_sha256(&manifest_bytes);
    let dsse = sign_dsse_envelope(
        AIRGAP_PAYLOAD_TYPE,
        &manifest_bytes,
        &[&signer_a, &signer_b],
    )?;
    let dsse_bytes = serde_json::to_vec_pretty(&dsse).map_err(bad_input)?;
    let (ts_json, snap_json, targets_json) = build_signed_tuf_chain(
        &signer_a,
        base.version,
        &manifest_sha,
        &manifest_bytes,
        expires,
    )?;
    let index_json = serde_json::to_vec_pretty(&serde_json::json!({
        "schemaVersion": 2,
        "mediaType": "application/vnd.oci.image.index.v1+json",
        "manifests": [{
            "mediaType": AIRGAP_PAYLOAD_TYPE,
            "digest": format!("sha256:{manifest_sha}"),
            "size": manifest_bytes.len(),
            "annotations": {
                "org.guardrails.airgap.bundle_id": base.bundle_id,
                "org.guardrails.airgap.bundle_version": base.version,
                "org.guardrails.airgap.root_fingerprint": root_fp,
            }
        }]
    }))
    .map_err(bad_input)?;

    tar_entries.extend([
        TarEntry {
            path: PATH_INDEX_JSON.into(),
            bytes: index_json,
        },
        TarEntry {
            path: format!("blobs/sha256/{manifest_sha}"),
            bytes: manifest_bytes.clone(),
        },
        TarEntry {
            path: PATH_MANIFEST_JSON.into(),
            bytes: manifest_bytes,
        },
        TarEntry {
            path: PATH_MANIFEST_DSSE.into(),
            bytes: dsse_bytes,
        },
        TarEntry {
            path: PATH_PROJECT_ROOT.into(),
            bytes: root_json,
        },
        TarEntry {
            path: PATH_TUF_TIMESTAMP.into(),
            bytes: ts_json,
        },
        TarEntry {
            path: PATH_TUF_SNAPSHOT.into(),
            bytes: snap_json,
        },
        TarEntry {
            path: PATH_TUF_TARGETS.into(),
            bytes: targets_json,
        },
    ]);
    tar_entries.sort_by(|a, b| a.path.cmp(&b.path));
    let tar_bytes = encode_tar(&tar_entries).map_err(bad_input)?;
    atomic_write_bytes(base.out, &tar_bytes, false)
        .map_err(|e| io_err(base.out, &e.to_string()))?;

    let (parts_manifest, parts_count) = match req.split_bytes {
        Some(chunk_bytes) => {
            let (pm, pm_path) = split_archive_to_parts(
                &tar_bytes,
                base.out,
                chunk_bytes,
                base.bundle_id,
                base.version,
            )?;
            (Some(pm_path.display().to_string()), pm.parts.len())
        }
        None => (None, 0),
    };

    Ok(AirgapBuildSummary {
        bundle_id: base.bundle_id.to_owned(),
        bundle_version: base.version.to_owned(),
        root_fingerprint: root_fp,
        manifest_sha256: manifest_sha,
        entries_count: files.len(),
        out: base.out.display().to_string(),
        parts_manifest,
        parts_count,
    })
}

fn resolve_notices_and_terms(
    req: &AirgapFullBuildRequest<'_>,
    files: &[AirgapArtifact],
) -> Result<(String, String), AirgapCliError> {
    if let Some(lock_path) = req.dependencies_lock_path {
        let raw = read_bounded_regular(lock_path, MAX_ASSET_FILE_BYTES)
            .map_err(|e| io_err(lock_path, &e.to_string()))?;
        let deps: DependenciesLockFile = serde_json::from_slice(&raw).map_err(bad_input)?;
        let source_paths: BTreeSet<String> = files
            .iter()
            .filter(|f| f.path.starts_with("sources/"))
            .map(|f| f.path.clone())
            .collect();
        return validate_dependencies_and_generate_notices(
            &deps,
            &source_paths,
            req.base.bundle_id,
            req.base.version,
        );
    }
    Ok((
        "Guardrails ADR (Apache-2.0).\n".to_owned(),
        format!(
            "bundle_id={}\nversion={}\nlicense=Apache-2.0\nnotices={PATH_NOTICES}\n",
            req.base.bundle_id, req.base.version
        ),
    ))
}

fn append_extended_meta(
    req: &AirgapFullBuildRequest<'_>,
    classes: BTreeSet<ArtefactClass>,
    notices_sha256: String,
    terms_sha256: String,
    files: &mut Vec<AirgapArtifact>,
) -> Result<(), AirgapCliError> {
    let bundle_kind = match req.delta_from_manifest_sha256 {
        Some(base_sha) => BundleTransferKind::Delta {
            base_version: req.delta_from_version.unwrap_or("unknown").to_owned(),
            base_manifest_sha256: base_sha.to_owned(),
        },
        None => BundleTransferKind::Full,
    };
    let upgrade_path = UpgradePathMetadata {
        from_version: req.delta_from_version.map(ToOwned::to_owned),
        to_version: req.base.version.to_owned(),
        minimum_base_version: req.minimum_base_version.map(ToOwned::to_owned),
        requires_delta_base_sha256: req.delta_from_manifest_sha256.map(ToOwned::to_owned),
        allowed_platforms: req.platforms.to_vec(),
    };
    let extended = ExtendedBundleDescriptor {
        bundle_kind,
        platforms: req.platforms.to_vec(),
        included_classes: classes.into_iter().collect(),
        yanked_releases: req.yanked_releases.to_vec(),
        upgrade_path: upgrade_path.clone(),
        notices_sha256,
        terms_sha256,
    };
    files.push(AirgapArtifact {
        path: PATH_UPGRADE_PATH.into(),
        bytes: serde_json::to_vec_pretty(&upgrade_path).map_err(bad_input)?,
    });
    files.push(AirgapArtifact {
        path: PATH_BUNDLE_EXTENDED.into(),
        bytes: serde_json::to_vec_pretty(&extended).map_err(bad_input)?,
    });
    if !req.yanked_releases.is_empty() {
        files.push(AirgapArtifact {
            path: PATH_YANKS_JSON.into(),
            bytes: serde_json::to_vec_pretty(req.yanked_releases).map_err(bad_input)?,
        });
    }
    Ok(())
}

fn infer_pack_id_and_version(rel_path: &str, bundle_version: &str) -> (String, String) {
    if !rel_path.starts_with("packs/") {
        return ("grdr.bundle".into(), bundle_version.to_owned());
    }
    let mut parts = rel_path.split('/');
    let _ = parts.next();
    let pack_id = match parts.next() {
        Some("essentials") => "grdr.essentials".into(),
        Some("detections") => "grdr.det.core".into(),
        Some("compliance") => "grdr.compliance".into(),
        Some(other) => format!("grdr.{other}"),
        None => "grdr.bundle".into(),
    };
    (pack_id, bundle_version.to_owned())
}

fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}

fn bad_input(err: impl ToString) -> AirgapCliError {
    AirgapCliError::InvalidInput(err.to_string())
}
