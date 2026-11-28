// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Ed25519 compliance pack signature verification over verified in-memory byte bundles.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

use grdr_crypto::{sha256_hex, verify_bytes};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::ComplyError;
use crate::limits::compliance_limits;
use crate::pack_fs::{
    MAX_BUNDLE_FILES, collect_dir_files, is_symlink_or_reparse, read_regular_text,
    reject_symlinks_on_existing_prefixes, validate_bundle_rel_path, verify_exact_dir_entry,
};
use crate::pack_toml::{
    CompliancePackManifest, SignerTrustStatus, TrustedRootEntry, compare_semver,
    is_safe_manifest_token, parse_compliance_pack_toml, parse_trust_roots_toml,
};

pub(crate) const PACK_SIG_DOMAIN: &str = "grdr.pack.manifest.v1";
const PACK_SIG_FORMAT: &str = "grdr.pack.signature.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackFileDigest {
    pub path: String,
    pub sha256: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PackSignatureDoc {
    pub format: String,
    pub pack_id: String,
    pub version: String,
    pub domain: String,
    pub signer_ref: String,
    pub verifier_ed25519_b64: String,
    pub manifest_sha256: String,
    pub files: Vec<PackFileDigest>,
    pub signature_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VerifiedPackBundle {
    pub(crate) manifest: CompliancePackManifest,
    pub(crate) sig: PackSignatureDoc,
    pub(crate) files: BTreeMap<String, Vec<u8>>,
}

pub(crate) fn verify_signed_bytes_bundle(
    expected_pack_id: &str,
    sig_raw: &str,
    trust_roots: &[TrustedRootEntry],
    min_version: Option<&str>,
    files: &[(&str, &[u8])],
    now: Timestamp,
) -> Result<VerifiedPackBundle, ComplyError> {
    let limits = compliance_limits()?;
    if files.len() > MAX_BUNDLE_FILES {
        return Err(ComplyError::VerificationFailed {
            detail: "compliance pack file count exceeds bundle limit".into(),
        });
    }

    let sig = verify_signature_envelope(expected_pack_id, sig_raw, trust_roots, min_version, now)?;

    let mut total_bytes: u64 = 0;
    let mut seen_lower = BTreeSet::new();
    let mut actual_digests = Vec::with_capacity(files.len());
    let mut file_map = BTreeMap::new();
    for (path, raw) in files {
        validate_bundle_rel_path(path, &mut seen_lower)?;
        let len_u64 = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if len_u64 > limits.max_pack_file_bytes {
            return Err(ComplyError::VerificationFailed {
                detail: format!("pack file `{path}` exceeds per-file byte limit"),
            });
        }
        total_bytes = total_bytes.saturating_add(len_u64);
        if total_bytes > limits.max_pack_bundle_bytes {
            return Err(ComplyError::VerificationFailed {
                detail: "compliance pack bundle total size exceeds limits.toml cap".into(),
            });
        }
        actual_digests.push(PackFileDigest {
            path: (*path).to_owned(),
            sha256: sha256_hex(raw),
            length: len_u64,
        });
        file_map.insert((*path).to_owned(), (*raw).to_vec());
    }
    actual_digests.sort_by(|a, b| a.path.cmp(&b.path));

    if actual_digests != sig.files {
        return Err(ComplyError::VerificationFailed {
            detail: "compliance pack files diverge from signed manifest".into(),
        });
    }

    let manifest_bytes =
        file_map
            .get("pack.toml")
            .ok_or_else(|| ComplyError::VerificationFailed {
                detail: "verified compliance bundle missing pack.toml".into(),
            })?;
    let manifest_raw =
        std::str::from_utf8(manifest_bytes).map_err(|e| ComplyError::VerificationFailed {
            detail: format!("non-UTF8 pack.toml: {e}"),
        })?;
    let manifest = parse_compliance_pack_toml(manifest_raw)?;
    if manifest.id != sig.pack_id || manifest.version != sig.version {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "verified pack.toml `{}@{}` diverges from signed `{}`@`{}`",
                manifest.id, manifest.version, sig.pack_id, sig.version
            ),
        });
    }

    Ok(VerifiedPackBundle {
        manifest,
        sig,
        files: file_map,
    })
}

pub(crate) fn verify_signed_dir(
    pack_dir: &Path,
    expected_pack_id: &str,
    trust_roots: &[TrustedRootEntry],
    min_version: Option<&str>,
    now: Timestamp,
) -> Result<VerifiedPackBundle, ComplyError> {
    let limits = compliance_limits()?;
    reject_symlinks_on_existing_prefixes(pack_dir)?;
    let root_meta =
        fs::symlink_metadata(pack_dir).map_err(|e| ComplyError::VerificationFailed {
            detail: format!(
                "cannot inspect pack directory `{}`: {e}",
                pack_dir.display()
            ),
        })?;
    if is_symlink_or_reparse(&root_meta) || !root_meta.is_dir() {
        return Err(ComplyError::VerificationFailed {
            detail: "pack_dir must be a real non-symlink directory".into(),
        });
    }

    verify_exact_dir_entry(pack_dir, "signature.json")?;
    let sig_raw = read_regular_text(&pack_dir.join("signature.json"), limits.max_pack_file_bytes)?;
    let sig_envelope =
        verify_signature_envelope(expected_pack_id, &sig_raw, trust_roots, min_version, now)?;
    if sig_envelope.files.len() > MAX_BUNDLE_FILES {
        return Err(ComplyError::VerificationFailed {
            detail: "signed compliance signature lists more files than MAX_BUNDLE_FILES".into(),
        });
    }

    let mut total_bytes: u64 = 0;
    let mut seen_lower = BTreeSet::new();
    let collected = collect_dir_files(
        pack_dir,
        pack_dir,
        0,
        limits.max_pack_file_bytes,
        limits.max_pack_bundle_bytes,
        &mut total_bytes,
        &mut seen_lower,
    )?;
    let refs: Vec<(&str, &[u8])> = collected
        .iter()
        .map(|(rel, bytes)| (rel.as_str(), bytes.as_slice()))
        .collect();
    verify_signed_bytes_bundle(
        expected_pack_id,
        &sig_raw,
        trust_roots,
        min_version,
        &refs,
        now,
    )
}

pub(crate) fn load_trust_roots_from_path(
    path: &Path,
) -> Result<Vec<TrustedRootEntry>, ComplyError> {
    let limits = compliance_limits()?;
    reject_symlinks_on_existing_prefixes(path)?;
    if let Some(parent) = path.parent().filter(|p| !p.as_os_str().is_empty()) {
        let parent_meta =
            fs::symlink_metadata(parent).map_err(|e| ComplyError::VerificationFailed {
                detail: format!("cannot stat trust-roots parent `{}`: {e}", parent.display()),
            })?;
        if is_symlink_or_reparse(&parent_meta) || !parent_meta.is_dir() {
            return Err(ComplyError::VerificationFailed {
                detail: "trust-roots parent directory cannot be a symlink or non-directory".into(),
            });
        }
    }
    let raw = read_regular_text(path, limits.max_pack_file_bytes)?;
    parse_trust_roots_toml(&raw)
}

fn verify_signature_envelope(
    expected_pack_id: &str,
    sig_raw: &str,
    trust_roots: &[TrustedRootEntry],
    min_version: Option<&str>,
    now: Timestamp,
) -> Result<PackSignatureDoc, ComplyError> {
    let sig: PackSignatureDoc =
        serde_json::from_str(sig_raw).map_err(|e| ComplyError::VerificationFailed {
            detail: format!("malformed compliance signature.json: {e}"),
        })?;
    if sig.format != PACK_SIG_FORMAT || sig.domain != PACK_SIG_DOMAIN {
        return Err(ComplyError::VerificationFailed {
            detail: "unexpected compliance signature format or domain".into(),
        });
    }
    if sig.pack_id != expected_pack_id {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "compliance pack_id mismatch (`{}` != `{expected_pack_id}`)",
                sig.pack_id
            ),
        });
    }
    if !is_safe_manifest_token(&sig.pack_id)
        || !is_safe_manifest_token(&sig.version)
        || !is_safe_manifest_token(&sig.signer_ref)
    {
        return Err(ComplyError::VerificationFailed {
            detail: "signature envelope contains whitespace or control characters".into(),
        });
    }

    let mut seen_lower = BTreeSet::new();
    for entry in &sig.files {
        validate_bundle_rel_path(&entry.path, &mut seen_lower)?;
        if !is_safe_manifest_token(&entry.sha256) || entry.sha256.len() != 64 {
            return Err(ComplyError::VerificationFailed {
                detail: format!("invalid digest metadata in signature for `{}`", entry.path),
            });
        }
    }

    let root = trust_roots
        .iter()
        .find(|r| r.signer_ref == sig.signer_ref)
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("untrusted compliance pack signer `{}`", sig.signer_ref),
        })?;
    if root.status != SignerTrustStatus::Active {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "compliance signer `{}` is not active ({:?})",
                sig.signer_ref, root.status
            ),
        });
    }
    if root.expires_at.is_some_and(|exp| now > exp) {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "compliance signer `{}` trust root has expired",
                sig.signer_ref
            ),
        });
    }
    if root.verifier_ed25519_b64 != sig.verifier_ed25519_b64 {
        return Err(ComplyError::VerificationFailed {
            detail: format!("verifier public key mismatch for `{}`", sig.signer_ref),
        });
    }

    if let Some(root_min) = root.min_version.as_deref()
        && compare_semver(&sig.version, root_min)? == Ordering::Less
    {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "pack version `{}` below signer min_version `{root_min}`",
                sig.version
            ),
        });
    }
    if let Some(floor_min) = min_version
        && compare_semver(&sig.version, floor_min)? == Ordering::Less
    {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "pack rollback rejected: version `{}` < `{floor_min}`",
                sig.version
            ),
        });
    }

    let payload = canonical_manifest_text(&sig.pack_id, &sig.version, &sig.files);
    if sha256_hex(payload.as_bytes()) != sig.manifest_sha256 {
        return Err(ComplyError::VerificationFailed {
            detail: "compliance pack manifest_sha256 mismatch".into(),
        });
    }
    verify_bytes(
        &root.verifier_ed25519_b64,
        PACK_SIG_DOMAIN,
        payload.as_bytes(),
        &sig.signature_b64,
    )
    .map_err(|e| ComplyError::VerificationFailed {
        detail: format!("compliance pack signature invalid: {e}"),
    })?;
    Ok(sig)
}

fn canonical_manifest_text(pack_id: &str, version: &str, files: &[PackFileDigest]) -> String {
    let mut lines = Vec::with_capacity(files.len().saturating_add(3));
    lines.push(PACK_SIG_DOMAIN.to_owned());
    lines.push(pack_id.to_owned());
    lines.push(version.to_owned());
    for f in files {
        lines.push(format!("{} {} {}", f.path, f.sha256, f.length));
    }
    lines.join("\n")
}
