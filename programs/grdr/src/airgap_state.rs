// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Air-gap trust anchor persistence, anti-rollback watermarks, and yank record loading.

use std::fs;
use std::path::Path;

use grdr_update::{
    AirgapBundleEntry, AirgapVerificationOutcome, RolloutHaltEntry, RootMetadata, SignedMetadata,
    TufRootKind, UpdateError, UpdateTrust, YankRecord, verify_root_self,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
use crate::airgap_bundle::root_fingerprint;
use crate::airgap_verify::{ParsedTarBundle, read_root_metadata_file};
use crate::fs_safe::{
    atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular,
    reject_symlinks_on_existing_prefixes,
};

const PINNED_ROOT_FILE: &str = "project-root.json";
const WATERMARKS_FILE: &str = "airgap-watermarks.json";
const INSTALLED_MANIFEST_FILE: &str = "installed-manifest.sha256";
const STATE_YANKS_FILE: &str = "yanks.json";
const MAX_STATE_JSON_BYTES: u64 = 1024 * 1024;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapStateWatermarks {
    pub last_root_version: u64,
    pub last_bundle_version: String,
    pub last_bundle_created_at: Timestamp,
    pub last_manifest_sha256: String,
}

pub fn resolve_and_persist_trust_anchor(
    override_root: Option<&Path>,
    state_dir: Option<&Path>,
    expected_fingerprint: Option<&str>,
    parsed: &ParsedTarBundle,
    now: Timestamp,
    persist_if_initialized: bool,
) -> Result<SignedMetadata<RootMetadata>, AirgapCliError> {
    let pinned_path = state_dir.map(|d| d.join(PINNED_ROOT_FILE));
    let mut should_persist = false;

    let selected = if let Some(ref pp) = pinned_path
        && fs::symlink_metadata(pp).is_ok()
    {
        let existing = read_root_metadata_file(pp)?;
        let mut trust = UpdateTrust::new(existing.clone(), now)?;
        let candidate = if let Some(root_path) = override_root {
            Some(read_root_metadata_file(root_path)?)
        } else {
            parsed.embedded_root.clone()
        };
        if let Some(cand) = candidate {
            if cand.signed.version > existing.signed.version {
                trust.rotate_root(TufRootKind::Project, cand.clone(), now)?;
                should_persist = true;
                cand
            } else if cand.signed.version < existing.signed.version {
                return Err(UpdateError::RollbackDetected {
                    role: "project::root".into(),
                    found: cand.signed.version,
                    trusted: existing.signed.version,
                }
                .into());
            } else {
                if cand.signed.keys != existing.signed.keys
                    || cand.signed.roles != existing.signed.roles
                    || cand.signed.root_kind != existing.signed.root_kind
                {
                    return Err(UpdateError::UnauthorizedRoot(
                        "candidate project root conflicts with pinned root at same version".into(),
                    )
                    .into());
                }
                existing
            }
        } else {
            existing
        }
    } else {
        let initial = if let Some(root_path) = override_root {
            read_root_metadata_file(root_path)?
        } else {
            let Some(expected_fp) = expected_fingerprint else {
                return Err(UpdateError::UnauthorizedRoot(
                    "no trust anchor provided: supply --root, an initialized --state-dir/project-root.json, or --expected-fingerprint verified via --print-root"
                        .into(),
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
            embedded
        };
        verify_root_self(&initial, now)?;
        should_persist = state_dir.is_some();
        initial
    };

    if let Some(expected_fp) = expected_fingerprint {
        let actual_fp = root_fingerprint(&selected.signed)?;
        if actual_fp != expected_fp {
            return Err(UpdateError::UnauthorizedRoot(format!(
                "project root fingerprint `{actual_fp}` != expected `{expected_fp}`"
            ))
            .into());
        }
    }

    if persist_if_initialized
        && should_persist
        && let Some(dir) = state_dir
        && let Some(ref pp) = pinned_path
    {
        ensure_safe_dir_all(dir, false).map_err(|e| io_err(dir, &e.to_string()))?;
        reject_symlinks_on_existing_prefixes(pp).map_err(|e| io_err(pp, &e.to_string()))?;
        let raw = serde_json::to_vec_pretty(&selected)
            .map_err(|e| UpdateError::MalformedMetadata(e.to_string()))?;
        atomic_write_bytes(pp, &raw, false).map_err(|e| io_err(pp, &e.to_string()))?;
    }

    Ok(selected)
}

pub fn parse_bundle_semver(raw: &str) -> Result<(u64, u64, u64, bool), AirgapCliError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > 64
        || !trimmed
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'+'))
    {
        return Err(AirgapCliError::InvalidInput(format!(
            "unsafe or malformed bundle version `{raw}`"
        )));
    }
    let no_build = trimmed.split('+').next().unwrap_or(trimmed);
    let (core, is_release) = match no_build.split_once('-') {
        Some((c, pre)) if !pre.is_empty() => (c, false),
        Some(_) => {
            return Err(AirgapCliError::InvalidInput(format!(
                "empty prerelease tag in `{raw}`"
            )));
        }
        None => (no_build, true),
    };
    let mut parts = core.split('.');
    let major = parse_ver_part(parts.next(), raw)?;
    let minor = parse_ver_part(parts.next(), raw)?;
    let patch = parse_ver_part(parts.next(), raw)?;
    if parts.next().is_some() {
        return Err(AirgapCliError::InvalidInput(format!(
            "invalid semver triple `{raw}`"
        )));
    }
    Ok((major, minor, patch, is_release))
}

fn parse_ver_part(part: Option<&str>, full: &str) -> Result<u64, AirgapCliError> {
    let seg =
        part.ok_or_else(|| AirgapCliError::InvalidInput(format!("invalid semver `{full}`")))?;
    if seg.is_empty() || !seg.bytes().all(|b| b.is_ascii_digit()) {
        return Err(AirgapCliError::InvalidInput(format!(
            "non-numeric semver component in `{full}`"
        )));
    }
    seg.parse::<u64>()
        .map_err(|_| AirgapCliError::InvalidInput(format!("semver overflow in `{full}`")))
}

pub fn validate_safe_path_segment(raw: &str, label: &str) -> Result<(), AirgapCliError> {
    if raw.is_empty()
        || raw.len() > 64
        || raw.contains("..")
        || !raw
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
    {
        return Err(AirgapCliError::InvalidInput(format!(
            "unsafe `{label}` value `{raw}`"
        )));
    }
    Ok(())
}

pub fn check_and_update_watermarks(
    state_dir: &Path,
    outcome: &AirgapVerificationOutcome,
    root_version: u64,
    bundle_created_at: Timestamp,
    manifest_sha256: &str,
    commit: bool,
) -> Result<(), AirgapCliError> {
    validate_safe_path_segment(&outcome.bundle_version, "bundle_version")?;
    let candidate_ver = parse_bundle_semver(&outcome.bundle_version)?;
    let wm_path = state_dir.join(WATERMARKS_FILE);
    if fs::symlink_metadata(&wm_path).is_ok() {
        let raw = read_bounded_regular(&wm_path, MAX_STATE_JSON_BYTES)
            .map_err(|e| io_err(&wm_path, &e.to_string()))?;
        let prev: AirgapStateWatermarks = serde_json::from_slice(&raw)
            .map_err(|e| UpdateError::MalformedMetadata(format!("invalid watermarks: {e}")))?;
        if root_version < prev.last_root_version {
            return Err(UpdateError::RollbackDetected {
                role: "project::root".into(),
                found: root_version,
                trusted: prev.last_root_version,
            }
            .into());
        }
        let prev_ver = parse_bundle_semver(&prev.last_bundle_version)?;
        if candidate_ver < prev_ver {
            return Err(UpdateError::RollbackDetected {
                role: "airgap::bundle_version".into(),
                found: candidate_ver
                    .0
                    .saturating_mul(1_000_000)
                    .saturating_add(candidate_ver.1.saturating_mul(1_000))
                    .saturating_add(candidate_ver.2),
                trusted: prev_ver
                    .0
                    .saturating_mul(1_000_000)
                    .saturating_add(prev_ver.1.saturating_mul(1_000))
                    .saturating_add(prev_ver.2),
            }
            .into());
        }
        if bundle_created_at < prev.last_bundle_created_at {
            return Err(UpdateError::RollbackDetected {
                role: "airgap::created_at".into(),
                found: u64::try_from(bundle_created_at.as_second().max(0)).unwrap_or(0),
                trusted: u64::try_from(prev.last_bundle_created_at.as_second().max(0)).unwrap_or(0),
            }
            .into());
        }
    }

    if commit {
        ensure_safe_dir_all(state_dir, false).map_err(|e| io_err(state_dir, &e.to_string()))?;
        let updated = AirgapStateWatermarks {
            last_root_version: root_version,
            last_bundle_version: outcome.bundle_version.clone(),
            last_bundle_created_at: bundle_created_at,
            last_manifest_sha256: manifest_sha256.to_owned(),
        };
        let encoded = serde_json::to_vec_pretty(&updated)
            .map_err(|e| UpdateError::MalformedMetadata(e.to_string()))?;
        atomic_write_bytes(&wm_path, &encoded, false)
            .map_err(|e| io_err(&wm_path, &e.to_string()))?;
        let inst_path = state_dir.join(INSTALLED_MANIFEST_FILE);
        atomic_write_bytes(&inst_path, manifest_sha256.as_bytes(), false)
            .map_err(|e| io_err(&inst_path, &e.to_string()))?;
    }
    Ok(())
}

pub fn load_yanks_for_verify(
    state_dir: Option<&Path>,
    yanks_file: Option<&Path>,
) -> Result<Vec<YankRecord>, AirgapCliError> {
    let mut yanks = Vec::new();
    if let Some(dir) = state_dir {
        let state_yanks = dir.join(STATE_YANKS_FILE);
        if fs::symlink_metadata(&state_yanks).is_ok() {
            yanks.extend(read_yanks_file(&state_yanks)?);
        }
    }
    if let Some(path) = yanks_file {
        yanks.extend(read_yanks_file(path)?);
    }
    Ok(yanks)
}

fn read_yanks_file(path: &Path) -> Result<Vec<YankRecord>, AirgapCliError> {
    let raw = read_bounded_regular(path, MAX_STATE_JSON_BYTES)
        .map_err(|e| io_err(path, &e.to_string()))?;
    serde_json::from_slice(&raw)
        .map_err(|e| UpdateError::MalformedMetadata(format!("invalid yanks JSON: {e}")).into())
}

pub fn yanks_to_halts(yanks: &[YankRecord]) -> Vec<RolloutHaltEntry> {
    yanks
        .iter()
        .map(|yk| RolloutHaltEntry {
            pack_id: yk.pack_id.clone(),
            version: yk.version.clone(),
            reason: format!("yanked ({:?})", yk.reason),
        })
        .collect()
}

pub fn check_yank_slice(
    yanks: &[YankRecord],
    outcome: &AirgapVerificationOutcome,
    manifest_sha256: &str,
    entries: &[AirgapBundleEntry],
) -> Result<(), AirgapCliError> {
    for yk in yanks {
        let digest_hit = !yk.sha256.is_empty()
            && (yk.sha256 == manifest_sha256 || entries.iter().any(|e| e.sha256 == yk.sha256));
        let bundle_ver_hit = (yk.pack_id == outcome.bundle_id || yk.pack_id == "*")
            && yk.version == outcome.bundle_version
            && (yk.sha256.is_empty() || yk.sha256 == "*" || yk.sha256 == manifest_sha256);
        let entry_hit = entries
            .iter()
            .any(|e| e.pack_id == yk.pack_id && e.version == yk.version);
        if digest_hit || bundle_ver_hit || entry_hit {
            return Err(UpdateError::HaltedRelease(format!(
                "yanked release {}@{} ({:?})",
                yk.pack_id, yk.version, yk.reason
            ))
            .into());
        }
    }
    Ok(())
}

fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
