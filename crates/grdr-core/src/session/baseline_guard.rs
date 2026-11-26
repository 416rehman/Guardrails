// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Workspace path/root validation, validated state deserialization, irreversibility gate, and honeytokens (`D-28`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use grdr_crypto::constant_time_eq;
use serde::de::Error as _;
use serde::{Deserialize, Deserializer};

use crate::analyze::path::{OsKind, PathFacts, SymlinkResolution, VolumeCase, resolve_path};
use crate::analyze::types::Resolution;
use crate::session::baseline::{
    EnvironmentEvidenceOrigin, HoneytokenCredential, LateLabelStatus, MAX_BASELINE_FILES,
    MAX_MUTATION_HISTORY, MassChangeBreakerState, TargetEnvironmentClass, WorkspaceBaselineTracker,
    WorkspaceMutation,
};

#[derive(Deserialize)]
struct RawWorkspaceBaselineTracker {
    snapshot_id: String,
    workspace_root: String,
    #[serde(default = "default_os_kind")]
    os: OsKind,
    #[serde(default = "default_volume_case")]
    volume_case: VolumeCase,
    baseline_files: BTreeMap<String, String>,
    #[serde(default)]
    modified_baseline_paths: BTreeSet<String>,
    created_paths: BTreeSet<String>,
    rejected_paths: BTreeMap<String, String>,
    mutations: VecDeque<WorkspaceMutation>,
    latest_seen_ms: i64,
    #[serde(default)]
    pending_future_ms: Option<i64>,
    breaker_state: MassChangeBreakerState,
}

const fn default_os_kind() -> OsKind {
    OsKind::Linux
}

const fn default_volume_case() -> VolumeCase {
    VolumeCase::CaseSensitive
}

impl<'de> Deserialize<'de> for WorkspaceBaselineTracker {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let raw = RawWorkspaceBaselineTracker::deserialize(deserializer)?;
        let snap_id = raw.snapshot_id.trim();
        if snap_id.is_empty()
            || snap_id != raw.snapshot_id
            || raw.snapshot_id.chars().any(char::is_control)
        {
            return Err(D::Error::custom(
                "invalid snapshot_id in restored workspace baseline",
            ));
        }
        validate_workspace_root(&raw.workspace_root, raw.os, raw.volume_case)
            .map_err(D::Error::custom)?;
        if raw.baseline_files.len() > MAX_BASELINE_FILES
            || raw.modified_baseline_paths.len() > MAX_BASELINE_FILES
            || raw.created_paths.len() > MAX_BASELINE_FILES
            || raw.rejected_paths.len() > MAX_BASELINE_FILES
            || raw.mutations.len() > MAX_MUTATION_HISTORY
        {
            return Err(D::Error::custom(
                "restored workspace baseline state exceeds capacity bounds",
            ));
        }
        for p in raw.baseline_files.keys() {
            let norm = canonicalize_within_workspace(
                &raw.workspace_root,
                raw.os,
                raw.volume_case,
                p,
                false,
            )
            .map_err(D::Error::custom)?;
            if norm != *p {
                return Err(D::Error::custom("non-canonical key in baseline_files"));
            }
        }
        for p in &raw.modified_baseline_paths {
            let norm = canonicalize_within_workspace(
                &raw.workspace_root,
                raw.os,
                raw.volume_case,
                p,
                false,
            )
            .map_err(D::Error::custom)?;
            if norm != *p || !raw.baseline_files.contains_key(p) {
                return Err(D::Error::custom(
                    "invalid or non-baseline key in modified_baseline_paths",
                ));
            }
        }
        for p in &raw.created_paths {
            let norm = canonicalize_within_workspace(
                &raw.workspace_root,
                raw.os,
                raw.volume_case,
                p,
                false,
            )
            .map_err(D::Error::custom)?;
            if norm != *p || raw.baseline_files.contains_key(p) {
                return Err(D::Error::custom(
                    "invalid or baseline-overlapping key in created_paths",
                ));
            }
        }
        for m in &raw.mutations {
            if m.is_symlink || m.timestamp_ms > raw.latest_seen_ms {
                return Err(D::Error::custom(
                    "invalid mutation entry in restored workspace baseline",
                ));
            }
            let norm = canonicalize_within_workspace(
                &raw.workspace_root,
                raw.os,
                raw.volume_case,
                &m.canonical_path,
                false,
            )
            .map_err(D::Error::custom)?;
            if norm != m.canonical_path {
                return Err(D::Error::custom(
                    "non-canonical path in restored mutations history",
                ));
            }
        }
        if let Some(pending_ms) = raw.pending_future_ms
            && (raw.mutations.is_empty()
                || pending_ms.saturating_sub(raw.latest_seen_ms)
                    <= crate::session::baseline::MAX_CLOCK_JUMP_OUTLIER_MS)
        {
            return Err(D::Error::custom(
                "invalid pending_future_ms in restored workspace baseline",
            ));
        }
        Ok(Self {
            snapshot_id: raw.snapshot_id,
            workspace_root: raw.workspace_root,
            os: raw.os,
            volume_case: raw.volume_case,
            baseline_files: raw.baseline_files,
            modified_baseline_paths: raw.modified_baseline_paths,
            created_paths: raw.created_paths,
            rejected_paths: raw.rejected_paths,
            mutations: raw.mutations,
            latest_seen_ms: raw.latest_seen_ms,
            pending_future_ms: raw.pending_future_ms,
            breaker_state: raw.breaker_state,
        })
    }
}

pub(super) fn validate_workspace_root(
    workspace_root: &str,
    os: OsKind,
    volume_case: VolumeCase,
) -> Result<(), &'static str> {
    let trimmed = workspace_root.trim();
    if trimmed.is_empty()
        || trimmed != workspace_root
        || trimmed.chars().any(char::is_control)
        || trimmed.starts_with("//")
        || trimmed.starts_with("\\\\")
    {
        return Err("invalid-workspace-root");
    }
    let norm_slashes = trimmed.replace('\\', "/");
    if norm_slashes.trim_matches('/').is_empty() {
        return Err("invalid-workspace-root");
    }
    let has_abs = trimmed.starts_with('/')
        || (trimmed.len() >= 3
            && trimmed
                .as_bytes()
                .first()
                .is_some_and(u8::is_ascii_alphabetic)
            && trimmed.as_bytes().get(1) == Some(&b':')
            && matches!(trimmed.as_bytes().get(2), Some(b'/' | b'\\')));
    if !has_abs {
        return Err("workspace-root-not-absolute");
    }
    let facts = PathFacts {
        os,
        volume_case,
        symlink: SymlinkResolution::Direct,
        workspace_root: Some(trimmed.to_owned()),
    };
    match resolve_path(trimmed, Some(&facts)) {
        Resolution::Resolved(cp) if !cp.escaped_workspace && cp.ads_stream.is_none() => {
            let canon = cp.base_without_ads.trim_end_matches('/');
            let b = canon.as_bytes();
            let is_bare_drive = matches!(b, [d, b':'] if d.is_ascii_alphabetic())
                || matches!(b, [d, b':', b'/'] if d.is_ascii_alphabetic());
            if canon.is_empty() || canon.starts_with("//") || is_bare_drive {
                Err("invalid-workspace-root")
            } else {
                Ok(())
            }
        }
        Resolution::Resolved(_) | Resolution::Unresolved(_) | Resolution::Malformed(_) => {
            Err("invalid-workspace-root")
        }
    }
}

pub(super) fn canonicalize_within_workspace(
    workspace_root: &str,
    os: OsKind,
    volume_case: VolumeCase,
    raw_path: &str,
    is_symlink: bool,
) -> Result<String, &'static str> {
    let rel = raw_path.trim();
    if rel.is_empty() || raw_path.chars().any(char::is_control) {
        return Err("empty-or-control-byte-path");
    }
    if is_symlink {
        return Err("symlink-not-restorable");
    }
    let rel_low = rel.to_ascii_lowercase();
    if rel.starts_with('~') || rel_low.starts_with("file:") {
        return Err("non-workspace-uri-or-tilde-path");
    }
    let bytes = rel.as_bytes();
    let has_drive =
        bytes.first().is_some_and(u8::is_ascii_alphabetic) && bytes.get(1) == Some(&b':');
    if has_drive && !matches!(bytes.get(2), Some(b'/' | b'\\')) {
        return Err("drive-relative-path-rejected");
    }
    let root_norm = workspace_root.trim_end_matches(['/', '\\']);
    let candidate = if rel.starts_with('/') || rel.starts_with('\\') || has_drive {
        rel.to_owned()
    } else {
        format!("{root_norm}/{rel}")
    };
    let facts = PathFacts {
        os,
        volume_case,
        symlink: SymlinkResolution::Direct,
        workspace_root: Some(workspace_root.to_owned()),
    };
    let root_canon = match resolve_path(workspace_root, Some(&facts)) {
        Resolution::Resolved(rc) if !rc.escaped_workspace && rc.ads_stream.is_none() => {
            rc.base_without_ads
        }
        _ => return Err("invalid-workspace-root"),
    };
    match resolve_path(&candidate, Some(&facts)) {
        Resolution::Resolved(cp) => {
            if cp.escaped_workspace {
                return Err("escaped-workspace-boundary");
            }
            let clean = cp.base_without_ads;
            let same_root = match volume_case {
                VolumeCase::CaseInsensitive => clean
                    .trim_end_matches('/')
                    .eq_ignore_ascii_case(root_canon.trim_end_matches('/')),
                VolumeCase::CaseSensitive => {
                    clean.trim_end_matches('/') == root_canon.trim_end_matches('/')
                }
            };
            if same_root {
                Err("workspace-root-not-file")
            } else {
                Ok(clean)
            }
        }
        Resolution::Unresolved(_) => Err("unresolved-workspace-path"),
        Resolution::Malformed(_) => Err("malformed-workspace-path"),
    }
}

/// Irreversibility gate (`D-28`): production targets are identified strictly by credential or explicit org tag,
/// NEVER lowered or dismissed by branch/path naming heuristics such as `"staging"` or `"dev"`.
#[must_use]
pub fn classify_target_environment(
    evidences: &[EnvironmentEvidenceOrigin],
) -> TargetEnvironmentClass {
    let is_prod = evidences.iter().any(|ev| {
        matches!(
            ev,
            EnvironmentEvidenceOrigin::ProdCredential
                | EnvironmentEvidenceOrigin::ProdEnvironmentTag
        )
    });
    if is_prod {
        TargetEnvironmentClass::Production
    } else {
        TargetEnvironmentClass::NonProduction
    }
}

/// Checks constant-time 64-hex HMAC tag equality against registered honeytoken credentials.
#[must_use]
pub fn check_honeytoken_hit<'a>(
    tokens: &'a [HoneytokenCredential],
    candidate_hmac_hex: &str,
) -> Option<&'a HoneytokenCredential> {
    let norm = candidate_hmac_hex.trim().to_ascii_lowercase();
    if norm.len() != 64 || !norm.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut matched: Option<&'a HoneytokenCredential> = None;
    for token in tokens {
        let expected = token.hmac_digest_hex.to_ascii_lowercase();
        let valid_token = expected.len() == 64 && expected.bytes().all(|b| b.is_ascii_hexdigit());
        if valid_token
            && constant_time_eq(expected.as_bytes(), norm.as_bytes())
            && matched.is_none()
        {
            matched = Some(token);
        }
    }
    matched
}

/// Evaluates whether an external MSIP/Purview/Drive sensitivity label arrived after decision (`label.late`, row 45).
#[must_use]
pub const fn check_label_arrival(
    decision_timestamp_ms: i64,
    label_arrived_ms: i64,
) -> LateLabelStatus {
    if label_arrived_ms > decision_timestamp_ms {
        LateLabelStatus::ArrivedAfterDecision
    } else {
        LateLabelStatus::Timely
    }
}
