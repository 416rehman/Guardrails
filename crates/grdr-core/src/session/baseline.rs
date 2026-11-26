// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! CoW workspace baseline/restore with path traversal guard, 200/60s mass-change breaker,
//! irreversibility gate, honeytokens, and MSIP/Purview/Drive late-label detection (`D-28`).

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use serde::{Deserialize, Serialize};

use crate::analyze::path::{OsKind, VolumeCase};
use crate::session::baseline_guard::{canonicalize_within_workspace, validate_workspace_root};
pub use crate::session::baseline_guard::{
    check_honeytoken_hit, check_label_arrival, classify_target_environment,
};

pub const MASS_CHANGE_THRESHOLD_DEFAULT: usize = 200;
pub const MASS_CHANGE_WINDOW_MS: i64 = 60_000;
pub const MAX_RESTORE_FILE_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const MAX_MUTATION_HISTORY: usize = 4_096;
const MAX_WINDOW_WRITES_OVERWRITE: usize = 2_000;
pub(super) const MAX_BASELINE_FILES: usize = 16_384;
pub(super) const MAX_CLOCK_JUMP_OUTLIER_MS: i64 = 3_600_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MassChangeBreakerState {
    #[default]
    Normal,
    TrippedPausedForRestore,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetEnvironmentClass {
    NonProduction,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnvironmentEvidenceOrigin {
    ProdCredential,
    ProdEnvironmentTag,
    StagingOrDevNameHeuristic,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceBaselineFile {
    pub canonical_path: String,
    pub baseline_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkspaceMutation {
    pub timestamp_ms: i64,
    pub canonical_path: String,
    pub post_sha256: Option<String>,
    pub byte_len: u64,
    pub is_symlink: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestoreFileTarget {
    pub canonical_path: String,
    pub expected_baseline_sha256: String,
}

#[derive(Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct RestorePlanReport {
    pub restore_targets: Vec<RestoreFileTarget>,
    pub remove_created: Vec<String>,
    pub not_restorable: Vec<(String, String)>,
}

#[derive(Clone, PartialEq, Eq, Serialize)]
pub struct WorkspaceBaselineTracker {
    pub snapshot_id: String,
    pub workspace_root: String,
    pub os: OsKind,
    pub volume_case: VolumeCase,
    pub baseline_files: BTreeMap<String, String>,
    pub modified_baseline_paths: BTreeSet<String>,
    pub created_paths: BTreeSet<String>,
    pub rejected_paths: BTreeMap<String, String>,
    pub mutations: VecDeque<WorkspaceMutation>,
    pub latest_seen_ms: i64,
    #[serde(default)]
    pub pending_future_ms: Option<i64>,
    pub breaker_state: MassChangeBreakerState,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HoneytokenCredential {
    pub token_id: String,
    pub deployed_path: String,
    pub hmac_digest_hex: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LateLabelStatus {
    Timely,
    ArrivedAfterDecision,
}

impl core::fmt::Debug for WorkspaceBaselineFile {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkspaceBaselineFile")
            .field("canonical_path_len", &self.canonical_path.len())
            .field("baseline_sha256", &self.baseline_sha256)
            .finish()
    }
}

impl core::fmt::Debug for WorkspaceMutation {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkspaceMutation")
            .field("timestamp_ms", &self.timestamp_ms)
            .field("canonical_path_len", &self.canonical_path.len())
            .field("has_post_sha256", &self.post_sha256.is_some())
            .field("byte_len", &self.byte_len)
            .field("is_symlink", &self.is_symlink)
            .finish()
    }
}

impl core::fmt::Debug for RestoreFileTarget {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RestoreFileTarget")
            .field("canonical_path_len", &self.canonical_path.len())
            .field("expected_baseline_sha256", &self.expected_baseline_sha256)
            .finish()
    }
}

impl core::fmt::Debug for RestorePlanReport {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("RestorePlanReport")
            .field("restore_targets_count", &self.restore_targets.len())
            .field("remove_created_count", &self.remove_created.len())
            .field("not_restorable_count", &self.not_restorable.len())
            .finish()
    }
}

impl core::fmt::Debug for WorkspaceBaselineTracker {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("WorkspaceBaselineTracker")
            .field("snapshot_id", &self.snapshot_id)
            .field("workspace_root_len", &self.workspace_root.len())
            .field("os", &self.os)
            .field("volume_case", &self.volume_case)
            .field("baseline_files_count", &self.baseline_files.len())
            .field(
                "modified_baseline_count",
                &self.modified_baseline_paths.len(),
            )
            .field("created_paths_count", &self.created_paths.len())
            .field("rejected_paths_count", &self.rejected_paths.len())
            .field("mutations_count", &self.mutations.len())
            .field("latest_seen_ms", &self.latest_seen_ms)
            .field("breaker_state", &self.breaker_state)
            .finish()
    }
}

impl core::fmt::Debug for HoneytokenCredential {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.debug_struct("HoneytokenCredential")
            .field("token_id", &self.token_id)
            .field("deployed_path_len", &self.deployed_path.len())
            .field("hmac_digest_hex", &self.hmac_digest_hex)
            .finish()
    }
}

impl WorkspaceBaselineTracker {
    #[must_use]
    pub fn from_snapshot(
        snapshot_id: impl Into<String>,
        files: impl IntoIterator<Item = WorkspaceBaselineFile>,
    ) -> Self {
        Self::from_snapshot_in_workspace(snapshot_id, "/workspace", files)
    }

    #[must_use]
    pub fn from_snapshot_in_workspace(
        snapshot_id: impl Into<String>,
        workspace_root: impl Into<String>,
        files: impl IntoIterator<Item = WorkspaceBaselineFile>,
    ) -> Self {
        Self::from_snapshot_in_workspace_with_profile(
            snapshot_id,
            workspace_root,
            OsKind::Linux,
            VolumeCase::CaseSensitive,
            files,
        )
    }

    #[must_use]
    pub fn from_snapshot_in_workspace_with_profile(
        snapshot_id: impl Into<String>,
        workspace_root: impl Into<String>,
        os: OsKind,
        volume_case: VolumeCase,
        files: impl IntoIterator<Item = WorkspaceBaselineFile>,
    ) -> Self {
        let root = workspace_root.into();
        let mut map = BTreeMap::new();
        let mut rejected = BTreeMap::new();
        let mut breaker_state = MassChangeBreakerState::Normal;
        if let Err(reason) = validate_workspace_root(&root, os, volume_case) {
            rejected.insert(root.clone(), reason.into());
            breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
            return Self {
                snapshot_id: snapshot_id.into(),
                workspace_root: root,
                os,
                volume_case,
                baseline_files: map,
                modified_baseline_paths: BTreeSet::new(),
                created_paths: BTreeSet::new(),
                rejected_paths: rejected,
                mutations: VecDeque::new(),
                latest_seen_ms: 0,
                pending_future_ms: None,
                breaker_state,
            };
        }
        for f in files {
            if map.len() >= MAX_BASELINE_FILES {
                if rejected.len() < MAX_BASELINE_FILES {
                    rejected.insert(f.canonical_path, "baseline-capacity-exceeded".into());
                }
                breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
                continue;
            }
            match canonicalize_within_workspace(&root, os, volume_case, &f.canonical_path, false) {
                Ok(norm) => {
                    map.insert(norm, f.baseline_sha256);
                }
                Err(reason) => {
                    if rejected.len() < MAX_BASELINE_FILES {
                        rejected.insert(f.canonical_path, reason.into());
                    }
                }
            }
        }
        Self {
            snapshot_id: snapshot_id.into(),
            workspace_root: root,
            os,
            volume_case,
            baseline_files: map,
            modified_baseline_paths: BTreeSet::new(),
            created_paths: BTreeSet::new(),
            rejected_paths: rejected,
            mutations: VecDeque::new(),
            latest_seen_ms: 0,
            pending_future_ms: None,
            breaker_state,
        }
    }

    /// Registers a baseline snapshot entry only when within `MAX_RESTORE_FILE_BYTES` (32 MiB cap).
    pub fn register_baseline_file_with_size(
        &mut self,
        raw_path: &str,
        baseline_sha256: String,
        byte_len: u64,
    ) -> Result<(), &'static str> {
        let norm = canonicalize_within_workspace(
            &self.workspace_root,
            self.os,
            self.volume_case,
            raw_path,
            false,
        )
        .inspect_err(|reason| {
            self.record_rejected_bounded(raw_path.to_owned(), reason);
        })?;
        if byte_len > MAX_RESTORE_FILE_BYTES {
            self.record_rejected_bounded(norm, "baseline-exceeds-32mib-cap");
            return Err("baseline-exceeds-32mib-cap");
        }
        if self.baseline_files.len() >= MAX_BASELINE_FILES {
            self.record_rejected_bounded(norm, "baseline-capacity-exceeded");
            self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
            return Err("baseline-capacity-exceeded");
        }
        self.baseline_files.insert(norm, baseline_sha256);
        Ok(())
    }

    fn record_rejected_bounded(&mut self, path: String, reason: &'static str) {
        if self.rejected_paths.len() < MAX_BASELINE_FILES {
            self.rejected_paths.insert(path, reason.into());
        } else {
            self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
        }
    }

    pub fn record_mutation(
        &mut self,
        canonical_path: impl Into<String>,
        post_sha256: Option<String>,
        timestamp_ms: i64,
    ) -> MassChangeBreakerState {
        self.record_mutation_bytes(canonical_path, post_sha256, timestamp_ms, 0, false)
    }

    /// Records a workspace file mutation with size/symlink checks, path normalization,
    /// persistent modified-baseline tracking, and bounded sliding-window mass-change breaker (`docs/design/16`).
    pub fn record_mutation_bytes(
        &mut self,
        raw_path: impl Into<String>,
        post_sha256: Option<String>,
        timestamp_ms: i64,
        byte_len: u64,
        is_symlink: bool,
    ) -> MassChangeBreakerState {
        let raw = raw_path.into();
        let norm_path = match canonicalize_within_workspace(
            &self.workspace_root,
            self.os,
            self.volume_case,
            &raw,
            is_symlink,
        ) {
            Ok(p) => p,
            Err(reason) => {
                let rej_key = if is_symlink {
                    canonicalize_within_workspace(
                        &self.workspace_root,
                        self.os,
                        self.volume_case,
                        &raw,
                        false,
                    )
                    .unwrap_or(raw)
                } else {
                    raw
                };
                self.record_rejected_bounded(rej_key, reason);
                self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
                return self.breaker_state;
            }
        };
        if self.baseline_files.contains_key(&norm_path) {
            if self.modified_baseline_paths.len() < MAX_BASELINE_FILES {
                self.modified_baseline_paths.insert(norm_path.clone());
            } else {
                self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
            }
        } else if self.created_paths.len() < MAX_BASELINE_FILES {
            self.created_paths.insert(norm_path.clone());
        } else {
            self.record_rejected_bounded(norm_path.clone(), "created-paths-capacity-exceeded");
            self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
        }

        let prev_latest = self.latest_seen_ms;
        let had_mutations = !self.mutations.is_empty();
        let mut is_future_outlier =
            had_mutations && timestamp_ms.saturating_sub(prev_latest) > MAX_CLOCK_JUMP_OUTLIER_MS;
        if is_future_outlier {
            if let Some(pending) = self.pending_future_ms
                && timestamp_ms >= pending.saturating_sub(MASS_CHANGE_WINDOW_MS)
                && timestamp_ms.saturating_sub(pending) <= MAX_CLOCK_JUMP_OUTLIER_MS
            {
                self.latest_seen_ms = prev_latest.max(pending.max(timestamp_ms));
                self.pending_future_ms = None;
                is_future_outlier = false;
            } else {
                self.pending_future_ms = Some(timestamp_ms);
            }
        } else {
            self.latest_seen_ms = if had_mutations {
                prev_latest.max(timestamp_ms)
            } else {
                timestamp_ms
            };
            self.pending_future_ms = None;
        }
        let effective_ts = if !had_mutations {
            timestamp_ms
        } else if is_future_outlier {
            prev_latest
        } else {
            timestamp_ms.max(prev_latest)
        };
        self.mutations.push_back(WorkspaceMutation {
            timestamp_ms: effective_ts,
            canonical_path: norm_path,
            post_sha256,
            byte_len,
            is_symlink,
        });

        if !is_future_outlier {
            let prune_before = self.latest_seen_ms.saturating_sub(MASS_CHANGE_WINDOW_MS);
            self.mutations.retain(|m| m.timestamp_ms >= prune_before);
        }
        while self.mutations.len() > MAX_MUTATION_HISTORY {
            self.mutations.pop_front();
        }

        let eval_anchor = if is_future_outlier {
            prev_latest
        } else {
            self.latest_seen_ms
        };
        let eval_cutoff = eval_anchor.saturating_sub(MASS_CHANGE_WINDOW_MS);
        let mut distinct_in_win = BTreeSet::new();
        let mut total_in_win: usize = 0;
        for m in &self.mutations {
            if m.timestamp_ms >= eval_cutoff && m.timestamp_ms <= eval_anchor {
                distinct_in_win.insert(m.canonical_path.as_str());
                total_in_win = total_in_win.saturating_add(1);
            }
        }
        if distinct_in_win.len() >= MASS_CHANGE_THRESHOLD_DEFAULT
            || total_in_win >= MAX_WINDOW_WRITES_OVERWRITE
        {
            self.breaker_state = MassChangeBreakerState::TrippedPausedForRestore;
        }
        self.breaker_state
    }

    /// Builds deterministic restore report covering reverted baseline files,
    /// newly created file removals, and un-restorable/oversized/symlink rejections.
    #[must_use]
    pub fn build_restore_report(&self) -> RestorePlanReport {
        let mut report = RestorePlanReport::default();
        let mut handled = BTreeSet::new();
        for modified in &self.modified_baseline_paths {
            let norm = match canonicalize_within_workspace(
                &self.workspace_root,
                self.os,
                self.volume_case,
                modified,
                false,
            ) {
                Ok(n) => n,
                Err(reason) => {
                    report
                        .not_restorable
                        .push((modified.clone(), reason.into()));
                    handled.insert(modified.clone());
                    continue;
                }
            };
            if let Some(reason) = self
                .rejected_paths
                .get(&norm)
                .or_else(|| self.rejected_paths.get(modified))
            {
                report.not_restorable.push((norm.clone(), reason.clone()));
                handled.insert(norm);
                continue;
            }
            if let Some(orig_hash) = self.baseline_files.get(&norm) {
                report.restore_targets.push(RestoreFileTarget {
                    canonical_path: norm.clone(),
                    expected_baseline_sha256: orig_hash.clone(),
                });
                handled.insert(norm);
            }
        }
        for created in &self.created_paths {
            let norm = match canonicalize_within_workspace(
                &self.workspace_root,
                self.os,
                self.volume_case,
                created,
                false,
            ) {
                Ok(n) => n,
                Err(reason) => {
                    report.not_restorable.push((created.clone(), reason.into()));
                    handled.insert(created.clone());
                    continue;
                }
            };
            if !self.baseline_files.contains_key(&norm)
                && !self.rejected_paths.contains_key(&norm)
                && !self.rejected_paths.contains_key(created)
            {
                report.remove_created.push(norm.clone());
                handled.insert(norm);
            }
        }
        for (bad_path, reason) in &self.rejected_paths {
            if !handled.contains(bad_path) {
                report
                    .not_restorable
                    .push((bad_path.clone(), reason.clone()));
            }
        }
        report
    }

    /// Builds deterministic restore list reverting modified baseline paths.
    #[must_use]
    pub fn build_restore_plan(&self) -> Vec<RestoreFileTarget> {
        self.build_restore_report().restore_targets
    }
}
