// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Two-phase resumable blob staging/promotion and `O_NOFOLLOW`-safe audit logging for `grdr server airgap import`.

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Write as _;
use std::path::Path;

use grdr_blob::FilesystemBlobStore;
use grdr_ports::{BlobPort as _, SingleCtx, TenantCtx, TenantPath};
use grdr_update::{AirgapArtifact, UpdateError, canonical_sha256};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::airgap::AirgapCliError;
use crate::fs_safe::{
    atomic_write_bytes, ensure_safe_dir_all, read_bounded_regular,
    reject_symlinks_on_existing_prefixes,
};

const MAX_RESUME_JSON_BYTES: u64 = 4 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UploadSessionStatus {
    InProgress,
    Completed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ResumableUploadState {
    pub session_id: String,
    pub bundle_sha256: String,
    pub status: UploadSessionStatus,
    pub uploaded_paths: BTreeSet<String>,
    pub total_entries: usize,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServerImportAuditEntry {
    pub operator_id: String,
    pub org_id: String,
    pub bundle_id: String,
    pub bundle_version: String,
    pub manifest_sha256: String,
    pub root_fingerprint: String,
    pub terms_accepted_digest: String,
    pub imported_blobs: usize,
    pub resumed_skipped_blobs: usize,
    pub registry_images_staged: usize,
    pub freshness_vouch_issued: bool,
    pub outbound_requests: u64,
    pub imported_at: Timestamp,
}

#[allow(clippy::too_many_arguments)]
pub fn stage_and_promote_bundle_blobs(
    blob_store_dir: &Path,
    state_dir: &Path,
    ctx: &SingleCtx,
    session_id: &str,
    bundle_version: &str,
    manifest_sha256: &str,
    artifacts: &[AirgapArtifact],
    chunk_bytes: usize,
    interrupt_after_blobs: Option<usize>,
    now: Timestamp,
) -> Result<(usize, usize), AirgapCliError> {
    let blob_store = FilesystemBlobStore::open(blob_store_dir)
        .map_err(|e| io_err(blob_store_dir, &e.to_string()))?;
    let session_path = state_dir.join(format!("upload-{session_id}.json"));
    let mut upload_state = load_or_init_upload_state(
        &session_path,
        session_id,
        manifest_sha256,
        artifacts.len(),
        now,
    )?;

    let read_ctx = TenantCtx::Single(ctx.clone());
    let mut imported_blobs = 0usize;
    let mut resumed_skipped_blobs = 0usize;
    let chunk_sz = chunk_bytes.max(1024);

    for item in artifacts {
        let staging_rel = format!("staging/{session_id}/{bundle_version}/{}", item.path);
        let staging_tp = TenantPath::parse(ctx, &staging_rel).map_err(|e| {
            AirgapCliError::InvalidInput(format!("staging tenant path `{staging_rel}`: {e}"))
        })?;
        let expected_sha = canonical_sha256(&item.bytes);

        if upload_state.uploaded_paths.contains(&item.path) {
            let existing_blob = blob_store
                .get(&read_ctx, &staging_tp)
                .map_err(|e| io_err(blob_store_dir, &e.to_string()))?;
            let Some(blob) = existing_blob else {
                return Err(UpdateError::ArtifactIntegrity {
                    target: staging_rel,
                    detail: "resumed staging blob missing from blob store".into(),
                }
                .into());
            };
            if canonical_sha256(&blob.bytes) != expected_sha {
                return Err(UpdateError::ArtifactIntegrity {
                    target: staging_rel,
                    detail: "resumed staging blob digest mismatch".into(),
                }
                .into());
            }
            resumed_skipped_blobs = resumed_skipped_blobs.saturating_add(1);
            continue;
        }

        let mut staged = Vec::with_capacity(item.bytes.len());
        for slice in item.bytes.chunks(chunk_sz) {
            staged.extend_from_slice(slice);
        }
        blob_store
            .put(ctx, &staging_tp, &staged)
            .map_err(|e| io_err(blob_store_dir, &e.to_string()))?;
        upload_state.uploaded_paths.insert(item.path.clone());
        upload_state.updated_at = Timestamp::now();
        imported_blobs = imported_blobs.saturating_add(1);
        persist_upload_state(&session_path, &upload_state)?;

        if let Some(limit) = interrupt_after_blobs
            && imported_blobs >= limit
        {
            return Err(AirgapCliError::InvalidInput(format!(
                "resumable upload paused at blob {imported_blobs} (staging only); resume with --resume-session {session_id}"
            )));
        }
    }

    for item in artifacts {
        let staging_rel = format!("staging/{session_id}/{bundle_version}/{}", item.path);
        let final_rel = format!("bundles/{bundle_version}/{}", item.path);
        let staging_tp = TenantPath::parse(ctx, &staging_rel).map_err(|e| {
            AirgapCliError::InvalidInput(format!("staging tenant path `{staging_rel}`: {e}"))
        })?;
        let final_tp = TenantPath::parse(ctx, &final_rel).map_err(|e| {
            AirgapCliError::InvalidInput(format!("bundle tenant path `{final_rel}`: {e}"))
        })?;
        let expected_sha = canonical_sha256(&item.bytes);
        let staged_obj = blob_store
            .get(&read_ctx, &staging_tp)
            .map_err(|e| io_err(blob_store_dir, &e.to_string()))?
            .ok_or_else(|| UpdateError::ArtifactIntegrity {
                target: staging_rel.clone(),
                detail: "staged blob disappeared before promotion".into(),
            })?;
        if canonical_sha256(&staged_obj.bytes) != expected_sha {
            return Err(UpdateError::ArtifactIntegrity {
                target: staging_rel,
                detail: "staged blob digest changed before promotion".into(),
            }
            .into());
        }
        blob_store
            .put(ctx, &final_tp, &staged_obj.bytes)
            .map_err(|e| io_err(blob_store_dir, &e.to_string()))?;
    }

    upload_state.status = UploadSessionStatus::Completed;
    upload_state.updated_at = Timestamp::now();
    persist_upload_state(&session_path, &upload_state)?;

    Ok((imported_blobs, resumed_skipped_blobs))
}

fn load_or_init_upload_state(
    path: &Path,
    session_id: &str,
    bundle_sha256: &str,
    total_entries: usize,
    now: Timestamp,
) -> Result<ResumableUploadState, AirgapCliError> {
    if fs::symlink_metadata(path).is_ok() {
        let raw = read_bounded_regular(path, MAX_RESUME_JSON_BYTES)
            .map_err(|e| io_err(path, &e.to_string()))?;
        let state: ResumableUploadState = serde_json::from_slice(&raw)
            .map_err(|e| AirgapCliError::InvalidInput(format!("corrupt upload session: {e}")))?;
        if state.session_id != session_id
            || state.bundle_sha256 != bundle_sha256
            || state.total_entries != total_entries
        {
            return Err(UpdateError::MixAndMatchDetected(
                "resumable upload session identity, digest, or entry count mismatch".into(),
            )
            .into());
        }
        return Ok(state);
    }
    Ok(ResumableUploadState {
        session_id: session_id.to_owned(),
        bundle_sha256: bundle_sha256.to_owned(),
        status: UploadSessionStatus::InProgress,
        uploaded_paths: BTreeSet::new(),
        total_entries,
        updated_at: now,
    })
}

fn persist_upload_state(path: &Path, state: &ResumableUploadState) -> Result<(), AirgapCliError> {
    let bytes = serde_json::to_vec_pretty(state)
        .map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    atomic_write_bytes(path, &bytes, false).map_err(|e| io_err(path, &e.to_string()))
}

pub fn append_audit_entry(
    path: &Path,
    entry: &ServerImportAuditEntry,
) -> Result<(), AirgapCliError> {
    reject_symlinks_on_existing_prefixes(path).map_err(|e| io_err(path, &e.to_string()))?;
    if let Some(parent) = path.parent() {
        ensure_safe_dir_all(parent, false).map_err(|e| io_err(parent, &e.to_string()))?;
    }
    let pre_meta = match fs::symlink_metadata(path) {
        Ok(m) => {
            if is_symlink_or_reparse(&m) || !m.is_file() {
                return Err(io_err(
                    path,
                    "audit log path must be a regular non-symlink file",
                ));
            }
            Some(m)
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => None,
        Err(err) => return Err(io_err(path, &err.to_string())),
    };

    let mut opts = OpenOptions::new();
    opts.create(true).append(true);
    #[cfg(windows)]
    {
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;
        opts.custom_flags(FILE_FLAG_OPEN_REPARSE_POINT);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt as _;
        #[cfg(any(
            target_os = "macos",
            target_os = "ios",
            target_os = "freebsd",
            target_os = "openbsd",
            target_os = "dragonfly"
        ))]
        const O_NOFOLLOW_FLAG: i32 = 0x0100;
        #[cfg(target_os = "netbsd")]
        const O_NOFOLLOW_FLAG: i32 = 0x0001_0000;
        #[cfg(target_os = "linux")]
        const O_NOFOLLOW_FLAG: i32 = 0o400_000;
        opts.custom_flags(O_NOFOLLOW_FLAG);
    }

    let mut file = opts.open(path).map_err(|e| io_err(path, &e.to_string()))?;
    let handle_meta = file.metadata().map_err(|e| io_err(path, &e.to_string()))?;
    if is_symlink_or_reparse(&handle_meta) || !handle_meta.is_file() {
        return Err(io_err(
            path,
            "opened audit log handle is not a regular file",
        ));
    }
    #[cfg(unix)]
    if let Some(ref pre) = pre_meta {
        use std::os::unix::fs::MetadataExt as _;
        if pre.dev() != handle_meta.dev() || pre.ino() != handle_meta.ino() {
            return Err(io_err(path, "audit log file changed during open"));
        }
    }
    #[cfg(not(unix))]
    let _ = pre_meta;

    let line =
        serde_json::to_string(entry).map_err(|e| AirgapCliError::InvalidInput(e.to_string()))?;
    writeln!(file, "{line}").map_err(|e| io_err(path, &e.to_string()))?;
    file.sync_all().map_err(|e| io_err(path, &e.to_string()))
}

fn is_symlink_or_reparse(meta: &fs::Metadata) -> bool {
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt as _;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        meta.file_type().is_symlink()
            || (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0
    }
    #[cfg(not(windows))]
    {
        meta.file_type().is_symlink()
    }
}

fn io_err(path: &Path, detail: &str) -> AirgapCliError {
    AirgapCliError::Io {
        path: path.display().to_string(),
        detail: detail.to_owned(),
    }
}
