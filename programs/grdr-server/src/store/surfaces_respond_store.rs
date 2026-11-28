// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Authenticated, crash-safe disk and shared object-store persistence for `RespondOperationsState` (`docs/design/18`).

use std::fs::{self, File, OpenOptions};
use std::io::{Read as _, Write as _};
#[cfg(unix)]
use std::os::unix::fs::{MetadataExt as _, OpenOptionsExt as _};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_core::detect::kill_switch::server_operational_limits;
use grdr_core::detect::response::GranularKillSwitchState;
use grdr_crypto::{SigningKeypair, constant_time_eq, open_token, seal_token};
use grdr_model::CodedError;
use grdr_model::error::{CODE_CONFLICT, CODE_STORE_CORRUPT, CODE_STORE_IO};

use crate::store::StorageBackend;
use crate::store::surfaces_respond::RespondOperationsState;

const RESPOND_STATE_FILENAME: &str = "respond-ops.json";
const RESPOND_SEAL_DOMAIN: &str = "grdr.respond.ops_state.seal.v1";
const RESPOND_AEAD_KEY_DOMAIN: &str = "grdr.respond.ops_state.aead.v1";
const MAX_RESPOND_STATE_BYTES: u64 = 16 * 1024 * 1024;
const ENVELOPE_VERSION: u8 = 1;

#[derive(Debug, Serialize, Deserialize)]
struct SealedRespondEnvelope {
    version: u8,
    key_id: String,
    sealed_token: String,
}

#[cfg(unix)]
const fn unix_o_nofollow_flag() -> Option<i32> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "x86")))]
    {
        Some(0o400_000)
    }
    #[cfg(all(target_os = "linux", any(target_arch = "aarch64", target_arch = "arm")))]
    {
        Some(0o100_000)
    }
    #[cfg(any(target_os = "macos", target_os = "freebsd", target_os = "openbsd"))]
    {
        Some(0x0100)
    }
    #[cfg(not(any(
        all(
            target_os = "linux",
            any(
                target_arch = "x86_64",
                target_arch = "x86",
                target_arch = "aarch64",
                target_arch = "arm"
            )
        ),
        target_os = "macos",
        target_os = "freebsd",
        target_os = "openbsd"
    )))]
    {
        None
    }
}

fn respond_state_dir(backend: &StorageBackend) -> Option<&Path> {
    match backend {
        StorageBackend::Memory => None,
        StorageBackend::Disk(dir) => Some(dir.as_path()),
        StorageBackend::Ha {
            object_store_dir, ..
        }
        | StorageBackend::Distributed {
            object_store_dir, ..
        } => Some(object_store_dir.as_path()),
    }
}

fn ensure_safe_directory(dir: &Path) -> Result<(), CodedError> {
    match fs::symlink_metadata(dir) {
        Ok(meta) => {
            if meta.file_type().is_symlink() || !meta.is_dir() {
                return Err(CodedError::new(
                    CODE_STORE_IO,
                    "Refusing symlink or non-directory respond state path",
                    "Remove symlink and restore regular directory for respond operations state.",
                ));
            }
            Ok(())
        }
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(CodedError::new(
            CODE_STORE_IO,
            format!("Stat respond state directory failed: {err}"),
            "Verify state directory permissions.",
        )),
    }
}

fn open_regular_bounded(path: &Path) -> Result<Option<Vec<u8>>, CodedError> {
    let pre_meta = match fs::symlink_metadata(path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
        Err(err) => {
            return Err(CodedError::new(
                CODE_STORE_IO,
                format!("Stat respond operations state failed: {err}"),
                "Verify state directory permissions.",
            ));
        }
    };
    if pre_meta.file_type().is_symlink() || !pre_meta.is_file() {
        return Err(CodedError::new(
            CODE_STORE_IO,
            "Refusing symlink or non-regular respond operations state file",
            "Remove symlink and verify state directory permissions.",
        ));
    }
    if pre_meta.len() > MAX_RESPOND_STATE_BYTES {
        return Err(CodedError::new(
            CODE_STORE_CORRUPT,
            "Respond operations state exceeds maximum allowed size",
            "Quarantine oversized respond-ops.json file.",
        ));
    }

    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        let nofollow = unix_o_nofollow_flag().ok_or_else(|| {
            CodedError::new(
                CODE_STORE_IO,
                "Unsupported Unix target lacks verified O_NOFOLLOW constant",
                "Use supported Linux, macOS, FreeBSD, or OpenBSD target.",
            )
        })?;
        opts.custom_flags(nofollow);
    }
    let file: File = opts.open(path).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Open respond operations state failed: {e}"),
            "Check file permissions.",
        )
    })?;
    let opened_meta = file.metadata().map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Inspect opened respond operations state failed: {e}"),
            "Check file permissions.",
        )
    })?;
    if !opened_meta.is_file() {
        return Err(CodedError::new(
            CODE_STORE_IO,
            "Opened respond operations state path is not a regular file",
            "Remove special file or symlink.",
        ));
    }
    #[cfg(unix)]
    if opened_meta.dev() != pre_meta.dev() || opened_meta.ino() != pre_meta.ino() {
        return Err(CodedError::new(
            CODE_STORE_IO,
            "Respond operations state file changed during open",
            "Retry cleanly without concurrent file replacement.",
        ));
    }

    let mut raw = Vec::new();
    let limit = MAX_RESPOND_STATE_BYTES.saturating_add(1);
    file.take(limit).read_to_end(&mut raw).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Read respond operations state failed: {e}"),
            "Check disk permissions.",
        )
    })?;
    if u64::try_from(raw.len()).unwrap_or(u64::MAX) > MAX_RESPOND_STATE_BYTES {
        return Err(CodedError::new(
            CODE_STORE_CORRUPT,
            "Respond operations state exceeded read limit",
            "Quarantine oversized respond-ops.json file.",
        ));
    }
    Ok(Some(raw))
}

pub(crate) fn load_persisted_respond(
    backend: &StorageBackend,
    signing_key: &SigningKeypair,
) -> Result<Option<RespondOperationsState>, CodedError> {
    let Some(dir) = respond_state_dir(backend) else {
        return Ok(None);
    };
    ensure_safe_directory(dir)?;
    let path = dir.join(RESPOND_STATE_FILENAME);
    let Some(raw) = open_regular_bounded(&path)? else {
        return Ok(None);
    };
    let envelope: SealedRespondEnvelope = serde_json::from_slice(&raw).map_err(|e| {
        CodedError::new(
            CODE_STORE_CORRUPT,
            format!("Corrupt sealed respond operations envelope: {e}"),
            "Inspect or quarantine unauthenticated respond-ops.json.",
        )
    })?;
    if envelope.version != ENVELOPE_VERSION
        || !constant_time_eq(envelope.key_id.as_bytes(), signing_key.key_id().as_bytes())
    {
        return Err(CodedError::new(
            CODE_STORE_CORRUPT,
            "Respond operations envelope version or key_id mismatch",
            "Restore respond-ops.json matching current deployment signing key.",
        ));
    }
    let aead_key = signing_key.derive_aead_key(RESPOND_AEAD_KEY_DOMAIN);
    let plaintext = open_token(
        &aead_key,
        RESPOND_SEAL_DOMAIN,
        signing_key.key_id().as_bytes(),
        &envelope.sealed_token,
    )
    .map_err(|_| {
        CodedError::new(
            CODE_STORE_CORRUPT,
            "Respond operations state authentication tag verification failed (tampered)",
            "Restore authenticated respond-ops.json from verified backup.",
        )
    })?;
    let parsed: RespondOperationsState = serde_json::from_slice(&plaintext).map_err(|e| {
        CodedError::new(
            CODE_STORE_CORRUPT,
            format!("Corrupt respond operations state JSON: {e}"),
            "Inspect or quarantine respond-ops.json.",
        )
    })?;
    parsed.validate_on_restore()?;
    Ok(Some(parsed))
}

pub(crate) fn save_persisted_respond(
    backend: &StorageBackend,
    signing_key: &SigningKeypair,
    respond: &RespondOperationsState,
) -> Result<(), CodedError> {
    let Some(dir) = respond_state_dir(backend) else {
        return Ok(());
    };
    ensure_safe_directory(dir)?;
    fs::create_dir_all(dir).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Create state directory failed: {e}"),
            "Verify state directory permissions.",
        )
    })?;
    ensure_safe_directory(dir)?;

    let path: PathBuf = dir.join(RESPOND_STATE_FILENAME);
    if let Ok(meta) = fs::symlink_metadata(&path)
        && meta.file_type().is_symlink()
    {
        return Err(CodedError::new(
            CODE_STORE_IO,
            "Refusing symlink target when persisting respond operations state",
            "Remove symlink from state directory.",
        ));
    }

    let plaintext = serde_json::to_vec(respond).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Serialize respond operations state failed: {e}"),
            "Inspect respond operations state fields.",
        )
    })?;
    let aead_key = signing_key.derive_aead_key(RESPOND_AEAD_KEY_DOMAIN);
    let sealed_token = seal_token(
        &aead_key,
        RESPOND_SEAL_DOMAIN,
        signing_key.key_id().as_bytes(),
        &plaintext,
    )
    .map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Seal respond operations state failed: {e}"),
            "Check OS entropy availability.",
        )
    })?;
    let envelope = SealedRespondEnvelope {
        version: ENVELOPE_VERSION,
        key_id: signing_key.key_id().to_owned(),
        sealed_token,
    };
    let encoded = serde_json::to_vec(&envelope).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Encode sealed respond envelope failed: {e}"),
            "Inspect envelope serialization.",
        )
    })?;

    let tmp = dir.join(format!("respond-ops.{}.tmp", Uuid::now_v7().simple()));
    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        let nofollow = unix_o_nofollow_flag().ok_or_else(|| {
            CodedError::new(
                CODE_STORE_IO,
                "Unsupported Unix target lacks verified O_NOFOLLOW constant",
                "Use supported Linux, macOS, FreeBSD, or OpenBSD target.",
            )
        })?;
        opts.mode(0o600).custom_flags(nofollow);
    }
    let mut file = opts.open(&tmp).map_err(|e| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Open temp respond operations state failed: {e}"),
            "Verify write permissions.",
        )
    })?;
    let write_res = (|| {
        file.write_all(&encoded)?;
        file.sync_all()
    })();
    drop(file);
    if let Err(err) = write_res {
        let _ = fs::remove_file(&tmp);
        return Err(CodedError::new(
            CODE_STORE_IO,
            format!("Write/sync respond operations state failed: {err}"),
            "Verify storage stability and permissions.",
        ));
    }
    if let Err(err) = fs::rename(&tmp, &path) {
        let _ = fs::remove_file(&tmp);
        return Err(CodedError::new(
            CODE_STORE_IO,
            format!("Commit respond operations state failed: {err}"),
            "Verify directory permissions.",
        ));
    }
    Ok(())
}

pub(crate) fn operational_caps() -> Result<(usize, usize), CodedError> {
    let cfg = server_operational_limits().map_err(|err| {
        CodedError::new(
            CODE_CONFLICT,
            format!("operational limits unavailable: {err}"),
            "Restore contracts/limits.toml.",
        )
    })?;
    let max_entries = usize::try_from(cfg.max_devices_default).unwrap_or(10_000);
    Ok((max_entries, cfg.max_batch_events.max(1)))
}

pub(crate) fn push_bounded<T>(vec: &mut Vec<T>, item: T, cap: usize) {
    if vec.len() >= cap {
        let excess = vec.len().saturating_sub(cap).saturating_add(1);
        vec.drain(..excess);
    }
    vec.push(item);
}

pub(crate) fn validate_respond_snapshot(state: &RespondOperationsState) -> Result<(), CodedError> {
    let (max_entries, max_batch) = operational_caps()?;
    let over = state.rosters.len() > max_entries
        || state.kill_states_by_org.len() > max_entries
        || state.replay_state.used_challenges.len() > max_entries
        || state.replay_state.signer_sign_counts.len() > max_entries
        || state.provider_hourly_orgs.len() > max_entries
        || state.freeze_by_key_scope.len() > max_entries
        || state.session_orgs.len() > max_entries
        || state.device_orgs.len() > max_entries
        || state.response_actions.len() > max_entries
        || state.incidents.len() > max_entries
        || state.triage_queue.len() > max_entries
        || state.suppressions.len() > max_entries
        || state.ticket_manifests.len() > max_batch
        || state.ticket_links.len() > max_entries
        || state.saved_hunts.len() > max_batch
        || state.hunt_runs.len() > max_batch
        || state.playbooks.len() > max_batch
        || state.playbook_simulate_started.len() > max_batch
        || state.playbook_promotions.len() > max_batch
        || state.playbook_runs.len() > max_batch;
    if over {
        return Err(CodedError::new(
            CODE_STORE_CORRUPT,
            "respond operations snapshot exceeds operational bounds",
            "Quarantine oversized respond-ops.json snapshot.",
        ));
    }
    for (org_id, ks) in &state.kill_states_by_org {
        if org_id.trim().is_empty() {
            return Err(CodedError::new(
                CODE_STORE_CORRUPT,
                "kill switch state has empty org_id key",
                "Remove corrupt respond-ops.json.",
            ));
        }
        GranularKillSwitchState::restore_checked(ks.clone(), 0).map_err(|err| {
            CodedError::new(
                CODE_STORE_CORRUPT,
                format!("kill switch snapshot validation failed for `{org_id}`: {err}"),
                "Quarantine corrupt respond-ops.json snapshot.",
            )
        })?;
    }
    for (org_id, roster) in &state.rosters {
        if org_id != &roster.org_id {
            return Err(CodedError::new(
                CODE_STORE_CORRUPT,
                "approver roster org_id key mismatch",
                "Quarantine corrupt respond-ops.json.",
            ));
        }
        roster.validate_entries_and_metadata()?;
    }
    Ok(())
}
