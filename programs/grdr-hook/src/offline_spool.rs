// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Protected-state-dir resolution (never `/tmp`) and P8-redacted 4 MiB offline hook spool
//! with bounded file locks and `0o600` permissions.

use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Component, Path, PathBuf};
use std::time::{Duration, Instant};

use grdr_crypto::{domain_sha256_hex, fill_random};
use grdr_peer_os::fs_open::{
    OpenNofollowAccess, check_no_ancestor_symlinks, create_private_dir_all, open_nofollow_file,
    set_private_file_mode, sync_parent_dir, verify_open_file_trust,
};

use crate::dialect::escape_json;
pub use crate::handover::{HANDOVER_MARKER_MAX_MS, active_handover_remaining_ms};

pub const HOOK_OFFLINE_SPOOL_CAP_BYTES: u64 = 4 * 1024 * 1024;
const MAX_OFFLINE_REASON_LEN: usize = 96;
const OFFLINE_LOCK_TIMEOUT_MS: u64 = 50;
const OFFLINE_ROTATE_OVERHEAD_BYTES: u64 = 64 * 1024;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OfflineQueueOutcome {
    pub path: PathBuf,
    pub total_bytes: u64,
    pub dropped_count: u64,
}

#[must_use]
pub fn resolve_protected_state_dir(protected: bool) -> PathBuf {
    if protected {
        return system_state_dir();
    }
    if let Some(explicit) = std::env::var_os("GRDR_STATE_DIR")
        && let Some(text) = explicit.to_str()
        && !text.trim().is_empty()
    {
        let candidate = PathBuf::from(text);
        if is_safe_non_temp_candidate(&candidate) {
            return candidate;
        }
    }
    user_default_state_dir().unwrap_or_else(system_state_dir)
}

#[must_use]
pub fn resolve_offline_spool_dir(protected: bool, state_dir: &Path) -> PathBuf {
    if !protected {
        return state_dir.to_path_buf();
    }
    user_default_state_dir()
        .map(|d| d.join("spool"))
        .unwrap_or_else(|| state_dir.to_path_buf())
}

#[must_use]
pub fn system_state_dir() -> PathBuf {
    crate::brand::HookBrandConfig::embedded().protected_state_dir()
}

pub fn enqueue_offline_metadata(
    state_dir: &Path,
    agent: &str,
    session_id: &str,
    target: &str,
    verdict: &str,
    reason: &str,
    ts_unix_ms: i64,
) -> std::io::Result<OfflineQueueOutcome> {
    let _dir = create_private_dir_all(state_dir).map_err(peer_to_io)?;

    let lock_path = state_dir.join("hook-offline-spool.lock");
    let lock_file = open_nofollow_file(&lock_path, OpenNofollowAccess::ReadWriteCreate, 0o600)
        .map_err(peer_to_io)?;
    set_private_file_mode(&lock_file).map_err(peer_to_io)?;
    try_lock_bounded(&lock_file, Duration::from_millis(OFFLINE_LOCK_TIMEOUT_MS))?;

    let queue_path = state_dir.join("hook-offline-spool.jsonl");
    let drops_path = state_dir.join("hook-offline-drops.count");
    let existing_drops = read_drops_count(&drops_path);

    let session_digest = domain_sha256_hex("grdr.offline.session.v1\0", session_id.as_bytes());
    let target_digest = domain_sha256_hex("grdr.offline.target.v1\0", target.as_bytes());
    let safe_reason = sanitize_offline_reason(reason);
    let line = format!(
        "{{\"ts_ms\":{ts_unix_ms},\"agent\":\"{}\",\"session_sha\":\"{}\",\"target_sha\":\"{}\",\"verdict\":\"{}\",\"reason\":\"{}\"}}\n",
        escape_json(agent),
        short_hex(&session_digest),
        short_hex(&target_digest),
        escape_json(verdict),
        escape_json(&safe_reason),
    );
    let line_len = u64::try_from(line.len()).unwrap_or(0);

    let mut file = open_nofollow_file(&queue_path, OpenNofollowAccess::AppendCreate, 0o600)
        .map_err(peer_to_io)?;
    set_private_file_mode(&file).map_err(peer_to_io)?;
    verify_open_file_trust(&file, false).map_err(peer_to_io)?;
    let current_len = file.metadata()?.len();

    if current_len.saturating_add(line_len) > HOOK_OFFLINE_SPOOL_CAP_BYTES {
        drop(file);
        return rotate_spool_queue(
            state_dir,
            &queue_path,
            &drops_path,
            &line,
            line_len,
            existing_drops,
        );
    }

    file.write_all(line.as_bytes())?;
    file.sync_data()?;
    Ok(OfflineQueueOutcome {
        path: queue_path,
        total_bytes: current_len.saturating_add(line_len),
        dropped_count: existing_drops,
    })
}

fn user_default_state_dir() -> Option<PathBuf> {
    let brand = crate::brand::HookBrandConfig::embedded();
    #[cfg(windows)]
    {
        if let Some(local_app) = std::env::var_os("LOCALAPPDATA")
            && let Some(text) = local_app.to_str()
            && !text.trim().is_empty()
        {
            let candidate = brand.user_state_candidate_local_appdata(text);
            if is_safe_non_temp_candidate(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
    #[cfg(not(windows))]
    {
        if let Some(xdg_state) = std::env::var_os("XDG_STATE_HOME")
            && let Some(text) = xdg_state.to_str()
            && !text.trim().is_empty()
        {
            let candidate = brand.user_state_candidate_xdg(text);
            if is_safe_non_temp_candidate(&candidate) {
                return Some(candidate);
            }
        }
        if let Some(home) = std::env::var_os("HOME")
            && let Some(text) = home.to_str()
            && !text.trim().is_empty()
        {
            let candidate = brand.user_state_candidate_home(text);
            if is_safe_non_temp_candidate(&candidate) {
                return Some(candidate);
            }
        }
        None
    }
}

fn rotate_spool_queue(
    state_dir: &Path,
    queue_path: &Path,
    drops_path: &Path,
    line: &str,
    line_len: u64,
    existing_drops: u64,
) -> std::io::Result<OfflineQueueOutcome> {
    let mut retained = Vec::new();
    let mut dropped = 0u64;
    if let Ok(existing_file) = open_nofollow_file(queue_path, OpenNofollowAccess::ReadOnly, 0o600) {
        let mut raw = Vec::new();
        let read_cap = HOOK_OFFLINE_SPOOL_CAP_BYTES.saturating_add(OFFLINE_ROTATE_OVERHEAD_BYTES);
        if existing_file
            .take(read_cap.saturating_add(1))
            .read_to_end(&mut raw)
            .is_ok()
        {
            let text = String::from_utf8_lossy(&raw);
            let mut running = 0u64;
            let keep_budget = HOOK_OFFLINE_SPOOL_CAP_BYTES
                .saturating_div(2)
                .saturating_sub(line_len);
            for old_line in text.lines().rev() {
                let sz = u64::try_from(old_line.len().saturating_add(1)).unwrap_or(0);
                if running.saturating_add(sz) <= keep_budget {
                    running = running.saturating_add(sz);
                    retained.push(old_line.to_string());
                } else {
                    dropped = dropped.saturating_add(1);
                }
            }
            retained.reverse();
        }
    }

    let tmp_queue = unique_tmp_path(state_dir, "hook-offline-spool.jsonl.tmp")?;
    {
        let mut tmp = open_nofollow_file(&tmp_queue, OpenNofollowAccess::TruncateCreate, 0o600)
            .map_err(peer_to_io)?;
        set_private_file_mode(&tmp).map_err(peer_to_io)?;
        for kept in &retained {
            writeln!(tmp, "{kept}")?;
        }
        tmp.write_all(line.as_bytes())?;
        tmp.sync_all()?;
    }
    fs::rename(&tmp_queue, queue_path)?;
    sync_parent_dir(state_dir).map_err(peer_to_io)?;

    let next_drops = existing_drops.saturating_add(dropped.max(1));
    let tmp_drops = unique_tmp_path(state_dir, "hook-offline-drops.count.tmp")?;
    {
        let mut tmp = open_nofollow_file(&tmp_drops, OpenNofollowAccess::TruncateCreate, 0o600)
            .map_err(peer_to_io)?;
        set_private_file_mode(&tmp).map_err(peer_to_io)?;
        tmp.write_all(next_drops.to_string().as_bytes())?;
        tmp.sync_all()?;
    }
    fs::rename(&tmp_drops, drops_path)?;
    sync_parent_dir(state_dir).map_err(peer_to_io)?;

    let total = open_nofollow_file(queue_path, OpenNofollowAccess::ReadOnly, 0o600)
        .and_then(|f| {
            f.metadata()
                .map_err(|e| grdr_peer_os::PeerError::PathUnsafe(e.to_string()))
        })
        .map_or(line_len, |m| m.len());
    Ok(OfflineQueueOutcome {
        path: queue_path.to_path_buf(),
        total_bytes: total,
        dropped_count: next_drops,
    })
}

fn read_drops_count(drops_path: &Path) -> u64 {
    let Ok(f) = open_nofollow_file(drops_path, OpenNofollowAccess::ReadOnly, 0o600) else {
        return 0;
    };
    let mut s = String::new();
    if f.take(64).read_to_string(&mut s).is_ok() {
        s.trim().parse::<u64>().unwrap_or(0)
    } else {
        0
    }
}

fn try_lock_bounded(lock_file: &File, timeout: Duration) -> std::io::Result<()> {
    let started = Instant::now();
    loop {
        match lock_file.try_lock() {
            Ok(()) => return Ok(()),
            Err(std::fs::TryLockError::WouldBlock) => {
                if started.elapsed() >= timeout {
                    return Err(std::io::Error::new(
                        std::io::ErrorKind::TimedOut,
                        "offline spool file lock timed out",
                    ));
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            Err(std::fs::TryLockError::Error(err)) => return Err(err),
        }
    }
}

fn unique_tmp_path(dir: &Path, prefix: &str) -> std::io::Result<PathBuf> {
    let mut rand = [0u8; 8];
    fill_random(&mut rand)
        .map_err(|e| std::io::Error::other(format!("random temp filename failed: {e}")))?;
    let mut suffix = String::with_capacity(16);
    for b in rand {
        suffix.push_str(&format!("{b:02x}"));
    }
    Ok(dir.join(format!("{prefix}.{}.{suffix}", std::process::id())))
}

fn is_safe_non_temp_candidate(path: &Path) -> bool {
    if !path.is_absolute()
        || path
            .components()
            .any(|c| matches!(c, Component::CurDir | Component::ParentDir))
    {
        return false;
    }
    if matches_temp_prefix(path, &std::env::temp_dir()) {
        return false;
    }
    for env_key in ["TEMP", "TMP", "TMPDIR"] {
        if let Some(val) = std::env::var_os(env_key)
            && matches_temp_prefix(path, Path::new(&val))
        {
            return false;
        }
    }
    for prefix in ["/tmp", "/var/tmp", "/private/tmp", "/dev/shm"] {
        if matches_temp_prefix(path, Path::new(prefix)) {
            return false;
        }
    }
    check_no_ancestor_symlinks(path).is_ok()
}

fn matches_temp_prefix(path: &Path, prefix: &Path) -> bool {
    let norm = |p: &Path| {
        p.to_string_lossy()
            .replace('\\', "/")
            .trim_end_matches('/')
            .to_ascii_lowercase()
    };
    let lhs = norm(path);
    let rhs = norm(prefix);
    !rhs.is_empty()
        && (lhs == rhs
            || lhs
                .strip_prefix(&rhs)
                .is_some_and(|rest| rest.starts_with('/')))
}

fn sanitize_offline_reason(reason: &str) -> String {
    let mut tokens = Vec::new();
    for raw_tok in reason.split_whitespace() {
        let stripped = raw_tok.trim_matches(|c: char| matches!(c, '"' | '\'' | '`'));
        let has_sensitive_marker = stripped.contains("://")
            || stripped.contains('\\')
            || stripped.starts_with('/')
            || stripped.contains("/home/")
            || stripped.contains("/Users/")
            || stripped.contains("/etc/")
            || stripped.contains("/var/")
            || stripped.contains("/tmp/")
            || stripped.contains('=');
        let tok = if has_sensitive_marker && !stripped.starts_with("GRDR-") {
            "[redacted]"
        } else {
            stripped
        };
        tokens.push(tok);
    }
    let joined = tokens.join(" ");
    let clean: String = joined
        .chars()
        .map(|c| {
            if c.is_control() || matches!(c, '"' | '`') {
                ' '
            } else {
                c
            }
        })
        .take(MAX_OFFLINE_REASON_LEN)
        .collect();
    if clean.trim().is_empty() {
        "offline".to_string()
    } else {
        clean
    }
}

fn short_hex(hex: &str) -> &str {
    let end = hex.len().min(16);
    hex.get(..end).unwrap_or(hex)
}

fn peer_to_io(err: grdr_peer_os::PeerError) -> std::io::Error {
    std::io::Error::new(std::io::ErrorKind::PermissionDenied, err.to_string())
}
