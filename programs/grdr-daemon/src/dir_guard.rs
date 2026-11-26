// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Directory security guards, P8 capture-level redaction, and local caller privilege checks.

use std::fs;
use std::path::{Component, Path, PathBuf};

use grdr_crypto::{SigningKeypair, sha256_hex};
#[cfg(unix)]
use grdr_peer_os::fs_open::restrict_dir_mode_value;
use grdr_peer_os::fs_open::{
    check_no_ancestor_symlinks, create_private_dir_all, open_nofollow_dir, verify_open_dir_trust,
};
use grdr_peer_os::{OsPeerReader, PeerReader};
use grdr_store_local::fs_hardening::{is_symlink_or_reparse, redact_path_label};
use grdr_wire::peer_auth::{Profile, VerifiedPeer};

const MIN_PROTECTED_LOCAL_ADMIN_INTEGRITY_RID: u32 = 0x3000;
const MIN_USER_LOCAL_ADMIN_INTEGRITY_RID: u32 = 0x2000;
const AGENT_ANCESTOR_NAMES: &[&str] = &[
    "claude",
    "claude-code",
    "cursor",
    "codex",
    "windsurf",
    "opencode",
    "aider",
    "copilot",
    "copilot-agent",
    "gemini",
    "goose",
];

pub(crate) struct LocalCallerClaims<'a> {
    pub profile: Profile,
    pub integrity_rid: Option<u32>,
    pub windows_sid: Option<&'a str>,
    pub uid: Option<u32>,
}

pub(crate) fn ensure_dir_secure(dir: &Path, public_readable: bool) -> Result<(), String> {
    check_no_ancestor_symlinks(dir).map_err(|e| format!("{}: {e}", redact_path_label(dir)))?;
    if !public_readable {
        create_private_dir_all(dir)
            .map_err(|e| format!("create private dir {}: {e}", redact_path_label(dir)))?;
        let handle = open_nofollow_dir(dir)
            .map_err(|e| format!("open private dir {}: {e}", redact_path_label(dir)))?;
        #[cfg(unix)]
        {
            restrict_dir_mode_value(&handle, 0o700)
                .map_err(|e| format!("chmod 0700 {}: {e}", redact_path_label(dir)))?;
        }
        verify_open_dir_trust(&handle, dir, false)
            .map_err(|e| format!("verify private dir {}: {e}", redact_path_label(dir)))?;
        return Ok(());
    }

    create_shared_dir_components(dir)?;
    let _handle = open_nofollow_dir(dir)
        .map_err(|e| format!("open state dir {}: {e}", redact_path_label(dir)))?;
    #[cfg(unix)]
    {
        restrict_dir_mode_value(&_handle, 0o755)
            .map_err(|e| format!("chmod 0755 {}: {e}", redact_path_label(dir)))?;
        verify_shared_unix_dir(&_handle, dir)?;
    }
    Ok(())
}

fn create_shared_dir_components(dir: &Path) -> Result<(), String> {
    let mut acc = PathBuf::new();
    for comp in dir.components() {
        acc.push(comp.as_os_str());
        if matches!(
            comp,
            Component::Prefix(_) | Component::RootDir | Component::CurDir
        ) {
            continue;
        }
        match fs::symlink_metadata(&acc) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) || !meta.is_dir() {
                    return Err(format!(
                        "refusing symlink or non-directory at {}",
                        redact_path_label(&acc)
                    ));
                }
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                create_single_shared_dir(&acc)?;
            }
            Err(err) => {
                return Err(format!("stat {}: {err}", redact_path_label(&acc)));
            }
        }
    }
    Ok(())
}

#[cfg(unix)]
fn create_single_shared_dir(dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::DirBuilderExt as _;
    let mut b = fs::DirBuilder::new();
    b.mode(0o755);
    b.create(dir)
        .map_err(|e| format!("create {}: {e}", redact_path_label(dir)))
}

#[cfg(not(unix))]
fn create_single_shared_dir(dir: &Path) -> Result<(), String> {
    fs::create_dir(dir).map_err(|e| format!("create {}: {e}", redact_path_label(dir)))
}

#[cfg(unix)]
fn verify_shared_unix_dir(handle: &fs::File, dir: &Path) -> Result<(), String> {
    use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
    let meta = handle
        .metadata()
        .map_err(|e| format!("stat {}: {e}", redact_path_label(dir)))?;
    let uid = meta.uid();
    let mode = meta.permissions().mode();
    let my_uid = grdr_peer_os::unix_peer::current_effective_ids()
        .map(|ids| ids.0)
        .unwrap_or(u32::MAX);
    if uid != 0 && uid != my_uid {
        return Err(format!("foreign owner on {}", redact_path_label(dir)));
    }
    if (mode & 0o022) != 0 {
        return Err(format!(
            "group/world writable bit set on {}",
            redact_path_label(dir)
        ));
    }
    Ok(())
}

pub(crate) fn derive_device_id(key: &SigningKeypair) -> String {
    let hex = sha256_hex(key.public_key_b64().as_bytes());
    let short = hex.get(..24).unwrap_or(&hex);
    format!("dev-{short}")
}

pub(crate) fn session_recorder_key(device_id: &str, session_id: &str) -> String {
    let digest = sha256_hex(format!("grdr.session.v1\0{device_id}\0{session_id}").as_bytes());
    let short = digest.get(..32).unwrap_or(&digest);
    format!("sess-{short}")
}

#[must_use]
pub(crate) fn p8_redact_target(target: &str) -> String {
    let hex = sha256_hex(format!("grdr.target.v1\0{target}").as_bytes());
    let short = hex.get(..16).unwrap_or(&hex);
    format!("sha256:{short}")
}

#[must_use]
pub(crate) fn scrub_p8_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len().min(256));
    for word in raw.split_whitespace() {
        if !out.is_empty() {
            out.push(' ');
        }
        let lower = word.to_ascii_lowercase();
        let has_user_path = lower.contains("/users/")
            || lower.contains("\\users\\")
            || lower.contains("/home/")
            || lower.contains(":/users/");
        let has_secret_prefix = lower.starts_with("sk-")
            || lower.starts_with("ghp_")
            || lower.starts_with("gho_")
            || lower.starts_with("ghs_")
            || lower.starts_with("glpat-")
            || lower.starts_with("akia");
        if has_user_path {
            out.push_str("<redacted-path>");
        } else if has_secret_prefix {
            out.push_str("<redacted-secret>");
        } else {
            out.push_str(word);
        }
        if out.len() >= 256 {
            break;
        }
    }
    out
}

pub(crate) fn caller_principal_from_peer(peer: &VerifiedPeer) -> crate::state::CallerPrincipal {
    crate::state::CallerPrincipal {
        uid: peer.uid(),
        windows_sid: peer.windows_sid().map(ToOwned::to_owned),
    }
}

pub(crate) fn default_principal() -> crate::state::CallerPrincipal {
    #[cfg(unix)]
    let uid = grdr_peer_os::unix_peer::current_effective_ids().map(|ids| ids.0);
    #[cfg(not(unix))]
    let uid = None;
    #[cfg(windows)]
    let windows_sid = grdr_peer_os::win_peer::current_process_sid().ok();
    #[cfg(not(windows))]
    let windows_sid = None;
    crate::state::CallerPrincipal { uid, windows_sid }
}

pub(crate) fn is_privileged_local_caller(peer: &VerifiedPeer) -> bool {
    let my_uid = grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.0);
    #[cfg(windows)]
    let expected_win_sid = grdr_peer_os::win_peer::current_process_sid().ok();
    #[cfg(not(windows))]
    let expected_win_sid: Option<String> = None;

    let agent_lineage = caller_has_agent_ancestry(peer.pid());
    let claims = LocalCallerClaims {
        profile: peer.profile(),
        integrity_rid: peer.integrity_rid(),
        windows_sid: peer.windows_sid(),
        uid: peer.uid(),
    };
    is_privileged_local_caller_with_context(
        &claims,
        expected_win_sid.as_deref(),
        my_uid,
        agent_lineage,
    )
}

pub(crate) fn is_privileged_local_caller_with_context(
    claims: &LocalCallerClaims<'_>,
    expected_win_sid: Option<&str>,
    daemon_uid: u32,
    agent_ancestry: bool,
) -> bool {
    if agent_ancestry {
        return false;
    }
    if claims.profile == Profile::Protected {
        if let Some(rid) = claims.integrity_rid {
            if rid < MIN_PROTECTED_LOCAL_ADMIN_INTEGRITY_RID {
                return false;
            }
            if let Some(sid) = claims.windows_sid
                && !is_protected_local_admin_sid(sid, expected_win_sid)
            {
                return false;
            }
        }
        if let Some(uid) = claims.uid
            && uid != 0
            && uid != daemon_uid
        {
            return false;
        }
        return claims.integrity_rid.is_some() || claims.uid.is_some();
    }

    if let Some(rid) = claims.integrity_rid {
        if rid < MIN_USER_LOCAL_ADMIN_INTEGRITY_RID {
            return false;
        }
        if let Some(expected_sid) = expected_win_sid
            && claims.windows_sid != Some(expected_sid)
        {
            return false;
        }
    }
    if let Some(uid) = claims.uid
        && uid != 0
        && uid != daemon_uid
    {
        return false;
    }
    true
}

fn is_protected_local_admin_sid(sid: &str, daemon_sid: Option<&str>) -> bool {
    matches!(sid, "S-1-5-18" | "S-1-5-32-544")
        || sid.ends_with("-500")
        || daemon_sid.is_some_and(|d| d == sid)
}

fn caller_has_agent_ancestry(pid: Option<u32>) -> bool {
    let Some(pid) = pid else {
        return true;
    };
    let reader = OsPeerReader;
    match reader.read_parent_chain(pid, 16) {
        Ok(chain) => {
            if chain.first().is_none_or(|head| head.exe_path.is_none()) {
                return true;
            }
            chain.iter().any(|node| {
                node.exe_path.as_deref().is_some_and(|exe| {
                    let stem = Path::new(exe)
                        .file_stem()
                        .and_then(|s| s.to_str())
                        .unwrap_or("")
                        .to_ascii_lowercase();
                    AGENT_ANCESTOR_NAMES.iter().any(|agent| *agent == stem)
                })
            })
        }
        Err(_) => true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn caller_has_agent_ancestry_fails_closed_on_missing_or_unverifiable_pid() {
        assert!(caller_has_agent_ancestry(None));
        assert!(caller_has_agent_ancestry(Some(u32::MAX - 1)));
    }

    #[test]
    fn protected_local_caller_rejects_medium_integrity_and_agent_lineage() {
        let med_win = LocalCallerClaims {
            profile: Profile::Protected,
            integrity_rid: Some(0x2000),
            windows_sid: Some("S-1-5-32-544"),
            uid: None,
        };
        assert!(!is_privileged_local_caller_with_context(
            &med_win,
            Some("S-1-5-18"),
            0,
            false
        ));

        let high_win = LocalCallerClaims {
            profile: Profile::Protected,
            integrity_rid: Some(0x3000),
            windows_sid: Some("S-1-5-32-544"),
            uid: None,
        };
        assert!(is_privileged_local_caller_with_context(
            &high_win,
            Some("S-1-5-18"),
            0,
            false
        ));
        assert!(!is_privileged_local_caller_with_context(
            &high_win,
            Some("S-1-5-18"),
            0,
            true
        ));

        let user_wrong_sid = LocalCallerClaims {
            profile: Profile::User,
            integrity_rid: Some(0x2000),
            windows_sid: Some("S-1-5-21-9-9-9-1002"),
            uid: None,
        };
        assert!(!is_privileged_local_caller_with_context(
            &user_wrong_sid,
            Some("S-1-5-21-9-9-9-1001"),
            1000,
            false
        ));
    }
}
