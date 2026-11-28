// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Kernel-backed Windows TCB policy verification replacing insecure snapshot basename stubs (`b.peer`).

use std::collections::BTreeMap;
use std::path::Path;

use crate::PeerError;

pub(crate) const TRUSTED_SESSION0_SYSTEM32_EXES: &[&str] =
    &["smss.exe", "wininit.exe", "services.exe"];
pub(crate) const TRUSTED_SVCHOST_EXE: &str = "svchost.exe";
pub(crate) const TRUSTED_WINLOGON_EXE: &str = "winlogon.exe";

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TcbVerifyPolicyInput<'a> {
    pub pid: u32,
    pub kernel_nt_image_path: &'a str,
    pub dos_device_prefix: &'a str,
    pub system_dir: &'a str,
    pub session_id: u32,
    pub signature_valid: bool,
    pub parent_verified_system32_name: Option<&'a str>,
    pub scm_active_service_pid: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct VerifiedTcbTarget {
    pub leaf_exe: String,
    pub disk_exe_path: String,
}

pub(crate) fn verify_tcb_policy(
    input: &TcbVerifyPolicyInput<'_>,
) -> Result<VerifiedTcbTarget, PeerError> {
    if !input.signature_valid {
        return Err(PeerError::Unverifiable(format!(
            "pid {} binary failed Windows Authenticode/Catalog verification",
            input.pid
        )));
    }
    let disk_path = resolve_system32_disk_path(
        input.kernel_nt_image_path,
        input.dos_device_prefix,
        input.system_dir,
    )
    .ok_or_else(|| {
        PeerError::Unverifiable(format!(
            "pid {} image path is outside verified Windows System32 directory",
            input.pid
        ))
    })?;

    let leaf = Path::new(&disk_path)
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    if TRUSTED_SESSION0_SYSTEM32_EXES
        .iter()
        .any(|&allowed| leaf == allowed)
    {
        if input.session_id != 0 {
            return Err(PeerError::Unverifiable(format!(
                "pid {} ({leaf}) running in unexpected session {}",
                input.pid, input.session_id
            )));
        }
        return Ok(VerifiedTcbTarget {
            leaf_exe: leaf,
            disk_exe_path: disk_path,
        });
    }

    if leaf == TRUSTED_WINLOGON_EXE {
        if input.session_id == 0 {
            return Err(PeerError::Unverifiable(format!(
                "pid {} (winlogon.exe) cannot occupy session 0",
                input.pid
            )));
        }
        if !input
            .parent_verified_system32_name
            .is_some_and(|p| p.eq_ignore_ascii_case("smss.exe"))
        {
            return Err(PeerError::Unverifiable(format!(
                "pid {} (winlogon.exe) missing verified System32 smss.exe parent",
                input.pid
            )));
        }
        return Ok(VerifiedTcbTarget {
            leaf_exe: leaf,
            disk_exe_path: disk_path,
        });
    }

    if leaf == TRUSTED_SVCHOST_EXE {
        if input.session_id != 0 {
            return Err(PeerError::Unverifiable(format!(
                "pid {} (svchost.exe) running outside session 0 ({})",
                input.pid, input.session_id
            )));
        }
        if !input
            .parent_verified_system32_name
            .is_some_and(|p| p.eq_ignore_ascii_case("services.exe"))
        {
            return Err(PeerError::Unverifiable(format!(
                "pid {} (svchost.exe) missing verified System32 services.exe parent",
                input.pid
            )));
        }
        if !input.scm_active_service_pid {
            return Err(PeerError::Unverifiable(format!(
                "pid {} (svchost.exe) is not bound to an active SCM Win32 service",
                input.pid
            )));
        }
        return Ok(VerifiedTcbTarget {
            leaf_exe: leaf,
            disk_exe_path: disk_path,
        });
    }

    Err(PeerError::Unverifiable(format!(
        "pid {} ({leaf}) is not an allowed Windows TCB root binary",
        input.pid
    )))
}

pub(crate) fn resolve_system32_disk_path(
    kernel_nt_image_path: &str,
    dos_device_prefix: &str,
    system_dir: &str,
) -> Option<String> {
    let nt = kernel_nt_image_path.trim();
    let sys_norm = system_dir.trim().trim_end_matches(['\\', '/']);
    if nt.is_empty() || sys_norm.len() < 3 {
        return None;
    }
    let drive_split = sys_norm.find(':')?;
    let drive_end = drive_split.checked_add(1)?;
    let sys_tail = sys_norm.get(drive_end..)?.replace('/', "\\");
    if !sys_tail.to_ascii_lowercase().ends_with("\\system32") {
        return None;
    }

    if nt.to_ascii_lowercase().starts_with("\\systemroot\\") {
        let win_root_tail = "\\systemroot\\system32\\";
        if nt.len() <= win_root_tail.len() {
            return None;
        }
        let prefix = nt.get(..win_root_tail.len())?;
        if !prefix.eq_ignore_ascii_case(win_root_tail) {
            return None;
        }
        let leaf = nt.get(win_root_tail.len()..)?;
        if leaf.is_empty() || leaf.contains('\\') || leaf.contains('/') || leaf.contains("..") {
            return None;
        }
        return Some(format!("{sys_norm}\\{leaf}"));
    }

    let dev = dos_device_prefix.trim().trim_end_matches(['\\', '/']);
    if dev.is_empty() {
        return None;
    }
    let expected_prefix = format!("{dev}{sys_tail}\\");
    if nt.len() <= expected_prefix.len() {
        return None;
    }
    let actual_prefix = nt.get(..expected_prefix.len())?;
    if !actual_prefix.eq_ignore_ascii_case(&expected_prefix) {
        return None;
    }
    let leaf = nt.get(expected_prefix.len()..)?;
    if leaf.is_empty() || leaf.contains('\\') || leaf.contains('/') || leaf.contains("..") {
        return None;
    }
    Some(format!("{sys_norm}\\{leaf}"))
}

pub(crate) fn check_parent_start_order(
    parent_started_100ns: u64,
    child_started_100ns: u64,
) -> Result<(), PeerError> {
    if parent_started_100ns == 0 || parent_started_100ns > child_started_100ns {
        return Err(PeerError::PidReuse);
    }
    Ok(())
}

#[cfg(windows)]
pub(crate) fn verify_tcb_process_on_access_denied(
    snap: &BTreeMap<u32, crate::win_proc::SnapshotProcEntry>,
    pid: u32,
) -> Result<(String, u64), PeerError> {
    verify_tcb_live(snap, pid, 0)
}

#[cfg(windows)]
fn verify_tcb_live(
    snap: &BTreeMap<u32, crate::win_proc::SnapshotProcEntry>,
    pid: u32,
    depth: u8,
) -> Result<(String, u64), PeerError> {
    if depth > 2 {
        return Err(PeerError::Unverifiable(
            "Windows TCB parent verification exceeded max depth".to_string(),
        ));
    }
    let started_before = crate::win_tcb_sys::kernel_process_create_time_100ns(pid)?;
    if started_before == 0 {
        return Err(PeerError::Unverifiable(format!(
            "pid {pid} has zero kernel create time"
        )));
    }
    let sys_dir = crate::win_tcb_sys::system32_directory()?;
    let drive_prefix = sys_dir
        .get(..2)
        .ok_or_else(|| PeerError::Unverifiable("invalid Windows System32 path prefix".into()))?;
    let dos_dev = crate::win_tcb_sys::query_dos_device(drive_prefix)?;
    let nt_path = crate::win_tcb_sys::query_kernel_process_image_path(pid)?;
    let session_id = crate::win_tcb_sys::query_process_session_id(pid)?;
    let candidate_disk = resolve_system32_disk_path(&nt_path, &dos_dev, &sys_dir)
        .ok_or_else(|| PeerError::Unverifiable(format!("pid {pid} not in System32")))?;
    crate::win_tcb_trust::ensure_no_reparse_points(&sys_dir, &candidate_disk)?;
    let sig_ok = crate::win_tcb_trust::verify_disk_binary_trusted(&candidate_disk);

    let leaf_lower = Path::new(&candidate_disk)
        .file_name()
        .and_then(|s| s.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();

    let parent_name = if let Some(entry) = snap.get(&pid)
        && matches!(leaf_lower.as_str(), "svchost.exe" | "winlogon.exe")
    {
        if entry.ppid == 0 || entry.ppid == pid {
            None
        } else {
            let (parent_disk, parent_started) =
                verify_tcb_live(snap, entry.ppid, depth.saturating_add(1))?;
            check_parent_start_order(parent_started, started_before)?;
            Path::new(&parent_disk)
                .file_name()
                .and_then(|s| s.to_str())
                .map(str::to_owned)
        }
    } else {
        None
    };

    let scm_ok = if leaf_lower == "svchost.exe" {
        crate::win_tcb_sys::scm_pid_hosts_active_service(pid)
    } else {
        false
    };

    let verified = verify_tcb_policy(&TcbVerifyPolicyInput {
        pid,
        kernel_nt_image_path: &nt_path,
        dos_device_prefix: &dos_dev,
        system_dir: &sys_dir,
        session_id,
        signature_valid: sig_ok,
        parent_verified_system32_name: parent_name.as_deref(),
        scm_active_service_pid: scm_ok,
    })?;

    let started_after = crate::win_tcb_sys::kernel_process_create_time_100ns(pid)?;
    if started_after != started_before {
        return Err(PeerError::PidReuse);
    }
    Ok((verified.disk_exe_path, started_after))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn resolves_only_clean_system32_nt_paths_and_enforces_session_signature_and_scm() {
        assert_eq!(
            resolve_system32_disk_path(
                "\\Device\\HarddiskVolume3\\Windows\\System32\\services.exe",
                "\\Device\\HarddiskVolume3",
                "C:\\Windows\\System32"
            )
            .as_deref(),
            Some("C:\\Windows\\System32\\services.exe")
        );
        assert_eq!(
            resolve_system32_disk_path(
                "\\SystemRoot\\System32\\smss.exe",
                "\\Device\\HarddiskVolume3",
                "C:\\Windows\\System32"
            )
            .as_deref(),
            Some("C:\\Windows\\System32\\smss.exe")
        );

        assert!(
            resolve_system32_disk_path(
                "\\Device\\HarddiskVolume3\\Users\\attacker\\Temp\\services.exe",
                "\\Device\\HarddiskVolume3",
                "C:\\Windows\\System32"
            )
            .is_none()
        );
        assert!(
            resolve_system32_disk_path(
                "\\Device\\HarddiskVolume3\\Windows\\System32\\sub\\services.exe",
                "\\Device\\HarddiskVolume3",
                "C:\\Windows\\System32"
            )
            .is_none()
        );

        let base = TcbVerifyPolicyInput {
            pid: 700,
            kernel_nt_image_path: "\\Device\\HarddiskVolume3\\Windows\\System32\\services.exe",
            dos_device_prefix: "\\Device\\HarddiskVolume3",
            system_dir: "C:\\Windows\\System32",
            session_id: 0,
            signature_valid: true,
            parent_verified_system32_name: None,
            scm_active_service_pid: false,
        };
        assert!(verify_tcb_policy(&base).is_ok());

        let mut unsigned = base.clone();
        unsigned.signature_valid = false;
        assert!(verify_tcb_policy(&unsigned).is_err());

        let mut wrong_session = base.clone();
        wrong_session.session_id = 1;
        assert!(verify_tcb_policy(&wrong_session).is_err());

        let mut svchost = base;
        svchost.kernel_nt_image_path = "\\Device\\HarddiskVolume3\\Windows\\System32\\svchost.exe";
        assert!(verify_tcb_policy(&svchost).is_err());
        svchost.parent_verified_system32_name = Some("services.exe");
        assert!(verify_tcb_policy(&svchost).is_err());
        svchost.scm_active_service_pid = true;
        assert!(verify_tcb_policy(&svchost).is_ok());

        assert!(check_parent_start_order(100, 100).is_ok());
        assert!(check_parent_start_order(100, 250).is_ok());
        assert_eq!(check_parent_start_order(0, 250), Err(PeerError::PidReuse));
        assert_eq!(check_parent_start_order(300, 250), Err(PeerError::PidReuse));
    }

    #[cfg(windows)]
    #[test]
    fn windows_live_kernel_tcb_checks_verify_system32_and_reject_unsigned_fake() {
        let self_pid = std::process::id();
        let kt = crate::win_tcb_sys::kernel_process_create_time_100ns(self_pid)
            .expect("kernel CreateTime for self PID");
        assert!(kt > 0);

        let sys_dir = crate::win_tcb_sys::system32_directory().expect("System32 directory");
        for bin in ["services.exe", "svchost.exe"] {
            let full = format!("{sys_dir}\\{bin}");
            assert!(
                crate::win_tcb_trust::verify_disk_binary_trusted(&full),
                "{full} must pass Authenticode/Catalog + Microsoft OS signer verification"
            );
        }

        let fake_path = std::env::temp_dir().join(format!("services-fake-{self_pid}.exe"));
        std::fs::write(&fake_path, b"MZ-not-signed").expect("write fake binary");
        assert!(
            !crate::win_tcb_trust::verify_disk_binary_trusted(&fake_path.to_string_lossy()),
            "unsigned fake binary must fail WinVerifyTrust"
        );
        let _ = std::fs::remove_file(&fake_path);

        let self_exe = std::env::current_exe().expect("current test executable");
        assert!(
            !crate::win_tcb_trust::verify_disk_binary_trusted(&self_exe.to_string_lossy()),
            "test executable must fail Microsoft OS TCB signer pinning"
        );

        let third_party_candidates = [
            "C:\\Program Files\\Git\\cmd\\git.exe",
            "C:\\Program Files\\nodejs\\node.exe",
        ];
        for candidate in third_party_candidates {
            if std::path::Path::new(candidate).exists() {
                assert!(
                    !crate::win_tcb_trust::verify_disk_binary_trusted(candidate),
                    "third-party signed binary {candidate} must fail Microsoft OS TCB signer pinning"
                );
            }
        }
    }
}
