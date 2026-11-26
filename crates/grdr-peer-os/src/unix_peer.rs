// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Unix domain peer credential readers (`SO_PEERCRED`/`SO_PEERPIDFD` on Linux,
//! `LOCAL_PEERTOKEN`/`getpeereid` on macOS) and root-down `openat`/`fstatat` path checks.

use grdr_wire::peer_auth::UnixPeerClaims;

pub use crate::unix_path::{
    current_effective_ids, inspect_unix_directory_live, inspect_unix_path_live,
    refresh_unix_directory_post_check, refresh_unix_path_post_connect,
};

use crate::PeerError;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UnixConnectStamp {
    pub boot_uptime_ms: u64,
    pub wall_unix_us: u64,
}

#[derive(Debug)]
pub struct UnixPeerHold {
    pub claims: UnixPeerClaims,
    #[cfg(unix)]
    _pidfd: Option<std::os::fd::OwnedFd>,
}

impl UnixConnectStamp {
    #[must_use]
    pub const fn for_platform(self) -> u64 {
        #[cfg(target_os = "macos")]
        {
            self.wall_unix_us
        }
        #[cfg(not(target_os = "macos"))]
        {
            self.boot_uptime_ms
        }
    }
}

#[cfg(unix)]
pub fn read_unix_socket_peer(
    fd: std::os::fd::BorrowedFd<'_>,
    stamp: UnixConnectStamp,
) -> Result<UnixPeerHold, PeerError> {
    use std::os::fd::AsRawFd;
    read_platform_unix_peer(fd.as_raw_fd(), stamp)
}

#[cfg(not(unix))]
pub fn read_unix_socket_peer(_stamp: UnixConnectStamp) -> Result<UnixPeerHold, PeerError> {
    Err(PeerError::Unverifiable(
        "unix peer credentials unavailable on non-unix host".to_string(),
    ))
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "SO_PEERCRED, SO_PEERPIDFD, pidfd_open, and sysconf(_SC_CLK_TCK) FFI"
)]
fn read_platform_unix_peer(
    raw_fd: libc::c_int,
    stamp: UnixConnectStamp,
) -> Result<UnixPeerHold, PeerError> {
    use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};

    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    const SO_PEERPIDFD: libc::c_int = 77;

    let mut cred = libc::ucred {
        pid: 0,
        uid: u32::MAX,
        gid: u32::MAX,
    };
    let expected_cred_len = std::mem::size_of::<libc::ucred>();
    let mut len = u32::try_from(expected_cred_len).unwrap_or(0);
    // SAFETY: `cred` points to stack storage of exact `socklen_t` size for `SOL_SOCKET` `SO_PEERCRED`.
    let rc = unsafe {
        libc::getsockopt(
            raw_fd,
            libc::SOL_SOCKET,
            libc::SO_PEERCRED,
            (&raw mut cred).cast::<libc::c_void>(),
            &mut len,
        )
    };
    if rc != 0
        || usize::try_from(len).ok() != Some(expected_cred_len)
        || cred.pid <= 0
        || cred.uid == u32::MAX
        || cred.gid == u32::MAX
    {
        return Err(PeerError::Unverifiable(format!(
            "SO_PEERCRED failed or returned invalid credentials: {}",
            std::io::Error::last_os_error()
        )));
    }

    let peer_pid = u32::try_from(cred.pid)
        .map_err(|_| PeerError::Unverifiable("negative peer pid".to_string()))?;

    let mut owned_pidfd: Option<OwnedFd> = None;
    #[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
    {
        let mut pidfd_raw: libc::c_int = -1;
        let expected_pidfd_len = std::mem::size_of::<libc::c_int>();
        let mut pidfd_len = u32::try_from(expected_pidfd_len).unwrap_or(0);
        // SAFETY: `pidfd_raw` is stack `c_int` sized for `SO_PEERPIDFD`.
        let pidfd_rc = unsafe {
            libc::getsockopt(
                raw_fd,
                libc::SOL_SOCKET,
                SO_PEERPIDFD,
                (&raw mut pidfd_raw).cast::<libc::c_void>(),
                &mut pidfd_len,
            )
        };
        if pidfd_rc == 0
            && pidfd_raw >= 0
            && usize::try_from(pidfd_len).ok() == Some(expected_pidfd_len)
        {
            // SAFETY: kernel `getsockopt(SO_PEERPIDFD)` returned a freshly opened fd owned here.
            owned_pidfd = Some(unsafe { OwnedFd::from_raw_fd(pidfd_raw) });
        }
    }
    if owned_pidfd.is_none() {
        // SAFETY: `SYS_pidfd_open` is invoked with validated positive PID and flags = 0.
        let opened = unsafe { libc::syscall(libc::SYS_pidfd_open, cred.pid, 0 as libc::c_uint) };
        if opened >= 0 {
            let fd_num = libc::c_int::try_from(opened).unwrap_or(-1);
            if fd_num >= 0 {
                // SAFETY: `pidfd_open` returned a valid non-negative fd owned exclusively here.
                owned_pidfd = Some(unsafe { OwnedFd::from_raw_fd(fd_num) });
            }
        }
    }

    let Some(ref pfd) = owned_pidfd else {
        return Err(PeerError::Unverifiable(
            "kernel pidfd unavailable for Unix peer".to_string(),
        ));
    };

    let proc_stat = std::fs::read_to_string(format!("/proc/{peer_pid}/stat"))
        .map_err(|_| PeerError::PidReuse)?;
    let proc_status = std::fs::read_to_string(format!("/proc/{peer_pid}/status"))
        .map_err(|_| PeerError::PidReuse)?;
    let obs = crate::parse_linux_proc_observation(peer_pid, &proc_status, &proc_stat, None)?;
    if let crate::PeerCredentials::Linux(linux_creds) = &obs.credentials
        && (linux_creds.uid != cred.uid || linux_creds.gid != cred.gid)
    {
        return Err(PeerError::PidReuse);
    }

    // SAFETY: `sysconf(_SC_CLK_TCK)` takes a static POSIX constant with no pointers.
    let clk_tck = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    let clk_tck_u64 = u64::try_from(clk_tck)
        .ok()
        .filter(|&v| v > 0)
        .ok_or_else(|| PeerError::Unverifiable("invalid sysconf(_SC_CLK_TCK)".to_string()))?;
    let started_ms = obs
        .started_at_ticks
        .saturating_mul(1_000)
        .checked_div(clk_tck_u64)
        .ok_or_else(|| PeerError::Unverifiable("zero clock tick divisor".to_string()))?;
    if started_ms == 0 || stamp.boot_uptime_ms == 0 || started_ms > stamp.boot_uptime_ms {
        return Err(PeerError::PidReuse);
    }

    // Verify pidfd AFTER reading /proc/<pid> stat+status so PID reap/reuse between reads is caught.
    let fdinfo_path = format!("/proc/self/fdinfo/{}", pfd.as_raw_fd());
    let fdinfo = std::fs::read_to_string(&fdinfo_path)
        .map_err(|err| PeerError::Unverifiable(format!("failed reading {fdinfo_path}: {err}")))?;
    let pid_matches = fdinfo
        .lines()
        .find_map(|line| line.strip_prefix("Pid:\t"))
        .and_then(|val| val.trim().parse::<u32>().ok())
        == Some(peer_pid);
    if !pid_matches {
        return Err(PeerError::PidReuse);
    }

    Ok(UnixPeerHold {
        claims: UnixPeerClaims {
            uid: cred.uid,
            gid: cred.gid,
            pid: Some(peer_pid),
            has_pidfd: true,
            peer_started_at_ticks: Some(started_ms),
            local_peertoken_verified: false,
        },
        _pidfd: owned_pidfd,
    })
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "getpeereid, LOCAL_PEERTOKEN audit_token_t, and proc_pidinfo FFI"
)]
fn read_platform_unix_peer(
    raw_fd: libc::c_int,
    stamp: UnixConnectStamp,
) -> Result<UnixPeerHold, PeerError> {
    const SOL_LOCAL: libc::c_int = 0;
    const LOCAL_PEERTOKEN: libc::c_int = 6;

    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: valid pointers to stack `uid_t` and `gid_t` for `getpeereid`.
    if unsafe { libc::getpeereid(raw_fd, &mut uid, &mut gid) } != 0
        || uid == u32::MAX
        || gid == u32::MAX
    {
        return Err(PeerError::Unverifiable(format!(
            "getpeereid failed: {}",
            std::io::Error::last_os_error()
        )));
    }

    let mut token = [0u32; 8];
    let expected_tok_len = std::mem::size_of::<[u32; 8]>();
    let mut tok_len = u32::try_from(expected_tok_len).unwrap_or(0);
    // SAFETY: `token` buffer matches `audit_token_t` size for `LOCAL_PEERTOKEN`.
    let tok_rc = unsafe {
        libc::getsockopt(
            raw_fd,
            SOL_LOCAL,
            LOCAL_PEERTOKEN,
            token.as_mut_ptr().cast::<libc::c_void>(),
            &mut tok_len,
        )
    };
    if tok_rc != 0 || usize::try_from(tok_len).ok() != Some(expected_tok_len) {
        return Err(PeerError::Unverifiable(format!(
            "LOCAL_PEERTOKEN failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let [_, euid, egid, _, _, pid_raw, _, pidversion] = token;
    if euid != uid || egid != gid || pid_raw == 0 || pidversion == 0 {
        return Err(PeerError::Unverifiable(
            "LOCAL_PEERTOKEN identity tuple mismatch against getpeereid".to_string(),
        ));
    }
    let pid_i32 = libc::c_int::try_from(pid_raw)
        .map_err(|_| PeerError::Unverifiable("invalid LOCAL_PEERTOKEN pid".to_string()))?;

    // SAFETY: `proc_bsdinfo` is a C POD struct valid under zero-initialization before `proc_pidinfo`.
    let mut bsd: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let bsd_sz = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).unwrap_or(0);
    // SAFETY: `bsd` is stack storage sized to `proc_bsdinfo` for `PROC_PIDTBSDINFO`.
    let got = unsafe {
        libc::proc_pidinfo(
            pid_i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut bsd).cast::<libc::c_void>(),
            bsd_sz,
        )
    };
    let mut started_us: Option<u64> = None;
    if got == bsd_sz {
        if bsd.pbi_uid != uid {
            return Err(PeerError::PidReuse);
        }
        let us = bsd
            .pbi_start_tvsec
            .saturating_mul(1_000_000)
            .saturating_add(bsd.pbi_start_tvusec);
        if us == 0 || stamp.wall_unix_us == 0 || us > stamp.wall_unix_us {
            return Err(PeerError::PidReuse);
        }
        started_us = Some(us);
    } else {
        let os_err = std::io::Error::last_os_error().raw_os_error();
        if !(os_err == Some(libc::EPERM) && uid == 0) {
            return Err(PeerError::Unverifiable(format!(
                "proc_pidinfo(PROC_PIDTBSDINFO) failed: {}",
                std::io::Error::last_os_error()
            )));
        }
    }

    Ok(UnixPeerHold {
        claims: UnixPeerClaims {
            uid,
            gid,
            pid: Some(pid_raw),
            has_pidfd: false,
            peer_started_at_ticks: started_us,
            local_peertoken_verified: true,
        },
        _pidfd: None,
    })
}

#[cfg(target_os = "macos")]
#[allow(
    unsafe_code,
    reason = "macOS proc_pidinfo(PROC_PIDTBSDINFO) and proc_pidpath parent-chain lookup"
)]
pub(crate) fn read_macos_peer_observation(pid: u32) -> Result<crate::PeerObservation, PeerError> {
    use crate::{ExeIdentity, MacOsAuditToken, PeerCredentials, PeerObservation, ProcessHold};

    let pid_i32 = libc::c_int::try_from(pid)
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| PeerError::Unverifiable(format!("invalid macOS pid {pid}")))?;

    // SAFETY: `proc_bsdinfo` is a C POD struct valid under zero-initialization before `proc_pidinfo`.
    let mut bsd: libc::proc_bsdinfo = unsafe { std::mem::zeroed() };
    let bsd_sz = libc::c_int::try_from(std::mem::size_of::<libc::proc_bsdinfo>()).unwrap_or(0);
    // SAFETY: `bsd` is stack storage sized to `proc_bsdinfo` for `PROC_PIDTBSDINFO`.
    let got = unsafe {
        libc::proc_pidinfo(
            pid_i32,
            libc::PROC_PIDTBSDINFO,
            0,
            (&raw mut bsd).cast::<libc::c_void>(),
            bsd_sz,
        )
    };
    if got != bsd_sz {
        let os_err = std::io::Error::last_os_error();
        if pid == 1 && os_err.raw_os_error() == Some(libc::EPERM) {
            return Ok(PeerObservation {
                credentials: PeerCredentials::MacOs(MacOsAuditToken {
                    uid: 0,
                    gid: 0,
                    pid: 1,
                    pidversion: 0,
                    audit_session_id: 0,
                }),
                hold: ProcessHold::Unheld,
                parent_pid: 0,
                started_at_ticks: 1,
                exe: Some(ExeIdentity {
                    exe_path: None,
                    signer_team_id: None,
                    signing_id: None,
                }),
            });
        }
        return Err(PeerError::Unverifiable(format!(
            "proc_pidinfo(PROC_PIDTBSDINFO, {pid}) failed: {os_err}"
        )));
    }
    let started_us = bsd
        .pbi_start_tvsec
        .saturating_mul(1_000_000)
        .saturating_add(bsd.pbi_start_tvusec);
    if started_us == 0 {
        return Err(PeerError::Unverifiable(format!(
            "missing start timestamp for macOS pid {pid}"
        )));
    }
    let exe_path = query_macos_proc_path(pid_i32).ok();
    Ok(PeerObservation {
        credentials: PeerCredentials::MacOs(MacOsAuditToken {
            uid: bsd.pbi_uid,
            gid: bsd.pbi_gid,
            pid,
            pidversion: 0,
            audit_session_id: 0,
        }),
        hold: ProcessHold::Unheld,
        parent_pid: bsd.pbi_ppid,
        started_at_ticks: started_us,
        exe: Some(ExeIdentity {
            exe_path,
            signer_team_id: None,
            signing_id: None,
        }),
    })
}

#[cfg(target_os = "macos")]
pub(crate) fn read_macos_exe_identity(pid: u32) -> Result<crate::ExeIdentity, PeerError> {
    let pid_i32 = libc::c_int::try_from(pid)
        .ok()
        .filter(|&p| p > 0)
        .ok_or_else(|| PeerError::Unverifiable(format!("invalid macOS pid {pid}")))?;
    let exe_path = query_macos_proc_path(pid_i32)?;
    Ok(crate::ExeIdentity {
        exe_path: Some(exe_path),
        signer_team_id: None,
        signing_id: None,
    })
}

#[cfg(target_os = "macos")]
#[allow(unsafe_code, reason = "macOS proc_pidpath bounded path lookup")]
fn query_macos_proc_path(pid_i32: libc::c_int) -> Result<String, PeerError> {
    let cap = usize::try_from(libc::PROC_PIDPATHINFO_MAXSIZE).unwrap_or(4096);
    let mut buf = vec![0u8; cap];
    let buf_sz = u32::try_from(buf.len()).unwrap_or(4096);
    let rc = {
        // SAFETY: `buf` is zeroed byte storage of length `buf_sz` valid for `proc_pidpath`.
        unsafe { libc::proc_pidpath(pid_i32, buf.as_mut_ptr().cast::<libc::c_void>(), buf_sz) }
    };
    if rc <= 0 {
        return Err(PeerError::Unverifiable(format!(
            "proc_pidpath({pid_i32}) failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    let len = usize::try_from(rc)
        .ok()
        .filter(|&n| n <= buf.len())
        .ok_or_else(|| PeerError::Unverifiable("invalid proc_pidpath byte length".to_string()))?;
    let bytes = buf.get(..len).unwrap_or(&[]);
    let nul = bytes.iter().position(|&b| b == 0).unwrap_or(bytes.len());
    String::from_utf8(bytes.get(..nul).unwrap_or(&[]).to_vec())
        .map_err(|e| PeerError::Unverifiable(format!("non-UTF8 proc_pidpath: {e}")))
}

#[cfg(all(unix, not(any(target_os = "linux", target_os = "macos"))))]
#[allow(unsafe_code, reason = "POSIX getpeereid fallback on generic Unix")]
fn read_platform_unix_peer(
    raw_fd: libc::c_int,
    _stamp: UnixConnectStamp,
) -> Result<UnixPeerHold, PeerError> {
    let mut uid: libc::uid_t = u32::MAX;
    let mut gid: libc::gid_t = u32::MAX;
    // SAFETY: stack `uid_t` and `gid_t` pointers passed to `getpeereid`.
    if unsafe { libc::getpeereid(raw_fd, &mut uid, &mut gid) } != 0 {
        return Err(PeerError::Unverifiable(format!(
            "getpeereid failed: {}",
            std::io::Error::last_os_error()
        )));
    }
    Ok(UnixPeerHold {
        claims: UnixPeerClaims {
            uid,
            gid,
            pid: None,
            has_pidfd: false,
            peer_started_at_ticks: None,
            local_peertoken_verified: false,
        },
        _pidfd: None,
    })
}
