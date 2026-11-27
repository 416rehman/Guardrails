// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod decision;
pub mod fs_open;
pub mod local_fs;
pub mod path_check;
mod scm_probe;
pub mod unix_path;
pub mod unix_peer;
#[cfg(windows)]
mod win_acl;
pub mod win_peer;
#[cfg(windows)]
mod win_proc;
#[cfg(windows)]
mod win_token;
#[cfg(windows)]
mod win_toolhelp;

use std::collections::BTreeSet;
use std::path::Path;

use grdr_model::CodedError;

pub use decision::{
    ExeIdentity, MacOsAuditToken, OwnerClass, ParentChainNode, PeerAuthDecision, PeerAuthPolicy,
    PeerCredentials, PeerEvidence, PeerObservation, PeerRefusal, PrincipalPolicy, ProcessHold,
    ProcessKey, ServiceProcessCheck, UnixPeerCreds, VerifiedPeer, WindowsPipePeer,
    evaluate_peer_auth,
};
pub use local_fs::OsLocalFs;
pub use path_check::{
    PathCheckOutcome, PathEntryType, PathNodeKind, PathWalkNode, inspect_filesystem_ancestors,
    verify_unix_path_nodes,
};

pub const CODE_PEER_PATH_FOREIGN: &str = "GRDR-PEER-0001";
pub const CODE_PEER_PATH_UNSAFE: &str = "GRDR-PEER-0002";
pub const CODE_PEER_SERVER_FOREIGN: &str = "GRDR-PEER-0003";
pub const CODE_PEER_SERVICE_RESTARTING: &str = "GRDR-PEER-0004";
pub const CODE_PEER_UNVERIFIABLE: &str = "GRDR-PEER-0005";
pub const CODE_PEER_PID_REUSE: &str = "GRDR-PEER-0006";
pub const MAX_PARENT_CHAIN_DEPTH: usize = 256;
const PROC_STAT_STARTTIME_OFFSET_AFTER_COMM: usize = 19;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum PeerError {
    #[error("GRDR-PEER-0001: endpoint ancestor owned by foreign principal")]
    PathForeign,
    #[error("GRDR-PEER-0002: endpoint path traversal unsafe: {0}")]
    PathUnsafe(String),
    #[error("GRDR-PEER-0003: server principal does not match expected owner")]
    ServerForeign,
    #[error("GRDR-PEER-0004: target Windows service is restarting")]
    ServiceRestarting,
    #[error("GRDR-PEER-0005: peer identity unverifiable: {0}")]
    Unverifiable(String),
    #[error("GRDR-PEER-0006: process start time indicates PID reuse")]
    PidReuse,
}

pub trait PeerReader: Send + Sync {
    fn read_peer(&self, pid: u32) -> Result<PeerObservation, PeerError>;
    fn read_exe_identity(&self, pid: u32) -> Result<ExeIdentity, PeerError>;
    fn read_parent_chain(
        &self,
        pid: u32,
        max_depth: usize,
    ) -> Result<Vec<ParentChainNode>, PeerError>;
    fn check_endpoint_path(
        &self,
        socket_path: &Path,
        expected_uid: u32,
        trusted_groups: &[u32],
    ) -> PathCheckOutcome;
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct OsProcessSnapshotEntry {
    pub pid: u32,
    pub parent_pid: u32,
    pub image_name: String,
    pub executable_path: Option<String>,
    pub session_id: Option<u32>,
    pub started_100ns: u64,
}

#[derive(Debug, Clone, Copy, Default)]
pub struct OsPeerReader;

#[cfg(windows)]
pub fn enumerate_windows_processes() -> Result<Vec<OsProcessSnapshotEntry>, PeerError> {
    win_toolhelp::enumerate_windows_processes_native()
}

#[cfg(not(windows))]
pub fn enumerate_windows_processes() -> Result<Vec<OsProcessSnapshotEntry>, PeerError> {
    Err(PeerError::Unverifiable(
        "native Windows process snapshot is only available on Windows hosts".to_owned(),
    ))
}

impl From<PeerError> for CodedError {
    fn from(err: PeerError) -> Self {
        let code = match &err {
            PeerError::PathForeign => CODE_PEER_PATH_FOREIGN,
            PeerError::PathUnsafe(_) => CODE_PEER_PATH_UNSAFE,
            PeerError::ServerForeign => CODE_PEER_SERVER_FOREIGN,
            PeerError::ServiceRestarting => CODE_PEER_SERVICE_RESTARTING,
            PeerError::Unverifiable(_) => CODE_PEER_UNVERIFIABLE,
            PeerError::PidReuse => CODE_PEER_PID_REUSE,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify endpoint directory ownership and peer kernel credentials.",
        )
    }
}

impl PeerReader for OsPeerReader {
    fn read_peer(&self, pid: u32) -> Result<PeerObservation, PeerError> {
        read_os_peer_observation(pid)
    }

    fn read_exe_identity(&self, pid: u32) -> Result<ExeIdentity, PeerError> {
        read_os_exe_identity(pid)
    }

    fn read_parent_chain(
        &self,
        pid: u32,
        max_depth: usize,
    ) -> Result<Vec<ParentChainNode>, PeerError> {
        collect_parent_chain(self, pid, max_depth)
    }

    fn check_endpoint_path(
        &self,
        socket_path: &Path,
        expected_uid: u32,
        trusted_groups: &[u32],
    ) -> PathCheckOutcome {
        #[cfg(unix)]
        {
            match inspect_filesystem_ancestors(socket_path) {
                Ok(nodes) => verify_unix_path_nodes(&nodes, expected_uid, None, trusted_groups),
                Err(err) => PathCheckOutcome::Unsafe {
                    node: PathNodeKind::Socket,
                    reason: err.to_string(),
                },
            }
        }
        #[cfg(not(unix))]
        {
            let _ = (socket_path, expected_uid, trusted_groups);
            PathCheckOutcome::NoPath
        }
    }
}

pub fn collect_parent_chain(
    reader: &dyn PeerReader,
    pid: u32,
    max_depth: usize,
) -> Result<Vec<ParentChainNode>, PeerError> {
    if max_depth == 0 || max_depth > MAX_PARENT_CHAIN_DEPTH {
        return Err(PeerError::Unverifiable(format!(
            "parent chain max_depth {max_depth} must be in 1..={MAX_PARENT_CHAIN_DEPTH}"
        )));
    }
    let mut chain = Vec::new();
    let mut seen_pids = BTreeSet::new();
    let mut current = pid;
    let mut child_started_at: Option<u64> = None;

    for _ in 0..max_depth {
        if current == 0 {
            break;
        }
        if !seen_pids.insert(current) {
            return Err(PeerError::PidReuse);
        }
        let obs = reader.read_peer(current)?;
        if let Some(child_start) = child_started_at
            && obs.started_at_ticks > child_start
        {
            return Err(PeerError::PidReuse);
        }
        let parent_pid = obs.parent_pid;
        chain.push(ParentChainNode {
            pid: current,
            ppid: parent_pid,
            exe_path: obs.exe.as_ref().and_then(|e| e.exe_path.clone()),
            started_at_ticks: obs.started_at_ticks,
        });
        child_started_at = Some(obs.started_at_ticks);
        if parent_pid == 0 {
            break;
        }
        if parent_pid == current {
            if current == 1 {
                break;
            }
            return Err(PeerError::PidReuse);
        }
        current = parent_pid;
    }
    Ok(chain)
}

#[cfg(target_os = "linux")]
fn read_os_peer_observation(pid: u32) -> Result<PeerObservation, PeerError> {
    let dir = Path::new("/proc").join(pid.to_string());
    let stat_before = std::fs::read_to_string(dir.join("stat"))
        .map_err(|e| PeerError::Unverifiable(format!("cannot read /proc/{pid}/stat: {e}")))?;
    let start_before = parse_proc_stat_starttime(&stat_before).ok_or_else(|| {
        PeerError::Unverifiable(format!("missing or invalid starttime in /proc/{pid}/stat"))
    })?;
    let status = std::fs::read_to_string(dir.join("status"))
        .map_err(|e| PeerError::Unverifiable(format!("cannot read /proc/{pid}/status: {e}")))?;
    let exe_path = std::fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| p.display().to_string());
    let stat_after = std::fs::read_to_string(dir.join("stat"))
        .map_err(|e| PeerError::Unverifiable(format!("cannot re-read /proc/{pid}/stat: {e}")))?;
    if parse_proc_stat_starttime(&stat_after) != Some(start_before) {
        return Err(PeerError::PidReuse);
    }
    parse_linux_proc_observation(pid, &status, &stat_after, exe_path)
}

#[cfg(target_os = "linux")]
fn read_os_exe_identity(pid: u32) -> Result<ExeIdentity, PeerError> {
    let exe = std::fs::read_link(format!("/proc/{pid}/exe"))
        .map_err(|e| PeerError::Unverifiable(format!("cannot read /proc/{pid}/exe: {e}")))?;
    Ok(ExeIdentity {
        exe_path: Some(exe.display().to_string()),
        signer_team_id: None,
        signing_id: None,
    })
}

#[cfg(target_os = "macos")]
fn read_os_peer_observation(pid: u32) -> Result<PeerObservation, PeerError> {
    unix_peer::read_macos_peer_observation(pid)
}

#[cfg(target_os = "macos")]
fn read_os_exe_identity(pid: u32) -> Result<ExeIdentity, PeerError> {
    unix_peer::read_macos_exe_identity(pid)
}

#[cfg(target_os = "windows")]
fn read_os_peer_observation(pid: u32) -> Result<PeerObservation, PeerError> {
    win_proc::read_windows_peer_observation(pid)
}

#[cfg(target_os = "windows")]
fn read_os_exe_identity(pid: u32) -> Result<ExeIdentity, PeerError> {
    win_proc::read_windows_exe_identity(pid)
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn read_os_peer_observation(pid: u32) -> Result<PeerObservation, PeerError> {
    Err(PeerError::Unverifiable(format!(
        "kernel peer handle reader for pid {pid} requires a Tier-1 OS backend"
    )))
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
fn read_os_exe_identity(pid: u32) -> Result<ExeIdentity, PeerError> {
    Err(PeerError::Unverifiable(format!(
        "executable identity lookup for pid {pid} requires a Tier-1 OS backend"
    )))
}

pub fn parse_linux_proc_observation(
    pid: u32,
    status_raw: &str,
    stat_raw: &str,
    exe_path: Option<String>,
) -> Result<PeerObservation, PeerError> {
    if pid == 0 {
        return Err(PeerError::Unverifiable(
            "pid 0 is invalid for peer inspection".into(),
        ));
    }
    let mut ppid: Option<u32> = None;
    let mut uid: Option<u32> = None;
    let mut gid: Option<u32> = None;
    for line in status_raw.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            let parsed = rest.trim().parse::<u32>().map_err(|e| {
                PeerError::Unverifiable(format!("invalid PPid in /proc/{pid}/status: {e}"))
            })?;
            ppid = Some(parsed);
        } else if let Some(rest) = line.strip_prefix("Uid:") {
            // /proc/<pid>/status lists real, effective, saved-set, fs UID; use effective UID (index 1).
            let effective = rest.split_whitespace().nth(1).ok_or_else(|| {
                PeerError::Unverifiable(format!("missing effective Uid in /proc/{pid}/status"))
            })?;
            let parsed = effective.parse::<u32>().map_err(|e| {
                PeerError::Unverifiable(format!("invalid Uid in /proc/{pid}/status: {e}"))
            })?;
            uid = Some(parsed);
        } else if let Some(rest) = line.strip_prefix("Gid:") {
            let effective = rest.split_whitespace().nth(1).ok_or_else(|| {
                PeerError::Unverifiable(format!("missing effective Gid in /proc/{pid}/status"))
            })?;
            let parsed = effective.parse::<u32>().map_err(|e| {
                PeerError::Unverifiable(format!("invalid Gid in /proc/{pid}/status: {e}"))
            })?;
            gid = Some(parsed);
        }
    }

    let ppid =
        ppid.ok_or_else(|| PeerError::Unverifiable(format!("missing PPid in /proc/{pid}/status")))?;
    let uid =
        uid.ok_or_else(|| PeerError::Unverifiable(format!("missing Uid in /proc/{pid}/status")))?;
    let gid =
        gid.ok_or_else(|| PeerError::Unverifiable(format!("missing Gid in /proc/{pid}/status")))?;
    let started_at_ticks = parse_proc_stat_starttime(stat_raw).ok_or_else(|| {
        PeerError::Unverifiable(format!("missing or invalid starttime in /proc/{pid}/stat"))
    })?;

    Ok(PeerObservation {
        credentials: PeerCredentials::Linux(UnixPeerCreds {
            uid,
            gid,
            pid,
            pidfd_verified: false,
        }),
        hold: ProcessHold::Unheld,
        parent_pid: ppid,
        started_at_ticks,
        exe: Some(ExeIdentity {
            exe_path,
            signer_team_id: None,
            signing_id: None,
        }),
    })
}

fn parse_proc_stat_starttime(stat_raw: &str) -> Option<u64> {
    let rparen = stat_raw.rfind(')')?;
    let after = stat_raw.get(rparen.saturating_add(1)..)?;
    let fields: Vec<&str> = after.split_whitespace().collect();
    fields
        .get(PROC_STAT_STARTTIME_OFFSET_AFTER_COMM)?
        .parse::<u64>()
        .ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    struct MockProcChainReader {
        entries: BTreeMap<u32, PeerObservation>,
    }

    impl PeerReader for MockProcChainReader {
        fn read_peer(&self, pid: u32) -> Result<PeerObservation, PeerError> {
            self.entries
                .get(&pid)
                .cloned()
                .ok_or_else(|| PeerError::Unverifiable("missing pid".into()))
        }

        fn read_exe_identity(&self, _pid: u32) -> Result<ExeIdentity, PeerError> {
            Err(PeerError::Unverifiable("unused".into()))
        }

        fn read_parent_chain(
            &self,
            pid: u32,
            max_depth: usize,
        ) -> Result<Vec<ParentChainNode>, PeerError> {
            collect_parent_chain(self, pid, max_depth)
        }

        fn check_endpoint_path(
            &self,
            _socket_path: &Path,
            _expected_uid: u32,
            _trusted_groups: &[u32],
        ) -> PathCheckOutcome {
            PathCheckOutcome::NoPath
        }
    }

    #[test]
    fn parses_linux_proc_fail_closed_without_root_default_or_unheld_escalation() {
        let status =
            "Name:\tclaude\nPPid:\t1200\nUid:\t1000\t0\t0\t0\nGid:\t1000\t1000\t1000\t1000\n";
        let stat = "2048 (claude) S 1200 2048 2048 0 -1 4194304 100 0 0 0 1 0 0 0 20 0 1 0 987654 1024 100";
        let obs =
            parse_linux_proc_observation(2048, status, stat, Some("/usr/local/bin/claude".into()))
                .unwrap();
        assert_eq!(obs.parent_pid, 1200);
        assert_eq!(obs.started_at_ticks, 987_654);
        assert_eq!(obs.hold, ProcessHold::Unheld);
        assert!(matches!(
            obs.credentials,
            PeerCredentials::Linux(UnixPeerCreds {
                uid: 0,
                pidfd_verified: false,
                ..
            })
        ));

        let missing_uid = "Name:\tclaude\nPPid:\t1200\nGid:\t1000\n";
        assert!(matches!(
            parse_linux_proc_observation(2048, missing_uid, stat, None),
            Err(PeerError::Unverifiable(_))
        ));

        let truncated_stat = "2048 (claude) S 1200";
        assert!(matches!(
            parse_linux_proc_observation(2048, status, truncated_stat, None),
            Err(PeerError::Unverifiable(_))
        ));
    }

    #[test]
    fn detects_parent_chain_cycles_and_parent_pid_reuse() {
        let mut entries = BTreeMap::new();
        entries.insert(
            200,
            PeerObservation {
                credentials: PeerCredentials::Linux(UnixPeerCreds {
                    uid: 1000,
                    gid: 1000,
                    pid: 200,
                    pidfd_verified: true,
                }),
                hold: ProcessHold::Unheld,
                parent_pid: 100,
                started_at_ticks: 500,
                exe: None,
            },
        );
        entries.insert(
            100,
            PeerObservation {
                credentials: PeerCredentials::Linux(UnixPeerCreds {
                    uid: 1000,
                    gid: 1000,
                    pid: 100,
                    pidfd_verified: true,
                }),
                hold: ProcessHold::Unheld,
                parent_pid: 200,
                started_at_ticks: 900,
                exe: None,
            },
        );
        let reader = MockProcChainReader { entries };
        assert_eq!(
            collect_parent_chain(&reader, 200, 8),
            Err(PeerError::PidReuse)
        );

        let mut equal_start_cycle = BTreeMap::new();
        equal_start_cycle.insert(
            300,
            PeerObservation {
                credentials: PeerCredentials::Linux(UnixPeerCreds {
                    uid: 1000,
                    gid: 1000,
                    pid: 300,
                    pidfd_verified: true,
                }),
                hold: ProcessHold::Unheld,
                parent_pid: 300,
                started_at_ticks: 500,
                exe: None,
            },
        );
        let reader2 = MockProcChainReader {
            entries: equal_start_cycle,
        };
        assert_eq!(
            collect_parent_chain(&reader2, 300, 8),
            Err(PeerError::PidReuse)
        );
        assert!(matches!(
            collect_parent_chain(&reader2, 300, MAX_PARENT_CHAIN_DEPTH.saturating_add(1)),
            Err(PeerError::Unverifiable(_))
        ));
    }
}
