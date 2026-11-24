// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod decision;
pub mod path_check;

use std::path::Path;

use grdr_model::CodedError;

pub use decision::{
    ExeIdentity, MacOsAuditToken, OwnerClass, ParentChainNode, PeerAuthDecision, PeerAuthPolicy,
    PeerCredentials, PeerEvidence, PeerObservation, PeerRefusal, ProcessHold, ProcessKey,
    ServiceProcessCheck, UnixPeerCreds, VerifiedPeer, WindowsPipePeer, evaluate_peer_auth,
};
pub use path_check::{
    PathCheckOutcome, PathNodeKind, PathWalkNode, inspect_filesystem_ancestors,
    verify_unix_path_nodes,
};

pub const CODE_PEER_PATH_FOREIGN: &str = "GRDR-PEER-0001";
pub const CODE_PEER_PATH_UNSAFE: &str = "GRDR-PEER-0002";
pub const CODE_PEER_SERVER_FOREIGN: &str = "GRDR-PEER-0003";
pub const CODE_PEER_SERVICE_RESTARTING: &str = "GRDR-PEER-0004";
pub const CODE_PEER_UNVERIFIABLE: &str = "GRDR-PEER-0005";
pub const CODE_PEER_PID_REUSE: &str = "GRDR-PEER-0006";

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

#[derive(Debug, Clone, Copy, Default)]
pub struct OsPeerReader;

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
        let mut chain = Vec::new();
        let mut current = pid;
        for _ in 0..max_depth {
            if current == 0 {
                break;
            }
            let obs = self.read_peer(current)?;
            let parent_pid = obs.parent_pid;
            chain.push(ParentChainNode {
                pid: current,
                ppid: parent_pid,
                exe_path: obs.exe.as_ref().and_then(|e| e.exe_path.clone()),
                started_at_ticks: obs.started_at_ticks,
            });
            if parent_pid == 0 || parent_pid == current {
                break;
            }
            current = parent_pid;
        }
        Ok(chain)
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

#[cfg(target_os = "linux")]
fn read_os_peer_observation(pid: u32) -> Result<PeerObservation, PeerError> {
    let dir = Path::new("/proc").join(pid.to_string());
    let status = std::fs::read_to_string(dir.join("status"))
        .map_err(|e| PeerError::Unverifiable(format!("cannot read /proc/{pid}/status: {e}")))?;
    let stat = std::fs::read_to_string(dir.join("stat"))
        .map_err(|e| PeerError::Unverifiable(format!("cannot read /proc/{pid}/stat: {e}")))?;
    let exe_path = std::fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| p.display().to_string());
    parse_linux_proc_observation(pid, &status, &stat, exe_path)
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

#[cfg(not(target_os = "linux"))]
fn read_os_peer_observation(pid: u32) -> Result<PeerObservation, PeerError> {
    Err(PeerError::Unverifiable(format!(
        "kernel peer handle reader for pid {pid} requires an active OS IPC handle"
    )))
}

#[cfg(not(target_os = "linux"))]
fn read_os_exe_identity(pid: u32) -> Result<ExeIdentity, PeerError> {
    Err(PeerError::Unverifiable(format!(
        "executable identity lookup for pid {pid} requires an active OS IPC handle"
    )))
}

pub fn parse_linux_proc_observation(
    pid: u32,
    status_raw: &str,
    stat_raw: &str,
    exe_path: Option<String>,
) -> Result<PeerObservation, PeerError> {
    let mut ppid = 0u32;
    let mut uid = 0u32;
    let mut gid = 0u32;
    for line in status_raw.lines() {
        if let Some(rest) = line.strip_prefix("PPid:") {
            ppid = rest.trim().parse::<u32>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Uid:")
            && let Some(first) = rest.split_whitespace().next()
        {
            uid = first.parse::<u32>().unwrap_or(0);
        } else if let Some(rest) = line.strip_prefix("Gid:")
            && let Some(first) = rest.split_whitespace().next()
        {
            gid = first.parse::<u32>().unwrap_or(0);
        }
    }

    let started_at_ticks = parse_proc_stat_starttime(stat_raw).unwrap_or(0);
    Ok(PeerObservation {
        credentials: PeerCredentials::Linux(UnixPeerCreds {
            uid,
            gid,
            pid,
            pidfd_verified: true,
        }),
        hold: ProcessHold::Confirmed {
            key: ProcessKey {
                pid,
                started_at_ticks,
            },
        },
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
    // Field index 19 after "(comm)" corresponds to field 22 (starttime) in /proc/pid/stat.
    fields.get(19)?.parse::<u64>().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_linux_proc_status_and_stat_for_peer_observation() {
        let status = "Name:\tclaude\nPPid:\t1200\nUid:\t1000\t1000\t1000\t1000\nGid:\t1000\t1000\t1000\t1000\n";
        let stat = "2048 (claude) S 1200 2048 2048 0 -1 4194304 100 0 0 0 1 0 0 0 20 0 1 0 987654 1024 100";
        let obs =
            parse_linux_proc_observation(2048, status, stat, Some("/usr/local/bin/claude".into()))
                .unwrap();
        assert_eq!(obs.parent_pid, 1200);
        assert_eq!(obs.started_at_ticks, 987_654);
        assert_eq!(
            obs.exe.as_ref().and_then(|e| e.exe_path.as_deref()),
            Some("/usr/local/bin/claude")
        );
    }
}
