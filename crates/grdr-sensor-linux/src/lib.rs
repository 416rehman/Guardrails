// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use jiff::Timestamp;

use grdr_model::error::CODE_STORE_IO;
use grdr_model::{ActionAttempt, ActionClass, CodedError, ControlPoint};
use grdr_ports::SensorPort;

const KNOWN_HARNESSES: &[&str] = &[
    "claude",
    "claude-code",
    "cursor",
    "codex",
    "gemini",
    "antigravity",
    "aider",
];

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SensorError {
    #[error("GRDR-SENSOR-0001: procfs root `{path}` unreadable: {detail}")]
    ProcIo { path: String, detail: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProcProcessSnapshot {
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub comm: String,
    pub cmdline: Vec<String>,
    pub exe_path: Option<String>,
    pub cwd: Option<String>,
}

#[derive(Debug, Clone)]
pub struct LinuxProcSensor {
    proc_root: PathBuf,
    device_id: String,
    device_name: String,
    seen_pids: HashSet<u32>,
}

impl Default for LinuxProcSensor {
    fn default() -> Self {
        Self::new(PathBuf::from("/proc"), "local-linux", "linux-host")
    }
}

impl LinuxProcSensor {
    pub fn new(
        proc_root: PathBuf,
        device_id: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Self {
        Self {
            proc_root,
            device_id: device_id.into(),
            device_name: device_name.into(),
            seen_pids: HashSet::new(),
        }
    }

    pub fn proc_root(&self) -> &Path {
        &self.proc_root
    }

    pub fn scan_proc_processes(
        &self,
        limit: usize,
    ) -> Result<Vec<ProcProcessSnapshot>, SensorError> {
        if limit == 0 || !self.proc_root.is_dir() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.proc_root).map_err(|e| SensorError::ProcIo {
            path: self.proc_root.display().to_string(),
            detail: e.to_string(),
        })?;

        let mut pids = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            let Some(name_str) = name.to_str() else {
                continue;
            };
            if let Ok(pid) = name_str.parse::<u32>() {
                pids.push(pid);
            }
        }
        pids.sort_unstable();

        let mut out = Vec::new();
        for pid in pids {
            if out.len() >= limit {
                break;
            }
            if let Some(proc_info) = read_pid_snapshot(&self.proc_root, pid) {
                out.push(proc_info);
            }
        }
        Ok(out)
    }
}

impl SensorPort for LinuxProcSensor {
    fn sensor_name(&self) -> &'static str {
        "linux-procfs"
    }

    fn poll_events(&mut self, max_events: usize) -> Result<Vec<ActionAttempt>, CodedError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        if !self.proc_root.is_dir() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.proc_root).map_err(|e| {
            CodedError::new(
                CODE_STORE_IO,
                format!("Procfs read failed at {}: {e}", self.proc_root.display()),
                "Check /proc mount visibility and read permissions.",
            )
        })?;

        let mut pids = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(raw) = name.to_str()
                && let Ok(pid) = raw.parse::<u32>()
                && !self.seen_pids.contains(&pid)
            {
                pids.push(pid);
            }
        }
        pids.sort_unstable();

        let now = Timestamp::now();
        let mut attempts = Vec::new();
        for pid in pids {
            if attempts.len() >= max_events {
                break;
            }
            self.seen_pids.insert(pid);
            let Some(snap) = read_pid_snapshot(&self.proc_root, pid) else {
                continue;
            };
            let target = if snap.cmdline.is_empty() {
                snap.comm.clone()
            } else {
                snap.cmdline.join(" ")
            };
            if target.trim().is_empty() {
                continue;
            }
            let agent_name = infer_agent_name(&snap);
            attempts.push(ActionAttempt {
                id: format!("att-proc-{pid}"),
                session_id: format!("sess-ppid-{}", snap.ppid),
                device_id: self.device_id.clone(),
                device_name: self.device_name.clone(),
                agent_name,
                action_class: ActionClass::Exec,
                control_point: ControlPoint::Sensor,
                target: target.clone(),
                summary: format!("Process pid={pid} uid={} cmd={}", snap.uid, snap.comm),
                timestamp: now,
                ..Default::default()
            });
        }
        Ok(attempts)
    }
}

pub fn decode_proc_cmdline(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&b| b == 0)
        .filter(|part| !part.is_empty())
        .map(|part| String::from_utf8_lossy(part).into_owned())
        .collect()
}

pub fn parse_proc_status(raw: &str) -> (String, u32, u32) {
    let mut comm = String::new();
    let mut ppid = 0u32;
    let mut uid = 0u32;

    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Name:") {
            comm = rest.trim().to_string();
        } else if let Some(rest) = line.strip_prefix("PPid:") {
            if let Ok(parsed) = rest.trim().parse::<u32>() {
                ppid = parsed;
            }
        } else if let Some(rest) = line.strip_prefix("Uid:")
            && let Some(first) = rest.split_whitespace().next()
            && let Ok(parsed) = first.parse::<u32>()
        {
            uid = parsed;
        }
    }
    (comm, ppid, uid)
}

fn read_pid_snapshot(proc_root: &Path, pid: u32) -> Option<ProcProcessSnapshot> {
    let dir = proc_root.join(pid.to_string());
    let status_raw = fs::read_to_string(dir.join("status")).ok()?;
    let (comm, ppid, uid) = parse_proc_status(&status_raw);
    let cmd_bytes = fs::read(dir.join("cmdline")).unwrap_or_default();
    let cmdline = decode_proc_cmdline(&cmd_bytes);
    let exe_path = fs::read_link(dir.join("exe"))
        .ok()
        .map(|p| p.display().to_string());
    let cwd = fs::read_link(dir.join("cwd"))
        .ok()
        .map(|p| p.display().to_string());

    Some(ProcProcessSnapshot {
        pid,
        ppid,
        uid,
        comm,
        cmdline,
        exe_path,
        cwd,
    })
}

fn infer_agent_name(snap: &ProcProcessSnapshot) -> String {
    let joined = snap.cmdline.join(" ").to_ascii_lowercase();
    let comm_lower = snap.comm.to_ascii_lowercase();
    for harness in KNOWN_HARNESSES {
        if comm_lower.contains(harness) || joined.contains(harness) {
            return (*harness).to_string();
        }
    }
    if snap.comm.trim().is_empty() {
        "linux-process".into()
    } else {
        snap.comm.clone()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_synthetic_procfs_and_satisfies_sensor_contract() {
        let root = std::env::temp_dir().join(format!("grdr-procfs-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);

        let p1 = root.join("1042");
        fs::create_dir_all(&p1).unwrap();
        fs::write(
            p1.join("status"),
            "Name:\tclaude\nUmask:\t0022\nPPid:\t1000\nUid:\t1000\t1000\t1000\t1000\n",
        )
        .unwrap();
        fs::write(p1.join("cmdline"), b"claude\0--print\0git status\0").unwrap();

        let p2 = root.join("2088");
        fs::create_dir_all(&p2).unwrap();
        fs::write(p2.join("status"), "Name:\tcurl\nPPid:\t1042\nUid:\t1000\n").unwrap();
        fs::write(
            p2.join("cmdline"),
            b"curl\0https://example.invalid/upload\0",
        )
        .unwrap();

        let mut sensor = LinuxProcSensor::new(root.clone(), "dev-linux-1", "workstation-linux");
        let snaps = sensor.scan_proc_processes(10).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].pid, 1042);
        assert_eq!(snaps[0].ppid, 1000);
        assert_eq!(snaps[0].uid, 1000);
        assert_eq!(snaps[0].cmdline, vec!["claude", "--print", "git status"]);

        // Contract check + second poll returns empty since both PIDs are recorded.
        assert!(grdr_ports_testkit::assert_sensor_port_contract(&mut sensor).is_ok());
        assert!(sensor.poll_events(10).unwrap().is_empty());

        let _ = fs::remove_dir_all(&root);
    }
}
