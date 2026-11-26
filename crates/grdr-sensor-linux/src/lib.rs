// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

pub mod catalogue;
pub mod cri;
pub mod ebpf_decoder;
pub mod ebpf_wire;
mod fs_safe;
pub mod probe;
pub mod seccheck;
pub mod slot_broker;

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use jiff::Timestamp;

use grdr_model::error::CODE_STORE_IO;
use grdr_model::log_safe::sanitize_log_fragment;
use grdr_model::{ActionAttempt, ActionClass, CodedError, ControlPoint};
use grdr_ports::SensorPort;

use crate::catalogue::HarnessCatalogue;
use crate::ebpf_decoder::{LinuxEventSource, RingbufDecoder, RingbufDecoderStats};
use crate::fs_safe::{open_nofollow_bounded_bytes, verify_non_symlink_dir};

pub const CODE_SENSOR_PROC_IO: &str = "GRDR-SENSOR-0001";
pub const CODE_SENSOR_CATALOGUE_LOAD: &str = "GRDR-SENSOR-0002";
pub const CODE_SENSOR_KERNEL_PROBE: &str = "GRDR-SENSOR-0003";
pub const CODE_SENSOR_RINGBUF_DECODE: &str = "GRDR-SENSOR-0004";
pub const CODE_SENSOR_CRI_NORMALIZE: &str = "GRDR-SENSOR-0005";
pub const CODE_SENSOR_SECCHECK_PARSE: &str = "GRDR-SENSOR-0006";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum SensorError {
    #[error("GRDR-SENSOR-0001: procfs root `{path}` unreadable: {detail}")]
    ProcIo { path: String, detail: String },
    #[error("GRDR-SENSOR-0002: harness or incumbent catalogue `{path}` failed: {detail}")]
    CatalogueLoad { path: String, detail: String },
    #[error("GRDR-SENSOR-0003: Linux kernel probe failed at `{path}`: {detail}")]
    KernelProbe { path: String, detail: String },
    #[error("GRDR-SENSOR-0004: eBPF ringbuf frame decode failed: {detail}")]
    RingbufDecode { detail: String },
    #[error("GRDR-SENSOR-0005: CRI workload metadata normalization failed: {detail}")]
    CriNormalize { detail: String },
    #[error("GRDR-SENSOR-0006: gVisor seccheck parse failed: {detail}")]
    SeccheckParse { detail: String },
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
    proc_read_max_bytes: u64,
    catalogue: HarnessCatalogue,
    seen_pids: HashSet<u32>,
}

#[derive(Debug)]
pub struct LinuxSensor<S: LinuxEventSource> {
    source: S,
    decoder: RingbufDecoder,
    catalogue: HarnessCatalogue,
    proc_fallback: Option<LinuxProcSensor>,
    device_id: String,
    device_name: String,
}

impl From<SensorError> for CodedError {
    fn from(err: SensorError) -> Self {
        let code = match &err {
            SensorError::ProcIo { .. } => CODE_SENSOR_PROC_IO,
            SensorError::CatalogueLoad { .. } => CODE_SENSOR_CATALOGUE_LOAD,
            SensorError::KernelProbe { .. } => CODE_SENSOR_KERNEL_PROBE,
            SensorError::RingbufDecode { .. } => CODE_SENSOR_RINGBUF_DECODE,
            SensorError::CriNormalize { .. } => CODE_SENSOR_CRI_NORMALIZE,
            SensorError::SeccheckParse { .. } => CODE_SENSOR_SECCHECK_PARSE,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify Linux procfs visibility, catalogue manifests, kernel LSM/BTF capabilities, and ringbuf framing.",
        )
    }
}

impl LinuxProcSensor {
    pub fn new(
        proc_root: PathBuf,
        device_id: impl Into<String>,
        device_name: impl Into<String>,
        proc_read_max_bytes: u64,
    ) -> Self {
        Self {
            proc_root,
            device_id: device_id.into(),
            device_name: device_name.into(),
            proc_read_max_bytes: proc_read_max_bytes.max(1024),
            catalogue: HarnessCatalogue::empty(),
            seen_pids: HashSet::new(),
        }
    }

    pub fn with_catalogue(mut self, catalogue: HarnessCatalogue) -> Self {
        self.catalogue = catalogue;
        self
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

        let entries = verify_non_symlink_dir(&self.proc_root, "proc_root")?;

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
            if let Some(proc_info) =
                read_pid_snapshot(&self.proc_root, pid, self.proc_read_max_bytes)
            {
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
        if max_events == 0 || !self.proc_root.is_dir() {
            return Ok(Vec::new());
        }

        let entries = verify_non_symlink_dir(&self.proc_root, "proc_root").map_err(|e| {
            CodedError::new(
                CODE_STORE_IO,
                format!("Procfs read failed at {}: {e}", self.proc_root.display()),
                "Check /proc mount visibility and non-symlink directory invariants.",
            )
        })?;

        let mut live_pids = HashSet::new();
        let mut new_pids = Vec::new();
        for entry in entries.flatten() {
            let name = entry.file_name();
            if let Some(raw) = name.to_str()
                && let Ok(pid) = raw.parse::<u32>()
            {
                live_pids.insert(pid);
                if !self.seen_pids.contains(&pid) {
                    new_pids.push(pid);
                }
            }
        }
        self.seen_pids.retain(|pid| live_pids.contains(pid));
        new_pids.sort_unstable();

        let now = Timestamp::now();
        let mut attempts = Vec::new();
        for pid in new_pids {
            if attempts.len() >= max_events {
                break;
            }
            self.seen_pids.insert(pid);
            let Some(snap) = read_pid_snapshot(&self.proc_root, pid, self.proc_read_max_bytes)
            else {
                continue;
            };
            let raw_target = if snap.cmdline.is_empty() {
                snap.comm.clone()
            } else {
                snap.cmdline.join(" ")
            };
            let target = sanitize_log_fragment(&raw_target, 512);
            if target.trim().is_empty() {
                continue;
            }
            let agent_name = infer_agent_name(&self.catalogue, &snap);
            let safe_comm = sanitize_log_fragment(&snap.comm, 64);
            attempts.push(ActionAttempt {
                id: format!("att-proc-{pid}"),
                session_id: format!("sess-ppid-{}", snap.ppid),
                device_id: self.device_id.clone(),
                device_name: self.device_name.clone(),
                agent_name,
                action_class: ActionClass::Exec,
                control_point: ControlPoint::Sensor,
                target,
                summary: format!("Process pid={pid} uid={} cmd={safe_comm}", snap.uid),
                timestamp: now,
                ..Default::default()
            });
        }
        Ok(attempts)
    }
}

impl<S: LinuxEventSource> LinuxSensor<S> {
    pub fn new(
        source: S,
        catalogue: HarnessCatalogue,
        proc_fallback: Option<LinuxProcSensor>,
        device_id: impl Into<String>,
        device_name: impl Into<String>,
    ) -> Self {
        Self {
            source,
            decoder: RingbufDecoder::new(),
            catalogue,
            proc_fallback,
            device_id: device_id.into(),
            device_name: device_name.into(),
        }
    }

    pub fn stats(&self) -> &RingbufDecoderStats {
        self.decoder.stats()
    }
}

impl<S: LinuxEventSource + Send + Sync> SensorPort for LinuxSensor<S> {
    fn sensor_name(&self) -> &'static str {
        "linux-ebpf"
    }

    fn poll_events(&mut self, max_events: usize) -> Result<Vec<ActionAttempt>, CodedError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        let frames = self
            .source
            .poll_raw_frames(max_events)
            .map_err(CodedError::from)?;
        let mut attempts = Vec::with_capacity(frames.len().min(max_events));
        for frame in frames.into_iter().take(max_events) {
            match self.decoder.decode_frame(&frame) {
                Ok(decoded) => {
                    attempts.push(self.decoder.to_action_attempt(
                        &decoded,
                        &self.device_id,
                        &self.device_name,
                        &self.catalogue,
                    ));
                }
                Err(err) => return Err(CodedError::from(err)),
            }
        }
        if attempts.len() < max_events
            && let Some(proc_sensor) = self.proc_fallback.as_mut()
        {
            let remaining = max_events.saturating_sub(attempts.len());
            let mut fallback = proc_sensor.poll_events(remaining)?;
            attempts.append(&mut fallback);
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

fn read_pid_snapshot(
    proc_root: &Path,
    pid: u32,
    max_proc_bytes: u64,
) -> Option<ProcProcessSnapshot> {
    let dir = proc_root.join(pid.to_string());
    let status_bytes =
        open_nofollow_bounded_bytes(&dir.join("status"), max_proc_bytes, "proc status").ok()?;
    let status_raw = String::from_utf8_lossy(&status_bytes);
    let (raw_comm, ppid, uid) = parse_proc_status(&status_raw);
    let comm = sanitize_log_fragment(&raw_comm, 64);
    let cmd_bytes =
        open_nofollow_bounded_bytes(&dir.join("cmdline"), max_proc_bytes, "proc cmdline")
            .unwrap_or_default();
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

fn infer_agent_name(catalogue: &HarnessCatalogue, snap: &ProcProcessSnapshot) -> String {
    if let Some(matched) =
        catalogue.match_process(&snap.comm, &snap.cmdline, snap.exe_path.as_deref(), &[])
    {
        return matched;
    }
    if snap.comm.trim().is_empty() {
        "linux-process".into()
    } else {
        snap.comm.clone()
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;

    use super::*;
    use crate::catalogue::{HarnessMatchKind, HarnessMatchRule};
    use crate::ebpf_wire::{RING_EVENT_HEADER_LEN, RING_EVENT_MAGIC, RING_EVENT_VERSION};

    struct VecFrameSource {
        frames: VecDeque<Vec<u8>>,
    }

    impl LinuxEventSource for VecFrameSource {
        fn poll_raw_frames(&mut self, max_frames: usize) -> Result<Vec<Vec<u8>>, SensorError> {
            let mut out = Vec::new();
            while out.len() < max_frames {
                let Some(next) = self.frames.pop_front() else {
                    break;
                };
                out.push(next);
            }
            Ok(out)
        }
    }

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

        let catalogue = HarnessCatalogue::from_rules(vec![HarnessMatchRule {
            id: "claude".into(),
            display_name: "Claude CLI".into(),
            kind: HarnessMatchKind::CommExact,
            patterns: vec!["claude".into()],
        }]);
        let mut sensor =
            LinuxProcSensor::new(root.clone(), "dev-linux-1", "workstation-linux", 32_768)
                .with_catalogue(catalogue);
        let snaps = sensor.scan_proc_processes(10).unwrap();
        assert_eq!(snaps.len(), 2);
        assert_eq!(snaps[0].pid, 1042);
        assert_eq!(snaps[0].ppid, 1000);
        assert_eq!(snaps[0].uid, 1000);
        assert_eq!(snaps[0].cmdline, vec!["claude", "--print", "git status"]);

        assert!(grdr_ports_testkit::assert_sensor_port_contract(&mut sensor).is_ok());
        assert!(sensor.poll_events(10).unwrap().is_empty());

        let _ = fs::remove_dir_all(&p2);
        assert!(sensor.poll_events(10).unwrap().is_empty());
        fs::create_dir_all(&p2).unwrap();
        fs::write(
            p2.join("status"),
            "Name:\tpython3\nPPid:\t1042\nUid:\t1000\n",
        )
        .unwrap();
        fs::write(p2.join("cmdline"), b"python3\0script.py\0").unwrap();
        let reused = sensor.poll_events(10).unwrap();
        assert_eq!(reused.len(), 1);
        assert_eq!(reused[0].target, "python3 script.py");

        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn linux_sensor_satisfies_sensor_port_contract_with_ringbuf_source() {
        let mut payload = Vec::new();
        payload.extend_from_slice(&42u32.to_le_bytes());
        payload.extend_from_slice(&[0u8; 16]);
        payload.extend_from_slice(&7u64.to_le_bytes());
        payload.push(4);
        payload.extend_from_slice(&12u16.to_le_bytes());
        payload.extend_from_slice(&6u16.to_le_bytes());
        payload.extend_from_slice(b"node");
        payload.extend_from_slice(b"/usr/bin/env");
        payload.extend_from_slice(b"env -i");

        let mut frame = Vec::with_capacity(RING_EVENT_HEADER_LEN + payload.len());
        frame.extend_from_slice(&RING_EVENT_MAGIC);
        frame.extend_from_slice(&RING_EVENT_VERSION.to_le_bytes());
        frame.extend_from_slice(&1u16.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        frame.push(1);
        frame.push(0);
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&10u64.to_le_bytes());
        frame.extend_from_slice(&1_700_000_000_000_000_000u64.to_le_bytes());
        frame.extend_from_slice(&((500u64 << 32) | 500u64).to_le_bytes());
        frame.extend_from_slice(&((1000u64 << 32) | 1000u64).to_le_bytes());
        frame.extend_from_slice(&payload);

        let mut queue = VecDeque::new();
        queue.push_back(frame);

        let mut sensor = LinuxSensor::new(
            VecFrameSource { frames: queue },
            HarnessCatalogue::empty(),
            None,
            "dev-linux-2",
            "node-linux",
        );
        assert!(grdr_ports_testkit::assert_sensor_port_contract(&mut sensor).is_ok());
        assert_eq!(sensor.stats().decoded_frames, 1);
    }
}
