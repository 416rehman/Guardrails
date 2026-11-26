// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use jiff::Timestamp;

use grdr_model::log_safe::sanitize_log_fragment;
use grdr_model::{ActionAttempt, ActionClass, ControlPoint};

use crate::SensorError;
use crate::catalogue::HarnessCatalogue;
use crate::ebpf_wire::{DecodedPayload, DecodedRingEvent, RingChannel, RingKind, decode_raw_frame};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct RingbufDecoderStats {
    pub decoded_frames: u64,
    pub rejected_frames: u64,
    pub lost_events_by_channel: BTreeMap<RingChannel, u64>,
    pub last_seq_by_channel: [Option<u64>; 5],
    pub seq_gaps: u64,
}

#[derive(Debug, Clone, Default)]
pub struct RingbufDecoder {
    stats: RingbufDecoderStats,
}

pub trait LinuxEventSource {
    fn poll_raw_frames(&mut self, max_frames: usize) -> Result<Vec<Vec<u8>>, SensorError>;
}

impl RingbufDecoder {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn stats(&self) -> &RingbufDecoderStats {
        &self.stats
    }

    pub fn decode_frame(&mut self, frame: &[u8]) -> Result<DecodedRingEvent, SensorError> {
        let decoded = decode_raw_frame(frame).inspect_err(|_| {
            self.stats.rejected_frames = self.stats.rejected_frames.saturating_add(1);
        })?;

        let idx = channel_index(decoded.header.channel);
        if let Some(slot) = self.stats.last_seq_by_channel.get_mut(idx) {
            if let Some(prev) = *slot
                && decoded.header.seq > prev.saturating_add(1)
            {
                self.stats.seq_gaps = self.stats.seq_gaps.saturating_add(1);
            }
            *slot = Some(decoded.header.seq);
        }
        self.stats.decoded_frames = self.stats.decoded_frames.saturating_add(1);

        if let DecodedPayload::Health {
            channel,
            dropped_events,
            ..
        } = decoded.payload
        {
            let entry = self
                .stats
                .lost_events_by_channel
                .entry(channel)
                .or_insert(0);
            *entry = entry.saturating_add(dropped_events);
        }

        Ok(decoded)
    }

    pub fn to_action_attempt(
        &self,
        event: &DecodedRingEvent,
        device_id: &str,
        device_name: &str,
        catalogue: &HarnessCatalogue,
    ) -> ActionAttempt {
        let hdr = event.header;
        let ts = i64::try_from(hdr.timestamp_ns)
            .ok()
            .and_then(|ns| Timestamp::from_nanosecond(i128::from(ns)).ok())
            .unwrap_or_else(Timestamp::now);

        match &event.payload {
            DecodedPayload::Execve {
                ppid: _,
                cgroup_id,
                comm,
                filename,
                argv_preview,
            } => {
                let safe_comm = sanitize_log_fragment(comm, 64);
                let safe_file = sanitize_log_fragment(filename, 256);
                let safe_argv = sanitize_log_fragment(argv_preview, 512);
                let argv: Vec<String> = safe_argv
                    .split_whitespace()
                    .map(ToString::to_string)
                    .collect();
                let agent_name = catalogue
                    .match_process(&safe_comm, &argv, Some(&safe_file), &[])
                    .unwrap_or_else(|| {
                        if safe_comm.trim().is_empty() {
                            "linux-process".into()
                        } else {
                            safe_comm.clone()
                        }
                    });
                let target = if safe_argv.is_empty() {
                    safe_file
                } else {
                    safe_argv
                };
                ActionAttempt {
                    id: format!("att-ebpf-{}", hdr.seq),
                    session_id: format!("sess-cg-{cgroup_id}"),
                    device_id: device_id.to_string(),
                    device_name: device_name.to_string(),
                    agent_name,
                    action_class: ActionClass::Exec,
                    control_point: ControlPoint::Sensor,
                    target,
                    summary: format!(
                        "eBPF execve tgid={} uid={} comm={} verdict={:?}",
                        hdr.tgid, hdr.uid, safe_comm, hdr.verdict
                    ),
                    timestamp: ts,
                    ..Default::default()
                }
            }
            DecodedPayload::FileOp {
                op,
                flags,
                cgroup_id,
                path,
                target_path,
            } => {
                let action_class = match (hdr.kind, op) {
                    (RingKind::FileUnlink, _) | (_, 2) => ActionClass::FileDelete,
                    (RingKind::FileRename, _) | (_, 1) => ActionClass::FileWrite,
                    _ if (flags & 0o3) != 0 => ActionClass::FileWrite,
                    _ => ActionClass::FileRead,
                };
                let safe_path = sanitize_log_fragment(path, 256);
                let safe_target_path = sanitize_log_fragment(target_path, 256);
                let target = if safe_target_path.is_empty() {
                    safe_path
                } else {
                    format!("{safe_path} -> {safe_target_path}")
                };
                ActionAttempt {
                    id: format!("att-ebpf-{}", hdr.seq),
                    session_id: format!("sess-cg-{cgroup_id}"),
                    device_id: device_id.to_string(),
                    device_name: device_name.to_string(),
                    agent_name: "linux-ebpf".into(),
                    action_class,
                    control_point: ControlPoint::Sensor,
                    target,
                    summary: format!(
                        "eBPF file tgid={} op={op} verdict={:?}",
                        hdr.tgid, hdr.verdict
                    ),
                    timestamp: ts,
                    ..Default::default()
                }
            }
            DecodedPayload::NetOp {
                op,
                port,
                cgroup_id,
                addr,
                ..
            } => ActionAttempt {
                id: format!("att-ebpf-{}", hdr.seq),
                session_id: format!("sess-cg-{cgroup_id}"),
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                agent_name: "linux-ebpf".into(),
                action_class: ActionClass::NetConnect,
                control_point: ControlPoint::Sensor,
                target: format!("{addr}:{port}"),
                summary: format!(
                    "eBPF net tgid={} op={op} verdict={:?}",
                    hdr.tgid, hdr.verdict
                ),
                timestamp: ts,
                ..Default::default()
            },
            DecodedPayload::Ipc {
                op,
                target_pid,
                prev_uid,
                next_uid,
                cgroup_id,
                detail,
            } => ActionAttempt {
                id: format!("att-ebpf-{}", hdr.seq),
                session_id: format!("sess-cg-{cgroup_id}"),
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                agent_name: "linux-ebpf".into(),
                action_class: ActionClass::Elevate,
                control_point: ControlPoint::Sensor,
                target: format!("pid:{target_pid}:{}", sanitize_log_fragment(detail, 128)),
                summary: format!(
                    "eBPF ipc op={op} uid={prev_uid}->{next_uid} verdict={:?}",
                    hdr.verdict
                ),
                timestamp: ts,
                ..Default::default()
            },
            DecodedPayload::ProcExit => ActionAttempt {
                id: format!("att-ebpf-{}", hdr.seq),
                session_id: format!("sess-tgid-{}", hdr.tgid),
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                agent_name: "linux-ebpf".into(),
                action_class: ActionClass::Exec,
                control_point: ControlPoint::Sensor,
                target: format!("exit:tgid:{}", hdr.tgid),
                summary: format!("eBPF proc_exit tgid={}", hdr.tgid),
                timestamp: ts,
                ..Default::default()
            },
            DecodedPayload::Health {
                channel,
                ring_utilization_permille,
                dropped_events,
            } => ActionAttempt {
                id: format!("att-ebpf-health-{}", hdr.seq),
                session_id: "sensor-health".into(),
                device_id: device_id.to_string(),
                device_name: device_name.to_string(),
                agent_name: "grdr-sensor-linux".into(),
                action_class: ActionClass::Exec,
                control_point: ControlPoint::Sensor,
                target: format!("ringbuf-loss:{channel:?}"),
                summary: format!(
                    "ringbuf drop telemetry channel={channel:?} dropped={dropped_events} util={ring_utilization_permille}permille"
                ),
                timestamp: ts,
                ..Default::default()
            },
        }
    }
}

const fn channel_index(channel: RingChannel) -> usize {
    match channel {
        RingChannel::Exec => 0,
        RingChannel::File => 1,
        RingChannel::Net => 2,
        RingChannel::Ipc => 3,
        RingChannel::Health => 4,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::catalogue::{HarnessMatchKind, HarnessMatchRule};
    use crate::ebpf_wire::{RING_EVENT_HEADER_LEN, RING_EVENT_MAGIC, RING_EVENT_VERSION};

    fn make_frame(kind: u16, channel: u8, seq: u64, payload: &[u8]) -> Vec<u8> {
        let mut frame = Vec::with_capacity(RING_EVENT_HEADER_LEN.saturating_add(payload.len()));
        frame.extend_from_slice(&RING_EVENT_MAGIC);
        frame.extend_from_slice(&RING_EVENT_VERSION.to_le_bytes());
        frame.extend_from_slice(&kind.to_le_bytes());
        frame.extend_from_slice(&(payload.len() as u16).to_le_bytes());
        frame.push(2);
        frame.push(channel);
        frame.extend_from_slice(&0u32.to_le_bytes());
        frame.extend_from_slice(&seq.to_le_bytes());
        frame.extend_from_slice(&1_700_000_000_000_000_000u64.to_le_bytes());
        let tgid_pid = (333u64 << 32) | 333u64;
        frame.extend_from_slice(&tgid_pid.to_le_bytes());
        let uid_gid = (1000u64 << 32) | 1000u64;
        frame.extend_from_slice(&uid_gid.to_le_bytes());
        frame.extend_from_slice(payload);
        frame
    }

    #[test]
    fn decodes_ringbuf_exec_and_tracks_loss_counters() {
        let mut exec_payload = Vec::new();
        exec_payload.extend_from_slice(&100u32.to_le_bytes());
        exec_payload.extend_from_slice(&[0u8; 16]);
        exec_payload.extend_from_slice(&99u64.to_le_bytes());
        exec_payload.push(6);
        exec_payload.extend_from_slice(&12u16.to_le_bytes());
        exec_payload.extend_from_slice(&10u16.to_le_bytes());
        exec_payload.extend_from_slice(b"runner");
        exec_payload.extend_from_slice(b"/usr/bin/git");
        exec_payload.extend_from_slice(b"git status");
        let exec_frame = make_frame(1, 0, 1, &exec_payload);

        let mut health_payload = Vec::new();
        health_payload.push(1);
        health_payload.extend_from_slice(&800u16.to_le_bytes());
        health_payload.extend_from_slice(&0x3FFu32.to_le_bytes());
        health_payload.extend_from_slice(&42u64.to_le_bytes());
        let health_frame = make_frame(11, 4, 3, &health_payload);

        let catalogue = HarnessCatalogue::from_rules(vec![HarnessMatchRule {
            id: "test-agent".into(),
            display_name: "Test Agent".into(),
            kind: HarnessMatchKind::CommExact,
            patterns: vec!["runner".into()],
        }]);
        let mut decoder = RingbufDecoder::new();
        let ev1 = decoder.decode_frame(&exec_frame).unwrap();
        let att1 = decoder.to_action_attempt(&ev1, "dev-1", "linux-box", &catalogue);
        assert_eq!(att1.agent_name, "test-agent");
        assert_eq!(att1.session_id, "sess-cg-99");
        assert_eq!(att1.action_class, ActionClass::Exec);
        assert_eq!(att1.target, "git status");

        let ev2 = decoder.decode_frame(&health_frame).unwrap();
        let att2 = decoder.to_action_attempt(&ev2, "dev-1", "linux-box", &catalogue);
        assert!(att2.target.contains("ringbuf-loss:File"));
        assert_eq!(decoder.stats().seq_gaps, 0);

        let exec_gap = make_frame(1, 0, 3, &exec_payload);
        let _ = decoder.decode_frame(&exec_gap).unwrap();
        assert_eq!(decoder.stats().seq_gaps, 1);
        assert_eq!(
            decoder
                .stats()
                .lost_events_by_channel
                .get(&RingChannel::File),
            Some(&42)
        );
    }

    #[test]
    fn rejects_corrupted_bounds_without_panicking() {
        let mut bad_payload = Vec::new();
        bad_payload.extend_from_slice(&[0u8; 28]);
        bad_payload.push(99);
        bad_payload.extend_from_slice(&0u16.to_le_bytes());
        bad_payload.extend_from_slice(&0u16.to_le_bytes());
        let frame = make_frame(1, 0, 1, &bad_payload);
        let mut decoder = RingbufDecoder::new();
        assert!(matches!(
            decoder.decode_frame(&frame),
            Err(SensorError::RingbufDecode { .. })
        ));
        assert_eq!(decoder.stats().rejected_frames, 1);
    }
}
