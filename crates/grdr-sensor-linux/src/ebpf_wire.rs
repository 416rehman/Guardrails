// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::net::{Ipv4Addr, Ipv6Addr};

use crate::SensorError;

pub const RING_EVENT_MAGIC: [u8; 4] = *b"GRDR";
pub const RING_EVENT_VERSION: u16 = 1;
pub const RING_EVENT_HEADER_LEN: usize = 48;
pub const MAX_COMM_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_ARGV_PREVIEW_LEN: usize = 256;
pub const MAX_DETAIL_LEN: usize = 128;
pub const MAX_FRAME_LEN: usize = RING_EVENT_HEADER_LEN + 562;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Ord, PartialOrd)]
pub enum RingChannel {
    Exec,
    File,
    Net,
    Ipc,
    Health,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingKind {
    Execve,
    FileOpen,
    FileRename,
    FileUnlink,
    NetConnect,
    NetBind,
    TaskPtrace,
    CredSetuid,
    ModuleOrBpfTamper,
    ProcExit,
    HealthLost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum KernelVerdict {
    Observed,
    Allowed,
    Denied,
    AuditOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodedHeader {
    pub kind: RingKind,
    pub payload_len: u16,
    pub verdict: KernelVerdict,
    pub channel: RingChannel,
    pub flags: u32,
    pub seq: u64,
    pub timestamp_ns: u64,
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DecodedPayload {
    Execve {
        ppid: u32,
        cgroup_id: u64,
        comm: String,
        filename: String,
        argv_preview: String,
    },
    FileOp {
        op: u8,
        flags: u32,
        cgroup_id: u64,
        path: String,
        target_path: String,
    },
    NetOp {
        op: u8,
        family: u16,
        port: u16,
        cgroup_id: u64,
        addr: String,
    },
    Ipc {
        op: u8,
        target_pid: u32,
        prev_uid: u32,
        next_uid: u32,
        cgroup_id: u64,
        detail: String,
    },
    ProcExit,
    Health {
        channel: RingChannel,
        ring_utilization_permille: u16,
        dropped_events: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedRingEvent {
    pub header: DecodedHeader,
    pub payload: DecodedPayload,
}

pub fn decode_raw_frame(frame: &[u8]) -> Result<DecodedRingEvent, SensorError> {
    if frame.len() > MAX_FRAME_LEN || frame.len() < RING_EVENT_HEADER_LEN {
        return Err(SensorError::RingbufDecode {
            detail: format!("invalid frame length {}", frame.len()),
        });
    }
    let magic = frame.get(0..4).ok_or_else(|| SensorError::RingbufDecode {
        detail: "missing magic".into(),
    })?;
    if magic != RING_EVENT_MAGIC {
        return Err(SensorError::RingbufDecode {
            detail: "invalid ringbuf magic".into(),
        });
    }
    let version = read_u16(frame, 4)?;
    if version != RING_EVENT_VERSION {
        return Err(SensorError::RingbufDecode {
            detail: format!("unsupported ringbuf version {version}"),
        });
    }
    let kind = decode_kind(read_u16(frame, 6)?)?;
    let payload_len = read_u16(frame, 8)?;
    let verdict = decode_verdict(read_u8(frame, 10)?)?;
    let channel = decode_channel(read_u8(frame, 11)?)?;
    if channel != expected_channel(kind) {
        return Err(SensorError::RingbufDecode {
            detail: format!("channel {channel:?} does not match kind {kind:?}"),
        });
    }
    let flags = read_u32(frame, 12)?;
    let seq = read_u64(frame, 16)?;
    let timestamp_ns = read_u64(frame, 24)?;
    let tgid_pid = read_u64(frame, 32)?;
    let uid_gid = read_u64(frame, 40)?;

    let end = RING_EVENT_HEADER_LEN
        .checked_add(usize::from(payload_len))
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "payload length overflow".into(),
        })?;
    if end != frame.len() {
        return Err(SensorError::RingbufDecode {
            detail: format!("frame length {} != declared end {end}", frame.len()),
        });
    }
    let body = frame
        .get(RING_EVENT_HEADER_LEN..end)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "payload truncated".into(),
        })?;

    let payload = match kind {
        RingKind::Execve => decode_execve(body)?,
        RingKind::FileOpen | RingKind::FileRename | RingKind::FileUnlink => decode_file_op(body)?,
        RingKind::NetConnect | RingKind::NetBind => decode_net_op(body)?,
        RingKind::TaskPtrace | RingKind::CredSetuid | RingKind::ModuleOrBpfTamper => {
            decode_ipc(body)?
        }
        RingKind::ProcExit => {
            if payload_len != 0 {
                return Err(SensorError::RingbufDecode {
                    detail: format!("proc_exit expected payload_len 0, got {payload_len}"),
                });
            }
            DecodedPayload::ProcExit
        }
        RingKind::HealthLost => decode_health(body)?,
    };

    Ok(DecodedRingEvent {
        header: DecodedHeader {
            kind,
            payload_len,
            verdict,
            channel,
            flags,
            seq,
            timestamp_ns,
            tgid: (tgid_pid >> 32) as u32,
            pid: tgid_pid as u32,
            uid: (uid_gid >> 32) as u32,
            gid: uid_gid as u32,
        },
        payload,
    })
}

fn decode_kind(raw: u16) -> Result<RingKind, SensorError> {
    match raw {
        1 => Ok(RingKind::Execve),
        2 => Ok(RingKind::FileOpen),
        3 => Ok(RingKind::FileRename),
        4 => Ok(RingKind::FileUnlink),
        5 => Ok(RingKind::NetConnect),
        6 => Ok(RingKind::NetBind),
        7 => Ok(RingKind::TaskPtrace),
        8 => Ok(RingKind::CredSetuid),
        9 => Ok(RingKind::ModuleOrBpfTamper),
        10 => Ok(RingKind::ProcExit),
        11 => Ok(RingKind::HealthLost),
        other => Err(SensorError::RingbufDecode {
            detail: format!("unknown event kind {other}"),
        }),
    }
}

fn decode_verdict(raw: u8) -> Result<KernelVerdict, SensorError> {
    match raw {
        0 => Ok(KernelVerdict::Observed),
        1 => Ok(KernelVerdict::Allowed),
        2 => Ok(KernelVerdict::Denied),
        3 => Ok(KernelVerdict::AuditOnly),
        other => Err(SensorError::RingbufDecode {
            detail: format!("unknown kernel verdict {other}"),
        }),
    }
}

fn decode_channel(raw: u8) -> Result<RingChannel, SensorError> {
    match raw {
        0 => Ok(RingChannel::Exec),
        1 => Ok(RingChannel::File),
        2 => Ok(RingChannel::Net),
        3 => Ok(RingChannel::Ipc),
        4 => Ok(RingChannel::Health),
        other => Err(SensorError::RingbufDecode {
            detail: format!("unknown ringbuf channel {other}"),
        }),
    }
}

const fn expected_channel(kind: RingKind) -> RingChannel {
    match kind {
        RingKind::Execve | RingKind::ProcExit => RingChannel::Exec,
        RingKind::FileOpen | RingKind::FileRename | RingKind::FileUnlink => RingChannel::File,
        RingKind::NetConnect | RingKind::NetBind => RingChannel::Net,
        RingKind::TaskPtrace | RingKind::CredSetuid | RingKind::ModuleOrBpfTamper => {
            RingChannel::Ipc
        }
        RingKind::HealthLost => RingChannel::Health,
    }
}

fn decode_execve(body: &[u8]) -> Result<DecodedPayload, SensorError> {
    if body.len() < 33 {
        return Err(SensorError::RingbufDecode {
            detail: "execve payload truncated".into(),
        });
    }
    let ppid = read_u32(body, 0)?;
    let cgroup_id = read_u64(body, 20)?;
    let comm_len = usize::from(read_u8(body, 28)?);
    let file_len = usize::from(read_u16(body, 29)?);
    let argv_len = usize::from(read_u16(body, 31)?);
    if comm_len > MAX_COMM_LEN || file_len > MAX_PATH_LEN || argv_len > MAX_ARGV_PREVIEW_LEN {
        return Err(SensorError::RingbufDecode {
            detail: "execve field exceeds bounded size".into(),
        });
    }
    let (comm, c1) = read_lossy_utf8(body, 33, comm_len)?;
    let (filename, c2) = read_lossy_utf8(body, c1, file_len)?;
    let (argv_preview, end) = read_lossy_utf8(body, c2, argv_len)?;
    if end != body.len() {
        return Err(SensorError::RingbufDecode {
            detail: "execve payload has unexpected trailing bytes".into(),
        });
    }
    Ok(DecodedPayload::Execve {
        ppid,
        cgroup_id,
        comm,
        filename,
        argv_preview,
    })
}

fn decode_file_op(body: &[u8]) -> Result<DecodedPayload, SensorError> {
    if body.len() < 37 {
        return Err(SensorError::RingbufDecode {
            detail: "file payload truncated".into(),
        });
    }
    let op = read_u8(body, 0)?;
    if op > 2 {
        return Err(SensorError::RingbufDecode {
            detail: format!("unknown file op {op}"),
        });
    }
    let flags = read_u32(body, 1)?;
    let cgroup_id = read_u64(body, 9)?;
    let path_len = usize::from(read_u16(body, 33)?);
    let target_len = usize::from(read_u16(body, 35)?);
    if path_len > MAX_PATH_LEN || target_len > MAX_PATH_LEN {
        return Err(SensorError::RingbufDecode {
            detail: "file path exceeds MAX_PATH_LEN".into(),
        });
    }
    let (path, next) = read_lossy_utf8(body, 37, path_len)?;
    let (target_path, end) = read_lossy_utf8(body, next, target_len)?;
    if end != body.len() {
        return Err(SensorError::RingbufDecode {
            detail: "file payload has unexpected trailing bytes".into(),
        });
    }
    Ok(DecodedPayload::FileOp {
        op,
        flags,
        cgroup_id,
        path,
        target_path,
    })
}

fn decode_net_op(body: &[u8]) -> Result<DecodedPayload, SensorError> {
    if body.len() != 35 {
        return Err(SensorError::RingbufDecode {
            detail: format!("net payload expected 35 bytes, got {}", body.len()),
        });
    }
    let op = read_u8(body, 0)?;
    if op > 1 {
        return Err(SensorError::RingbufDecode {
            detail: format!("unknown net op {op}"),
        });
    }
    let family = read_u16(body, 1)?;
    if family != 2 && family != 10 {
        return Err(SensorError::RingbufDecode {
            detail: format!("unsupported socket family {family}"),
        });
    }
    let port = read_u16(body, 5)?;
    let cgroup_id = read_u64(body, 7)?;
    let addr_bytes = body.get(19..35).ok_or_else(|| SensorError::RingbufDecode {
        detail: "net addr truncated".into(),
    })?;
    let addr = if family == 2 {
        let mut v4 = [0u8; 4];
        if let Some(first_four) = addr_bytes.get(..4) {
            v4.copy_from_slice(first_four);
        }
        Ipv4Addr::from(v4).to_string()
    } else {
        let mut v6 = [0u8; 16];
        v6.copy_from_slice(addr_bytes);
        Ipv6Addr::from(v6).to_string()
    };
    Ok(DecodedPayload::NetOp {
        op,
        family,
        port,
        cgroup_id,
        addr,
    })
}

fn decode_ipc(body: &[u8]) -> Result<DecodedPayload, SensorError> {
    if body.len() < 31 {
        return Err(SensorError::RingbufDecode {
            detail: "ipc payload truncated".into(),
        });
    }
    let op = read_u8(body, 0)?;
    if op > 4 {
        return Err(SensorError::RingbufDecode {
            detail: format!("unknown ipc op {op}"),
        });
    }
    let target_pid = read_u32(body, 1)?;
    let prev_uid = read_u32(body, 5)?;
    let next_uid = read_u32(body, 9)?;
    let cgroup_id = read_u64(body, 13)?;
    let detail_len = usize::from(read_u16(body, 29)?);
    if detail_len > MAX_DETAIL_LEN {
        return Err(SensorError::RingbufDecode {
            detail: "ipc detail exceeds MAX_DETAIL_LEN".into(),
        });
    }
    let (detail, end) = read_lossy_utf8(body, 31, detail_len)?;
    if end != body.len() {
        return Err(SensorError::RingbufDecode {
            detail: "ipc payload has unexpected trailing bytes".into(),
        });
    }
    Ok(DecodedPayload::Ipc {
        op,
        target_pid,
        prev_uid,
        next_uid,
        cgroup_id,
        detail,
    })
}

fn decode_health(body: &[u8]) -> Result<DecodedPayload, SensorError> {
    if body.len() != 15 {
        return Err(SensorError::RingbufDecode {
            detail: format!("health payload expected 15 bytes, got {}", body.len()),
        });
    }
    Ok(DecodedPayload::Health {
        channel: decode_channel(read_u8(body, 0)?)?,
        ring_utilization_permille: read_u16(body, 1)?,
        dropped_events: read_u64(body, 7)?,
    })
}

fn read_lossy_utf8(src: &[u8], offset: usize, len: usize) -> Result<(String, usize), SensorError> {
    let end = offset
        .checked_add(len)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "offset overflow".into(),
        })?;
    let slice = src
        .get(offset..end)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "segment truncated".into(),
        })?;
    Ok((String::from_utf8_lossy(slice).into_owned(), end))
}

fn read_u8(src: &[u8], offset: usize) -> Result<u8, SensorError> {
    src.get(offset)
        .copied()
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "u8 out of bounds".into(),
        })
}

fn read_u16(src: &[u8], offset: usize) -> Result<u16, SensorError> {
    let end = offset
        .checked_add(2)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "u16 overflow".into(),
        })?;
    let slice = src
        .get(offset..end)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "u16 out of bounds".into(),
        })?;
    let mut arr = [0u8; 2];
    arr.copy_from_slice(slice);
    Ok(u16::from_le_bytes(arr))
}

fn read_u32(src: &[u8], offset: usize) -> Result<u32, SensorError> {
    let end = offset
        .checked_add(4)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "u32 overflow".into(),
        })?;
    let slice = src
        .get(offset..end)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "u32 out of bounds".into(),
        })?;
    let mut arr = [0u8; 4];
    arr.copy_from_slice(slice);
    Ok(u32::from_le_bytes(arr))
}

fn read_u64(src: &[u8], offset: usize) -> Result<u64, SensorError> {
    let end = offset
        .checked_add(8)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "u64 overflow".into(),
        })?;
    let slice = src
        .get(offset..end)
        .ok_or_else(|| SensorError::RingbufDecode {
            detail: "u64 out of bounds".into(),
        })?;
    let mut arr = [0u8; 8];
    arr.copy_from_slice(slice);
    Ok(u64::from_le_bytes(arr))
}
