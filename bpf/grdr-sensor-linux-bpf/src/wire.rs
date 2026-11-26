// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub const RING_EVENT_MAGIC: [u8; 4] = *b"GRDR";
pub const RING_EVENT_VERSION: u16 = 1;
pub const RINGBUF_SIZE_PER_CPU_BYTES: u32 = 262_144;
pub const RING_EVENT_HEADER_LEN: usize = 48;
pub const MAX_COMM_LEN: usize = 16;
pub const MAX_PATH_LEN: usize = 256;
pub const MAX_ARGV_PREVIEW_LEN: usize = 256;
pub const MAX_DETAIL_LEN: usize = 128;
pub const FILE_FLAG_TRUNCATED: u32 = 0x0001;
pub const MAX_EXEC_PAYLOAD_LEN: usize = 562;
pub const MAX_FILE_PAYLOAD_LEN: usize = 549;
pub const MAX_NET_PAYLOAD_LEN: usize = 35;
pub const MAX_IPC_PAYLOAD_LEN: usize = 160;
pub const MAX_HEALTH_PAYLOAD_LEN: usize = 15;
pub const MAX_RING_FRAME_LEN: usize = RING_EVENT_HEADER_LEN + MAX_EXEC_PAYLOAD_LEN;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RingbufChannel {
    Exec = 0,
    File = 1,
    Net = 2,
    Ipc = 3,
    Health = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u16)]
pub enum RingEventKind {
    Execve = 1,
    FileOpen = 2,
    FileRename = 3,
    FileUnlink = 4,
    NetConnect = 5,
    NetBind = 6,
    TaskPtrace = 7,
    CredSetuid = 8,
    ModuleOrBpfTamper = 9,
    ProcExit = 10,
    HealthLost = 11,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum RingEventVerdict {
    Observed = 0,
    Allowed = 1,
    Denied = 2,
    AuditOnly = 3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum FileOpKind {
    Open = 0,
    Rename = 1,
    Unlink = 2,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum NetOpKind {
    Connect = 0,
    Bind = 1,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum IpcOpKind {
    Ptrace = 0,
    Setuid = 1,
    BpfLoad = 2,
    KernelModule = 3,
    Kill = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WireDecodeError {
    BufferTooShort,
    InvalidMagic,
    UnsupportedVersion,
    UnknownKind,
    UnknownChannel,
    ChannelMismatch,
    UnknownVerdict,
    UnknownSubtype,
    InvalidAddressFamily,
    PayloadTooLarge,
    BoundsExceeded,
    LengthMismatch,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct RingTaskIds {
    pub tgid: u32,
    pub pid: u32,
    pub uid: u32,
    pub gid: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct RingEventHeader {
    pub magic: [u8; 4],
    pub version: u16,
    pub kind: RingEventKind,
    pub payload_len: u16,
    pub verdict: RingEventVerdict,
    pub channel: RingbufChannel,
    pub flags: u32,
    pub seq: u64,
    pub timestamp_ns: u64,
    pub tgid_pid: u64,
    pub uid_gid: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct ExecvePayload {
    pub ppid: u32,
    pub mnt_ns_inum: u32,
    pub pid_ns_inum: u32,
    pub net_ns_inum: u32,
    pub user_ns_inum: u32,
    pub cgroup_id: u64,
    pub comm_len: u8,
    pub filename_len: u16,
    pub argv_len: u16,
    pub comm: [u8; MAX_COMM_LEN],
    pub filename: [u8; MAX_PATH_LEN],
    pub argv_preview: [u8; MAX_ARGV_PREVIEW_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct FileOpPayload {
    pub op: FileOpKind,
    pub flags: u32,
    pub mode: u32,
    pub cgroup_id: u64,
    pub dev: u64,
    pub ino: u64,
    pub path_len: u16,
    pub target_path_len: u16,
    pub path: [u8; MAX_PATH_LEN],
    pub target_path: [u8; MAX_PATH_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct NetOpPayload {
    pub op: NetOpKind,
    pub family: u16,
    pub protocol: u16,
    pub port: u16,
    pub cgroup_id: u64,
    pub egress_ifindex: u32,
    pub addr: [u8; 16],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct IpcSecurityPayload {
    pub op: IpcOpKind,
    pub target_pid: u32,
    pub prev_uid: u32,
    pub next_uid: u32,
    pub cgroup_id: u64,
    pub capability_bits: u64,
    pub detail_len: u16,
    pub detail: [u8; MAX_DETAIL_LEN],
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(C)]
pub struct HealthPayload {
    pub channel: RingbufChannel,
    pub ring_utilization_permille: u16,
    pub active_hooks_mask: u32,
    pub dropped_events: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RingEventRecord {
    Execve(ExecvePayload),
    FileOp(FileOpPayload),
    NetOp(NetOpPayload),
    Ipc(IpcSecurityPayload),
    ProcExit,
    Health(HealthPayload),
}

impl RingbufChannel {
    pub const fn from_u8(raw: u8) -> Result<Self, WireDecodeError> {
        match raw {
            0 => Ok(Self::Exec),
            1 => Ok(Self::File),
            2 => Ok(Self::Net),
            3 => Ok(Self::Ipc),
            4 => Ok(Self::Health),
            _ => Err(WireDecodeError::UnknownChannel),
        }
    }
}

impl RingEventKind {
    pub const fn from_u16(raw: u16) -> Result<Self, WireDecodeError> {
        match raw {
            1 => Ok(Self::Execve),
            2 => Ok(Self::FileOpen),
            3 => Ok(Self::FileRename),
            4 => Ok(Self::FileUnlink),
            5 => Ok(Self::NetConnect),
            6 => Ok(Self::NetBind),
            7 => Ok(Self::TaskPtrace),
            8 => Ok(Self::CredSetuid),
            9 => Ok(Self::ModuleOrBpfTamper),
            10 => Ok(Self::ProcExit),
            11 => Ok(Self::HealthLost),
            _ => Err(WireDecodeError::UnknownKind),
        }
    }

    pub const fn channel(self) -> RingbufChannel {
        match self {
            Self::Execve | Self::ProcExit => RingbufChannel::Exec,
            Self::FileOpen | Self::FileRename | Self::FileUnlink => RingbufChannel::File,
            Self::NetConnect | Self::NetBind => RingbufChannel::Net,
            Self::TaskPtrace | Self::CredSetuid | Self::ModuleOrBpfTamper => RingbufChannel::Ipc,
            Self::HealthLost => RingbufChannel::Health,
        }
    }
}

impl RingEventVerdict {
    pub const fn from_u8(raw: u8) -> Result<Self, WireDecodeError> {
        match raw {
            0 => Ok(Self::Observed),
            1 => Ok(Self::Allowed),
            2 => Ok(Self::Denied),
            3 => Ok(Self::AuditOnly),
            _ => Err(WireDecodeError::UnknownVerdict),
        }
    }
}

impl FileOpKind {
    pub const fn from_u8(raw: u8) -> Result<Self, WireDecodeError> {
        match raw {
            0 => Ok(Self::Open),
            1 => Ok(Self::Rename),
            2 => Ok(Self::Unlink),
            _ => Err(WireDecodeError::UnknownSubtype),
        }
    }
}

impl NetOpKind {
    pub const fn from_u8(raw: u8) -> Result<Self, WireDecodeError> {
        match raw {
            0 => Ok(Self::Connect),
            1 => Ok(Self::Bind),
            _ => Err(WireDecodeError::UnknownSubtype),
        }
    }
}

impl IpcOpKind {
    pub const fn from_u8(raw: u8) -> Result<Self, WireDecodeError> {
        match raw {
            0 => Ok(Self::Ptrace),
            1 => Ok(Self::Setuid),
            2 => Ok(Self::BpfLoad),
            3 => Ok(Self::KernelModule),
            4 => Ok(Self::Kill),
            _ => Err(WireDecodeError::UnknownSubtype),
        }
    }
}
