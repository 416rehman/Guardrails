// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::wire::{RINGBUF_SIZE_PER_CPU_BYTES, RingbufChannel};

const HOOKS: &[BpfHookSpec] = &[
    BpfHookSpec {
        name: "lsm_bprm_check_security",
        section: "lsm/bprm_check_security",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::Exec,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_file_open",
        section: "lsm/file_open",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::File,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_inode_unlink",
        section: "lsm/inode_unlink",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::File,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_inode_rename",
        section: "lsm/inode_rename",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::File,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_socket_connect",
        section: "lsm/socket_connect",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::Net,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_socket_bind",
        section: "lsm/socket_bind",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::Net,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_ptrace_access_check",
        section: "lsm/ptrace_access_check",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::Ipc,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_task_fix_setuid",
        section: "lsm/task_fix_setuid",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::Ipc,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_bpf",
        section: "lsm/bpf",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::Ipc,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "lsm_kernel_module_request",
        section: "lsm/kernel_module_request",
        attach: BpfAttachKind::Lsm,
        channel: RingbufChannel::Ipc,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: true,
    },
    BpfHookSpec {
        name: "tp_sched_process_fork",
        section: "tracepoint/sched/sched_process_fork",
        attach: BpfAttachKind::Tracepoint,
        channel: RingbufChannel::Exec,
        enforcing: false,
        min_kernel_major: 5,
        min_kernel_minor: 8,
        requires_bpf_lsm: false,
    },
    BpfHookSpec {
        name: "tp_sched_process_exec",
        section: "tracepoint/sched/sched_process_exec",
        attach: BpfAttachKind::Tracepoint,
        channel: RingbufChannel::Exec,
        enforcing: false,
        min_kernel_major: 5,
        min_kernel_minor: 8,
        requires_bpf_lsm: false,
    },
    BpfHookSpec {
        name: "tp_sched_process_exit",
        section: "tracepoint/sched/sched_process_exit",
        attach: BpfAttachKind::Tracepoint,
        channel: RingbufChannel::Exec,
        enforcing: false,
        min_kernel_major: 5,
        min_kernel_minor: 8,
        requires_bpf_lsm: false,
    },
    BpfHookSpec {
        name: "fmod_ret_ptrace_fallback",
        section: "fmod_ret/security_ptrace_access_check",
        attach: BpfAttachKind::FmodRet,
        channel: RingbufChannel::Ipc,
        enforcing: true,
        min_kernel_major: 5,
        min_kernel_minor: 7,
        requires_bpf_lsm: false,
    },
    BpfHookSpec {
        name: "cgroup_connect4",
        section: "cgroup/connect4",
        attach: BpfAttachKind::CgroupSockAddr,
        channel: RingbufChannel::Net,
        enforcing: true,
        min_kernel_major: 4,
        min_kernel_minor: 17,
        requires_bpf_lsm: false,
    },
    BpfHookSpec {
        name: "cgroup_connect6",
        section: "cgroup/connect6",
        attach: BpfAttachKind::CgroupSockAddr,
        channel: RingbufChannel::Net,
        enforcing: true,
        min_kernel_major: 4,
        min_kernel_minor: 17,
        requires_bpf_lsm: false,
    },
];

const MAPS: &[BpfMapSpec] = &[
    BpfMapSpec {
        name: "exec_events",
        kind: BpfMapKind::RingBuf,
        max_entries: RINGBUF_SIZE_PER_CPU_BYTES,
        ringbuf_bytes: RINGBUF_SIZE_PER_CPU_BYTES,
    },
    BpfMapSpec {
        name: "file_events",
        kind: BpfMapKind::RingBuf,
        max_entries: RINGBUF_SIZE_PER_CPU_BYTES,
        ringbuf_bytes: RINGBUF_SIZE_PER_CPU_BYTES,
    },
    BpfMapSpec {
        name: "net_events",
        kind: BpfMapKind::RingBuf,
        max_entries: RINGBUF_SIZE_PER_CPU_BYTES,
        ringbuf_bytes: RINGBUF_SIZE_PER_CPU_BYTES,
    },
    BpfMapSpec {
        name: "ipc_events",
        kind: BpfMapKind::RingBuf,
        max_entries: RINGBUF_SIZE_PER_CPU_BYTES,
        ringbuf_bytes: RINGBUF_SIZE_PER_CPU_BYTES,
    },
    BpfMapSpec {
        name: "health_events",
        kind: BpfMapKind::RingBuf,
        max_entries: RINGBUF_SIZE_PER_CPU_BYTES,
        ringbuf_bytes: RINGBUF_SIZE_PER_CPU_BYTES,
    },
    BpfMapSpec {
        name: "proc_lineage",
        kind: BpfMapKind::TaskStorage,
        max_entries: 0,
        ringbuf_bytes: 0,
    },
    BpfMapSpec {
        name: "expectation_map",
        kind: BpfMapKind::LruHash,
        max_entries: 16_384,
        ringbuf_bytes: 0,
    },
    BpfMapSpec {
        name: "protected_paths",
        kind: BpfMapKind::Hash,
        max_entries: 1_024,
        ringbuf_bytes: 0,
    },
    BpfMapSpec {
        name: "hook_config",
        kind: BpfMapKind::Array,
        max_entries: 1,
        ringbuf_bytes: 0,
    },
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BpfAttachKind {
    Lsm = 0,
    LsmSleepable = 1,
    Tracepoint = 2,
    RawTracepoint = 3,
    FmodRet = 4,
    CgroupSock = 5,
    CgroupSockAddr = 6,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum BpfMapKind {
    RingBuf = 0,
    TaskStorage = 1,
    LruHash = 2,
    Hash = 3,
    Array = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfHookSpec {
    pub name: &'static str,
    pub section: &'static str,
    pub attach: BpfAttachKind,
    pub channel: RingbufChannel,
    pub enforcing: bool,
    pub min_kernel_major: u16,
    pub min_kernel_minor: u16,
    pub requires_bpf_lsm: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfMapSpec {
    pub name: &'static str,
    pub kind: BpfMapKind,
    pub max_entries: u32,
    pub ringbuf_bytes: u32,
}

pub const fn hook_inventory() -> &'static [BpfHookSpec] {
    HOOKS
}

pub const fn map_inventory() -> &'static [BpfMapSpec] {
    MAPS
}
