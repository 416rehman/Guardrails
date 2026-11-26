// SPDX-License-Identifier: GPL-2.0-only OR BSD-2-Clause
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![no_std]
#![deny(clippy::arithmetic_side_effects)]

pub mod hooks;
pub mod hooks_inventory;
pub mod lineage;
pub mod wire;
pub mod wire_bytes;
pub mod wire_codec;

pub use hooks::{
    EnforcementMode, ExpectationKey, ExpectationRule, HookAuditReason, HookDecision,
    HookEvalOutcome, HookPolicyState, fnv1a_64,
};
pub use hooks_inventory::{
    BpfAttachKind, BpfHookSpec, BpfMapKind, BpfMapSpec, hook_inventory, map_inventory,
};
pub use lineage::{
    AgentRootSpec, DEFAULT_LINEAGE_CAPACITY, IsolationScope, LineageError, LineageState,
    LineageTable, MAX_LINEAGE_DEPTH, ProcLineageEntry, TaskNsIds,
};
pub use wire::{
    ExecvePayload, FILE_FLAG_TRUNCATED, FileOpKind, FileOpPayload, HealthPayload, IpcOpKind,
    IpcSecurityPayload, MAX_ARGV_PREVIEW_LEN, MAX_COMM_LEN, MAX_DETAIL_LEN, MAX_PATH_LEN,
    MAX_RING_FRAME_LEN, NetOpKind, NetOpPayload, RING_EVENT_HEADER_LEN, RING_EVENT_MAGIC,
    RING_EVENT_VERSION, RINGBUF_SIZE_PER_CPU_BYTES, RingEventHeader, RingEventKind,
    RingEventRecord, RingEventVerdict, RingTaskIds, RingbufChannel, WireDecodeError,
};
pub use wire_codec::{decode_event_frame, encode_event_frame};
