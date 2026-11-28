// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::sync::{Mutex, MutexGuard};

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusSubscription, CODE_BUS_BEYOND_LOG,
    CODE_BUS_INVALID_INPUT, CODE_BUS_IO, CODE_BUS_STALE_FENCE, FencingToken, SingleCtx, TenantCtx,
};

use crate::config::{CODE_NATS_STREAM_FULL, NatsConfig};

const MAX_WIRE_HISTORY_ENTRIES: usize = 1_024;
const MAX_WIRE_SEEN_IDS: usize = 16_384;

#[derive(Debug, Clone)]
pub(crate) struct StoredNatsMessage {
    pub(crate) subject: String,
    pub(crate) msg_id: String,
    pub(crate) message: BusMessage,
}

#[derive(Debug, Default)]
pub(crate) struct PartitionState {
    pub(crate) messages: Vec<StoredNatsMessage>,
    pub(crate) total_bytes: u64,
    pub(crate) seen_msg_ids: BTreeSet<String>,
}

#[derive(Debug, Default)]
pub(crate) struct WirePartitionTracker {
    pub(crate) history: VecDeque<(String, String)>,
    seen_order: VecDeque<String>,
    seen_set: BTreeSet<String>,
    pub(crate) total_bytes: u64,
    pub(crate) total_msgs: usize,
    pub(crate) last_offset: u64,
}

#[derive(Debug, Default)]
pub(crate) struct NatsBusState {
    pub(crate) partitions: BTreeMap<(String, u32), PartitionState>,
    pub(crate) wire_trackers: BTreeMap<(String, u32), WirePartitionTracker>,
    pub(crate) consumers: BTreeMap<(String, String, u32), BusSubscription>,
    pub(crate) ack_subjects: BTreeMap<(String, String, u32, u64), String>,
}

pub(crate) struct MemAppendTarget<'a> {
    pub(crate) subject: &'a str,
    pub(crate) stream: &'a str,
    pub(crate) partition: u32,
    pub(crate) now_ms: i64,
}

impl WirePartitionTracker {
    pub(crate) fn contains_msg_id(&self, msg_id: &str) -> bool {
        self.seen_set.contains(msg_id)
    }

    pub(crate) fn record_published(&mut self, subject: String, msg_id: String, payload_len: u64) {
        self.total_bytes = self.total_bytes.saturating_add(payload_len);
        self.total_msgs = self.total_msgs.saturating_add(1);
        if self.history.len() >= MAX_WIRE_HISTORY_ENTRIES {
            let _ = self.history.pop_front();
        }
        self.history.push_back((subject, msg_id.clone()));
        if self.seen_set.insert(msg_id.clone()) {
            if self.seen_order.len() >= MAX_WIRE_SEEN_IDS
                && let Some(evicted) = self.seen_order.pop_front()
            {
                self.seen_set.remove(&evicted);
            }
            self.seen_order.push_back(msg_id);
        }
    }
}

pub(crate) fn mem_append(
    guard: &mut NatsBusState,
    config: &NatsConfig,
    ctx: &SingleCtx,
    target: MemAppendTarget<'_>,
    prepared: Vec<(String, BTreeMap<String, String>, &BusAppendMessage)>,
) -> Result<BusOffsetRange, CodedError> {
    let MemAppendTarget {
        subject,
        stream,
        partition,
        now_ms,
    } = target;
    let max_bytes_per_stream = config.max_bytes_per_stream;
    let max_msgs_per_stream = config.max_msgs_per_stream;
    let key = (stream.to_string(), partition);
    let (cur_bytes, cur_msgs, new_bytes, new_count) = {
        let existing = guard.partitions.get(&key);
        let cur_bytes = existing.map_or(0, |p| p.total_bytes);
        let cur_msgs = existing.map_or(0, |p| p.messages.len());
        let mut nb = 0u64;
        let mut nc = 0usize;
        let mut seen = BTreeSet::new();
        for (msg_id, _, msg) in &prepared {
            if existing.is_some_and(|p| p.seen_msg_ids.contains(msg_id))
                || !seen.insert(msg_id.clone())
            {
                continue;
            }
            nb = nb.saturating_add(u64::try_from(msg.payload.len()).unwrap_or(u64::MAX));
            nc = nc.saturating_add(1);
        }
        (cur_bytes, cur_msgs, nb, nc)
    };
    if cur_bytes.saturating_add(new_bytes) > max_bytes_per_stream
        || cur_msgs.saturating_add(new_count) > max_msgs_per_stream
    {
        return Err(CodedError::new(
            CODE_NATS_STREAM_FULL,
            format!("JetStream stream `{stream}` exceeded capacity limits."),
            "Return retry_after_ms flow control or increase max_bytes_per_stream.",
        ));
    }

    let part = guard.partitions.entry(key).or_default();
    let first_offset = u64::try_from(part.messages.len()).unwrap_or(u64::MAX);
    let mut last_offset = first_offset.saturating_sub(1);
    let mut inserted_any = false;
    for (msg_id, clean_hdrs, msg) in prepared {
        if !part.seen_msg_ids.insert(msg_id.clone()) {
            continue;
        }
        let offset = u64::try_from(part.messages.len()).unwrap_or(u64::MAX);
        last_offset = offset;
        inserted_any = true;
        part.total_bytes = part
            .total_bytes
            .saturating_add(u64::try_from(msg.payload.len()).unwrap_or(u64::MAX));
        part.messages.push(StoredNatsMessage {
            subject: subject.to_string(),
            msg_id,
            message: BusMessage {
                stream: stream.to_string(),
                partition,
                offset,
                organisation_id: ctx.organisation_id().clone(),
                delegation_id: ctx.delegation_id().map(str::to_string),
                delegation_epoch: ctx.delegation_epoch(),
                key: msg.key.clone(),
                headers: clean_hdrs,
                payload: msg.payload.clone(),
                appended_at_ms: now_ms,
            },
        });
    }
    if !inserted_any {
        let head = u64::try_from(part.messages.len().saturating_sub(1)).unwrap_or(0);
        return Ok(BusOffsetRange {
            first_offset: head,
            last_offset: head,
        });
    }
    Ok(BusOffsetRange {
        first_offset,
        last_offset,
    })
}

pub(crate) fn mem_subscribe(
    guard: &mut NatsBusState,
    consumer_group: &str,
    stream: &str,
    partition: u32,
    holder: &str,
    fence: FencingToken,
) -> Result<BusSubscription, CodedError> {
    let key = (consumer_group.to_string(), stream.to_string(), partition);
    let next = match guard.consumers.get(&key) {
        Some(existing) if fence < existing.fence => {
            return Err(CodedError::new(
                CODE_BUS_STALE_FENCE,
                format!(
                    "Consumer subscribe rejected stale fence {} (current {}).",
                    fence.value(),
                    existing.fence.value()
                ),
                "Re-acquire partition lease before subscribing.",
            ));
        }
        Some(existing) => BusSubscription {
            consumer_group: consumer_group.to_string(),
            stream: stream.to_string(),
            partition,
            holder: holder.to_string(),
            fence,
            committed_offset: existing.committed_offset,
            checkpoint: existing.checkpoint.clone(),
        },
        None => BusSubscription {
            consumer_group: consumer_group.to_string(),
            stream: stream.to_string(),
            partition,
            holder: holder.to_string(),
            fence,
            committed_offset: None,
            checkpoint: None,
        },
    };
    guard.consumers.insert(key, next.clone());
    Ok(next)
}

pub(crate) fn mem_fetch(
    guard: &NatsBusState,
    ctx: &TenantCtx,
    stream: &str,
    partition: u32,
    after_offset: Option<u64>,
    limit: usize,
) -> Vec<BusMessage> {
    let Some(part) = guard.partitions.get(&(stream.to_string(), partition)) else {
        return Vec::new();
    };
    part.messages
        .iter()
        .map(|stored| &stored.message)
        .filter(|m| {
            let offset_ok = after_offset.is_none_or(|prev| m.offset > prev);
            offset_ok && ctx.contains(&m.organisation_id)
        })
        .take(limit)
        .cloned()
        .collect()
}

pub(crate) fn mem_commit(
    guard: &mut NatsBusState,
    consumer_group: &str,
    stream: &str,
    partition: u32,
    offset: u64,
    checkpoint: Option<&str>,
    fence: FencingToken,
) -> Result<(), CodedError> {
    let head_len = guard
        .partitions
        .get(&(stream.to_string(), partition))
        .map_or(0, |p| p.messages.len());
    let head_u64 = u64::try_from(head_len).unwrap_or(u64::MAX);
    if head_len == 0 || offset >= head_u64 {
        return Err(CodedError::new(
            CODE_BUS_BEYOND_LOG,
            format!("Commit offset {offset} is beyond partition head."),
            "Commit an offset that has already been appended.",
        ));
    }

    let key = (consumer_group.to_string(), stream.to_string(), partition);
    let Some(sub) = guard.consumers.get_mut(&key) else {
        return Err(CodedError::new(
            CODE_BUS_STALE_FENCE,
            "Consumer is not subscribed to this partition.",
            "Call subscribe with a valid lease fence first.",
        ));
    };
    if sub.fence != fence {
        return Err(CodedError::new(
            CODE_BUS_STALE_FENCE,
            format!(
                "Commit fence {} does not match subscriber fence {}.",
                fence.value(),
                sub.fence.value()
            ),
            "Stop writing and refresh partition lease.",
        ));
    }
    if sub.committed_offset.is_some_and(|prev| offset < prev) {
        return Err(CodedError::new(
            CODE_BUS_INVALID_INPUT,
            "Committed offset cannot move backwards.",
            "Commit offsets monotonically.",
        ));
    }
    sub.committed_offset = Some(offset);
    if let Some(cp) = checkpoint {
        sub.checkpoint = Some(cp.to_string());
    }
    Ok(())
}

pub(crate) fn mem_lag(
    guard: &NatsBusState,
    consumer_group: &str,
    stream: &str,
    partition: u32,
) -> BusLag {
    let head_offset = guard
        .partitions
        .get(&(stream.to_string(), partition))
        .and_then(|p| p.messages.last().map(|m| m.message.offset));
    let committed_offset = guard
        .consumers
        .get(&(consumer_group.to_string(), stream.to_string(), partition))
        .and_then(|c| c.committed_offset);
    let pending_messages = match (head_offset, committed_offset) {
        (None, _) => 0,
        (Some(head), None) => head.saturating_add(1),
        (Some(head), Some(comm)) => head.saturating_sub(comm),
    };
    BusLag {
        stream: stream.to_string(),
        partition,
        head_offset,
        committed_offset,
        pending_messages,
    }
}

pub(crate) fn resolve_msg_id(
    msg: &BusAppendMessage,
    stream: &str,
    partition: u32,
    now_ms: i64,
    idx: usize,
) -> Result<String, CodedError> {
    let mut found: Option<String> = None;
    for (k, v) in &msg.headers {
        if k.eq_ignore_ascii_case("Nats-Msg-Id") {
            if found.as_ref().is_some_and(|prev| prev != v) {
                return Err(CodedError::new(
                    CODE_BUS_INVALID_INPUT,
                    "Duplicate Nats-Msg-Id headers with conflicting values.",
                    "Provide at most one Nats-Msg-Id header.",
                ));
            }
            found = Some(v.clone());
        }
    }
    if let Some(explicit) = found {
        return Ok(explicit);
    }
    if msg
        .key
        .chars()
        .any(|c| matches!(c, '\r' | '\n' | '\0') || c.is_control())
        || stream
            .chars()
            .any(|c| matches!(c, '\r' | '\n' | '\0') || c.is_control())
    {
        return Err(CodedError::new(
            CODE_BUS_INVALID_INPUT,
            "Bus key or stream contains forbidden control characters.",
            "Strip CR/LF/NUL characters from message keys and stream names.",
        ));
    }
    Ok(format!("{}/{stream}/p{partition}/{now_ms}/{idx}", msg.key))
}

pub(crate) fn lock_state<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, CodedError> {
    mutex.lock().map_err(|_| {
        CodedError::new(
            CODE_BUS_IO,
            "NATS JetStream bus mutex poisoned.",
            "Recreate NatsJetStreamBus.",
        )
    })
}
