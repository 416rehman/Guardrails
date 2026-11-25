// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusPort, BusSubscription,
    CODE_BUS_BEYOND_LOG, CODE_BUS_INVALID_INPUT, CODE_BUS_IO, CODE_BUS_STALE_FENCE, FencingToken,
    SingleCtx, TenantCtx,
};

use crate::config::{CODE_NATS_STREAM_FULL, NatsConfig, NatsTransportMode, subject_for};
use crate::wire::{encode_hpub_cmd, publish_batch_wire};

#[derive(Debug, Clone)]
struct StoredNatsMessage {
    subject: String,
    msg_id: String,
    message: BusMessage,
}

#[derive(Debug, Default)]
struct PartitionState {
    messages: Vec<StoredNatsMessage>,
    total_bytes: u64,
    seen_msg_ids: BTreeSet<String>,
}

#[derive(Debug, Default)]
struct NatsBusState {
    partitions: BTreeMap<(String, u32), PartitionState>,
    consumers: BTreeMap<(String, String, u32), BusSubscription>,
}

#[derive(Debug)]
pub struct NatsJetStreamBus {
    config: NatsConfig,
    state: Mutex<NatsBusState>,
}

impl NatsJetStreamBus {
    pub fn open_embedded() -> Result<Self, CodedError> {
        Self::connect(NatsConfig::embedded_default())
    }

    pub fn connect(config: NatsConfig) -> Result<Self, CodedError> {
        config.validate()?;
        Ok(Self {
            config,
            state: Mutex::new(NatsBusState::default()),
        })
    }

    pub fn config(&self) -> &NatsConfig {
        &self.config
    }

    pub fn subject_history(
        &self,
        stream: &str,
        partition: u32,
    ) -> Result<Vec<(String, String)>, CodedError> {
        let guard = lock_state(&self.state)?;
        let Some(part) = guard.partitions.get(&(stream.to_string(), partition)) else {
            return Ok(Vec::new());
        };
        Ok(part
            .messages
            .iter()
            .map(|m| (m.subject.clone(), m.msg_id.clone()))
            .collect())
    }
}

impl BusPort for NatsJetStreamBus {
    fn append(
        &self,
        ctx: &SingleCtx,
        stream: &str,
        partition: u32,
        messages: &[BusAppendMessage],
        now_ms: i64,
    ) -> Result<BusOffsetRange, CodedError> {
        if stream.trim().is_empty() || messages.is_empty() {
            return Err(CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Stream name and message batch must be non-empty.",
                "Provide a valid stream name and at least one message.",
            ));
        }

        let subject = subject_for(ctx.organisation_id(), stream, partition);
        let mut prepared = Vec::with_capacity(messages.len());
        for (idx, msg) in messages.iter().enumerate() {
            let msg_id = resolve_msg_id(msg, stream, partition, now_ms, idx)?;
            let frame = encode_hpub_cmd(&subject, &msg_id, &msg.headers, &msg.payload)?;
            prepared.push((msg_id, frame, msg));
        }

        let (wire_frames, all_dup_range) = {
            let guard = lock_state(&self.state)?;
            let key = (stream.to_string(), partition);
            let existing = guard.partitions.get(&key);
            let cur_bytes = existing.map_or(0, |p| p.total_bytes);
            let cur_msgs = existing.map_or(0, |p| p.messages.len());

            let mut new_bytes = 0u64;
            let mut new_count = 0usize;
            let mut batch_seen = BTreeSet::new();
            let mut frames_to_send = Vec::new();
            for (msg_id, frame, msg) in &prepared {
                let already_seen = existing.is_some_and(|p| p.seen_msg_ids.contains(msg_id))
                    || !batch_seen.insert(msg_id.clone());
                if already_seen {
                    continue;
                }
                new_bytes =
                    new_bytes.saturating_add(u64::try_from(msg.payload.len()).unwrap_or(u64::MAX));
                new_count = new_count.saturating_add(1);
                frames_to_send.push(frame.clone());
            }

            if cur_bytes.saturating_add(new_bytes) > self.config.max_bytes_per_stream
                || cur_msgs.saturating_add(new_count) > self.config.max_msgs_per_stream
            {
                return Err(CodedError::new(
                    CODE_NATS_STREAM_FULL,
                    format!("JetStream stream `{stream}` exceeded capacity limits."),
                    "Return retry_after_ms flow control or increase max_bytes_per_stream.",
                ));
            }
            let head = u64::try_from(cur_msgs.saturating_sub(1)).unwrap_or(u64::MAX);
            (
                frames_to_send,
                (new_count == 0).then_some(BusOffsetRange {
                    first_offset: head,
                    last_offset: head,
                }),
            )
        };

        if let Some(dup_range) = all_dup_range {
            return Ok(dup_range);
        }

        if let NatsTransportMode::JetStreamTcp { server_url } = &self.config.transport {
            publish_batch_wire(
                server_url,
                &self.config.client_name,
                self.config.connect_timeout_ms,
                &wire_frames,
            )?;
        }

        let mut guard = lock_state(&self.state)?;
        let part = guard
            .partitions
            .entry((stream.to_string(), partition))
            .or_default();

        let mut new_bytes = 0u64;
        let mut new_count = 0usize;
        let mut check_seen = BTreeSet::new();
        for (msg_id, _, msg) in &prepared {
            if !part.seen_msg_ids.contains(msg_id) && check_seen.insert(msg_id.clone()) {
                new_bytes =
                    new_bytes.saturating_add(u64::try_from(msg.payload.len()).unwrap_or(u64::MAX));
                new_count = new_count.saturating_add(1);
            }
        }
        if part.total_bytes.saturating_add(new_bytes) > self.config.max_bytes_per_stream
            || part.messages.len().saturating_add(new_count) > self.config.max_msgs_per_stream
        {
            return Err(CodedError::new(
                CODE_NATS_STREAM_FULL,
                format!("JetStream stream `{stream}` exceeded capacity limits."),
                "Return retry_after_ms flow control or increase max_bytes_per_stream.",
            ));
        }

        let first_offset = u64::try_from(part.messages.len()).unwrap_or(u64::MAX);
        let mut last_offset = first_offset.saturating_sub(1);
        let mut inserted_any = false;
        for (msg_id, _, msg) in prepared {
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
                subject: subject.clone(),
                msg_id,
                message: BusMessage {
                    stream: stream.to_string(),
                    partition,
                    offset,
                    organisation_id: ctx.organisation_id().clone(),
                    delegation_id: ctx.delegation_id().map(str::to_string),
                    delegation_epoch: ctx.delegation_epoch(),
                    key: msg.key.clone(),
                    headers: msg.headers.clone(),
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

    fn subscribe(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        holder: &str,
        fence: FencingToken,
        _expiry_ms: i64,
    ) -> Result<BusSubscription, CodedError> {
        let mut guard = lock_state(&self.state)?;
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

    fn fetch(
        &self,
        ctx: &TenantCtx,
        stream: &str,
        partition: u32,
        after_offset: Option<u64>,
        limit: usize,
    ) -> Result<Vec<BusMessage>, CodedError> {
        let guard = lock_state(&self.state)?;
        let Some(part) = guard.partitions.get(&(stream.to_string(), partition)) else {
            return Ok(Vec::new());
        };
        Ok(part
            .messages
            .iter()
            .map(|stored| &stored.message)
            .filter(|m| {
                let offset_ok = after_offset.is_none_or(|prev| m.offset > prev);
                offset_ok && ctx.contains(&m.organisation_id)
            })
            .take(limit)
            .cloned()
            .collect())
    }

    fn commit(
        &self,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        offset: u64,
        checkpoint: Option<&str>,
        fence: FencingToken,
    ) -> Result<(), CodedError> {
        let mut guard = lock_state(&self.state)?;
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

    fn lag(
        &self,
        _ctx: &TenantCtx,
        consumer_group: &str,
        stream: &str,
        partition: u32,
    ) -> Result<BusLag, CodedError> {
        let guard = lock_state(&self.state)?;
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
        Ok(BusLag {
            stream: stream.to_string(),
            partition,
            head_offset,
            committed_offset,
            pending_messages,
        })
    }
}

fn resolve_msg_id(
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

fn lock_state<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, CodedError> {
    mutex.lock().map_err(|_| {
        CodedError::new(
            CODE_BUS_IO,
            "NATS JetStream bus mutex poisoned.",
            "Recreate NatsJetStreamBus.",
        )
    })
}
