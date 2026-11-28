// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;
use std::sync::Mutex;

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusPort, BusSubscription,
    CODE_BUS_BEYOND_LOG, CODE_BUS_INVALID_INPUT, CODE_BUS_STALE_FENCE, FencingToken, SingleCtx,
    TenantCtx,
};

use crate::bus_mem::{
    MemAppendTarget, NatsBusState, lock_state, mem_append, mem_commit, mem_fetch, mem_lag,
    mem_subscribe, resolve_msg_id,
};
use crate::config::{
    CODE_NATS_STREAM_FULL, CODE_NATS_WIRE, NatsConfig, NatsTransportMode, subject_for,
};
use crate::js_wire::{
    JsPullParams, ack_js_message, ensure_js_consumer, publish_js_batch, pull_js_messages,
    query_js_head_offset, query_js_lag,
};
use crate::wire::{NatsWireConnection, NatsWireOptions};
use crate::wire_codec::{encode_hpub_cmd, strip_reserved_grdr_headers};

const MAX_DURABLE_CACHED_ACKS: usize = 4_096;

#[derive(Debug)]
struct NatsJetStreamBusInner {
    config: NatsConfig,
    state: Mutex<NatsBusState>,
    wire_conn: Mutex<Option<NatsWireConnection>>,
}

#[derive(Debug)]
pub struct NatsJetStreamBus {
    inner: Box<NatsJetStreamBusInner>,
}

impl NatsJetStreamBus {
    pub fn open_embedded() -> Result<Self, CodedError> {
        Self::connect(NatsConfig::embedded_default())
    }

    pub fn connect(config: NatsConfig) -> Result<Self, CodedError> {
        config.validate()?;
        Ok(Self {
            inner: Box::new(NatsJetStreamBusInner {
                config,
                state: Mutex::new(NatsBusState::default()),
                wire_conn: Mutex::new(None),
            }),
        })
    }

    pub fn config(&self) -> &NatsConfig {
        &self.inner.config
    }

    pub fn subject_history(
        &self,
        stream: &str,
        partition: u32,
    ) -> Result<Vec<(String, String)>, CodedError> {
        let guard = lock_state(&self.inner.state)?;
        if let Some(tracker) = guard.wire_trackers.get(&(stream.to_string(), partition)) {
            return Ok(tracker.history.iter().cloned().collect());
        }
        let Some(part) = guard.partitions.get(&(stream.to_string(), partition)) else {
            return Ok(Vec::new());
        };
        Ok(part
            .messages
            .iter()
            .map(|m| (m.subject.clone(), m.msg_id.clone()))
            .collect())
    }

    fn wire_opts(&self) -> NatsWireOptions<'_> {
        NatsWireOptions {
            client_name: &self.inner.config.client_name,
            timeout_ms: self.inner.config.connect_timeout_ms,
            tls_ca_pem: self.inner.config.tls_ca_pem.as_deref(),
            tls_handshake: self.inner.config.tls_handshake,
            auth: self.inner.config.auth.as_ref(),
        }
    }

    fn with_jetstream_conn<F, R>(&self, server_url: &str, f: F) -> Result<R, CodedError>
    where
        F: FnOnce(&mut NatsWireConnection) -> Result<R, CodedError>,
    {
        let mut slot = lock_state(&self.inner.wire_conn)?;
        let mut conn = match slot.take() {
            Some(c) => c,
            None => NatsWireConnection::connect(server_url, &self.wire_opts())?,
        };
        if !conn.is_jetstream() {
            conn.close();
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                "NATS server did not enable JetStream support; refusing unacknowledged downgrade.",
                "Connect to a JetStream-enabled NATS cluster over verified TLS.",
            ));
        }
        let res = f(&mut conn);
        if res.is_ok() && conn.is_jetstream() {
            *slot = Some(conn);
        } else {
            conn.close();
        }
        res
    }

    fn validate_wire_commit(
        &self,
        server_url: &str,
        consumer_group: &str,
        stream: &str,
        partition: u32,
        offset: u64,
        fence: FencingToken,
    ) -> Result<Vec<String>, CodedError> {
        let spec = self.inner.config.stream_spec(stream, partition);
        let head =
            self.with_jetstream_conn(server_url, |conn| query_js_head_offset(conn, &spec))?;
        if head.is_none_or(|h| offset > h) {
            return Err(CodedError::new(
                CODE_BUS_BEYOND_LOG,
                format!("Commit offset {offset} is beyond partition head."),
                "Commit an offset that has already been appended.",
            ));
        }

        let mut guard = lock_state(&self.inner.state)?;
        let key = (consumer_group.to_string(), stream.to_string(), partition);
        let Some(sub) = guard.consumers.get(&key) else {
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

        let existing: Vec<(u64, String)> = guard
            .ack_subjects
            .iter()
            .filter(|((cg, st, p, off), _)| {
                cg == consumer_group && st == stream && *p == partition && *off <= offset
            })
            .map(|((_, _, _, off), subj)| (*off, subj.clone()))
            .collect();
        for (off, _) in &existing {
            guard.ack_subjects.remove(&(
                consumer_group.to_string(),
                stream.to_string(),
                partition,
                *off,
            ));
        }
        Ok(existing.into_iter().map(|(_, s)| s).collect())
    }

    fn append_wire_mode(
        &self,
        server_url: &str,
        ctx: &SingleCtx,
        stream: &str,
        partition: u32,
        messages: &[BusAppendMessage],
        now_ms: i64,
    ) -> Result<BusOffsetRange, CodedError> {
        let subject = subject_for(ctx.organisation_id(), stream, partition);
        let mut prepared = Vec::with_capacity(messages.len());
        for (idx, msg) in messages.iter().enumerate() {
            let msg_id = resolve_msg_id(msg, stream, partition, now_ms, idx)?;
            let clean_hdrs = strip_reserved_grdr_headers(&msg.headers);
            let _ = encode_hpub_cmd(&subject, &msg_id, &clean_hdrs, &msg.payload)?;
            prepared.push((msg_id, msg));
        }

        let (js_pairs_new, all_dup_range) = {
            let guard = lock_state(&self.inner.state)?;
            let key = (stream.to_string(), partition);
            let existing = guard.wire_trackers.get(&key);
            let cur_bytes = existing.map_or(0, |t| t.total_bytes);
            let cur_msgs = existing.map_or(0, |t| t.total_msgs);

            let mut new_bytes = 0u64;
            let mut new_count = 0usize;
            let mut batch_seen = BTreeSet::new();
            let mut pairs = Vec::new();
            for (msg_id, msg) in &prepared {
                let already = existing.is_some_and(|t| t.contains_msg_id(msg_id))
                    || !batch_seen.insert(msg_id.clone());
                if already {
                    continue;
                }
                new_bytes =
                    new_bytes.saturating_add(u64::try_from(msg.payload.len()).unwrap_or(u64::MAX));
                new_count = new_count.saturating_add(1);
                pairs.push((msg_id.clone(), *msg));
            }
            if cur_bytes.saturating_add(new_bytes) > self.inner.config.max_bytes_per_stream
                || cur_msgs.saturating_add(new_count) > self.inner.config.max_msgs_per_stream
            {
                return Err(CodedError::new(
                    CODE_NATS_STREAM_FULL,
                    format!("JetStream stream `{stream}` exceeded capacity limits."),
                    "Return retry_after_ms flow control or increase max_bytes_per_stream.",
                ));
            }
            let dup = (new_count == 0).then(|| {
                let off = existing.map_or(0, |t| t.last_offset);
                BusOffsetRange {
                    first_offset: off,
                    last_offset: off,
                }
            });
            (pairs, dup)
        };
        if let Some(dup_range) = all_dup_range {
            return Ok(dup_range);
        }

        let spec = self.inner.config.stream_spec(stream, partition);
        let range = self.with_jetstream_conn(server_url, |conn| {
            publish_js_batch(conn, &spec, ctx, &subject, &js_pairs_new, now_ms)
        })?;

        let mut guard = lock_state(&self.inner.state)?;
        let tracker = guard
            .wire_trackers
            .entry((stream.to_string(), partition))
            .or_default();
        for (msg_id, msg) in js_pairs_new {
            let plen = u64::try_from(msg.payload.len()).unwrap_or(u64::MAX);
            tracker.record_published(subject.clone(), msg_id, plen);
        }
        tracker.last_offset = range.last_offset;
        Ok(range)
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
        validate_bus_token("stream", stream)?;
        if messages.is_empty() {
            return Err(CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Stream name and message batch must be non-empty.",
                "Provide a valid stream name and at least one message.",
            ));
        }
        if let NatsTransportMode::JetStreamTcp { server_url } = &self.inner.config.transport {
            let url = server_url.clone();
            self.append_wire_mode(&url, ctx, stream, partition, messages, now_ms)
        } else {
            let subject = subject_for(ctx.organisation_id(), stream, partition);
            let mut prepared = Vec::with_capacity(messages.len());
            for (idx, msg) in messages.iter().enumerate() {
                let msg_id = resolve_msg_id(msg, stream, partition, now_ms, idx)?;
                let clean_hdrs = strip_reserved_grdr_headers(&msg.headers);
                let _ = encode_hpub_cmd(&subject, &msg_id, &clean_hdrs, &msg.payload)?;
                prepared.push((msg_id, clean_hdrs, msg));
            }
            let mut guard = lock_state(&self.inner.state)?;
            mem_append(
                &mut guard,
                &self.inner.config,
                ctx,
                MemAppendTarget {
                    subject: &subject,
                    stream,
                    partition,
                    now_ms,
                },
                prepared,
            )
        }
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
        validate_bus_token("consumer_group", consumer_group)?;
        validate_bus_token("stream", stream)?;
        validate_bus_token("holder", holder)?;
        if let NatsTransportMode::JetStreamTcp { server_url } = &self.inner.config.transport {
            let spec = self.inner.config.stream_spec(stream, partition);
            let url = server_url.clone();
            self.with_jetstream_conn(&url, |conn| {
                let _ = ensure_js_consumer(conn, &spec, consumer_group, stream, partition)?;
                Ok(())
            })?;
        }
        let mut guard = lock_state(&self.inner.state)?;
        mem_subscribe(&mut guard, consumer_group, stream, partition, holder, fence)
    }

    fn fetch(
        &self,
        ctx: &TenantCtx,
        stream: &str,
        partition: u32,
        after_offset: Option<u64>,
        limit: usize,
    ) -> Result<Vec<BusMessage>, CodedError> {
        validate_bus_token("stream", stream)?;
        if limit == 0 {
            return Ok(Vec::new());
        }
        if let NatsTransportMode::JetStreamTcp { server_url } = &self.inner.config.transport {
            let spec = self.inner.config.stream_spec(stream, partition);
            let url = server_url.clone();
            let pull = self.with_jetstream_conn(&url, |conn| {
                pull_js_messages(
                    conn,
                    &JsPullParams {
                        spec: &spec,
                        consumer_group: "",
                        stream,
                        partition,
                        ctx: Some(ctx),
                        after_offset,
                        limit,
                    },
                )
            })?;
            return Ok(pull.messages.into_iter().take(limit).collect());
        }
        let guard = lock_state(&self.inner.state)?;
        Ok(mem_fetch(
            &guard,
            ctx,
            stream,
            partition,
            after_offset,
            limit,
        ))
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
        validate_bus_token("consumer_group", consumer_group)?;
        validate_bus_token("stream", stream)?;
        if let NatsTransportMode::JetStreamTcp { server_url } = &self.inner.config.transport {
            let url = server_url.clone();
            let spec = self.inner.config.stream_spec(stream, partition);
            let mut ack_subjects =
                self.validate_wire_commit(&url, consumer_group, stream, partition, offset, fence)?;
            let mut extra_acks = Vec::new();
            self.with_jetstream_conn(&url, |conn| {
                if ack_subjects.is_empty() {
                    let batch = usize::try_from(offset.saturating_add(1)).unwrap_or(1_024);
                    let pulled = pull_js_messages(
                        conn,
                        &JsPullParams {
                            spec: &spec,
                            consumer_group,
                            stream,
                            partition,
                            ctx: None,
                            after_offset: None,
                            limit: batch,
                        },
                    )?;
                    for (off, subj) in pulled.ack_subjects {
                        if off <= offset {
                            ack_subjects.push(subj);
                        } else {
                            extra_acks.push((off, subj));
                        }
                    }
                }
                for ack_subj in &ack_subjects {
                    ack_js_message(conn, ack_subj)?;
                }
                Ok(())
            })?;

            let mut guard = lock_state(&self.inner.state)?;
            for (off, subj) in extra_acks {
                if guard.ack_subjects.len() < MAX_DURABLE_CACHED_ACKS {
                    guard.ack_subjects.insert(
                        (
                            consumer_group.to_string(),
                            stream.to_string(),
                            partition,
                            off,
                        ),
                        subj,
                    );
                }
            }
            let key = (consumer_group.to_string(), stream.to_string(), partition);
            let Some(sub) = guard.consumers.get_mut(&key) else {
                return Err(CodedError::new(
                    CODE_BUS_STALE_FENCE,
                    "Consumer subscription disappeared during commit.",
                    "Re-acquire partition lease before committing.",
                ));
            };
            if sub.fence != fence {
                return Err(CodedError::new(
                    CODE_BUS_STALE_FENCE,
                    format!(
                        "Commit fence {} superseded by concurrent fence {}.",
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
            return Ok(());
        }
        let mut guard = lock_state(&self.inner.state)?;
        mem_commit(
            &mut guard,
            consumer_group,
            stream,
            partition,
            offset,
            checkpoint,
            fence,
        )
    }

    fn lag(
        &self,
        _ctx: &TenantCtx,
        consumer_group: &str,
        stream: &str,
        partition: u32,
    ) -> Result<BusLag, CodedError> {
        validate_bus_token("consumer_group", consumer_group)?;
        validate_bus_token("stream", stream)?;
        if let NatsTransportMode::JetStreamTcp { server_url } = &self.inner.config.transport {
            let spec = self.inner.config.stream_spec(stream, partition);
            let url = server_url.clone();
            return self.with_jetstream_conn(&url, |conn| {
                query_js_lag(conn, &spec, consumer_group, stream, partition)
            });
        }
        let guard = lock_state(&self.inner.state)?;
        Ok(mem_lag(&guard, consumer_group, stream, partition))
    }
}

fn validate_bus_token(field: &str, value: &str) -> Result<(), CodedError> {
    if value.trim().is_empty()
        || value
            .chars()
            .any(|c| matches!(c, '\r' | '\n' | '\0') || c.is_control())
    {
        return Err(CodedError::new(
            CODE_BUS_INVALID_INPUT,
            format!("NATS bus field `{field}` cannot be empty or contain control characters."),
            "Provide a valid non-empty identifier without control characters.",
        ));
    }
    Ok(())
}
