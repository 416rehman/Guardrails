// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::{Mutex, MutexGuard};

use grdr_model::CodedError;
use grdr_model::error::CODE_STORE_IO;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusPort, BusSubscription,
    CODE_BUS_BEYOND_LOG, CODE_BUS_INVALID_INPUT, CODE_BUS_STALE_FENCE, FencingToken, SingleCtx,
    TenantCtx,
};

#[derive(Debug, Default)]
struct MemBusInner {
    partitions: BTreeMap<(String, u32), Vec<BusMessage>>,
    consumers: BTreeMap<(String, String, u32), BusSubscription>,
}

#[derive(Debug, Default)]
pub struct MemoryLogBus {
    inner: Mutex<MemBusInner>,
}

impl BusPort for MemoryLogBus {
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
        let mut g = lock_bus(&self.inner)?;
        let log = g.partitions.entry((stream.into(), partition)).or_default();
        let first_offset = u64::try_from(log.len()).unwrap_or(u64::MAX);
        for (idx, msg) in messages.iter().enumerate() {
            let offset = first_offset.saturating_add(u64::try_from(idx).unwrap_or(u64::MAX));
            log.push(BusMessage {
                stream: stream.into(),
                partition,
                offset,
                organisation_id: ctx.organisation_id().clone(),
                delegation_id: ctx.delegation_id().map(str::to_string),
                delegation_epoch: ctx.delegation_epoch(),
                key: msg.key.clone(),
                headers: msg.headers.clone(),
                payload: msg.payload.clone(),
                appended_at_ms: now_ms,
            });
        }
        let last_offset = first_offset
            .saturating_add(u64::try_from(messages.len().saturating_sub(1)).unwrap_or(u64::MAX));
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
        let mut g = lock_bus(&self.inner)?;
        let key = (consumer_group.into(), stream.into(), partition);
        let next = match g.consumers.get(&key) {
            Some(existing) if fence < existing.fence => {
                return Err(CodedError::new(
                    CODE_BUS_STALE_FENCE,
                    format!(
                        "Stale consumer fence {} (current {}).",
                        fence.value(),
                        existing.fence.value()
                    ),
                    "Re-acquire partition lease before subscribing.",
                ));
            }
            Some(existing) => BusSubscription {
                consumer_group: consumer_group.into(),
                stream: stream.into(),
                partition,
                holder: holder.into(),
                fence,
                committed_offset: existing.committed_offset,
                checkpoint: existing.checkpoint.clone(),
            },
            None => BusSubscription {
                consumer_group: consumer_group.into(),
                stream: stream.into(),
                partition,
                holder: holder.into(),
                fence,
                committed_offset: None,
                checkpoint: None,
            },
        };
        g.consumers.insert(key, next.clone());
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
        let g = lock_bus(&self.inner)?;
        let Some(log) = g.partitions.get(&(stream.into(), partition)) else {
            return Ok(Vec::new());
        };
        Ok(log
            .iter()
            .filter(|m| {
                let offset_ok = match after_offset {
                    Some(prev) => m.offset > prev,
                    None => true,
                };
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
        let mut g = lock_bus(&self.inner)?;
        let head_len = g
            .partitions
            .get(&(stream.into(), partition))
            .map_or(0, Vec::len);
        let head_u64 = u64::try_from(head_len).unwrap_or(u64::MAX);
        if head_len == 0 || offset >= head_u64 {
            return Err(CodedError::new(
                CODE_BUS_BEYOND_LOG,
                format!("Commit offset {offset} is beyond partition head."),
                "Commit an offset that has already been appended.",
            ));
        }
        let key = (consumer_group.into(), stream.into(), partition);
        let Some(sub) = g.consumers.get_mut(&key) else {
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
            sub.checkpoint = Some(cp.into());
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
        let g = lock_bus(&self.inner)?;
        let head_offset = g
            .partitions
            .get(&(stream.into(), partition))
            .and_then(|v| v.last().map(|m| m.offset));
        let committed_offset = g
            .consumers
            .get(&(consumer_group.into(), stream.into(), partition))
            .and_then(|c| c.committed_offset);
        let pending_messages = match (head_offset, committed_offset) {
            (None, _) => 0,
            (Some(head), None) => head.saturating_add(1),
            (Some(head), Some(comm)) => head.saturating_sub(comm),
        };
        Ok(BusLag {
            stream: stream.into(),
            partition,
            head_offset,
            committed_offset,
            pending_messages,
        })
    }
}

fn lock_bus<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, CodedError> {
    mutex.lock().map_err(|_| {
        CodedError::new(
            CODE_STORE_IO,
            "In-memory bus testkit mutex poisoned.",
            "Recreate MemoryLogBus.",
        )
    })
}
