// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use rusqlite::{Connection, OptionalExtension};

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusSubscription, CODE_BUS_IO,
    FencingToken, OrgId, SingleCtx, TenantCtx,
};

use crate::bus_pg_wire::{
    beyond_log_err, bus_codec_err, compute_pending, non_monotonic_commit_err, stale_fence_err,
};

pub(crate) const OFFLINE_BUS_SCHEMA_SQL: &str = "
CREATE TABLE IF NOT EXISTS bus_partition (
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    next_offset INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (stream, partition)
);
CREATE TABLE IF NOT EXISTS bus_message (
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    offset_seq INTEGER NOT NULL,
    organisation_id TEXT NOT NULL,
    delegation_id TEXT,
    delegation_epoch INTEGER,
    msg_key TEXT NOT NULL,
    headers_json TEXT NOT NULL,
    payload BLOB NOT NULL,
    appended_at_ms INTEGER NOT NULL,
    PRIMARY KEY (stream, partition, offset_seq)
);
CREATE TABLE IF NOT EXISTS bus_consumer (
    consumer_group TEXT NOT NULL,
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    holder TEXT NOT NULL,
    fence INTEGER NOT NULL,
    expiry_ms INTEGER NOT NULL,
    committed_offset INTEGER,
    checkpoint TEXT,
    PRIMARY KEY (consumer_group, stream, partition)
);
";

pub(crate) fn append_offline(
    conn: &mut Connection,
    ctx: &SingleCtx,
    stream: &str,
    partition: u32,
    messages: &[BusAppendMessage],
    now_ms: i64,
) -> Result<BusOffsetRange, CodedError> {
    let tx = conn.transaction().map_err(bus_sql_err)?;
    let next: Option<i64> = tx
        .query_row(
            "SELECT next_offset FROM bus_partition WHERE stream = ?1 AND partition = ?2",
            rusqlite::params![stream, i64::from(partition)],
            |r| r.get(0),
        )
        .optional()
        .map_err(bus_sql_err)?;
    let start_offset = u64::try_from(next.unwrap_or(0)).unwrap_or(0);
    let count = u64::try_from(messages.len()).unwrap_or(0);
    let new_next = start_offset.saturating_add(count);
    tx.execute(
        "INSERT INTO bus_partition (stream, partition, next_offset) VALUES (?1, ?2, ?3)
         ON CONFLICT(stream, partition) DO UPDATE SET next_offset = excluded.next_offset",
        rusqlite::params![
            stream,
            i64::from(partition),
            i64::try_from(new_next).unwrap_or(i64::MAX)
        ],
    )
    .map_err(bus_sql_err)?;

    for (idx, msg) in messages.iter().enumerate() {
        let off = start_offset.saturating_add(u64::try_from(idx).unwrap_or(0));
        let hdr_json = serde_json::to_string(&msg.headers).map_err(bus_codec_err)?;
        tx.execute(
            "INSERT INTO bus_message (
                stream, partition, offset_seq, organisation_id, delegation_id,
                delegation_epoch, msg_key, headers_json, payload, appended_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
            rusqlite::params![
                stream,
                i64::from(partition),
                i64::try_from(off).unwrap_or(i64::MAX),
                ctx.organisation_id().as_str(),
                ctx.delegation_id().map(str::to_string),
                ctx.delegation_epoch().and_then(|e| i64::try_from(e).ok()),
                msg.key,
                hdr_json,
                msg.payload,
                now_ms,
            ],
        )
        .map_err(bus_sql_err)?;
    }
    tx.commit().map_err(bus_sql_err)?;
    Ok(BusOffsetRange {
        first_offset: start_offset,
        last_offset: new_next.saturating_sub(1),
    })
}

pub(crate) fn subscribe_offline(
    conn: &mut Connection,
    consumer_group: &str,
    stream: &str,
    partition: u32,
    holder: &str,
    fence: FencingToken,
    expiry_ms: i64,
) -> Result<BusSubscription, CodedError> {
    let tx = conn.transaction().map_err(bus_sql_err)?;
    let existing: Option<(i64, Option<i64>, Option<String>)> = tx
        .query_row(
            "SELECT fence, committed_offset, checkpoint FROM bus_consumer
             WHERE consumer_group = ?1 AND stream = ?2 AND partition = ?3",
            rusqlite::params![consumer_group, stream, i64::from(partition)],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(bus_sql_err)?;
    let (committed_offset, checkpoint) = match existing {
        Some((cur_fence, co, cp)) => {
            let cur_u64 = u64::try_from(cur_fence).unwrap_or(0);
            if fence.value() < cur_u64 {
                return Err(stale_fence_err(cur_u64, fence.value()));
            }
            (co.and_then(|v| u64::try_from(v).ok()), cp)
        }
        None => (None, None),
    };
    tx.execute(
        "INSERT INTO bus_consumer (
            consumer_group, stream, partition, holder, fence, expiry_ms, committed_offset, checkpoint
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)
         ON CONFLICT(consumer_group, stream, partition) DO UPDATE SET
            holder = excluded.holder,
            fence = excluded.fence,
            expiry_ms = excluded.expiry_ms",
        rusqlite::params![
            consumer_group,
            stream,
            i64::from(partition),
            holder,
            i64::try_from(fence.value()).unwrap_or(i64::MAX),
            expiry_ms,
            committed_offset.and_then(|v| i64::try_from(v).ok()),
            checkpoint,
        ],
    )
    .map_err(bus_sql_err)?;
    tx.commit().map_err(bus_sql_err)?;
    Ok(BusSubscription {
        consumer_group: consumer_group.to_string(),
        stream: stream.to_string(),
        partition,
        holder: holder.to_string(),
        fence,
        committed_offset,
        checkpoint,
    })
}

pub(crate) fn fetch_offline(
    conn: &Connection,
    ctx: &TenantCtx,
    stream: &str,
    partition: u32,
    after_offset: Option<u64>,
    limit: usize,
) -> Result<Vec<BusMessage>, CodedError> {
    let min_off = after_offset.map_or(0, |o| o.saturating_add(1));
    let orgs: Vec<&str> = ctx
        .organisation_ids()
        .into_iter()
        .map(|o| o.as_str())
        .collect();
    if orgs.is_empty() {
        return Ok(Vec::new());
    }
    let placeholders = (0..orgs.len())
        .map(|i| format!("?{}", 5usize.saturating_add(i)))
        .collect::<Vec<_>>()
        .join(", ");
    let sql = format!(
        "SELECT offset_seq, organisation_id, delegation_id, delegation_epoch, msg_key, headers_json, payload, appended_at_ms
         FROM bus_message
         WHERE stream = ?1 AND partition = ?2 AND offset_seq >= ?3 AND organisation_id IN ({placeholders})
         ORDER BY offset_seq ASC LIMIT ?4"
    );
    let mut params: Vec<rusqlite::types::Value> = vec![
        rusqlite::types::Value::from(stream.to_string()),
        rusqlite::types::Value::from(i64::from(partition)),
        rusqlite::types::Value::from(i64::try_from(min_off).unwrap_or(i64::MAX)),
        rusqlite::types::Value::from(i64::try_from(limit).unwrap_or(i64::MAX)),
    ];
    for org in orgs {
        params.push(rusqlite::types::Value::from(org.to_string()));
    }
    let mut stmt = conn.prepare(&sql).map_err(bus_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params_from_iter(params), |r| {
            Ok((
                r.get::<_, i64>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, Option<String>>(2)?,
                r.get::<_, Option<i64>>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, Vec<u8>>(6)?,
                r.get::<_, i64>(7)?,
            ))
        })
        .map_err(bus_sql_err)?;
    let mut out = Vec::new();
    for item in rows {
        let (off, org_raw, del_id, del_ep, key, hdr_json, payload, ts) =
            item.map_err(bus_sql_err)?;
        let headers: BTreeMap<String, String> =
            serde_json::from_str(&hdr_json).map_err(bus_codec_err)?;
        out.push(BusMessage {
            stream: stream.to_string(),
            partition,
            offset: u64::try_from(off).unwrap_or(0),
            organisation_id: OrgId::new(org_raw)?,
            delegation_id: del_id,
            delegation_epoch: del_ep.and_then(|v| u64::try_from(v).ok()),
            key,
            headers,
            payload,
            appended_at_ms: ts,
        });
    }
    Ok(out)
}

pub(crate) fn commit_offline(
    conn: &mut Connection,
    consumer_group: &str,
    stream: &str,
    partition: u32,
    offset: u64,
    checkpoint: Option<&str>,
    fence: FencingToken,
) -> Result<(), CodedError> {
    let tx = conn.transaction().map_err(bus_sql_err)?;
    let next_opt: Option<i64> = tx
        .query_row(
            "SELECT next_offset FROM bus_partition WHERE stream = ?1 AND partition = ?2",
            rusqlite::params![stream, i64::from(partition)],
            |r| r.get(0),
        )
        .optional()
        .map_err(bus_sql_err)?;
    let head = next_opt.and_then(|n| {
        if n > 0 {
            u64::try_from(n.saturating_sub(1)).ok()
        } else {
            None
        }
    });
    match head {
        Some(h) if offset <= h => {}
        _ => return Err(beyond_log_err(offset, head)),
    }
    let current: Option<(i64, Option<i64>)> = tx
        .query_row(
            "SELECT fence, committed_offset FROM bus_consumer WHERE consumer_group = ?1 AND stream = ?2 AND partition = ?3",
            rusqlite::params![consumer_group, stream, i64::from(partition)],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(bus_sql_err)?;
    let Some((cur_fence_i64, prev_committed_opt)) = current else {
        return Err(stale_fence_err(0, fence.value()));
    };
    let cur_fence = u64::try_from(cur_fence_i64).unwrap_or(0);
    if fence.value() != cur_fence {
        return Err(stale_fence_err(cur_fence, fence.value()));
    }
    if let Some(prev_i64) = prev_committed_opt
        && let Ok(prev_u64) = u64::try_from(prev_i64)
        && offset < prev_u64
    {
        return Err(non_monotonic_commit_err(prev_u64, offset));
    }
    let updated = tx
        .execute(
            "UPDATE bus_consumer SET committed_offset = ?4, checkpoint = ?5, fence = ?6
             WHERE consumer_group = ?1 AND stream = ?2 AND partition = ?3
               AND fence = ?6 AND (committed_offset IS NULL OR committed_offset <= ?4)",
            rusqlite::params![
                consumer_group,
                stream,
                i64::from(partition),
                i64::try_from(offset).unwrap_or(i64::MAX),
                checkpoint,
                i64::try_from(fence.value()).unwrap_or(i64::MAX),
            ],
        )
        .map_err(bus_sql_err)?;
    if updated == 0 {
        return Err(stale_fence_err(cur_fence, fence.value()));
    }
    tx.commit().map_err(bus_sql_err)?;
    Ok(())
}

pub(crate) fn lag_offline(
    conn: &Connection,
    consumer_group: &str,
    stream: &str,
    partition: u32,
) -> Result<BusLag, CodedError> {
    let next_opt: Option<i64> = conn
        .query_row(
            "SELECT next_offset FROM bus_partition WHERE stream = ?1 AND partition = ?2",
            rusqlite::params![stream, i64::from(partition)],
            |r| r.get(0),
        )
        .optional()
        .map_err(bus_sql_err)?;
    let head_offset = next_opt.and_then(|n| {
        if n > 0 {
            u64::try_from(n.saturating_sub(1)).ok()
        } else {
            None
        }
    });
    let committed_opt: Option<Option<i64>> = conn
        .query_row(
            "SELECT committed_offset FROM bus_consumer WHERE consumer_group = ?1 AND stream = ?2 AND partition = ?3",
            rusqlite::params![consumer_group, stream, i64::from(partition)],
            |r| r.get(0),
        )
        .optional()
        .map_err(bus_sql_err)?;
    let committed_offset = committed_opt.flatten().and_then(|v| u64::try_from(v).ok());
    Ok(BusLag {
        stream: stream.to_string(),
        partition,
        head_offset,
        committed_offset,
        pending_messages: compute_pending(head_offset, committed_offset),
    })
}

pub(crate) fn bus_sql_err(err: rusqlite::Error) -> CodedError {
    CodedError::new(
        CODE_BUS_IO,
        format!("PostgreSQL log bus offline SQLite error: {err}"),
        "Check local SQLite bus state.",
    )
}
