// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use base64::Engine;
use base64::engine::general_purpose::STANDARD as B64;

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusSubscription, CODE_BUS_BEYOND_LOG,
    CODE_BUS_INVALID_INPUT, CODE_BUS_IO, CODE_BUS_STALE_FENCE, FencingToken, OrgId, SingleCtx,
    TenantCtx,
};

use crate::config::CODE_PG_RLS;
use crate::dialect::rls_session_statements;
use crate::pool::PgConnectionPool;
use crate::wire::WireStatement;
use crate::wire_codec::format_pg_text_array;

pub(crate) const PG_BUS_ATOMIC_DDL_SQL: &str = "
BEGIN;
CREATE TABLE IF NOT EXISTS bus_partition (
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    next_offset BIGINT NOT NULL DEFAULT 0,
    PRIMARY KEY (stream, partition)
);
CREATE TABLE IF NOT EXISTS bus_message (
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    offset_seq BIGINT NOT NULL,
    organisation_id TEXT NOT NULL,
    delegation_id TEXT,
    delegation_epoch BIGINT,
    msg_key TEXT NOT NULL,
    headers_json JSONB NOT NULL,
    payload BYTEA NOT NULL,
    appended_at_ms BIGINT NOT NULL,
    PRIMARY KEY (stream, partition, offset_seq)
);
CREATE TABLE IF NOT EXISTS bus_consumer (
    consumer_group TEXT NOT NULL,
    stream TEXT NOT NULL,
    partition INTEGER NOT NULL,
    holder TEXT NOT NULL,
    fence BIGINT NOT NULL,
    expiry_ms BIGINT NOT NULL,
    committed_offset BIGINT,
    checkpoint TEXT,
    PRIMARY KEY (consumer_group, stream, partition)
);
ALTER TABLE bus_message ENABLE ROW LEVEL SECURITY;
ALTER TABLE bus_message FORCE ROW LEVEL SECURITY;
DROP POLICY IF EXISTS grdr_bus_message_rls ON bus_message;
DROP POLICY IF EXISTS grdr_bus_message_select_rls ON bus_message;
DROP POLICY IF EXISTS grdr_bus_message_insert_rls ON bus_message;
DROP POLICY IF EXISTS grdr_bus_message_update_rls ON bus_message;
DROP POLICY IF EXISTS grdr_bus_message_delete_rls ON bus_message;
CREATE POLICY grdr_bus_message_select_rls ON bus_message FOR SELECT USING (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
    OR (
        NULLIF(current_setting('app.org_ids', true), '') IS NOT NULL
        AND organisation_id = ANY(string_to_array(current_setting('app.org_ids', true), ','))
    )
);
CREATE POLICY grdr_bus_message_insert_rls ON bus_message FOR INSERT WITH CHECK (
    organisation_id = NULLIF(current_setting('app.org_id', true), '')
);
CREATE POLICY grdr_bus_message_update_rls ON bus_message FOR UPDATE
    USING (organisation_id = NULLIF(current_setting('app.org_id', true), ''))
    WITH CHECK (organisation_id = NULLIF(current_setting('app.org_id', true), ''));
CREATE POLICY grdr_bus_message_delete_rls ON bus_message FOR DELETE
    USING (organisation_id = NULLIF(current_setting('app.org_id', true), ''));
COMMIT;
";

pub(crate) fn bus_rls_statements(ctx: &TenantCtx) -> Result<Vec<String>, CodedError> {
    let mut stmts = rls_session_statements(ctx)?;
    match ctx {
        TenantCtx::Single(_) => {
            stmts.push("SET LOCAL app.org_ids = ''".into());
        }
        TenantCtx::Set(set) => {
            let mut safe_orgs = Vec::with_capacity(set.organisation_ids().len());
            for org in set.organisation_ids() {
                safe_orgs.push(sanitize_org_token(org.as_str())?);
            }
            stmts.push("SET LOCAL app.org_id = ''".into());
            stmts.push(format!("SET LOCAL app.org_ids = '{}'", safe_orgs.join(",")));
        }
    }
    Ok(stmts)
}

pub(crate) fn append_wire(
    pool: &PgConnectionPool,
    ctx: &SingleCtx,
    stream: &str,
    partition: u32,
    messages: &[BusAppendMessage],
    now_ms: i64,
) -> Result<BusOffsetRange, CodedError> {
    let rls = bus_rls_statements(&TenantCtx::Single(ctx.clone()))?;
    let org = ctx.organisation_id().as_str();
    let del_id = ctx.delegation_id().map(str::to_string);
    let del_epoch = ctx.delegation_epoch().map(|e| e.to_string());
    let part_str = partition.to_string();
    let count_str = messages.len().to_string();

    let alloc_sql = "INSERT INTO bus_partition (stream, partition, next_offset) \
        VALUES ($1, $2::int, $3::bigint) \
        ON CONFLICT (stream, partition) DO UPDATE \
        SET next_offset = bus_partition.next_offset + $3::bigint \
        RETURNING (next_offset - $3::bigint)::text;";
    let insert_sql = "INSERT INTO bus_message (
        stream, partition, offset_seq, organisation_id, delegation_id,
        delegation_epoch, msg_key, headers_json, payload, appended_at_ms
    ) SELECT $1, $2::int, (p.next_offset - $10::bigint + $11::bigint), \
             $3, $4, $5::bigint, $6, $7::jsonb, decode($8, 'base64'), $9::bigint \
      FROM bus_partition p WHERE p.stream = $1 AND p.partition = $2::int;";

    let mut stmts = Vec::with_capacity(1usize.saturating_add(messages.len()));
    stmts.push(WireStatement {
        sql: alloc_sql,
        params: vec![
            Some(stream.to_string()),
            Some(part_str.clone()),
            Some(count_str.clone()),
        ],
    });

    for (idx, msg) in messages.iter().enumerate() {
        let headers_json = serde_json::to_string(&msg.headers).map_err(bus_codec_err)?;
        let payload_b64 = B64.encode(&msg.payload);
        stmts.push(WireStatement {
            sql: insert_sql,
            params: vec![
                Some(stream.to_string()),
                Some(part_str.clone()),
                Some(org.to_string()),
                del_id.clone(),
                del_epoch.clone(),
                Some(msg.key.clone()),
                Some(headers_json),
                Some(payload_b64),
                Some(now_ms.to_string()),
                Some(count_str.clone()),
                Some(idx.to_string()),
            ],
        });
    }

    let res = pool.execute_tx(&rls, &stmts)?;
    let first_offset = res
        .first()
        .and_then(|rows| rows.first())
        .and_then(|row| row.first())
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<u64>().ok())
        .ok_or_else(|| bus_wire_parse_err("next_offset"))?;
    let last_offset = first_offset
        .saturating_add(u64::try_from(messages.len()).unwrap_or(0))
        .saturating_sub(1);
    Ok(BusOffsetRange {
        first_offset,
        last_offset,
    })
}

pub(crate) fn subscribe_wire(
    pool: &PgConnectionPool,
    consumer_group: &str,
    stream: &str,
    partition: u32,
    holder: &str,
    fence: FencingToken,
    expiry_ms: i64,
) -> Result<BusSubscription, CodedError> {
    let upsert_sql = "INSERT INTO bus_consumer (
        consumer_group, stream, partition, holder, fence, expiry_ms, committed_offset, checkpoint
    ) VALUES ($1, $2, $3::int, $4, $5::bigint, $6::bigint, NULL, NULL)
    ON CONFLICT (consumer_group, stream, partition) DO UPDATE SET
        holder = excluded.holder,
        fence = excluded.fence,
        expiry_ms = excluded.expiry_ms
    WHERE excluded.fence >= bus_consumer.fence
    RETURNING committed_offset::text, checkpoint;";
    let res = pool.execute_tx(
        &[],
        &[WireStatement {
            sql: upsert_sql,
            params: vec![
                Some(consumer_group.to_string()),
                Some(stream.to_string()),
                Some(partition.to_string()),
                Some(holder.to_string()),
                Some(fence.value().to_string()),
                Some(expiry_ms.to_string()),
            ],
        }],
    )?;
    let Some(first_row) = res.first().and_then(|rows| rows.first()) else {
        return Err(stale_fence_err(0, fence.value()));
    };
    let committed_offset = first_row
        .first()
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    let checkpoint = first_row.get(1).cloned().flatten();

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

pub(crate) fn fetch_wire(
    pool: &PgConnectionPool,
    ctx: &TenantCtx,
    stream: &str,
    partition: u32,
    after_offset: Option<u64>,
    limit: usize,
) -> Result<Vec<BusMessage>, CodedError> {
    let rls = bus_rls_statements(ctx)?;
    let min_offset = after_offset.map_or(0, |o| o.saturating_add(1));
    let org_ids: Vec<String> = ctx
        .organisation_ids()
        .into_iter()
        .map(|org| org.as_str().to_string())
        .collect();
    if org_ids.is_empty() {
        return Ok(Vec::new());
    }
    let org_array = format_pg_text_array(&org_ids);
    let sql = "SELECT offset_seq::text, organisation_id, delegation_id, delegation_epoch::text, \
        msg_key, headers_json::text, encode(payload, 'base64'), appended_at_ms::text \
        FROM bus_message \
        WHERE stream = $1 AND partition = $2::int AND offset_seq >= $3::bigint \
          AND organisation_id = ANY($5::text[]) \
        ORDER BY offset_seq ASC LIMIT $4::int;";
    let res = pool.execute_tx(
        &rls,
        &[WireStatement {
            sql,
            params: vec![
                Some(stream.to_string()),
                Some(partition.to_string()),
                Some(min_offset.to_string()),
                Some(limit.to_string()),
                Some(org_array),
            ],
        }],
    )?;
    let mut out = Vec::new();
    let Some(rows) = res.first() else {
        return Ok(out);
    };
    for row in rows {
        let offset = row
            .first()
            .and_then(|v| v.as_deref())
            .and_then(|s| s.parse::<u64>().ok())
            .ok_or_else(|| bus_wire_parse_err("offset_seq"))?;
        let org_raw = row
            .get(1)
            .and_then(|v| v.as_deref())
            .ok_or_else(|| bus_wire_parse_err("organisation_id"))?;
        let organisation_id = OrgId::new(org_raw.to_string())?;
        let delegation_id = row.get(2).cloned().flatten();
        let delegation_epoch = row
            .get(3)
            .and_then(|v| v.as_deref())
            .and_then(|s| s.parse::<u64>().ok());
        let key = row
            .get(4)
            .and_then(|v| v.as_deref())
            .unwrap_or("")
            .to_string();
        let headers_raw = row.get(5).and_then(|v| v.as_deref()).unwrap_or("{}");
        let headers: BTreeMap<String, String> =
            serde_json::from_str(headers_raw).map_err(bus_codec_err)?;
        let payload_b64 = row
            .get(6)
            .and_then(|v| v.as_deref())
            .unwrap_or("")
            .replace(['\r', '\n'], "");
        let payload = B64.decode(payload_b64).map_err(|e| {
            CodedError::new(
                CODE_BUS_IO,
                format!("Invalid base64 payload: {e}"),
                "Inspect bus message payload.",
            )
        })?;
        let appended_at_ms = row
            .get(7)
            .and_then(|v| v.as_deref())
            .and_then(|s| s.parse::<i64>().ok())
            .unwrap_or(0);
        out.push(BusMessage {
            stream: stream.to_string(),
            partition,
            offset,
            organisation_id,
            delegation_id,
            delegation_epoch,
            key,
            headers,
            payload,
            appended_at_ms,
        });
    }
    Ok(out)
}

pub(crate) fn commit_wire(
    pool: &PgConnectionPool,
    consumer_group: &str,
    stream: &str,
    partition: u32,
    offset: u64,
    checkpoint: Option<&str>,
    fence: FencingToken,
) -> Result<(), CodedError> {
    let update_sql = "WITH target AS (
        SELECT p.next_offset
        FROM bus_partition p
        WHERE p.stream = $2 AND p.partition = $3::int
    )
    UPDATE bus_consumer c
    SET committed_offset = $4::bigint,
        checkpoint = $5,
        fence = $6::bigint
    FROM target t
    WHERE c.consumer_group = $1
      AND c.stream = $2
      AND c.partition = $3::int
      AND t.next_offset - 1 >= $4::bigint
      AND c.fence = $6::bigint
      AND (c.committed_offset IS NULL OR c.committed_offset <= $4::bigint)
    RETURNING c.fence::text;";
    let part_str = partition.to_string();
    let res = pool.execute_tx(
        &[],
        &[
            WireStatement {
                sql: update_sql,
                params: vec![
                    Some(consumer_group.to_string()),
                    Some(stream.to_string()),
                    Some(part_str.clone()),
                    Some(offset.to_string()),
                    checkpoint.map(ToString::to_string),
                    Some(fence.value().to_string()),
                ],
            },
            WireStatement {
                sql: "SELECT (next_offset - 1)::text FROM bus_partition WHERE stream = $1 AND partition = $2::int;",
                params: vec![Some(stream.to_string()), Some(part_str.clone())],
            },
            WireStatement {
                sql: "SELECT fence::text, committed_offset::text FROM bus_consumer WHERE consumer_group = $1 AND stream = $2 AND partition = $3::int;",
                params: vec![
                    Some(consumer_group.to_string()),
                    Some(stream.to_string()),
                    Some(part_str),
                ],
            },
        ],
    )?;

    if res.first().is_some_and(|rows| !rows.is_empty()) {
        return Ok(());
    }

    let head_offset = res
        .get(1)
        .and_then(|rows| rows.first())
        .and_then(|row| row.first())
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&v| v >= 0)
        .and_then(|v| u64::try_from(v).ok());
    match head_offset {
        Some(head) if offset <= head => {}
        _ => return Err(beyond_log_err(offset, head_offset)),
    }

    let Some(consumer_row) = res.get(2).and_then(|rows| rows.first()) else {
        return Err(stale_fence_err(0, fence.value()));
    };
    let current_fence = consumer_row
        .first()
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<u64>().ok())
        .unwrap_or(0);
    if current_fence != fence.value() {
        return Err(stale_fence_err(current_fence, fence.value()));
    }
    let committed = consumer_row
        .get(1)
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    if let Some(prev) = committed
        && offset < prev
    {
        return Err(non_monotonic_commit_err(prev, offset));
    }

    Err(stale_fence_err(current_fence, fence.value()))
}

pub(crate) fn lag_wire(
    pool: &PgConnectionPool,
    consumer_group: &str,
    stream: &str,
    partition: u32,
) -> Result<BusLag, CodedError> {
    let res = pool.execute_tx(
        &[],
        &[
            WireStatement {
                sql: "SELECT (next_offset - 1)::text FROM bus_partition WHERE stream = $1 AND partition = $2::int;",
                params: vec![Some(stream.to_string()), Some(partition.to_string())],
            },
            WireStatement {
                sql: "SELECT committed_offset::text FROM bus_consumer WHERE consumer_group = $1 AND stream = $2 AND partition = $3::int;",
                params: vec![
                    Some(consumer_group.to_string()),
                    Some(stream.to_string()),
                    Some(partition.to_string()),
                ],
            },
        ],
    )?;
    let head_offset = res
        .first()
        .and_then(|r| r.first())
        .and_then(|row| row.first())
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<i64>().ok())
        .filter(|&v| v >= 0)
        .and_then(|v| u64::try_from(v).ok());
    let committed_offset = res
        .get(1)
        .and_then(|r| r.first())
        .and_then(|row| row.first())
        .and_then(|v| v.as_deref())
        .and_then(|s| s.parse::<u64>().ok());
    Ok(BusLag {
        stream: stream.to_string(),
        partition,
        head_offset,
        committed_offset,
        pending_messages: compute_pending(head_offset, committed_offset),
    })
}

pub(crate) fn compute_pending(head_offset: Option<u64>, committed_offset: Option<u64>) -> u64 {
    match (head_offset, committed_offset) {
        (Some(head), Some(committed)) => head.saturating_sub(committed),
        (Some(head), None) => head.saturating_add(1),
        (None, _) => 0,
    }
}

pub(crate) fn stale_fence_err(expected: u64, got: u64) -> CodedError {
    CodedError::new(
        CODE_BUS_STALE_FENCE,
        format!("Stale fencing token {got} (current fence {expected})."),
        "Acquire a fresh partition lease before committing.",
    )
}

pub(crate) fn beyond_log_err(offset: u64, head: Option<u64>) -> CodedError {
    CodedError::new(
        CODE_BUS_BEYOND_LOG,
        format!("Cannot commit offset {offset} beyond partition head {head:?}."),
        "Commit an offset that has been appended.",
    )
}

pub(crate) fn non_monotonic_commit_err(prev: u64, got: u64) -> CodedError {
    CodedError::new(
        CODE_BUS_INVALID_INPUT,
        format!("Cannot regress committed offset from {prev} to {got}."),
        "Commit monotonically non-decreasing offsets.",
    )
}

pub(crate) fn bus_codec_err(err: serde_json::Error) -> CodedError {
    CodedError::new(
        CODE_BUS_IO,
        format!("PostgreSQL log bus JSON codec error: {err}"),
        "Ensure bus message headers are valid UTF-8 strings.",
    )
}

fn sanitize_org_token(raw: &str) -> Result<String, CodedError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || !trimmed
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '-' | '_' | '.'))
    {
        return Err(CodedError::new(
            CODE_PG_RLS,
            format!("Invalid tenant RLS context token `{trimmed}`."),
            "Mint TenantCtx from validated OrgId identifiers only.",
        ));
    }
    Ok(trimmed.to_string())
}

fn bus_wire_parse_err(field: &str) -> CodedError {
    CodedError::new(
        CODE_BUS_IO,
        format!("Missing or invalid PostgreSQL bus wire column `{field}`."),
        "Verify PostgreSQL bus_partition / bus_message schema.",
    )
}
