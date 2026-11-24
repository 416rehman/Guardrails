// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::types::Value;
use rusqlite::{Connection, OptionalExtension};

use grdr_model::CodedError;
use grdr_ports::{
    BusAppendMessage, BusLag, BusMessage, BusOffsetRange, BusPort, BusSubscription,
    CODE_BUS_BEYOND_LOG, CODE_BUS_INVALID_INPUT, CODE_BUS_IO, CODE_BUS_STALE_FENCE, FencingToken,
    OrgId, SingleCtx, TenantCtx,
};

use crate::schema::configure_and_init_bus;

#[derive(Debug)]
pub struct SqliteLogBus {
    conn: Mutex<Connection>,
}

impl SqliteLogBus {
    pub fn open(path: &Path) -> Result<Self, CodedError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                CodedError::new(
                    CODE_BUS_IO,
                    format!("Failed creating bus directory {}: {e}", parent.display()),
                    "Verify write permissions in --data-dir.",
                )
            })?;
        }
        let mut conn = Connection::open(path).map_err(|e| {
            CodedError::new(
                CODE_BUS_IO,
                format!("Failed opening SQLite bus {}: {e}", path.display()),
                "Verify bus SQLite path and permissions.",
            )
        })?;
        configure_and_init_bus(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    pub fn open_in_memory() -> Result<Self, CodedError> {
        let mut conn = Connection::open_in_memory().map_err(|e| {
            CodedError::new(
                CODE_BUS_IO,
                format!("Failed opening in-memory SQLite bus: {e}"),
                "Check SQLite runtime availability.",
            )
        })?;
        configure_and_init_bus(&mut conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock_conn(&self) -> Result<MutexGuard<'_, Connection>, CodedError> {
        self.conn.lock().map_err(|_| {
            CodedError::new(
                CODE_BUS_IO,
                "SQLite log bus mutex poisoned.",
                "Restart the log bus adapter.",
            )
        })
    }
}

impl BusPort for SqliteLogBus {
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
        let batch_len = i64::try_from(messages.len()).map_err(|_| {
            CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Bus append batch exceeds i64 bounds.",
                "Split batch into smaller chunks.",
            )
        })?;
        let part_i64 = i64::from(partition);
        let org = ctx.organisation_id().as_str();
        let del_id = ctx.delegation_id();
        let del_epoch = ctx
            .delegation_epoch()
            .map(i64::try_from)
            .transpose()
            .map_err(|_| {
                CodedError::new(
                    CODE_BUS_INVALID_INPUT,
                    "Delegation epoch exceeds i64 bounds.",
                    "Use a valid delegation epoch.",
                )
            })?;

        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(bus_sql_err)?;
        tx.execute(
            "INSERT OR IGNORE INTO bus_partition (stream, partition, next_offset) VALUES (?1, ?2, 0)",
            rusqlite::params![stream, part_i64],
        )
        .map_err(bus_sql_err)?;
        let new_next: i64 = tx
            .query_row(
                "UPDATE bus_partition SET next_offset = next_offset + ?3 WHERE stream = ?1 AND partition = ?2 RETURNING next_offset",
                rusqlite::params![stream, part_i64, batch_len],
                |row| row.get(0),
            )
            .map_err(bus_sql_err)?;
        let start_i64 = new_next.saturating_sub(batch_len);
        let first_offset = u64::try_from(start_i64).unwrap_or(0);

        for (idx, msg) in messages.iter().enumerate() {
            let idx_i64 = i64::try_from(idx).unwrap_or(i64::MAX);
            let msg_offset = start_i64.saturating_add(idx_i64);
            let headers_json = serde_json::to_string(&msg.headers).map_err(|e| {
                CodedError::new(
                    CODE_BUS_INVALID_INPUT,
                    format!("Failed encoding bus message headers: {e}"),
                    "Check bus headers.",
                )
            })?;
            tx.execute(
                "INSERT INTO bus_message (
                    stream, partition, offset, organisation_id, delegation_id, delegation_epoch,
                    msg_key, headers_json, payload, appended_at_ms
                 ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, ?10)",
                rusqlite::params![
                    stream,
                    part_i64,
                    msg_offset,
                    org,
                    del_id,
                    del_epoch,
                    msg.key,
                    headers_json,
                    msg.payload,
                    now_ms
                ],
            )
            .map_err(bus_sql_err)?;
        }
        tx.commit().map_err(bus_sql_err)?;
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
        expiry_ms: i64,
    ) -> Result<BusSubscription, CodedError> {
        let fence_i64 = i64::try_from(fence.value()).map_err(|_| {
            CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Fencing token exceeds i64 bounds.",
                "Use a monotonic u64 within i64 range.",
            )
        })?;
        let part_i64 = i64::from(partition);
        let conn = self.lock_conn()?;

        let updated: Option<(Option<i64>, Option<String>)> = conn
            .query_row(
                "INSERT INTO bus_consumer (consumer_group, stream, partition, committed_offset, checkpoint, holder, fence, expiry_ms)
                 VALUES (?1, ?2, ?3, NULL, NULL, ?4, ?5, ?6)
                 ON CONFLICT(consumer_group, stream, partition) DO UPDATE SET
                   holder = excluded.holder,
                   fence = excluded.fence,
                   expiry_ms = excluded.expiry_ms
                 WHERE bus_consumer.fence <= excluded.fence
                 RETURNING committed_offset, checkpoint",
                rusqlite::params![consumer_group, stream, part_i64, holder, fence_i64, expiry_ms],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(bus_sql_err)?;

        let Some((committed_i64, checkpoint)) = updated else {
            return Err(CodedError::new(
                CODE_BUS_STALE_FENCE,
                format!("Consumer subscribe rejected stale fence {}.", fence.value()),
                "Re-acquire partition lease before subscribing.",
            ));
        };

        Ok(BusSubscription {
            consumer_group: consumer_group.into(),
            stream: stream.into(),
            partition,
            holder: holder.into(),
            fence,
            committed_offset: committed_i64.and_then(|v| u64::try_from(v).ok()),
            checkpoint,
        })
    }

    fn fetch(
        &self,
        ctx: &TenantCtx,
        stream: &str,
        partition: u32,
        after_offset: Option<u64>,
        limit: usize,
    ) -> Result<Vec<BusMessage>, CodedError> {
        if limit == 0 {
            return Ok(Vec::new());
        }
        let conn = self.lock_conn()?;
        let part_i64 = i64::from(partition);
        let min_offset_inclusive: i64 = match after_offset {
            Some(prev) => i64::try_from(prev.saturating_add(1)).unwrap_or(i64::MAX),
            None => 0,
        };
        let org_count = ctx.organisation_ids().len();
        let placeholders = (0..org_count)
            .map(|offset| format!("?{}", offset.saturating_add(4)))
            .collect::<Vec<_>>()
            .join(", ");
        let limit_idx = org_count.saturating_add(4);
        let sql = format!(
            "SELECT offset, organisation_id, delegation_id, delegation_epoch, msg_key, headers_json, payload, appended_at_ms
             FROM bus_message
             WHERE stream = ?1 AND partition = ?2 AND offset >= ?3 AND organisation_id IN ({placeholders})
             ORDER BY offset ASC
             LIMIT ?{limit_idx}"
        );
        let mut params = vec![
            Value::from(stream.to_string()),
            Value::from(part_i64),
            Value::from(min_offset_inclusive),
        ];
        for org in ctx.organisation_ids() {
            params.push(Value::from(org.as_str().to_string()));
        }
        params.push(Value::from(i64::try_from(limit).unwrap_or(i64::MAX)));

        let mut stmt = conn.prepare(&sql).map_err(bus_sql_err)?;
        let rows = stmt
            .query_map(rusqlite::params_from_iter(params), |row| {
                let offset_i64: i64 = row.get(0)?;
                let org_str: String = row.get(1)?;
                let delegation_id: Option<String> = row.get(2)?;
                let delegation_epoch: Option<i64> = row.get(3)?;
                let key: String = row.get(4)?;
                let headers_json: String = row.get(5)?;
                let payload: Vec<u8> = row.get(6)?;
                let appended_at_ms: i64 = row.get(7)?;
                Ok((
                    offset_i64,
                    org_str,
                    delegation_id,
                    delegation_epoch,
                    key,
                    headers_json,
                    payload,
                    appended_at_ms,
                ))
            })
            .map_err(bus_sql_err)?;

        let mut out = Vec::new();
        for item in rows {
            let (
                offset_i64,
                org_str,
                delegation_id,
                delegation_epoch,
                key,
                headers_json,
                payload,
                appended_at_ms,
            ) = item.map_err(bus_sql_err)?;
            let organisation_id = OrgId::new(org_str)?;
            let headers: BTreeMap<String, String> =
                serde_json::from_str(&headers_json).map_err(|e| {
                    CodedError::new(
                        CODE_BUS_IO,
                        format!("Failed decoding bus headers: {e}"),
                        "Inspect stored bus message metadata.",
                    )
                })?;
            out.push(BusMessage {
                stream: stream.into(),
                partition,
                offset: u64::try_from(offset_i64).unwrap_or(0),
                organisation_id,
                delegation_id,
                delegation_epoch: delegation_epoch.and_then(|e| u64::try_from(e).ok()),
                key,
                headers,
                payload,
                appended_at_ms,
            });
        }
        Ok(out)
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
        let offset_i64 = i64::try_from(offset).map_err(|_| {
            CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Commit offset exceeds i64 bounds.",
                "Pass a valid bus offset.",
            )
        })?;
        let fence_i64 = i64::try_from(fence.value()).map_err(|_| {
            CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Fence exceeds i64 bounds.",
                "Pass a valid fencing token.",
            )
        })?;
        let part_i64 = i64::from(partition);
        let mut conn = self.lock_conn()?;
        let tx = conn.transaction().map_err(bus_sql_err)?;

        let next_offset: Option<i64> = tx
            .query_row(
                "SELECT next_offset FROM bus_partition WHERE stream = ?1 AND partition = ?2",
                rusqlite::params![stream, part_i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(bus_sql_err)?;

        let Some(head_next) = next_offset else {
            return Err(CodedError::new(
                CODE_BUS_BEYOND_LOG,
                format!("Commit offset {offset} is beyond empty partition head."),
                "Append messages before committing offsets.",
            ));
        };
        if offset_i64 >= head_next {
            return Err(CodedError::new(
                CODE_BUS_BEYOND_LOG,
                format!("Commit offset {offset} is beyond partition head {head_next}."),
                "Commit an offset that has already been appended.",
            ));
        }

        let current: Option<(i64, Option<i64>)> = tx
            .query_row(
                "SELECT fence, committed_offset FROM bus_consumer WHERE consumer_group = ?1 AND stream = ?2 AND partition = ?3",
                rusqlite::params![consumer_group, stream, part_i64],
                |row| Ok((row.get(0)?, row.get(1)?)),
            )
            .optional()
            .map_err(bus_sql_err)?;

        let Some((stored_fence, stored_committed)) = current else {
            return Err(CodedError::new(
                CODE_BUS_STALE_FENCE,
                "Consumer is not subscribed to this partition.",
                "Call subscribe with a valid lease fence first.",
            ));
        };
        if stored_fence != fence_i64 {
            return Err(CodedError::new(
                CODE_BUS_STALE_FENCE,
                format!(
                    "Commit fence {} does not match subscriber fence {stored_fence}.",
                    fence.value()
                ),
                "Stop writing and refresh partition lease.",
            ));
        }
        if stored_committed.is_some_and(|prev| offset_i64 < prev) {
            return Err(CodedError::new(
                CODE_BUS_INVALID_INPUT,
                "Committed offset cannot move backwards.",
                "Commit offsets monotonically.",
            ));
        }

        tx.execute(
            "UPDATE bus_consumer
             SET committed_offset = ?1, checkpoint = COALESCE(?2, checkpoint)
             WHERE consumer_group = ?3 AND stream = ?4 AND partition = ?5 AND fence = ?6",
            rusqlite::params![
                offset_i64,
                checkpoint,
                consumer_group,
                stream,
                part_i64,
                fence_i64
            ],
        )
        .map_err(bus_sql_err)?;
        tx.commit().map_err(bus_sql_err)?;
        Ok(())
    }

    fn lag(
        &self,
        _ctx: &TenantCtx,
        consumer_group: &str,
        stream: &str,
        partition: u32,
    ) -> Result<BusLag, CodedError> {
        let conn = self.lock_conn()?;
        let part_i64 = i64::from(partition);
        let next_offset: Option<i64> = conn
            .query_row(
                "SELECT next_offset FROM bus_partition WHERE stream = ?1 AND partition = ?2",
                rusqlite::params![stream, part_i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(bus_sql_err)?;
        let committed_i64: Option<i64> = conn
            .query_row(
                "SELECT committed_offset FROM bus_consumer WHERE consumer_group = ?1 AND stream = ?2 AND partition = ?3",
                rusqlite::params![consumer_group, stream, part_i64],
                |row| row.get(0),
            )
            .optional()
            .map_err(bus_sql_err)?
            .flatten();

        let head_offset = next_offset
            .filter(|n| *n > 0)
            .and_then(|n| u64::try_from(n.saturating_sub(1)).ok());
        let committed_offset = committed_i64.and_then(|c| u64::try_from(c).ok());
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

fn bus_sql_err(err: rusqlite::Error) -> CodedError {
    CodedError::new(
        CODE_BUS_IO,
        format!("SQLite log bus query failed: {err}"),
        "Inspect SQLite bus database state.",
    )
}
