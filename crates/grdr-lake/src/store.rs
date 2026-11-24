// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use grdr_crypto::AeadKey;
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_IO, CODE_LAKE_NOT_FOUND, CODE_LAKE_STALE_FENCE, ErasureReceipt, EventsPort,
    FencingToken, LakeBatch, LakeCompactionResult, LakeFlushResult, LakeManifest, LakeQueryIr,
    LakeQueryResult, LegalHold, LegalHoldRequest, LegalHoldScope, LegalHoldState, OrgId,
    RetentionClass, SingleCtx, TenantCtx, TenantPath,
};

use crate::crypto::{SessionKeyLookup, ensure_session_key, seal_content_fields};
use crate::flush::{FlushContext, flush_org_batches, json_io_err};
use crate::query::run_lake_query;
use crate::retention::{load_active_holds, run_retention_and_compaction};
use crate::schema::{configure_and_migrate_catalogue, lake_sql_err};

struct HoldRow {
    scope_json: String,
    reason: String,
    incident_ref: Option<String>,
    created_by: String,
    created_at_ms: i64,
    expires_at_ms: Option<i64>,
}

#[derive(Debug)]
pub struct LakeStore<B: BlobPort> {
    blobs: B,
    catalogue: Mutex<Connection>,
    memtable: Mutex<BTreeMap<String, Vec<LakeBatch>>>,
    org_kek: AeadKey,
    pitr_lag_ms: i64,
}

impl<B: BlobPort> LakeStore<B> {
    pub fn open(catalogue_path: &Path, blobs: B, org_kek: AeadKey) -> Result<Self, CodedError> {
        if let Some(parent) = catalogue_path.parent()
            && !parent.as_os_str().is_empty()
        {
            fs::create_dir_all(parent).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!(
                        "Failed creating lake catalogue dir {}: {e}",
                        parent.display()
                    ),
                    "Verify write permissions in data directory.",
                )
            })?;
        }
        let mut conn = Connection::open(catalogue_path).map_err(lake_sql_err)?;
        configure_and_migrate_catalogue(&mut conn)?;
        Ok(Self {
            blobs,
            catalogue: Mutex::new(conn),
            memtable: Mutex::new(BTreeMap::new()),
            org_kek,
            pitr_lag_ms: 0,
        })
    }

    pub fn open_in_memory(blobs: B, org_kek: AeadKey) -> Result<Self, CodedError> {
        let mut conn = Connection::open_in_memory().map_err(lake_sql_err)?;
        configure_and_migrate_catalogue(&mut conn)?;
        Ok(Self {
            blobs,
            catalogue: Mutex::new(conn),
            memtable: Mutex::new(BTreeMap::new()),
            org_kek,
            pitr_lag_ms: 0,
        })
    }

    pub fn with_pitr_lag_ms(mut self, pitr_lag_ms: i64) -> Self {
        self.pitr_lag_ms = pitr_lag_ms.max(0);
        self
    }

    pub fn blobs(&self) -> &B {
        &self.blobs
    }

    fn lock_cat(&self) -> Result<MutexGuard<'_, Connection>, CodedError> {
        self.catalogue.lock().map_err(|_| {
            CodedError::new(
                CODE_LAKE_IO,
                "Lake catalogue mutex poisoned.",
                "Restart storage subsystem.",
            )
        })
    }

    fn lock_mem(&self) -> Result<MutexGuard<'_, BTreeMap<String, Vec<LakeBatch>>>, CodedError> {
        self.memtable.lock().map_err(|_| {
            CodedError::new(
                CODE_LAKE_IO,
                "Lake memtable mutex poisoned.",
                "Restart storage subsystem.",
            )
        })
    }
}

impl<B: BlobPort> EventsPort for LakeStore<B> {
    fn append(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        batch: &LakeBatch,
    ) -> Result<u64, CodedError> {
        let org_id = ctx.organisation_id();
        let conn = self.lock_cat()?;
        check_and_advance_fence(&conn, org_id, fence)?;

        let mut sealed_batch = batch.clone();
        for rec in &mut sealed_batch.records {
            if rec.content_fields.is_empty() {
                continue;
            }
            match ensure_session_key(
                &conn,
                &self.org_kek,
                org_id,
                &rec.root_session_id,
                rec.received_at_ms,
            )? {
                SessionKeyLookup::Active(session_key) => {
                    rec.content_fields = seal_content_fields(
                        &session_key,
                        org_id,
                        &rec.event_id,
                        &rec.content_fields,
                    )?;
                }
                SessionKeyLookup::Destroyed | SessionKeyLookup::Missing => {
                    rec.content_fields.clear();
                }
            }
        }
        drop(conn);

        let count = u64::try_from(sealed_batch.records.len()).unwrap_or(u64::MAX);
        let mut mem = self.lock_mem()?;
        mem.entry(org_id.as_str().to_string())
            .or_default()
            .push(sealed_batch);
        Ok(count)
    }

    fn flush(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        due_before_ms: i64,
        now_ms: i64,
    ) -> Result<LakeFlushResult, CodedError> {
        let org_id = ctx.organisation_id();
        let mut conn = self.lock_cat()?;
        let (snapshot_seq, manifest_seq) = check_and_advance_fence(&conn, org_id, fence)?;

        let mut mem = self.lock_mem()?;
        let org_batches = mem.entry(org_id.as_str().to_string()).or_default();
        let mut due_batches = Vec::new();
        let mut keep_batches = Vec::new();
        for batch in org_batches.drain(..) {
            let max_rx = batch
                .records
                .iter()
                .map(|r| r.received_at_ms)
                .max()
                .unwrap_or(now_ms);
            if max_rx <= due_before_ms {
                due_batches.push(batch);
            } else {
                keep_batches.push(batch);
            }
        }
        *org_batches = keep_batches;
        drop(mem);

        if due_batches.is_empty() {
            return Ok(LakeFlushResult {
                organisation_id: org_id.clone(),
                snapshot_id: snapshot_seq,
                committed_through: None,
                segments_written: 0,
                archive_segments_written: 0,
                rows_flushed: 0,
                manifest_seq: if manifest_seq == 0 {
                    None
                } else {
                    Some(manifest_seq)
                },
            });
        }

        flush_org_batches(
            &mut conn,
            &self.blobs,
            ctx,
            FlushContext {
                fence,
                snapshot_seq,
                manifest_seq,
                now_ms,
            },
            due_batches,
        )
    }

    fn execute_query_ir(
        &self,
        ctx: &TenantCtx,
        query: &LakeQueryIr,
    ) -> Result<LakeQueryResult, CodedError> {
        let conn = self.lock_cat()?;
        let mem = self.lock_mem()?;
        run_lake_query(&conn, &self.blobs, &self.org_kek, ctx, &mem, query)
    }

    fn place_hold(
        &self,
        ctx: &SingleCtx,
        hold: &LegalHoldRequest,
    ) -> Result<LegalHold, CodedError> {
        let conn = self.lock_cat()?;
        let record = LegalHold {
            organisation_id: ctx.organisation_id().clone(),
            hold_id: hold.hold_id.clone(),
            scope: hold.scope.clone(),
            reason: hold.reason.clone(),
            incident_ref: hold.incident_ref.clone(),
            created_by: hold.created_by.clone(),
            created_at_ms: hold.created_at_ms,
            expires_at_ms: hold.expires_at_ms,
            state: LegalHoldState::Active,
        };
        conn.execute(
            "INSERT INTO lake_holds (
                organisation_id, hold_id, scope_json, reason, incident_ref, created_by,
                created_at_ms, expires_at_ms, state_json
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(organisation_id, hold_id) DO UPDATE SET
               scope_json = excluded.scope_json,
               reason = excluded.reason,
               incident_ref = excluded.incident_ref,
               expires_at_ms = excluded.expires_at_ms,
               state_json = excluded.state_json",
            rusqlite::params![
                ctx.organisation_id().as_str(),
                record.hold_id,
                serde_json::to_string(&record.scope).map_err(json_io_err)?,
                record.reason,
                record.incident_ref,
                record.created_by,
                record.created_at_ms,
                record.expires_at_ms,
                serde_json::to_string(&record.state).map_err(json_io_err)?
            ],
        )
        .map_err(lake_sql_err)?;
        Ok(record)
    }

    fn release_hold(
        &self,
        ctx: &SingleCtx,
        hold_id: &str,
        now_ms: i64,
    ) -> Result<LegalHold, CodedError> {
        let conn = self.lock_cat()?;
        let row: Option<HoldRow> = conn
            .query_row(
                "SELECT scope_json, reason, incident_ref, created_by, created_at_ms, expires_at_ms
                 FROM lake_holds WHERE organisation_id = ?1 AND hold_id = ?2",
                rusqlite::params![ctx.organisation_id().as_str(), hold_id],
                |r| {
                    Ok(HoldRow {
                        scope_json: r.get(0)?,
                        reason: r.get(1)?,
                        incident_ref: r.get(2)?,
                        created_by: r.get(3)?,
                        created_at_ms: r.get(4)?,
                        expires_at_ms: r.get(5)?,
                    })
                },
            )
            .optional()
            .map_err(lake_sql_err)?;
        let Some(hold) = row else {
            return Err(CodedError::new(
                CODE_LAKE_NOT_FOUND,
                format!("Hold `{hold_id}` not found."),
                "List active holds and verify hold_id.",
            ));
        };
        let state = LegalHoldState::Released {
            released_at_ms: now_ms,
        };
        conn.execute(
            "UPDATE lake_holds SET state_json = ?3 WHERE organisation_id = ?1 AND hold_id = ?2",
            rusqlite::params![
                ctx.organisation_id().as_str(),
                hold_id,
                serde_json::to_string(&state).map_err(json_io_err)?
            ],
        )
        .map_err(lake_sql_err)?;
        Ok(LegalHold {
            organisation_id: ctx.organisation_id().clone(),
            hold_id: hold_id.to_string(),
            scope: serde_json::from_str::<LegalHoldScope>(&hold.scope_json).map_err(json_io_err)?,
            reason: hold.reason,
            incident_ref: hold.incident_ref,
            created_by: hold.created_by,
            created_at_ms: hold.created_at_ms,
            expires_at_ms: hold.expires_at_ms,
            state,
        })
    }

    fn erase_session(
        &self,
        ctx: &SingleCtx,
        root_session_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<ErasureReceipt, CodedError> {
        let org_id = ctx.organisation_id();
        let conn = self.lock_cat()?;
        let destruction_record_id = format!("erasure-{}", Uuid::now_v7().simple());
        let state_log_key = format!("state-log/{destruction_record_id}.json");
        let state_log_payload = serde_json::to_vec(&serde_json::json!({
            "kind": "session_content_key_destruction",
            "organisation_id": org_id.as_str(),
            "root_session_id": root_session_id,
            "reason": reason,
            "erased_at_ms": now_ms,
            "destruction_record_id": destruction_record_id,
        }))
        .map_err(json_io_err)?;
        self.blobs.put(
            ctx,
            &TenantPath::parse(ctx, &state_log_key)?,
            &state_log_payload,
        )?;

        let updated = conn
            .execute(
                "UPDATE lake_content_keys
                 SET state = 'destroyed', wrapped_key = '', destroyed_at_ms = ?3, destruction_record_id = ?4
                 WHERE organisation_id = ?1 AND root_session_id = ?2 AND state = 'active'",
                rusqlite::params![org_id.as_str(), root_session_id, now_ms, destruction_record_id],
            )
            .map_err(lake_sql_err)?;

        let active_holds = load_active_holds(&conn, org_id, now_ms)?;
        let mut stmt = conn
            .prepare(
                "SELECT object_key, day, root_session_ids_json, reduced_at_ms
                 FROM lake_archive_segments WHERE organisation_id = ?1",
            )
            .map_err(lake_sql_err)?;
        let arch_rows = stmt
            .query_map(rusqlite::params![org_id.as_str()], |row| {
                Ok((
                    row.get::<_, String>(0)?,
                    row.get::<_, String>(1)?,
                    row.get::<_, String>(2)?,
                    row.get::<_, Option<i64>>(3)?,
                ))
            })
            .map_err(lake_sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(lake_sql_err)?;
        drop(stmt);

        let mut archive_segments_reduced = 0usize;
        let mut held_segments_deferred = 0usize;
        let session_list = vec![root_session_id.to_string()];
        for (obj_key, day, sess_json, reduced_at) in arch_rows {
            let sessions: Vec<String> = serde_json::from_str(&sess_json).map_err(json_io_err)?;
            if !sessions.iter().any(|s| s == root_session_id) {
                continue;
            }
            if active_holds
                .iter()
                .any(|h| h.covers(RetentionClass::Content, &day, &[], &session_list))
            {
                held_segments_deferred = held_segments_deferred.saturating_add(1);
                continue;
            }
            if reduced_at.is_none() {
                conn.execute(
                    "UPDATE lake_archive_segments SET reduced_at_ms = ?3
                     WHERE organisation_id = ?1 AND object_key = ?2",
                    rusqlite::params![org_id.as_str(), obj_key, now_ms],
                )
                .map_err(lake_sql_err)?;
                archive_segments_reduced = archive_segments_reduced.saturating_add(1);
            }
        }

        Ok(ErasureReceipt {
            organisation_id: org_id.clone(),
            root_session_id: root_session_id.to_string(),
            destruction_record_id,
            erased_at_ms: now_ms,
            keys_destroyed: updated,
            archive_segments_reduced,
            held_segments_deferred,
            state_log_key,
        })
    }

    fn compact_and_retain(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        now_ms: i64,
    ) -> Result<LakeCompactionResult, CodedError> {
        let mut conn = self.lock_cat()?;
        check_and_advance_fence(&conn, ctx.organisation_id(), fence)?;
        run_retention_and_compaction(&mut conn, &self.blobs, ctx, now_ms, self.pitr_lag_ms)
    }

    fn manifest(&self, ctx: &TenantCtx) -> Result<Option<LakeManifest>, CodedError> {
        let conn = self.lock_cat()?;
        let mut latest: Option<LakeManifest> = None;
        for org_id in ctx.organisation_ids() {
            let row: Option<(i64, Option<String>, String, String, i64, String)> = conn
                .query_row(
                    "SELECT manifest_seq, prev_manifest_digest, manifest_digest, object_key, created_at_ms, entries_json
                     FROM lake_manifests WHERE organisation_id = ?1
                     ORDER BY manifest_seq DESC LIMIT 1",
                    rusqlite::params![org_id.as_str()],
                    |r| {
                        Ok((
                            r.get(0)?,
                            r.get(1)?,
                            r.get(2)?,
                            r.get(3)?,
                            r.get(4)?,
                            r.get(5)?,
                        ))
                    },
                )
                .optional()
                .map_err(lake_sql_err)?;
            if let Some((seq, prev, digest, obj_key, created_at_ms, entries_json)) = row {
                let manifest = LakeManifest {
                    organisation_id: org_id.clone(),
                    manifest_seq: u64::try_from(seq).unwrap_or(0),
                    prev_manifest_digest: prev,
                    manifest_digest: digest,
                    object_key: obj_key,
                    created_at_ms,
                    entries: serde_json::from_str(&entries_json).map_err(json_io_err)?,
                };
                if latest
                    .as_ref()
                    .is_none_or(|cur| manifest.created_at_ms >= cur.created_at_ms)
                {
                    latest = Some(manifest);
                }
            }
        }
        Ok(latest)
    }
}

fn check_and_advance_fence(
    conn: &Connection,
    org_id: &OrgId,
    fence: FencingToken,
) -> Result<(u64, u64), CodedError> {
    let fence_i64 = i64::try_from(fence.value()).map_err(|_| {
        CodedError::new(
            CODE_LAKE_IO,
            "Fencing token exceeds i64 bounds.",
            "Use a monotonic fencing token within i64 bounds.",
        )
    })?;
    let row: Option<(i64, i64, i64)> = conn
        .query_row(
            "INSERT INTO lake_fencing (organisation_id, current_fence, snapshot_seq, manifest_seq)
             VALUES (?1, ?2, 0, 0)
             ON CONFLICT(organisation_id) DO UPDATE SET
               current_fence = excluded.current_fence
             WHERE lake_fencing.current_fence <= excluded.current_fence
             RETURNING current_fence, snapshot_seq, manifest_seq",
            rusqlite::params![org_id.as_str(), fence_i64],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(lake_sql_err)?;
    let Some((_, snap, man)) = row else {
        return Err(CodedError::new(
            CODE_LAKE_STALE_FENCE,
            format!("Lake operation rejected stale fence {}.", fence.value()),
            "Re-acquire partition lease before writing to lake.",
        ));
    };
    Ok((
        u64::try_from(snap).unwrap_or(0),
        u64::try_from(man).unwrap_or(0),
    ))
}
