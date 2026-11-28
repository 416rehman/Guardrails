// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::sync::{Mutex, MutexGuard};

use rusqlite::{Connection, OptionalExtension};

use grdr_crypto::{AeadKey, SigningKeypair};
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_IO, CODE_LAKE_STALE_FENCE, ErasureReceipt, EventsPort, FencingToken,
    LakeBatch, LakeCompactionResult, LakeFlushResult, LakeManifest, LakeQueryIr, LakeQueryResult,
    LegalHold, LegalHoldRequest, OrgId, SingleCtx, TenantCtx,
};

use crate::compaction::read_daily_put_stats;
use crate::crypto::{SessionKeyLookup, ensure_session_key, seal_content_fields};
use crate::erasure::{
    ErasureRequest, erase_session_records, place_hold_record, release_hold_record,
};
use crate::flush::{FlushContext, flush_org_batches, json_io_err};
use crate::manifest_verify::{
    daily_agg_rows_conn, export_segment_as_par1_conn, verify_manifest_chain_conn,
};
use crate::query::run_lake_query;
use crate::retention::run_retention_and_compaction;
use crate::schema::{configure_and_migrate_catalogue, lake_sql_err};

const DEFAULT_PITR_LAG_MS: i64 = 7 * 86_400_000;

pub struct LakeStore<B: BlobPort> {
    blobs: B,
    catalogue: Mutex<Connection>,
    memtable: Mutex<BTreeMap<String, Vec<LakeBatch>>>,
    org_kek: AeadKey,
    pitr_lag_ms: i64,
    signing_key: Option<SigningKeypair>,
    trusted_manifest_keys: Vec<[u8; 32]>,
}

impl<B: BlobPort + std::fmt::Debug> std::fmt::Debug for LakeStore<B> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("LakeStore")
            .field("blobs", &self.blobs)
            .field("pitr_lag_ms", &self.pitr_lag_ms)
            .field(
                "signing_key",
                &self.signing_key.as_ref().map(|_| "[REDACTED]"),
            )
            .field(
                "trusted_manifest_keys_count",
                &self.trusted_manifest_keys.len(),
            )
            .finish_non_exhaustive()
    }
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
            pitr_lag_ms: DEFAULT_PITR_LAG_MS,
            signing_key: None,
            trusted_manifest_keys: Vec::new(),
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
            pitr_lag_ms: DEFAULT_PITR_LAG_MS,
            signing_key: None,
            trusted_manifest_keys: Vec::new(),
        })
    }

    pub fn with_pitr_lag_ms(mut self, pitr_lag_ms: i64) -> Self {
        self.pitr_lag_ms = pitr_lag_ms.max(0);
        self
    }

    pub fn with_signing_key(mut self, signing_key: SigningKeypair) -> Self {
        let pk = signing_key.public_key_bytes();
        if !self.trusted_manifest_keys.contains(&pk) {
            self.trusted_manifest_keys.push(pk);
        }
        self.signing_key = Some(signing_key);
        self
    }

    pub fn with_trusted_manifest_keys(mut self, keys: Vec<[u8; 32]>) -> Self {
        for pk in keys {
            if !self.trusted_manifest_keys.contains(&pk) {
                self.trusted_manifest_keys.push(pk);
            }
        }
        self
    }

    pub fn blobs(&self) -> &B {
        &self.blobs
    }

    pub fn daily_put_stats(&self, ctx: &SingleCtx, day: &str) -> Result<(u64, u64), CodedError> {
        let conn = self.lock_cat()?;
        read_daily_put_stats(&conn, ctx.organisation_id(), day)
    }

    pub fn daily_agg_rows(
        &self,
        ctx: &SingleCtx,
        day: &str,
    ) -> Result<Vec<(String, String, u64)>, CodedError> {
        let conn = self.lock_cat()?;
        daily_agg_rows_conn(&conn, ctx.organisation_id(), day)
    }

    pub fn export_segment_as_par1(
        &self,
        ctx: &TenantCtx,
        org_id: &OrgId,
        object_key: &str,
    ) -> Result<Vec<u8>, CodedError> {
        let conn = self.lock_cat()?;
        export_segment_as_par1_conn(&conn, &self.blobs, &self.org_kek, ctx, org_id, object_key)
    }

    pub fn verify_manifest_chain(&self, ctx: &TenantCtx) -> Result<usize, CodedError> {
        let conn = self.lock_cat()?;
        verify_manifest_chain_conn(&conn, ctx, &self.trusted_manifest_keys)
    }

    pub fn verify_manifest_chain_with_keys(
        &self,
        ctx: &TenantCtx,
        trusted_pubkeys: &[[u8; 32]],
    ) -> Result<usize, CodedError> {
        let conn = self.lock_cat()?;
        verify_manifest_chain_conn(&conn, ctx, trusted_pubkeys)
    }

    #[cfg(test)]
    pub(crate) fn org_kek(&self) -> &AeadKey {
        &self.org_kek
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

        let due_batches = {
            let mem = self.lock_mem()?;
            mem.get(org_id.as_str())
                .map(|batches| {
                    batches
                        .iter()
                        .filter(|b| {
                            b.records
                                .iter()
                                .map(|r| r.received_at_ms)
                                .max()
                                .unwrap_or(now_ms)
                                <= due_before_ms
                        })
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default()
        };

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

        let flushed_keys: BTreeSet<(u32, u64, String)> = due_batches
            .iter()
            .map(|b| (b.partition, b.bus_offset, b.lane.clone()))
            .collect();

        let res = flush_org_batches(
            &mut conn,
            &self.blobs,
            &self.org_kek,
            ctx,
            FlushContext {
                fence,
                snapshot_seq,
                manifest_seq,
                now_ms,
                signing_key: self.signing_key.as_ref(),
            },
            due_batches,
        )?;

        let mut mem = self.lock_mem()?;
        if let Some(org_batches) = mem.get_mut(org_id.as_str()) {
            org_batches
                .retain(|b| !flushed_keys.contains(&(b.partition, b.bus_offset, b.lane.clone())));
        }
        Ok(res)
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
        place_hold_record(&conn, ctx, hold)
    }

    fn release_hold(
        &self,
        ctx: &SingleCtx,
        hold_id: &str,
        now_ms: i64,
    ) -> Result<LegalHold, CodedError> {
        let conn = self.lock_cat()?;
        release_hold_record(&conn, ctx, hold_id, now_ms)
    }

    fn erase_session(
        &self,
        ctx: &SingleCtx,
        root_session_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<ErasureReceipt, CodedError> {
        let mut conn = self.lock_cat()?;
        let mut mem = self.lock_mem()?;
        let org_mem = mem.get_mut(ctx.organisation_id().as_str());
        erase_session_records(
            &mut conn,
            &self.blobs,
            &self.org_kek,
            org_mem,
            ErasureRequest {
                ctx,
                root_session_id,
                reason,
                now_ms,
            },
        )
    }

    fn compact_and_retain(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        now_ms: i64,
    ) -> Result<LakeCompactionResult, CodedError> {
        let mut conn = self.lock_cat()?;
        check_and_advance_fence(&conn, ctx.organisation_id(), fence)?;
        run_retention_and_compaction(
            &mut conn,
            &self.blobs,
            &self.org_kek,
            ctx,
            now_ms,
            self.pitr_lag_ms,
        )
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
