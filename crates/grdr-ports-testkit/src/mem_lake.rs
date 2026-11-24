// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::sync::{Mutex, MutexGuard};

use grdr_model::CodedError;
use grdr_model::error::CODE_STORE_IO;
use grdr_ports::{
    CODE_LAKE_HOLD_ACTIVE, CODE_LAKE_NOT_FOUND, CODE_LAKE_STALE_FENCE, ContentKeyState,
    ErasureReceipt, EventsPort, FencingToken, LakeBatch, LakeCompactionResult, LakeFlushResult,
    LakeManifest, LakeQueryIr, LakeQueryResult, LakeRecord, LegalHold, LegalHoldRequest,
    LegalHoldState, OrgId, RetentionClass, SessionContentKey, SingleCtx, TenantCtx,
};

use crate::mem_lake_ops::{
    MemSegment, OrgLakeState, expire_content_keys, flush_due_batches, partition_due_batches,
    retain_segments,
};
use crate::query_eval::evaluate_query_ir;

#[derive(Debug, Default)]
pub struct MemoryEventLake {
    orgs: Mutex<BTreeMap<String, OrgLakeState>>,
}

impl MemoryEventLake {
    pub fn content_key_state(&self, org: &OrgId, root_session_id: &str) -> Option<ContentKeyState> {
        let g = self.orgs.lock().ok()?;
        g.get(org.as_str())
            .and_then(|s| s.content_keys.get(root_session_id))
            .map(|k| k.state.clone())
    }
}

impl EventsPort for MemoryEventLake {
    fn append(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        batch: &LakeBatch,
    ) -> Result<u64, CodedError> {
        let mut g = lock_lake(&self.orgs)?;
        let org_state = g
            .entry(ctx.organisation_id().as_str().to_string())
            .or_default();
        if fence.value() < org_state.fence {
            return Err(CodedError::new(
                CODE_LAKE_STALE_FENCE,
                format!("Lake append rejected stale fence {}.", fence.value()),
                "Re-acquire partition lease before appending.",
            ));
        }
        org_state.fence = fence.value();
        let mut sanitized = batch.clone();
        for rec in &mut sanitized.records {
            if !rec.content_fields.is_empty() {
                let entry = org_state
                    .content_keys
                    .entry(rec.root_session_id.clone())
                    .or_insert_with(|| SessionContentKey {
                        organisation_id: ctx.organisation_id().clone(),
                        root_session_id: rec.root_session_id.clone(),
                        key_id: format!("sck-{}", rec.root_session_id),
                        wrapped_key: format!("wrapped:{}", rec.root_session_id),
                        created_at_ms: rec.received_at_ms,
                        destroy_after_ms: rec
                            .received_at_ms
                            .saturating_add(RetentionClass::Content.retention_ms()),
                        state: ContentKeyState::Active,
                    });
                if matches!(entry.state, ContentKeyState::Destroyed { .. }) {
                    rec.content_fields.clear();
                }
            }
        }
        let appended = u64::try_from(sanitized.records.len()).unwrap_or(u64::MAX);
        org_state.tail.push(sanitized);
        Ok(appended)
    }

    fn flush(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        due_before_ms: i64,
        now_ms: i64,
    ) -> Result<LakeFlushResult, CodedError> {
        let mut g = lock_lake(&self.orgs)?;
        let org_state = g
            .entry(ctx.organisation_id().as_str().to_string())
            .or_default();
        if fence.value() < org_state.fence {
            return Err(CodedError::new(
                CODE_LAKE_STALE_FENCE,
                format!("Lake flush rejected stale fence {}.", fence.value()),
                "Re-acquire partition lease before flushing.",
            ));
        }
        org_state.fence = fence.value();

        let (due_batches, keep_batches) =
            partition_due_batches(&mut org_state.tail, due_before_ms, now_ms);
        org_state.tail = keep_batches;
        if due_batches.is_empty() {
            return Ok(LakeFlushResult {
                organisation_id: ctx.organisation_id().clone(),
                snapshot_id: org_state.snapshot_seq,
                committed_through: None,
                segments_written: 0,
                archive_segments_written: 0,
                rows_flushed: 0,
                manifest_seq: org_state.manifests.last().map(|m| m.manifest_seq),
            });
        }

        let (committed_through, segments_written, archive_segments_written, rows_flushed) =
            flush_due_batches(ctx.organisation_id(), org_state, due_batches, now_ms);

        Ok(LakeFlushResult {
            organisation_id: ctx.organisation_id().clone(),
            snapshot_id: org_state.snapshot_seq,
            committed_through,
            segments_written,
            archive_segments_written,
            rows_flushed,
            manifest_seq: Some(org_state.manifest_seq),
        })
    }

    fn execute_query_ir(
        &self,
        ctx: &TenantCtx,
        query: &LakeQueryIr,
    ) -> Result<LakeQueryResult, CodedError> {
        let g = lock_lake(&self.orgs)?;
        let mut rows_with_org: Vec<(OrgId, LakeRecord, bool, bool)> = Vec::new();
        let mut scanned_segments = 0usize;
        let mut tail_rows = 0usize;
        let mut seen_keys: BTreeSet<(String, String, u64, String, u64)> = BTreeSet::new();

        for org_id in ctx.organisation_ids() {
            let Some(org_state) = g.get(org_id.as_str()) else {
                continue;
            };
            for batch in &org_state.tail {
                for rec in &batch.records {
                    if seen_keys.insert(dedup_key(org_id, rec)) {
                        let shredded = is_shredded(org_state, &rec.root_session_id);
                        tail_rows = tail_rows.saturating_add(1);
                        rows_with_org.push((org_id.clone(), rec.clone(), shredded, true));
                    }
                }
            }
            for seg in &org_state.segments {
                if seg.logically_deleted_at_ms.is_some() {
                    continue;
                }
                scanned_segments = scanned_segments.saturating_add(1);
                for rec in &seg.records {
                    if seen_keys.insert(dedup_key(org_id, rec)) {
                        let shredded = is_shredded(org_state, &rec.root_session_id);
                        rows_with_org.push((org_id.clone(), rec.clone(), shredded, false));
                    }
                }
            }
        }

        evaluate_query_ir(&rows_with_org, query, scanned_segments, tail_rows)
    }

    fn place_hold(
        &self,
        ctx: &SingleCtx,
        hold: &LegalHoldRequest,
    ) -> Result<LegalHold, CodedError> {
        let mut g = lock_lake(&self.orgs)?;
        let org_state = g
            .entry(ctx.organisation_id().as_str().to_string())
            .or_default();
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
        org_state.holds.insert(hold.hold_id.clone(), record.clone());
        Ok(record)
    }

    fn release_hold(
        &self,
        ctx: &SingleCtx,
        hold_id: &str,
        now_ms: i64,
    ) -> Result<LegalHold, CodedError> {
        let mut g = lock_lake(&self.orgs)?;
        let org_state = g.get_mut(ctx.organisation_id().as_str()).ok_or_else(|| {
            CodedError::new(
                CODE_LAKE_NOT_FOUND,
                format!("Hold `{hold_id}` not found."),
                "List active holds and verify hold_id.",
            )
        })?;
        let hold = org_state.holds.get_mut(hold_id).ok_or_else(|| {
            CodedError::new(
                CODE_LAKE_NOT_FOUND,
                format!("Hold `{hold_id}` not found."),
                "List active holds and verify hold_id.",
            )
        })?;
        hold.state = LegalHoldState::Released {
            released_at_ms: now_ms,
        };
        Ok(hold.clone())
    }

    fn erase_session(
        &self,
        ctx: &SingleCtx,
        root_session_id: &str,
        _reason: &str,
        now_ms: i64,
    ) -> Result<ErasureReceipt, CodedError> {
        let mut g = lock_lake(&self.orgs)?;
        let org_state = g
            .entry(ctx.organisation_id().as_str().to_string())
            .or_default();
        let active_holds: Vec<LegalHold> = org_state
            .holds
            .values()
            .filter(|h| h.is_active_at(now_ms))
            .cloned()
            .collect();
        let session_list = vec![root_session_id.to_string()];

        if let Some(key) = org_state.content_keys.get(root_session_id)
            && matches!(key.state, ContentKeyState::Active)
        {
            let key_day = crate::mem_lake_ops::day_from_ms(key.created_at_ms);
            if active_holds
                .iter()
                .any(|h| h.covers(RetentionClass::Content, &key_day, &[], &session_list))
            {
                return Err(CodedError::new(
                    CODE_LAKE_HOLD_ACTIVE,
                    format!(
                        "Cannot erase session `{root_session_id}` while an active legal hold applies."
                    ),
                    "Release blocking legal holds before re-running session erasure.",
                ));
            }
        }
        for arch in &org_state.archives {
            if arch.root_session_ids.contains(root_session_id)
                && active_holds
                    .iter()
                    .any(|h| h.covers(RetentionClass::Content, &arch.day, &[], &session_list))
            {
                return Err(CodedError::new(
                    CODE_LAKE_HOLD_ACTIVE,
                    format!(
                        "Cannot erase archive segment for session `{root_session_id}` under active legal hold."
                    ),
                    "Release blocking legal holds before re-running session erasure.",
                ));
            }
        }

        let destruction_record_id = format!("erasure-{root_session_id}-{now_ms}");
        let mut keys_destroyed = 0usize;
        if let Some(key) = org_state.content_keys.get_mut(root_session_id)
            && matches!(key.state, ContentKeyState::Active)
        {
            key.wrapped_key.clear();
            key.state = ContentKeyState::Destroyed {
                destroyed_at_ms: now_ms,
                destruction_record_id: destruction_record_id.clone(),
            };
            keys_destroyed = 1;
        }
        clear_session_content(
            &mut org_state.tail,
            &mut org_state.segments,
            root_session_id,
        );

        let mut archive_segments_reduced = 0usize;
        for arch in &mut org_state.archives {
            if arch.root_session_ids.contains(root_session_id) && !arch.reduced {
                arch.reduced = true;
                archive_segments_reduced = archive_segments_reduced.saturating_add(1);
            }
        }

        Ok(ErasureReceipt {
            organisation_id: ctx.organisation_id().clone(),
            root_session_id: root_session_id.to_string(),
            destruction_record_id: destruction_record_id.clone(),
            erased_at_ms: now_ms,
            keys_destroyed,
            archive_segments_reduced,
            held_segments_deferred: 0,
            state_log_key: format!("state-log/{destruction_record_id}.json"),
        })
    }

    fn compact_and_retain(
        &self,
        ctx: &SingleCtx,
        fence: FencingToken,
        now_ms: i64,
    ) -> Result<LakeCompactionResult, CodedError> {
        let mut g = lock_lake(&self.orgs)?;
        let org_state = g
            .entry(ctx.organisation_id().as_str().to_string())
            .or_default();
        if fence.value() < org_state.fence {
            return Err(CodedError::new(
                CODE_LAKE_STALE_FENCE,
                format!("Compaction rejected stale fence {}.", fence.value()),
                "Re-acquire partition lease before compacting.",
            ));
        }
        org_state.fence = fence.value();
        let active_holds: Vec<LegalHold> = org_state
            .holds
            .values()
            .filter(|h| h.is_active_at(now_ms))
            .cloned()
            .collect();

        let (segments_deleted, segments_held, observables_written) =
            retain_segments(&mut org_state.segments, &active_holds, now_ms);
        let keys_destroyed =
            expire_content_keys(&mut org_state.content_keys, &active_holds, now_ms);

        Ok(LakeCompactionResult {
            organisation_id: ctx.organisation_id().clone(),
            segments_compacted: org_state
                .segments
                .iter()
                .filter(|s| s.logically_deleted_at_ms.is_none())
                .count(),
            segments_logically_deleted: segments_deleted,
            segments_physically_deleted: segments_deleted,
            segments_held,
            observables_written,
            keys_destroyed,
        })
    }

    fn manifest(&self, ctx: &TenantCtx) -> Result<Option<LakeManifest>, CodedError> {
        let g = lock_lake(&self.orgs)?;
        let mut latest: Option<LakeManifest> = None;
        for org_id in ctx.organisation_ids() {
            if let Some(m) = g.get(org_id.as_str()).and_then(|s| s.manifests.last())
                && latest
                    .as_ref()
                    .is_none_or(|cur| m.created_at_ms >= cur.created_at_ms)
            {
                latest = Some(m.clone());
            }
        }
        Ok(latest)
    }
}

fn dedup_key(org: &OrgId, rec: &LakeRecord) -> (String, String, u64, String, u64) {
    (
        org.as_str().to_string(),
        rec.device_id.clone(),
        rec.epoch,
        rec.lane.clone(),
        rec.seq,
    )
}

fn is_shredded(org_state: &OrgLakeState, root_session_id: &str) -> bool {
    org_state
        .content_keys
        .get(root_session_id)
        .is_some_and(|k| matches!(k.state, ContentKeyState::Destroyed { .. }))
}

fn clear_session_content(
    tail: &mut [LakeBatch],
    segments: &mut [MemSegment],
    root_session_id: &str,
) {
    for batch in tail {
        for rec in &mut batch.records {
            if rec.root_session_id == root_session_id {
                rec.content_fields.clear();
            }
        }
    }
    for seg in segments {
        for rec in &mut seg.records {
            if rec.root_session_id == root_session_id {
                rec.content_fields.clear();
            }
        }
    }
}

fn lock_lake<T>(mutex: &Mutex<T>) -> Result<MutexGuard<'_, T>, CodedError> {
    mutex.lock().map_err(|_| {
        CodedError::new(
            CODE_STORE_IO,
            "Memory event lake mutex poisoned.",
            "Recreate MemoryEventLake.",
        )
    })
}
