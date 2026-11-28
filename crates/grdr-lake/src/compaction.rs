// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use uuid::Uuid;

use grdr_crypto::AeadKey;
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_IO, LakeObservable, LegalHold, OrgId, RetentionClass, SingleCtx, TenantCtx,
    TenantPath,
};

use crate::crypto::{derive_segment_dek, sha256_hex};
use crate::fuse_filter::ObservableFuseFilter;
use crate::parquet_modular::{open_modular_parquet, seal_modular_parquet};
use crate::schema::lake_sql_err;

#[derive(Debug, Clone)]
struct CompactCandidate {
    segment_id: String,
    retention_class: RetentionClass,
    day: String,
    object_key: String,
    device_ids: Vec<String>,
    session_ids: Vec<String>,
    min_observed_ms: i64,
    max_observed_ms: i64,
    fence: i64,
}

#[derive(Debug, Clone, Default)]
pub(crate) struct CompactionPassStats {
    pub(crate) compacted_groups: usize,
    pub(crate) retired_source_segments: usize,
}

pub(crate) fn lake_daily_put_limit() -> Result<u64, CodedError> {
    let cfg = grdr_schema::limits::load_embedded_limits().map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Failed loading embedded limits config: {e}"),
            "Verify embedded contracts/limits.toml configuration.",
        )
    })?;
    Ok(u64::from(cfg.server.lake.small_org_day_max_puts))
}

pub(crate) fn lake_target_objects_per_day() -> Result<usize, CodedError> {
    let cfg = grdr_schema::limits::load_embedded_limits().map_err(|e| {
        CodedError::new(
            CODE_LAKE_IO,
            format!("Failed loading embedded limits config: {e}"),
            "Verify embedded contracts/limits.toml configuration.",
        )
    })?;
    usize::try_from(cfg.server.lake.small_org_day_max_objects).map_err(|_| {
        CodedError::new(
            CODE_LAKE_IO,
            "Embedded small_org_day_max_objects exceeds usize.",
            "Verify embedded contracts/limits.toml configuration.",
        )
    })
}

pub(crate) fn reserve_daily_puts(
    conn: &mut Connection,
    org_id: &OrgId,
    planned_puts: &BTreeMap<String, u64>,
) -> Result<(), CodedError> {
    if planned_puts.values().all(|&delta| delta == 0) {
        return Ok(());
    }
    let max_puts = lake_daily_put_limit()?;
    let tx = conn.transaction().map_err(lake_sql_err)?;
    for (day, &puts_delta) in planned_puts {
        if puts_delta == 0 {
            continue;
        }
        let cur = read_daily_put_stats(&tx, org_id, day)?;
        let next_puts = cur.0.checked_add(puts_delta).ok_or_else(|| {
            CodedError::new(
                CODE_LAKE_IO,
                format!("Daily lake PUT counter overflow for org `{}` on day `{day}`.", org_id.as_str()),
                "Batch events or run compaction to coalesce small segments within daily PUT budget.",
            )
        })?;
        if next_puts > max_puts {
            return Err(CodedError::new(
                CODE_LAKE_IO,
                format!(
                    "Daily lake PUT budget exceeded for org `{}` on day `{day}` ({next_puts} > {max_puts}).",
                    org_id.as_str()
                ),
                "Batch events or run compaction to coalesce small segments within daily PUT budget.",
            ));
        }
        tx.execute(
            "INSERT INTO lake_put_ledger (organisation_id, day, put_count, data_objects_count)
             VALUES (?1, ?2, ?3, ?4)
             ON CONFLICT(organisation_id, day) DO UPDATE SET
               put_count = excluded.put_count",
            rusqlite::params![
                org_id.as_str(),
                day,
                i64::try_from(next_puts).unwrap_or(i64::MAX),
                i64::try_from(cur.1).unwrap_or(i64::MAX)
            ],
        )
        .map_err(lake_sql_err)?;
    }
    tx.commit().map_err(lake_sql_err)?;
    Ok(())
}

pub(crate) fn record_daily_data_objects(
    conn: &Connection,
    org_id: &OrgId,
    day: &str,
    data_objects_delta: u64,
) -> Result<(), CodedError> {
    if data_objects_delta == 0 {
        return Ok(());
    }
    let cur = read_daily_put_stats(conn, org_id, day)?;
    let next_objs = cur.1.saturating_add(data_objects_delta);
    conn.execute(
        "INSERT INTO lake_put_ledger (organisation_id, day, put_count, data_objects_count)
         VALUES (?1, ?2, ?3, ?4)
         ON CONFLICT(organisation_id, day) DO UPDATE SET
           data_objects_count = excluded.data_objects_count",
        rusqlite::params![
            org_id.as_str(),
            day,
            i64::try_from(cur.0).unwrap_or(i64::MAX),
            i64::try_from(next_objs).unwrap_or(i64::MAX)
        ],
    )
    .map_err(lake_sql_err)?;
    Ok(())
}

pub(crate) fn read_daily_put_stats(
    conn: &Connection,
    org_id: &OrgId,
    day: &str,
) -> Result<(u64, u64), CodedError> {
    use rusqlite::OptionalExtension as _;
    let row: Option<(i64, i64)> = conn
        .query_row(
            "SELECT put_count, data_objects_count FROM lake_put_ledger
             WHERE organisation_id = ?1 AND day = ?2",
            rusqlite::params![org_id.as_str(), day],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()
        .map_err(lake_sql_err)?;
    Ok(row.map_or((0, 0), |(p, o)| {
        (u64::try_from(p).unwrap_or(0), u64::try_from(o).unwrap_or(0))
    }))
}

pub(crate) fn coalesce_day_segments<B: BlobPort>(
    conn: &mut Connection,
    blobs: &B,
    org_kek: &AeadKey,
    ctx: &SingleCtx,
    active_holds: &[LegalHold],
    now_ms: i64,
) -> Result<CompactionPassStats, CodedError> {
    let org_id = ctx.organisation_id();
    let candidates = load_compact_candidates(conn, org_id.as_str())?;
    let mut by_partition: BTreeMap<(RetentionClass, String), Vec<CompactCandidate>> =
        BTreeMap::new();
    for item in candidates {
        let held = active_holds.iter().any(|h| {
            h.covers(
                item.retention_class,
                &item.day,
                &item.device_ids,
                &item.session_ids,
            )
        });
        if !held {
            by_partition
                .entry((item.retention_class, item.day.clone()))
                .or_default()
                .push(item);
        }
    }

    let max_puts = lake_daily_put_limit()?;
    let target_max_objects = lake_target_objects_per_day()?;
    let read_ctx = TenantCtx::Single(ctx.clone());
    let mut stats = CompactionPassStats::default();
    for ((class, day), group) in by_partition {
        if group.len() < 2 && group.len() <= target_max_objects {
            continue;
        }
        let (put_count, _) = read_daily_put_stats(conn, org_id, &day)?;
        if put_count.saturating_add(1) > max_puts {
            continue;
        }

        let mut merged_records = Vec::new();
        let mut seen = BTreeSet::new();
        let mut all_obs: Vec<LakeObservable> = Vec::new();
        let mut dev_set = BTreeSet::new();
        let mut sess_set = BTreeSet::new();
        let mut min_obs = i64::MAX;
        let mut max_obs = i64::MIN;
        let mut max_fence = 0i64;

        for seg in &group {
            max_fence = max_fence.max(seg.fence);
            min_obs = min_obs.min(seg.min_observed_ms);
            max_obs = max_obs.max(seg.max_observed_ms);
            for d in &seg.device_ids {
                dev_set.insert(d.clone());
            }
            for s in &seg.session_ids {
                sess_set.insert(s.clone());
            }
            let path = TenantPath::parse(ctx, &seg.object_key)?;
            let Some(blob) = blobs.get(&read_ctx, &path)? else {
                return Err(CodedError::new(
                    CODE_LAKE_IO,
                    format!(
                        "Compaction source segment `{}` missing in object store.",
                        seg.object_key
                    ),
                    "Restore missing segment blob before compacting.",
                ));
            };
            let (_, dek) = derive_segment_dek(org_kek, org_id, class.as_str(), &day);
            let recs = open_modular_parquet(
                org_id,
                class,
                &day,
                &seg.object_key,
                &dek,
                &blob.bytes,
                None,
            )?;
            for rec in recs {
                let k = (rec.device_id.clone(), rec.epoch, rec.lane.clone(), rec.seq);
                if seen.insert(k) {
                    all_obs.extend(rec.observables.iter().cloned());
                    merged_records.push(rec);
                }
            }
        }
        if merged_records.is_empty() {
            continue;
        }
        merged_records.sort_by(|a, b| {
            (
                &a.device_id,
                &a.root_session_id,
                a.epoch,
                a.monotonic_ns,
                &a.lane,
                a.seq,
            )
                .cmp(&(
                    &b.device_id,
                    &b.root_session_id,
                    b.epoch,
                    b.monotonic_ns,
                    &b.lane,
                    b.seq,
                ))
        });

        let new_seg_id = format!("seg-{}-compact-{}", class.as_str(), Uuid::now_v7().simple());
        let new_key = format!("class={}/day={day}/{new_seg_id}.parquet", class.as_str());
        let (data_key_id, day_dek) = derive_segment_dek(org_kek, org_id, class.as_str(), &day);
        let new_bytes = seal_modular_parquet(
            org_id,
            class,
            &day,
            &new_key,
            &data_key_id,
            &day_dek,
            &merged_records,
        )?;
        let digest = sha256_hex(&new_bytes);
        let filter_bytes = ObservableFuseFilter::build(&all_obs).encode();
        let planned_put = BTreeMap::from([(day.clone(), 1u64)]);
        reserve_daily_puts(conn, org_id, &planned_put)?;
        blobs.put(ctx, &TenantPath::parse(ctx, &new_key)?, &new_bytes)?;

        let tx = conn.transaction().map_err(lake_sql_err)?;
        record_daily_data_objects(&tx, org_id, &day, 1)?;
        let dev_json = serde_json::to_string(&dev_set.into_iter().collect::<Vec<_>>())
            .map_err(crate::flush::json_io_err)?;
        let sess_json = serde_json::to_string(&sess_set.into_iter().collect::<Vec<_>>())
            .map_err(crate::flush::json_io_err)?;

        tx.execute(
            "INSERT INTO lake_segments (
                organisation_id, segment_id, retention_class, day, object_key, row_count, size_bytes,
                digest_sha256, schema_rev, data_key_id, device_ids_json, root_session_ids_json,
                min_observed_ms, max_observed_ms, fence, logical_deleted_at_ms, physical_deleted_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?13, ?14, NULL, NULL)",
            rusqlite::params![
                org_id.as_str(),
                new_seg_id,
                class.as_str(),
                day,
                new_key,
                i64::try_from(merged_records.len()).unwrap_or(i64::MAX),
                i64::try_from(new_bytes.len()).unwrap_or(i64::MAX),
                digest,
                data_key_id,
                dev_json,
                sess_json,
                min_obs,
                max_obs,
                max_fence
            ],
        )
        .map_err(lake_sql_err)?;
        tx.execute(
            "INSERT INTO lake_segment_filters (organisation_id, segment_id, filter_blob, observable_count)
             VALUES (?1, ?2, ?3, ?4)",
            rusqlite::params![
                org_id.as_str(),
                new_seg_id,
                filter_bytes,
                i64::try_from(all_obs.len()).unwrap_or(i64::MAX)
            ],
        )
        .map_err(lake_sql_err)?;

        for rec in &merged_records {
            for obs in &rec.observables {
                tx.execute(
                    "INSERT OR IGNORE INTO lake_observables (organisation_id, observable_type, value, segment_id, event_id)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        org_id.as_str(),
                        obs.observable_type,
                        obs.value,
                        new_seg_id,
                        rec.event_id
                    ],
                )
                .map_err(lake_sql_err)?;
            }
        }
        for old in &group {
            tx.execute(
                "UPDATE lake_segments SET logical_deleted_at_ms = ?3
                 WHERE organisation_id = ?1 AND segment_id = ?2",
                rusqlite::params![org_id.as_str(), old.segment_id, now_ms],
            )
            .map_err(lake_sql_err)?;
            tx.execute(
                "DELETE FROM lake_observables
                 WHERE organisation_id = ?1 AND segment_id = ?2",
                rusqlite::params![org_id.as_str(), old.segment_id],
            )
            .map_err(lake_sql_err)?;
            tx.execute(
                "DELETE FROM lake_segment_filters
                 WHERE organisation_id = ?1 AND segment_id = ?2",
                rusqlite::params![org_id.as_str(), old.segment_id],
            )
            .map_err(lake_sql_err)?;
            stats.retired_source_segments = stats.retired_source_segments.saturating_add(1);
        }
        tx.commit().map_err(lake_sql_err)?;
        stats.compacted_groups = stats.compacted_groups.saturating_add(1);
    }

    Ok(stats)
}

fn load_compact_candidates(
    conn: &Connection,
    org_id: &str,
) -> Result<Vec<CompactCandidate>, CodedError> {
    let mut stmt = conn
        .prepare(
            "SELECT segment_id, retention_class, day, object_key, device_ids_json,
                    root_session_ids_json, min_observed_ms, max_observed_ms, fence
             FROM lake_segments
             WHERE organisation_id = ?1 AND logical_deleted_at_ms IS NULL
             ORDER BY day ASC, retention_class ASC, segment_id ASC",
        )
        .map_err(lake_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params![org_id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, String>(1)?,
                r.get::<_, String>(2)?,
                r.get::<_, String>(3)?,
                r.get::<_, String>(4)?,
                r.get::<_, String>(5)?,
                r.get::<_, i64>(6)?,
                r.get::<_, i64>(7)?,
                r.get::<_, i64>(8)?,
            ))
        })
        .map_err(lake_sql_err)?;

    let mut out = Vec::new();
    for row in rows {
        let (seg_id, cls_str, day, key, dev_json, sess_json, min_ms, max_ms, fence) =
            row.map_err(lake_sql_err)?;
        let Some(retention_class) = RetentionClass::parse(&cls_str) else {
            continue;
        };
        let device_ids = serde_json::from_str(&dev_json).map_err(crate::flush::json_io_err)?;
        let session_ids = serde_json::from_str(&sess_json).map_err(crate::flush::json_io_err)?;
        out.push(CompactCandidate {
            segment_id: seg_id,
            retention_class,
            day,
            object_key: key,
            device_ids,
            session_ids,
            min_observed_ms: min_ms,
            max_observed_ms: max_ms,
            fence,
        });
    }
    Ok(out)
}
