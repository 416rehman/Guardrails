// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use grdr_crypto::AeadKey;
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_IO, FencingToken, LakeBatch, LakeFlushResult, LakeManifest,
    LakeManifestEntry, LakeRecord, OrgId, RetentionClass, SingleCtx, TenantPath,
};

use crate::crypto::{
    ArchivePayload, archive_seal_domain, day_from_ms, derive_segment_dek, seal_envelope,
    segment_seal_domain, sha256_hex,
};
use crate::query::SealedSegmentBlob;
use crate::schema::lake_sql_err;

const MS_PER_DAY: i64 = 86_400_000;
const MAX_BACKDATE_MS: i64 = 30 * MS_PER_DAY;

pub(crate) struct FlushContext {
    pub(crate) fence: FencingToken,
    pub(crate) snapshot_seq: u64,
    pub(crate) manifest_seq: u64,
    pub(crate) now_ms: i64,
}

struct ManifestMeta<'a> {
    prev_digest: Option<&'a str>,
    manifest_digest: &'a str,
    manifest_key: &'a str,
    entries_json: &'a str,
}

struct SegmentInsert {
    seg_id: String,
    class: RetentionClass,
    day: String,
    rel_key: String,
    row_count: u64,
    size_bytes: u64,
    digest: String,
    data_key_id: String,
    records: Vec<LakeRecord>,
}

struct ArchiveInsert {
    arch_key: String,
    lane: String,
    day: String,
    sessions: Vec<String>,
    digest: String,
}

pub(crate) fn clamp_observed_ms(observed_ms: i64, received_at_ms: i64) -> i64 {
    let min_ms = received_at_ms.saturating_sub(MAX_BACKDATE_MS).max(0);
    let max_ms = received_at_ms.saturating_add(MS_PER_DAY);
    observed_ms.clamp(min_ms, max_ms)
}

pub(crate) fn flush_org_batches<B: BlobPort>(
    conn: &mut Connection,
    blobs: &B,
    org_kek: &AeadKey,
    ctx: &SingleCtx,
    mut flush_ctx: FlushContext,
    due_batches: Vec<LakeBatch>,
) -> Result<LakeFlushResult, CodedError> {
    let org_id = ctx.organisation_id();
    let mut committed_through: Option<u64> = None;
    let mut grouped: BTreeMap<(RetentionClass, String), Vec<LakeRecord>> = BTreeMap::new();
    let mut archive_rows = Vec::new();
    let mut rows_flushed = 0usize;

    for batch in due_batches {
        committed_through =
            Some(committed_through.map_or(batch.bus_offset, |cur| cur.max(batch.bus_offset)));
        let mut session_ids = BTreeSet::new();
        let mut archive_day = day_from_ms(flush_ctx.now_ms)?;
        let mut batch_records = Vec::with_capacity(batch.records.len());
        for mut rec in batch.records {
            rec.observed_time_ms = clamp_observed_ms(rec.observed_time_ms, rec.received_at_ms);
            let day = day_from_ms(rec.observed_time_ms)?;
            archive_day = day.clone();
            session_ids.insert(rec.root_session_id.clone());
            rows_flushed = rows_flushed.saturating_add(1);
            batch_records.push(rec.clone());
            grouped
                .entry((rec.retention_class, day))
                .or_default()
                .push(rec);
        }
        if !batch.archive_bytes.is_empty() {
            let arch_key = format!(
                "class=archive/lane={}/day={archive_day}/{}.seg",
                batch.lane,
                Uuid::now_v7().simple()
            );
            let payload = ArchivePayload {
                lane: batch.lane.clone(),
                day: archive_day.clone(),
                records: batch_records,
                raw_archive_b64: Some(B64_URL.encode(&batch.archive_bytes)),
                reduced_sessions: Vec::new(),
            };
            let plain_bytes = serde_json::to_vec(&payload).map_err(json_io_err)?;
            let (arch_key_id, arch_dek) =
                derive_segment_dek(org_kek, org_id, "archive", &archive_day);
            let sealed_bytes = seal_envelope(
                &arch_dek,
                &arch_key_id,
                archive_seal_domain(),
                &[org_id.as_str(), "archive", &archive_day, &arch_key],
                &plain_bytes,
            )?;
            let tenant_path = TenantPath::parse(ctx, &arch_key)?;
            blobs.put(ctx, &tenant_path, &sealed_bytes)?;
            archive_rows.push(ArchiveInsert {
                arch_key,
                lane: batch.lane,
                day: archive_day,
                sessions: session_ids.into_iter().collect(),
                digest: sha256_hex(&sealed_bytes),
            });
        }
    }

    let mut manifest_entries = Vec::new();
    let mut segment_inserts = Vec::new();
    for ((class, day), mut records) in grouped {
        records.sort_by(|a, b| {
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
        flush_ctx.snapshot_seq = flush_ctx.snapshot_seq.saturating_add(1);
        let seg_id = format!("seg-{}-{}", class.as_str(), Uuid::now_v7().simple());
        let rel_key = format!("class={}/day={day}/{seg_id}.json", class.as_str());
        let blob_payload = SealedSegmentBlob {
            segment_id: seg_id.clone(),
            retention_class: class,
            day: day.clone(),
            records: records.clone(),
        };
        let plain_bytes = serde_json::to_vec(&blob_payload).map_err(json_io_err)?;
        let (data_key_id, seg_dek) = derive_segment_dek(org_kek, org_id, class.as_str(), &day);
        let bytes = seal_envelope(
            &seg_dek,
            &data_key_id,
            segment_seal_domain(),
            &[org_id.as_str(), class.as_str(), &day, &rel_key],
            &plain_bytes,
        )?;
        let tenant_path = TenantPath::parse(ctx, &rel_key)?;
        blobs.put(ctx, &tenant_path, &bytes)?;
        let digest = sha256_hex(&bytes);
        let size_bytes = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        let row_count = u64::try_from(records.len()).unwrap_or(u64::MAX);
        manifest_entries.push(LakeManifestEntry {
            object_key: rel_key.clone(),
            retention_class: class,
            day: day.clone(),
            row_count,
            size_bytes,
            digest_sha256: digest.clone(),
            schema_rev: 1,
            data_key_id: data_key_id.clone(),
        });
        segment_inserts.push(SegmentInsert {
            seg_id,
            class,
            day,
            rel_key,
            row_count,
            size_bytes,
            digest,
            data_key_id,
            records,
        });
    }

    flush_ctx.manifest_seq = flush_ctx.manifest_seq.saturating_add(1);
    let prev_digest: Option<String> = conn
        .query_row(
            "SELECT manifest_digest FROM lake_manifests
             WHERE organisation_id = ?1 ORDER BY manifest_seq DESC LIMIT 1",
            rusqlite::params![org_id.as_str()],
            |row| row.get(0),
        )
        .optional()
        .map_err(lake_sql_err)?;
    let entries_json = serde_json::to_string(&manifest_entries).map_err(json_io_err)?;
    let manifest_chain_material = format!(
        "{}:{}:{}:{}:{}",
        org_id.as_str(),
        flush_ctx.manifest_seq,
        prev_digest.as_deref().unwrap_or("genesis"),
        flush_ctx.now_ms,
        entries_json
    );
    let manifest_digest = sha256_hex(manifest_chain_material.as_bytes());
    let manifest_key = format!("class=manifest/seq-{}.json", flush_ctx.manifest_seq);
    let manifest_obj = LakeManifest {
        organisation_id: org_id.clone(),
        manifest_seq: flush_ctx.manifest_seq,
        prev_manifest_digest: prev_digest.clone(),
        manifest_digest: manifest_digest.clone(),
        object_key: manifest_key.clone(),
        created_at_ms: flush_ctx.now_ms,
        entries: manifest_entries,
    };
    let manifest_bytes = serde_json::to_vec(&manifest_obj).map_err(json_io_err)?;
    blobs.put(
        ctx,
        &TenantPath::parse(ctx, &manifest_key)?,
        &manifest_bytes,
    )?;

    let segments_written = segment_inserts.len();
    let archive_segments_written = archive_rows.len();
    let meta = ManifestMeta {
        prev_digest: prev_digest.as_deref(),
        manifest_digest: &manifest_digest,
        manifest_key: &manifest_key,
        entries_json: &entries_json,
    };
    commit_flush_tx(
        conn,
        org_id,
        &flush_ctx,
        &meta,
        archive_rows,
        segment_inserts,
    )?;

    Ok(LakeFlushResult {
        organisation_id: org_id.clone(),
        snapshot_id: flush_ctx.snapshot_seq,
        committed_through,
        segments_written,
        archive_segments_written,
        rows_flushed,
        manifest_seq: Some(flush_ctx.manifest_seq),
    })
}

fn commit_flush_tx(
    conn: &mut Connection,
    org_id: &OrgId,
    flush_ctx: &FlushContext,
    meta: &ManifestMeta<'_>,
    archive_rows: Vec<ArchiveInsert>,
    segment_inserts: Vec<SegmentInsert>,
) -> Result<(), CodedError> {
    let tx = conn.transaction().map_err(lake_sql_err)?;
    for arch in archive_rows {
        let sess_json = serde_json::to_string(&arch.sessions).map_err(json_io_err)?;
        tx.execute(
            "INSERT INTO lake_archive_segments (
                organisation_id, object_key, lane, day, root_session_ids_json, digest_sha256,
                reduced_at_ms, logical_deleted_at_ms, physical_deleted_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, NULL, NULL, NULL)",
            rusqlite::params![
                org_id.as_str(),
                arch.arch_key,
                arch.lane,
                arch.day,
                sess_json,
                arch.digest
            ],
        )
        .map_err(lake_sql_err)?;
    }

    for seg in segment_inserts {
        let device_ids: Vec<String> = seg
            .records
            .iter()
            .map(|r| r.device_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let session_ids: Vec<String> = seg
            .records
            .iter()
            .map(|r| r.root_session_id.clone())
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        let min_obs = seg
            .records
            .iter()
            .map(|r| r.observed_time_ms)
            .min()
            .unwrap_or(flush_ctx.now_ms);
        let max_obs = seg
            .records
            .iter()
            .map(|r| r.observed_time_ms)
            .max()
            .unwrap_or(flush_ctx.now_ms);
        tx.execute(
            "INSERT INTO lake_segments (
                organisation_id, segment_id, retention_class, day, object_key, row_count, size_bytes,
                digest_sha256, schema_rev, data_key_id, device_ids_json, root_session_ids_json,
                min_observed_ms, max_observed_ms, fence, logical_deleted_at_ms, physical_deleted_at_ms
             ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, 1, ?9, ?10, ?11, ?12, ?13, ?14, NULL, NULL)",
            rusqlite::params![
                org_id.as_str(),
                seg.seg_id,
                seg.class.as_str(),
                seg.day,
                seg.rel_key,
                i64::try_from(seg.row_count).unwrap_or(i64::MAX),
                i64::try_from(seg.size_bytes).unwrap_or(i64::MAX),
                seg.digest,
                seg.data_key_id,
                serde_json::to_string(&device_ids).map_err(json_io_err)?,
                serde_json::to_string(&session_ids).map_err(json_io_err)?,
                min_obs,
                max_obs,
                i64::try_from(flush_ctx.fence.value()).unwrap_or(i64::MAX)
            ],
        )
        .map_err(lake_sql_err)?;

        for rec in seg.records {
            for obs in rec.observables {
                tx.execute(
                    "INSERT OR IGNORE INTO lake_observables (organisation_id, observable_type, value, segment_id, event_id)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    rusqlite::params![
                        org_id.as_str(),
                        obs.observable_type,
                        obs.value,
                        seg.seg_id,
                        rec.event_id
                    ],
                )
                .map_err(lake_sql_err)?;
            }
        }
    }

    tx.execute(
        "INSERT INTO lake_manifests (
            organisation_id, manifest_seq, prev_manifest_digest, manifest_digest,
            object_key, created_at_ms, entries_json
         ) VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
        rusqlite::params![
            org_id.as_str(),
            i64::try_from(flush_ctx.manifest_seq).unwrap_or(i64::MAX),
            meta.prev_digest,
            meta.manifest_digest,
            meta.manifest_key,
            flush_ctx.now_ms,
            meta.entries_json
        ],
    )
    .map_err(lake_sql_err)?;
    tx.execute(
        "UPDATE lake_fencing SET snapshot_seq = ?2, manifest_seq = ?3 WHERE organisation_id = ?1",
        rusqlite::params![
            org_id.as_str(),
            i64::try_from(flush_ctx.snapshot_seq).unwrap_or(i64::MAX),
            i64::try_from(flush_ctx.manifest_seq).unwrap_or(i64::MAX)
        ],
    )
    .map_err(lake_sql_err)?;
    tx.commit().map_err(lake_sql_err)?;
    Ok(())
}

pub(crate) fn json_io_err(err: serde_json::Error) -> CodedError {
    CodedError::new(
        CODE_LAKE_IO,
        format!("Lake JSON encoding error: {err}"),
        "Inspect lake batch record payloads.",
    )
}
