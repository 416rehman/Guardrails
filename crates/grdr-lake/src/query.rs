// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::{Connection, OptionalExtension};

use grdr_crypto::AeadKey;
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_INVALID_QUERY, HuntTable, LakeQueryIr, LakeQueryResult, LakeRecord, OrgId,
    RetentionClass, TenantCtx, TenantPath, parse_hunt_sql,
};

use crate::crypto::{SessionKeyLookup, derive_segment_dek, load_session_key, open_content_fields};
use crate::fuse_filter::ObservableFuseFilter;
use crate::parquet_modular::{ParquetSliceDecryptCtx, read_modular_parquet_projected};
use crate::query_eval::evaluate_rows;
use crate::schema::lake_sql_err;

const BASE_QUERY_COLUMNS: &[&str] = &[
    "event_id",
    "device_id",
    "epoch",
    "lane",
    "seq",
    "retention_class",
    "category",
    "root_session_id",
    "observed_time_ms",
];

#[derive(Debug, Clone)]
struct SegmentScanEntry {
    segment_id: String,
    object_key: String,
    class_str: String,
    day: String,
    size_bytes: u64,
    session_ids_json: String,
}

pub(crate) fn run_lake_query<B: BlobPort>(
    conn: &Connection,
    blobs: &B,
    org_kek: &AeadKey,
    ctx: &TenantCtx,
    tail_batches: &BTreeMap<String, Vec<grdr_ports::LakeBatch>>,
    query: &LakeQueryIr,
) -> Result<LakeQueryResult, CodedError> {
    validate_query_content_policy(query)?;
    let mut seen_keys: BTreeSet<(String, String, u64, String, u64)> = BTreeSet::new();
    let mut rows: Vec<(OrgId, LakeRecord, bool)> = Vec::new();
    let mut scanned_segments = 0usize;
    let mut tail_rows_merged = 0usize;
    let wants_content = query_wants_content(query);
    let projected_cols = projected_parquet_columns(query);

    for org_id in ctx.organisation_ids() {
        if let Some(batches) = tail_batches.get(org_id.as_str()) {
            for batch in batches {
                for rec in &batch.records {
                    let key = dedup_key(org_id, rec);
                    if seen_keys.insert(key) {
                        let (plain_rec, shredded) =
                            unseal_record_if_needed(conn, org_kek, org_id, rec, wants_content)?;
                        tail_rows_merged = tail_rows_merged.saturating_add(1);
                        rows.push((org_id.clone(), plain_rec, shredded));
                    }
                }
            }
        }

        let segments = load_candidate_segments(conn, org_id.as_str(), query)?;
        for seg in segments {
            if !segment_matches_metadata_and_filter(conn, org_id.as_str(), &seg, query)? {
                continue;
            }
            let Some(class) = RetentionClass::parse(&seg.class_str) else {
                continue;
            };
            let tenant_path =
                TenantPath::parse(&grdr_ports::SingleCtx::new(org_id.clone()), &seg.object_key)?;
            let (_, seg_dek) = derive_segment_dek(org_kek, org_id, &seg.class_str, &seg.day);
            let decrypt_ctx = ParquetSliceDecryptCtx {
                org_id,
                class,
                day: &seg.day,
                rel_key: &seg.object_key,
                day_dek: &seg_dek,
            };
            let Some((records, _)) = read_modular_parquet_projected(
                blobs,
                ctx,
                &tenant_path,
                seg.size_bytes,
                &decrypt_ctx,
                projected_cols.as_deref(),
            )?
            else {
                continue;
            };
            scanned_segments = scanned_segments.saturating_add(1);
            for rec in records {
                let key = dedup_key(org_id, &rec);
                if seen_keys.insert(key) {
                    let (plain_rec, shredded) =
                        unseal_record_if_needed(conn, org_kek, org_id, &rec, wants_content)?;
                    rows.push((org_id.clone(), plain_rec, shredded));
                }
            }
        }
    }

    evaluate_rows(&rows, query, scanned_segments, tail_rows_merged)
}

fn load_candidate_segments(
    conn: &Connection,
    org_id: &str,
    query: &LakeQueryIr,
) -> Result<Vec<SegmentScanEntry>, CodedError> {
    let class_filter: Option<&'static str> = match query {
        LakeQueryIr::Scan {
            retention_class, ..
        }
        | LakeQueryIr::Aggregate {
            retention_class, ..
        } => Some(retention_class.as_str()),
        LakeQueryIr::Export {
            retention_class, ..
        } => retention_class.map(|c| c.as_str()),
        LakeQueryIr::Hunt {
            sql_select,
            include_content,
            ..
        } => {
            let parsed = parse_hunt_sql(sql_select, *include_content)?;
            match parsed.table {
                HuntTable::Decision => Some("decision"),
                HuntTable::Activity => Some("activity"),
                HuntTable::Content => Some("content"),
                HuntTable::Events => None,
            }
        }
        LakeQueryIr::Timeline { .. } | LakeQueryIr::Lookup { .. } => None,
    };

    let mut out = Vec::new();
    if let Some(rc) = class_filter {
        let mut stmt = conn
            .prepare(
                "SELECT segment_id, object_key, retention_class, day, size_bytes, root_session_ids_json
                 FROM lake_segments
                 WHERE organisation_id = ?1 AND retention_class = ?2 AND logical_deleted_at_ms IS NULL
                 ORDER BY day ASC, segment_id ASC",
            )
            .map_err(lake_sql_err)?;
        let iter = stmt
            .query_map(rusqlite::params![org_id, rc], map_segment_row)
            .map_err(lake_sql_err)?;
        for row in iter {
            out.push(row.map_err(lake_sql_err)?);
        }
    } else {
        let mut stmt = conn
            .prepare(
                "SELECT segment_id, object_key, retention_class, day, size_bytes, root_session_ids_json
                 FROM lake_segments
                 WHERE organisation_id = ?1 AND logical_deleted_at_ms IS NULL
                 ORDER BY day ASC, segment_id ASC",
            )
            .map_err(lake_sql_err)?;
        let iter = stmt
            .query_map(rusqlite::params![org_id], map_segment_row)
            .map_err(lake_sql_err)?;
        for row in iter {
            out.push(row.map_err(lake_sql_err)?);
        }
    }
    Ok(out)
}

fn map_segment_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SegmentScanEntry> {
    let size_raw: i64 = row.get(4)?;
    Ok(SegmentScanEntry {
        segment_id: row.get(0)?,
        object_key: row.get(1)?,
        class_str: row.get(2)?,
        day: row.get(3)?,
        size_bytes: u64::try_from(size_raw).unwrap_or(0),
        session_ids_json: row.get(5)?,
    })
}

fn segment_matches_metadata_and_filter(
    conn: &Connection,
    org_id: &str,
    seg: &SegmentScanEntry,
    query: &LakeQueryIr,
) -> Result<bool, CodedError> {
    match query {
        LakeQueryIr::Timeline {
            root_session_id, ..
        } => {
            let sessions: Vec<String> =
                serde_json::from_str(&seg.session_ids_json).unwrap_or_default();
            Ok(sessions.iter().any(|s| s == root_session_id))
        }
        LakeQueryIr::Lookup {
            observable_type,
            value,
            ..
        } => {
            let blob: Option<Vec<u8>> = conn
                .query_row(
                    "SELECT filter_blob FROM lake_segment_filters
                     WHERE organisation_id = ?1 AND segment_id = ?2",
                    rusqlite::params![org_id, seg.segment_id],
                    |r| r.get(0),
                )
                .optional()
                .map_err(lake_sql_err)?;
            let Some(bytes) = blob else {
                return Ok(true);
            };
            let Some(filter) = ObservableFuseFilter::decode(&bytes) else {
                return Ok(true);
            };
            Ok(filter.may_contain(observable_type.as_deref(), value))
        }
        _ => Ok(true),
    }
}

fn projected_parquet_columns(query: &LakeQueryIr) -> Option<Vec<&'static str>> {
    let mut cols: Vec<&'static str> = BASE_QUERY_COLUMNS.to_vec();
    match query {
        LakeQueryIr::Lookup { .. } => {
            cols.push("session_id");
            cols.push("observables_json");
            Some(cols)
        }
        LakeQueryIr::Timeline {
            include_content, ..
        }
        | LakeQueryIr::Export {
            include_content, ..
        } => {
            cols.push("session_id");
            cols.push("monotonic_ns");
            cols.push("received_at_ms");
            cols.push("schema_rev");
            cols.push("tool_call_id");
            cols.push("fields_json");
            if *include_content {
                cols.push("content_fields_json");
            }
            Some(cols)
        }
        LakeQueryIr::Scan {
            projection,
            predicates,
            include_content,
            ..
        } => {
            if projection.is_empty() || projection.iter().any(|p| p == "session_id") {
                cols.push("session_id");
            }
            let need_fields = projection.is_empty()
                || projection.iter().any(|p| !is_core_column(p))
                || predicates.iter().any(|p| !is_core_column(&p.field));
            if need_fields {
                cols.push("fields_json");
            }
            if *include_content {
                cols.push("content_fields_json");
            }
            Some(cols)
        }
        LakeQueryIr::Aggregate {
            group_by,
            aggregations,
            predicates,
            ..
        } => {
            if group_by.iter().any(|c| c == "session_id") {
                cols.push("session_id");
            }
            let need_fields = group_by.iter().any(|c| !is_core_column(c))
                || predicates.iter().any(|p| !is_core_column(&p.field))
                || aggregations
                    .iter()
                    .any(|a| a.field.as_deref().is_some_and(|f| !is_core_column(f)));
            if need_fields {
                cols.push("fields_json");
            }
            Some(cols)
        }
        LakeQueryIr::Hunt {
            include_content, ..
        } => {
            cols.push("session_id");
            cols.push("fields_json");
            if *include_content {
                cols.push("content_fields_json");
            }
            Some(cols)
        }
    }
}

fn is_core_column(col: &str) -> bool {
    matches!(
        col,
        "event_id" | "device_id" | "category" | "root_session_id" | "session_id" | "lane" | "seq"
    )
}

fn unseal_record_if_needed(
    conn: &Connection,
    org_kek: &AeadKey,
    org_id: &OrgId,
    rec: &LakeRecord,
    include_content: bool,
) -> Result<(LakeRecord, bool), CodedError> {
    let key_state = load_session_key(conn, org_kek, org_id, &rec.root_session_id)?;
    let shredded = matches!(key_state, SessionKeyLookup::Destroyed);
    let mut out = rec.clone();
    if !include_content || shredded || out.content_fields.is_empty() {
        out.content_fields.clear();
        return Ok((out, shredded));
    }
    if let SessionKeyLookup::Active(session_key) = key_state {
        out.content_fields =
            open_content_fields(&session_key, org_id, &out.event_id, &out.content_fields)?;
    } else {
        out.content_fields.clear();
    }
    Ok((out, false))
}

fn validate_query_content_policy(query: &LakeQueryIr) -> Result<(), CodedError> {
    let deny = |field: &str| {
        CodedError::new(
            CODE_LAKE_INVALID_QUERY,
            format!("Query accesses content field `{field}` without content authorization."),
            "Set include_content = true or remove `content.*` fields from the query.",
        )
    };
    match query {
        LakeQueryIr::Scan {
            predicates,
            projection,
            include_content,
            ..
        } if !*include_content => {
            for col in projection {
                if col.starts_with("content.") {
                    return Err(deny(col));
                }
            }
            for pred in predicates {
                if pred.field.starts_with("content.") {
                    return Err(deny(&pred.field));
                }
            }
        }
        LakeQueryIr::Aggregate {
            group_by,
            aggregations,
            predicates,
            ..
        } => {
            for col in group_by {
                if col.starts_with("content.") {
                    return Err(deny(col));
                }
            }
            for pred in predicates {
                if pred.field.starts_with("content.") {
                    return Err(deny(&pred.field));
                }
            }
            for agg in aggregations {
                if let Some(field) = agg.field.as_deref()
                    && field.starts_with("content.")
                {
                    return Err(deny(field));
                }
            }
        }
        LakeQueryIr::Hunt {
            sql_select,
            include_content,
            ..
        } => {
            let _ = parse_hunt_sql(sql_select, *include_content)?;
        }
        _ => {}
    }
    Ok(())
}

fn query_wants_content(query: &LakeQueryIr) -> bool {
    match query {
        LakeQueryIr::Timeline {
            include_content, ..
        }
        | LakeQueryIr::Scan {
            include_content, ..
        }
        | LakeQueryIr::Hunt {
            include_content, ..
        }
        | LakeQueryIr::Export {
            include_content, ..
        } => *include_content,
        LakeQueryIr::Aggregate { .. } | LakeQueryIr::Lookup { .. } => false,
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
