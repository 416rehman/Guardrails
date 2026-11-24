// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use rusqlite::Connection;
use serde::{Deserialize, Serialize};

use grdr_crypto::AeadKey;
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_IO, LakeQueryIr, LakeQueryResult, LakeRecord, OrgId, RetentionClass,
    TenantCtx, TenantPath,
};

use crate::crypto::{SessionKeyLookup, load_session_key, open_content_fields};
use crate::query_eval::evaluate_rows;
use crate::schema::lake_sql_err;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub(crate) struct SealedSegmentBlob {
    pub(crate) segment_id: String,
    pub(crate) retention_class: RetentionClass,
    pub(crate) day: String,
    pub(crate) records: Vec<LakeRecord>,
}

pub(crate) fn run_lake_query<B: BlobPort>(
    conn: &Connection,
    blobs: &B,
    org_kek: &AeadKey,
    ctx: &TenantCtx,
    tail_batches: &BTreeMap<String, Vec<grdr_ports::LakeBatch>>,
    query: &LakeQueryIr,
) -> Result<LakeQueryResult, CodedError> {
    let mut seen_keys: BTreeSet<(String, String, u64, String, u64)> = BTreeSet::new();
    let mut rows: Vec<(OrgId, LakeRecord, bool)> = Vec::new();
    let mut scanned_segments = 0usize;
    let mut tail_rows_merged = 0usize;

    for org_id in ctx.organisation_ids() {
        if let Some(batches) = tail_batches.get(org_id.as_str()) {
            for batch in batches {
                for rec in &batch.records {
                    let key = dedup_key(org_id, rec);
                    if seen_keys.insert(key) {
                        let (plain_rec, shredded) = unseal_record_if_needed(
                            conn,
                            org_kek,
                            org_id,
                            rec,
                            query_wants_content(query),
                        )?;
                        tail_rows_merged = tail_rows_merged.saturating_add(1);
                        rows.push((org_id.clone(), plain_rec, shredded));
                    }
                }
            }
        }

        let mut stmt = conn
            .prepare(
                "SELECT object_key FROM lake_segments
                 WHERE organisation_id = ?1 AND logical_deleted_at_ms IS NULL
                 ORDER BY day ASC, segment_id ASC",
            )
            .map_err(lake_sql_err)?;
        let keys: Vec<String> = stmt
            .query_map(rusqlite::params![org_id.as_str()], |row| row.get(0))
            .map_err(lake_sql_err)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(lake_sql_err)?;

        for rel_key in keys {
            let tenant_path =
                TenantPath::parse(&grdr_ports::SingleCtx::new(org_id.clone()), &rel_key)?;
            let Some(blob) = blobs.get(ctx, &tenant_path)? else {
                continue;
            };
            scanned_segments = scanned_segments.saturating_add(1);
            let segment: SealedSegmentBlob = serde_json::from_slice(&blob.bytes).map_err(|e| {
                CodedError::new(
                    CODE_LAKE_IO,
                    format!("Corrupt lake segment `{rel_key}`: {e}"),
                    "Verify lake segment object integrity.",
                )
            })?;
            for rec in segment.records {
                let key = dedup_key(org_id, &rec);
                if seen_keys.insert(key) {
                    let (plain_rec, shredded) = unseal_record_if_needed(
                        conn,
                        org_kek,
                        org_id,
                        &rec,
                        query_wants_content(query),
                    )?;
                    rows.push((org_id.clone(), plain_rec, shredded));
                }
            }
        }
    }

    evaluate_rows(&rows, query, scanned_segments, tail_rows_merged)
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
        if shredded {
            out.content_fields.clear();
        }
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
