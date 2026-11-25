// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use rusqlite::Connection;

use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_IO, LakeCompactionResult, LegalHold, LegalHoldScope, LegalHoldState, OrgId,
    RetentionClass, SingleCtx, TenantPath,
};

use crate::crypto::day_from_ms;
use crate::schema::lake_sql_err;

pub(crate) fn load_active_holds(
    conn: &Connection,
    org_id: &OrgId,
    now_ms: i64,
) -> Result<Vec<LegalHold>, CodedError> {
    let mut stmt = conn
        .prepare(
            "SELECT hold_id, scope_json, reason, incident_ref, created_by, created_at_ms, expires_at_ms, state_json
             FROM lake_holds WHERE organisation_id = ?1",
        )
        .map_err(lake_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params![org_id.as_str()], |row| {
            let hold_id: String = row.get(0)?;
            let scope_json: String = row.get(1)?;
            let reason: String = row.get(2)?;
            let incident_ref: Option<String> = row.get(3)?;
            let created_by: String = row.get(4)?;
            let created_at_ms: i64 = row.get(5)?;
            let expires_at_ms: Option<i64> = row.get(6)?;
            let state_json: String = row.get(7)?;
            Ok((
                hold_id,
                scope_json,
                reason,
                incident_ref,
                created_by,
                created_at_ms,
                expires_at_ms,
                state_json,
            ))
        })
        .map_err(lake_sql_err)?;

    let mut out = Vec::new();
    for item in rows {
        let (
            hold_id,
            scope_json,
            reason,
            incident_ref,
            created_by,
            created_at_ms,
            expires_at_ms,
            state_json,
        ) = item.map_err(lake_sql_err)?;
        let scope: LegalHoldScope = serde_json::from_str(&scope_json).map_err(codec_err)?;
        let state: LegalHoldState = serde_json::from_str(&state_json).map_err(codec_err)?;
        let hold = LegalHold {
            organisation_id: org_id.clone(),
            hold_id,
            scope,
            reason,
            incident_ref,
            created_by,
            created_at_ms,
            expires_at_ms,
            state,
        };
        if hold.is_active_at(now_ms) {
            out.push(hold);
        }
    }
    Ok(out)
}

pub(crate) fn run_retention_and_compaction<B: BlobPort>(
    conn: &mut Connection,
    blobs: &B,
    ctx: &SingleCtx,
    now_ms: i64,
    pitr_lag_ms: i64,
) -> Result<LakeCompactionResult, CodedError> {
    let org_id = ctx.organisation_id();
    let active_holds = load_active_holds(conn, org_id, now_ms)?;
    let mut stmt = conn
        .prepare(
            "SELECT segment_id, retention_class, day, object_key, device_ids_json, root_session_ids_json,
                    max_observed_ms, logical_deleted_at_ms, physical_deleted_at_ms
             FROM lake_segments WHERE organisation_id = ?1",
        )
        .map_err(lake_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params![org_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
                row.get::<_, String>(4)?,
                row.get::<_, String>(5)?,
                row.get::<_, i64>(6)?,
                row.get::<_, Option<i64>>(7)?,
                row.get::<_, Option<i64>>(8)?,
            ))
        })
        .map_err(lake_sql_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(lake_sql_err)?;
    drop(stmt);

    let mut active_segments = 0usize;
    let mut logically_deleted = 0usize;
    let mut physically_deleted = 0usize;
    let mut segments_held = 0usize;

    for (seg_id, class_str, day, object_key, dev_json, sess_json, max_obs, log_del, phys_del) in
        rows
    {
        if phys_del.is_some() {
            continue;
        }
        let class = RetentionClass::parse(&class_str).ok_or_else(|| {
            CodedError::new(
                CODE_LAKE_IO,
                format!("Invalid retention_class `{class_str}` in lake_segments."),
                "Inspect lake_segments catalogue integrity.",
            )
        })?;
        let devices: Vec<String> = serde_json::from_str(&dev_json).map_err(codec_err)?;
        let sessions: Vec<String> = serde_json::from_str(&sess_json).map_err(codec_err)?;
        let is_held = active_holds
            .iter()
            .any(|h| h.covers(class, &day, &devices, &sessions));

        if let Some(deleted_at) = log_del {
            if !is_held && now_ms.saturating_sub(deleted_at) >= pitr_lag_ms {
                let path = TenantPath::parse(ctx, &object_key)?;
                let _ = blobs.delete(ctx, &path)?;
                conn.execute(
                    "UPDATE lake_segments SET physical_deleted_at_ms = ?3
                     WHERE organisation_id = ?1 AND segment_id = ?2",
                    rusqlite::params![org_id.as_str(), seg_id, now_ms],
                )
                .map_err(lake_sql_err)?;
                physically_deleted = physically_deleted.saturating_add(1);
            }
            continue;
        }

        if now_ms.saturating_sub(max_obs) > class.retention_ms() {
            if is_held {
                segments_held = segments_held.saturating_add(1);
                active_segments = active_segments.saturating_add(1);
            } else {
                conn.execute(
                    "UPDATE lake_segments SET logical_deleted_at_ms = ?3
                     WHERE organisation_id = ?1 AND segment_id = ?2",
                    rusqlite::params![org_id.as_str(), seg_id, now_ms],
                )
                .map_err(lake_sql_err)?;
                logically_deleted = logically_deleted.saturating_add(1);
                if pitr_lag_ms == 0 {
                    let path = TenantPath::parse(ctx, &object_key)?;
                    let _ = blobs.delete(ctx, &path)?;
                    conn.execute(
                        "UPDATE lake_segments SET physical_deleted_at_ms = ?3
                         WHERE organisation_id = ?1 AND segment_id = ?2",
                        rusqlite::params![org_id.as_str(), seg_id, now_ms],
                    )
                    .map_err(lake_sql_err)?;
                    physically_deleted = physically_deleted.saturating_add(1);
                }
            }
        } else {
            active_segments = active_segments.saturating_add(1);
        }
    }

    let keys_destroyed = expire_old_keys(conn, org_id, &active_holds, now_ms)?;
    let observables_written: i64 = conn
        .query_row(
            "SELECT COUNT(*) FROM lake_observables WHERE organisation_id = ?1",
            rusqlite::params![org_id.as_str()],
            |row| row.get(0),
        )
        .map_err(lake_sql_err)?;

    Ok(LakeCompactionResult {
        organisation_id: org_id.clone(),
        segments_compacted: active_segments,
        segments_logically_deleted: logically_deleted,
        segments_physically_deleted: physically_deleted,
        segments_held,
        observables_written: usize::try_from(observables_written).unwrap_or(0),
        keys_destroyed,
    })
}

fn expire_old_keys(
    conn: &Connection,
    org_id: &OrgId,
    active_holds: &[LegalHold],
    now_ms: i64,
) -> Result<usize, CodedError> {
    let mut stmt = conn
        .prepare(
            "SELECT root_session_id, created_at_ms, destroy_after_ms
             FROM lake_content_keys
             WHERE organisation_id = ?1 AND state = 'active' AND destroy_after_ms <= ?2",
        )
        .map_err(lake_sql_err)?;
    let due_keys = stmt
        .query_map(rusqlite::params![org_id.as_str(), now_ms], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, i64>(1)?,
                row.get::<_, i64>(2)?,
            ))
        })
        .map_err(lake_sql_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(lake_sql_err)?;
    drop(stmt);

    let mut destroyed = 0usize;
    for (root_session_id, created_at_ms, _) in due_keys {
        let day = day_from_ms(created_at_ms)?;
        let sessions = vec![root_session_id.clone()];
        let held = active_holds
            .iter()
            .any(|h| h.covers(RetentionClass::Content, &day, &[], &sessions));
        if !held {
            let rec_id = format!("retire-{root_session_id}-{now_ms}");
            conn.execute(
                "UPDATE lake_content_keys
                 SET state = 'destroyed', wrapped_key = '', destroyed_at_ms = ?3, destruction_record_id = ?4
                 WHERE organisation_id = ?1 AND root_session_id = ?2",
                rusqlite::params![org_id.as_str(), root_session_id, now_ms, rec_id],
            )
            .map_err(lake_sql_err)?;
            destroyed = destroyed.saturating_add(1);
        }
    }
    Ok(destroyed)
}

fn codec_err(err: serde_json::Error) -> CodedError {
    CodedError::new(
        CODE_LAKE_IO,
        format!("Failed decoding lake catalogue JSON: {err}"),
        "Inspect lake catalogue rows.",
    )
}
