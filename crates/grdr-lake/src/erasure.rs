// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use rusqlite::{Connection, OptionalExtension};
use uuid::Uuid;

use grdr_crypto::AeadKey;
use grdr_model::CodedError;
use grdr_ports::{
    BlobPort, CODE_LAKE_HOLD_ACTIVE, CODE_LAKE_IO, CODE_LAKE_NOT_FOUND, ErasureReceipt, LakeBatch,
    LegalHold, LegalHoldRequest, LegalHoldScope, LegalHoldState, OrgId, RetentionClass, SingleCtx,
    TenantCtx, TenantPath,
};

use crate::crypto::{
    ArchivePayload, archive_seal_domain, day_from_ms, derive_segment_dek, open_envelope,
    seal_envelope, sha256_hex,
};
use crate::flush::json_io_err;
use crate::retention::load_active_holds;
use crate::schema::lake_sql_err;

pub(crate) struct ErasureRequest<'a> {
    pub(crate) ctx: &'a SingleCtx,
    pub(crate) root_session_id: &'a str,
    pub(crate) reason: &'a str,
    pub(crate) now_ms: i64,
}

struct HoldRow {
    scope_json: String,
    reason: String,
    incident_ref: Option<String>,
    created_by: String,
    created_at_ms: i64,
    expires_at_ms: Option<i64>,
}

struct ArchiveSegmentRow {
    object_key: String,
    day: String,
    sessions_json: String,
    reduced_at_ms: Option<i64>,
}

struct SessionScope {
    devices: Vec<String>,
    segments: Vec<(RetentionClass, String, Vec<String>)>,
}

pub(crate) fn place_hold_record(
    conn: &Connection,
    ctx: &SingleCtx,
    hold: &LegalHoldRequest,
) -> Result<LegalHold, CodedError> {
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

pub(crate) fn release_hold_record(
    conn: &Connection,
    ctx: &SingleCtx,
    hold_id: &str,
    now_ms: i64,
) -> Result<LegalHold, CodedError> {
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

pub(crate) fn erase_session_records<B: BlobPort>(
    conn: &mut Connection,
    blobs: &B,
    org_kek: &AeadKey,
    mem_batches: Option<&mut Vec<LakeBatch>>,
    req: ErasureRequest<'_>,
) -> Result<ErasureReceipt, CodedError> {
    let ErasureRequest {
        ctx,
        root_session_id,
        reason,
        now_ms,
    } = req;
    let org_id = ctx.organisation_id();
    let tx = conn.transaction().map_err(lake_sql_err)?;
    let active_holds = load_active_holds(&tx, org_id, now_ms)?;
    let session_list = vec![root_session_id.to_string()];

    let mem_slice = mem_batches.as_deref().map_or(&[][..], Vec::as_slice);
    let scope = collect_session_scope(&tx, org_id, root_session_id, mem_slice)?;
    let session_devices = scope.devices;
    let matching_segments = scope.segments;
    let hold_blocks_class = |class: RetentionClass, day: &str, devs: &[String]| {
        active_holds
            .iter()
            .any(|h| h.covers(class, day, devs, &session_list))
    };

    let key_day: Option<String> = tx
        .query_row(
            "SELECT created_at_ms FROM lake_content_keys
             WHERE organisation_id = ?1 AND root_session_id = ?2 AND state = 'active'",
            rusqlite::params![org_id.as_str(), root_session_id],
            |row| row.get::<_, i64>(0),
        )
        .optional()
        .map_err(lake_sql_err)?
        .map(day_from_ms)
        .transpose()?;

    if let Some(day) = key_day.as_deref()
        && hold_blocks_class(RetentionClass::Content, day, &session_devices)
    {
        return Err(CodedError::new(
            CODE_LAKE_HOLD_ACTIVE,
            format!("Cannot erase session `{root_session_id}` while an active legal hold applies."),
            "Release blocking legal holds before re-running session erasure.",
        ));
    }

    for (seg_class, seg_day, seg_devs) in &matching_segments {
        if hold_blocks_class(*seg_class, seg_day, seg_devs)
            || hold_blocks_class(*seg_class, seg_day, &session_devices)
        {
            return Err(CodedError::new(
                CODE_LAKE_HOLD_ACTIVE,
                format!(
                    "Cannot erase segment data on `{seg_day}` for session `{root_session_id}` under active legal hold."
                ),
                "Release blocking legal holds before re-running session erasure.",
            ));
        }
    }

    let arch_rows = load_archive_rows(&tx, org_id.as_str())?;
    let mut target_archives = Vec::new();
    for row in arch_rows {
        let sessions: Vec<String> =
            serde_json::from_str(&row.sessions_json).map_err(json_io_err)?;
        if !sessions.iter().any(|s| s == root_session_id) {
            continue;
        }
        let archive_held = [
            RetentionClass::Content,
            RetentionClass::Activity,
            RetentionClass::Decision,
        ]
        .iter()
        .any(|class| hold_blocks_class(*class, &row.day, &session_devices));
        if archive_held {
            return Err(CodedError::new(
                CODE_LAKE_HOLD_ACTIVE,
                format!(
                    "Cannot erase archive segment `{}` for session `{root_session_id}` under active legal hold.",
                    row.object_key
                ),
                "Release blocking legal holds before re-running session erasure.",
            ));
        }
        if row.reduced_at_ms.is_none() {
            target_archives.push(row);
        }
    }

    let destruction_record_id = format!("erasure-{}", Uuid::now_v7().simple());
    let updated = tx
        .execute(
            "UPDATE lake_content_keys
             SET state = 'destroyed', wrapped_key = '', destroyed_at_ms = ?3, destruction_record_id = ?4
             WHERE organisation_id = ?1 AND root_session_id = ?2 AND state = 'active'",
            rusqlite::params![org_id.as_str(), root_session_id, now_ms, destruction_record_id],
        )
        .map_err(lake_sql_err)?;

    let read_ctx = TenantCtx::Single(ctx.clone());
    let mut archive_segments_reduced = 0usize;
    for row in target_archives {
        let digest = reduce_archive_blob(
            blobs,
            org_kek,
            ctx,
            &read_ctx,
            &row.object_key,
            &row.day,
            root_session_id,
        )?;
        tx.execute(
            "UPDATE lake_archive_segments SET reduced_at_ms = ?3, digest_sha256 = ?4
             WHERE organisation_id = ?1 AND object_key = ?2",
            rusqlite::params![org_id.as_str(), row.object_key, now_ms, digest],
        )
        .map_err(lake_sql_err)?;
        archive_segments_reduced = archive_segments_reduced.saturating_add(1);
    }

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
    blobs.put(
        ctx,
        &TenantPath::parse(ctx, &state_log_key)?,
        &state_log_payload,
    )?;
    tx.commit().map_err(lake_sql_err)?;

    if let Some(batches) = mem_batches {
        for batch in batches {
            let mut touches_session = false;
            for rec in &mut batch.records {
                if rec.root_session_id == root_session_id {
                    rec.content_fields.clear();
                    touches_session = true;
                }
            }
            if touches_session {
                batch.archive_bytes.clear();
            }
        }
    }

    Ok(ErasureReceipt {
        organisation_id: org_id.clone(),
        root_session_id: root_session_id.to_string(),
        destruction_record_id,
        erased_at_ms: now_ms,
        keys_destroyed: updated,
        archive_segments_reduced,
        held_segments_deferred: 0,
        state_log_key,
    })
}

fn collect_session_scope(
    tx: &Connection,
    org_id: &OrgId,
    root_session_id: &str,
    mem_batches: &[LakeBatch],
) -> Result<SessionScope, CodedError> {
    let mut devices = BTreeSet::new();
    let mut segments = Vec::new();
    let mut stmt = tx
        .prepare(
            "SELECT retention_class, day, device_ids_json, root_session_ids_json
             FROM lake_segments
             WHERE organisation_id = ?1 AND physical_deleted_at_ms IS NULL",
        )
        .map_err(lake_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params![org_id.as_str()], |row| {
            Ok((
                row.get::<_, String>(0)?,
                row.get::<_, String>(1)?,
                row.get::<_, String>(2)?,
                row.get::<_, String>(3)?,
            ))
        })
        .map_err(lake_sql_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(lake_sql_err)?;
    drop(stmt);

    for (class_str, day, dev_json, sess_json) in rows {
        let sessions: Vec<String> = serde_json::from_str(&sess_json).map_err(json_io_err)?;
        if !sessions.iter().any(|s| s == root_session_id) {
            continue;
        }
        let devs: Vec<String> = serde_json::from_str(&dev_json).map_err(json_io_err)?;
        let Some(class) = RetentionClass::parse(&class_str) else {
            return Err(CodedError::new(
                CODE_LAKE_IO,
                format!("Invalid retention_class `{class_str}` in lake_segments."),
                "Inspect lake_segments catalogue integrity.",
            ));
        };
        devices.extend(devs.iter().cloned());
        segments.push((class, day, devs));
    }

    for batch in mem_batches {
        for rec in &batch.records {
            if rec.root_session_id == root_session_id {
                devices.insert(rec.device_id.clone());
                let day = day_from_ms(rec.observed_time_ms)?;
                segments.push((rec.retention_class, day, vec![rec.device_id.clone()]));
            }
        }
    }

    Ok(SessionScope {
        devices: devices.into_iter().collect(),
        segments,
    })
}

fn load_archive_rows(
    conn: &Connection,
    org_id: &str,
) -> Result<Vec<ArchiveSegmentRow>, CodedError> {
    let mut stmt = conn
        .prepare(
            "SELECT object_key, day, root_session_ids_json, reduced_at_ms
             FROM lake_archive_segments WHERE organisation_id = ?1",
        )
        .map_err(lake_sql_err)?;
    let rows = stmt
        .query_map(rusqlite::params![org_id], |row| {
            Ok(ArchiveSegmentRow {
                object_key: row.get(0)?,
                day: row.get(1)?,
                sessions_json: row.get(2)?,
                reduced_at_ms: row.get(3)?,
            })
        })
        .map_err(lake_sql_err)?
        .collect::<Result<Vec<_>, _>>()
        .map_err(lake_sql_err)?;
    Ok(rows)
}

fn reduce_archive_blob<B: BlobPort>(
    blobs: &B,
    org_kek: &AeadKey,
    ctx: &SingleCtx,
    read_ctx: &TenantCtx,
    object_key: &str,
    day: &str,
    root_session_id: &str,
) -> Result<String, CodedError> {
    let path = TenantPath::parse(ctx, object_key)?;
    let Some(obj) = blobs.get(read_ctx, &path)? else {
        return Err(CodedError::new(
            CODE_LAKE_IO,
            format!("Archive segment `{object_key}` missing during erasure reduction."),
            "Verify object store integrity.",
        ));
    };
    let org_id = ctx.organisation_id();
    let (key_id, arch_dek) = derive_segment_dek(org_kek, org_id, "archive", day);
    let plain_bytes = open_envelope(
        &arch_dek,
        archive_seal_domain(),
        &[org_id.as_str(), "archive", day, object_key],
        &obj.bytes,
    )?;
    let mut payload: ArchivePayload = serde_json::from_slice(&plain_bytes).map_err(json_io_err)?;
    for rec in &mut payload.records {
        if rec.root_session_id == root_session_id {
            rec.content_fields.clear();
        }
    }
    payload.raw_archive_b64 = None;
    if !payload
        .reduced_sessions
        .iter()
        .any(|s| s == root_session_id)
    {
        payload.reduced_sessions.push(root_session_id.to_string());
    }
    let reduced_plain = serde_json::to_vec(&payload).map_err(json_io_err)?;
    let sealed_reduced = seal_envelope(
        &arch_dek,
        &key_id,
        archive_seal_domain(),
        &[org_id.as_str(), "archive", day, object_key],
        &reduced_plain,
    )?;
    blobs.put(ctx, &path, &sealed_reduced)?;
    Ok(sha256_hex(&sealed_reduced))
}
