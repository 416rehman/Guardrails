// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

use rusqlite::{Connection, OptionalExtension, TransactionBehavior, params};

use crate::fs_hardening::{
    ensure_regular_non_symlink_if_exists, is_symlink_or_reparse, redact_path_label,
    set_private_file_perms,
};
use crate::recorder::{MIN_RECORDER_TTL_SECS, RecorderError, RecorderGapEntry};

pub(crate) fn purge_expired_rows(
    conn: &mut Connection,
    approx_bytes: &mut u64,
    now_unix_s: i64,
    ttl_secs: i64,
) -> Result<Option<RecorderGapEntry>, RecorderError> {
    if ttl_secs < MIN_RECORDER_TTL_SECS {
        return Err(RecorderError::InvalidArgument {
            detail: format!("ttl_secs must be >= {MIN_RECORDER_TTL_SECS}"),
        });
    }
    let cutoff = now_unix_s.saturating_sub(ttl_secs);
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;

    let stats: Option<(Option<i64>, Option<i64>, i64)> = tx
        .query_row(
            "SELECT MIN(ts_unix_s), MAX(ts_unix_s), COUNT(*) \
             FROM recorder_events WHERE ts_unix_s < ?1",
            params![cutoff],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()
        .map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;

    let Some((Some(first_ts), Some(last_ts), count)) = stats else {
        tx.commit().map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
        return Ok(None);
    };
    if count <= 0 {
        tx.commit().map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
        return Ok(None);
    }

    let deleted_bytes: i64 = tx
        .query_row(
            "SELECT COALESCE(SUM(LENGTH(payload_zstd) + 128), 0) \
             FROM recorder_events WHERE ts_unix_s < ?1",
            params![cutoff],
            |r| r.get(0),
        )
        .map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
    tx.execute(
        "DELETE FROM recorder_events WHERE ts_unix_s < ?1",
        params![cutoff],
    )
    .map_err(|err| RecorderError::Sqlite {
        detail: err.to_string(),
    })?;
    tx.execute(
        "INSERT INTO recorder_gaps \
         (created_at_unix_s, first_dropped_ts, last_dropped_ts, dropped_count, reason) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![now_unix_s, first_ts, last_ts, count, "recorder-expired"],
    )
    .map_err(|err| RecorderError::Sqlite {
        detail: err.to_string(),
    })?;
    let gap_id = tx.last_insert_rowid();
    tx.commit().map_err(|err| RecorderError::Sqlite {
        detail: err.to_string(),
    })?;
    *approx_bytes = approx_bytes.saturating_sub(u64::try_from(deleted_bytes.max(0)).unwrap_or(0));
    conn.execute_batch("PRAGMA incremental_vacuum(64);")
        .map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;

    Ok(Some(RecorderGapEntry {
        id: gap_id,
        created_at_unix_s: now_unix_s,
        first_dropped_ts: first_ts,
        last_dropped_ts: last_ts,
        dropped_count: u64::try_from(count).unwrap_or(0),
        reason: "recorder-expired".to_string(),
    }))
}

pub(crate) fn enforce_cache_cap_rows(
    conn: &mut Connection,
    approx_bytes: &mut u64,
    cache_cap_bytes: u64,
    now_unix_s: i64,
) -> Result<(), RecorderError> {
    if *approx_bytes <= cache_cap_bytes {
        return Ok(());
    }
    let floor_cutoff = now_unix_s.saturating_sub(MIN_RECORDER_TTL_SECS);
    let mut evicted_any = false;
    while *approx_bytes > cache_cap_bytes {
        if evict_cap_batch(
            conn,
            approx_bytes,
            now_unix_s,
            Some(floor_cutoff),
            "recorder-cache-cap",
        )? > 0
        {
            evicted_any = true;
            continue;
        }
        if evict_cap_batch(conn, approx_bytes, now_unix_s, None, "recorder-short")? > 0 {
            evicted_any = true;
            continue;
        }
        *approx_bytes = 0;
        break;
    }
    if evicted_any {
        conn.execute_batch("PRAGMA incremental_vacuum(64);")
            .map_err(|err| RecorderError::Sqlite {
                detail: err.to_string(),
            })?;
    }
    Ok(())
}

fn evict_cap_batch(
    conn: &mut Connection,
    approx_bytes: &mut u64,
    now_unix_s: i64,
    ts_lt: Option<i64>,
    reason: &str,
) -> Result<u64, RecorderError> {
    let tx = conn
        .transaction_with_behavior(TransactionBehavior::Immediate)
        .map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
    let batch_stats: Option<(Option<i64>, Option<i64>, i64, i64)> = match ts_lt {
        Some(cutoff) => tx
            .query_row(
                "SELECT MIN(ts_unix_s), MAX(ts_unix_s), COUNT(*), \
                 COALESCE(SUM(LENGTH(payload_zstd) + 128), 0) FROM (\
                     SELECT ts_unix_s, payload_zstd FROM recorder_events \
                     WHERE ts_unix_s < ?1 ORDER BY id ASC LIMIT 64\
                 )",
                params![cutoff],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional(),
        None => tx
            .query_row(
                "SELECT MIN(ts_unix_s), MAX(ts_unix_s), COUNT(*), \
                 COALESCE(SUM(LENGTH(payload_zstd) + 128), 0) FROM (\
                     SELECT ts_unix_s, payload_zstd FROM recorder_events \
                     ORDER BY id ASC LIMIT 64\
                 )",
                [],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
            )
            .optional(),
    }
    .map_err(|err| RecorderError::Sqlite {
        detail: err.to_string(),
    })?;
    let Some((Some(first_ts), Some(last_ts), cnt, bytes_raw)) = batch_stats else {
        tx.commit().map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
        return Ok(0);
    };
    if cnt <= 0 {
        tx.commit().map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
        return Ok(0);
    }
    match ts_lt {
        Some(cutoff) => tx.execute(
            "DELETE FROM recorder_events WHERE id IN (\
                 SELECT id FROM recorder_events WHERE ts_unix_s < ?1 ORDER BY id ASC LIMIT 64\
             )",
            params![cutoff],
        ),
        None => tx.execute(
            "DELETE FROM recorder_events WHERE id IN (\
                 SELECT id FROM recorder_events ORDER BY id ASC LIMIT 64\
             )",
            [],
        ),
    }
    .map_err(|err| RecorderError::Sqlite {
        detail: err.to_string(),
    })?;
    tx.execute(
        "INSERT INTO recorder_gaps \
         (created_at_unix_s, first_dropped_ts, last_dropped_ts, dropped_count, reason) \
         VALUES (?1, ?2, ?3, ?4, ?5)",
        params![now_unix_s, first_ts, last_ts, cnt, reason],
    )
    .map_err(|err| RecorderError::Sqlite {
        detail: err.to_string(),
    })?;
    tx.commit().map_err(|err| RecorderError::Sqlite {
        detail: err.to_string(),
    })?;
    let reclaimed = u64::try_from(bytes_raw.max(0)).unwrap_or(0);
    *approx_bytes = approx_bytes.saturating_sub(reclaimed);
    Ok(u64::try_from(cnt).unwrap_or(0))
}

pub(crate) fn ensure_sqlite_family_not_symlink(db_path: &Path) -> Result<(), RecorderError> {
    ensure_regular_non_symlink_if_exists(db_path)
        .map_err(|detail| RecorderError::InvalidArgument { detail })?;
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(db_path, suffix);
        ensure_regular_non_symlink_if_exists(&sidecar)
            .map_err(|detail| RecorderError::InvalidArgument { detail })?;
    }
    Ok(())
}

pub(crate) fn enforce_sqlite_sidecars_private(db_path: &Path) -> Result<(), RecorderError> {
    for suffix in ["-wal", "-shm"] {
        let sidecar = sidecar_path(db_path, suffix);
        match std::fs::symlink_metadata(&sidecar) {
            Ok(meta) => {
                if is_symlink_or_reparse(&meta) || !meta.file_type().is_file() {
                    return Err(RecorderError::InvalidArgument {
                        detail: format!(
                            "refusing symlink sidecar at {}",
                            redact_path_label(&sidecar)
                        ),
                    });
                }
                set_private_file_perms(&sidecar)
                    .map_err(|detail| RecorderError::InvalidArgument { detail })?;
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(RecorderError::Sqlite {
                    detail: format!("stat sidecar {}: {err}", redact_path_label(&sidecar)),
                });
            }
        }
    }
    Ok(())
}

fn sidecar_path(base: &Path, suffix: &str) -> PathBuf {
    let mut os = base.as_os_str().to_os_string();
    os.push(suffix);
    PathBuf::from(os)
}
