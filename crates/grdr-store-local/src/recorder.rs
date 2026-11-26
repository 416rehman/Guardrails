// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Local SQLite flight recorder (`recorder.db`) with RFC 8878 zstd compression,
//! 256 MiB cache cap, `secure_delete`, >=24h TTL retention, and bounded look-back queries.

#[cfg(unix)]
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};

use rusqlite::{Connection, params};
use thiserror::Error;

use crate::fs_hardening::{ensure_private_dir_all, redact_path_label, set_private_file_perms};
use crate::recorder_retention::{
    enforce_cache_cap_rows, enforce_sqlite_sidecars_private, ensure_sqlite_family_not_symlink,
    purge_expired_rows,
};
use crate::zstd_frame::{ZstdFrameError, compress_zstd_frame, decompress_zstd_frame};

pub const DEFAULT_RECORDER_TTL_SECS: i64 = 72 * 3600;
pub const MIN_RECORDER_TTL_SECS: i64 = 24 * 3600;
pub const MAX_DECOMPRESSED_RECORD_BYTES: usize = 4 * 1024 * 1024;
const MAX_QUERY_LIMIT: usize = 10_000;
const MAX_QUERY_TOTAL_BYTES: usize = 32 * 1024 * 1024;
const DEFAULT_MAX_GAP_LIST_LIMIT: usize = 1_000;
const DEFAULT_CACHE_CAP_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SESSION_ID_BYTES: usize = 256;

#[derive(Debug, Error)]
pub enum RecorderError {
    #[error("GRDR-LSTORE-0014: SQLite recorder error: {detail}")]
    Sqlite { detail: String },
    #[error("GRDR-LSTORE-0015: recorder compression error: {0}")]
    Compression(#[from] ZstdFrameError),
    #[error("GRDR-LSTORE-0016: invalid recorder query or TTL argument: {detail}")]
    InvalidArgument { detail: String },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RecorderCaptureLevel {
    MetadataOnly,
    Redacted,
    Full,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecordedEntry {
    pub id: i64,
    pub ts_unix_s: i64,
    pub lane: String,
    pub kind: String,
    pub session_id: String,
    pub payload: Vec<u8>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RecorderGapEntry {
    pub id: i64,
    pub created_at_unix_s: i64,
    pub first_dropped_ts: i64,
    pub last_dropped_ts: i64,
    pub dropped_count: u64,
    pub reason: String,
}

#[derive(Debug)]
pub struct FlightRecorderDb {
    conn: Connection,
    db_path: PathBuf,
    cache_cap_bytes: u64,
    approx_bytes: u64,
}

impl FlightRecorderDb {
    pub fn open(path: impl AsRef<Path>) -> Result<Self, RecorderError> {
        let cap = grdr_schema::limits::load_embedded_limits()
            .map(|l| u64::from(l.endpoint.disk_mb.cache_cap).saturating_mul(1024 * 1024))
            .unwrap_or(DEFAULT_CACHE_CAP_BYTES);
        Self::open_with_cache_cap(path, cap)
    }

    pub fn open_with_cache_cap(
        path: impl AsRef<Path>,
        cache_cap_bytes: u64,
    ) -> Result<Self, RecorderError> {
        if cache_cap_bytes < 1024 {
            return Err(RecorderError::InvalidArgument {
                detail: "cache_cap_bytes must be >= 1024 bytes".to_string(),
            });
        }
        let target = path.as_ref();
        if let Some(parent) = target.parent()
            && !parent.as_os_str().is_empty()
        {
            ensure_private_dir_all(parent)
                .map_err(|detail| RecorderError::InvalidArgument { detail })?;
        }
        ensure_sqlite_family_not_symlink(target)?;
        #[cfg(unix)]
        let pre_meta = std::fs::symlink_metadata(target).ok();

        let conn = Connection::open(target).map_err(|err| RecorderError::Sqlite {
            detail: format!("open {}: {err}", redact_path_label(target)),
        })?;
        ensure_sqlite_family_not_symlink(target)?;
        #[cfg(unix)]
        if let Some(pre) = pre_meta {
            let post = std::fs::symlink_metadata(target).map_err(|err| RecorderError::Sqlite {
                detail: format!("re-stat {}: {err}", redact_path_label(target)),
            })?;
            if pre.dev() != post.dev() || pre.ino() != post.ino() {
                return Err(RecorderError::InvalidArgument {
                    detail: format!(
                        "recorder file swapped during open at {}",
                        redact_path_label(target)
                    ),
                });
            }
        }
        set_private_file_perms(target)
            .map_err(|detail| RecorderError::InvalidArgument { detail })?;
        conn.execute_batch(
            "PRAGMA auto_vacuum = INCREMENTAL;\
             PRAGMA journal_mode = WAL;\
             PRAGMA synchronous = NORMAL;\
             PRAGMA secure_delete = ON;\
             PRAGMA busy_timeout = 5000;\
             CREATE TABLE IF NOT EXISTS recorder_events (\
                 id INTEGER PRIMARY KEY AUTOINCREMENT,\
                 ts_unix_s INTEGER NOT NULL,\
                 lane TEXT NOT NULL,\
                 kind TEXT NOT NULL,\
                 session_id TEXT NOT NULL,\
                 payload_zstd BLOB NOT NULL\
             );\
             CREATE INDEX IF NOT EXISTS idx_recorder_ts_id ON recorder_events (ts_unix_s, id);\
             CREATE TABLE IF NOT EXISTS recorder_gaps (\
                 id INTEGER PRIMARY KEY AUTOINCREMENT,\
                 created_at_unix_s INTEGER NOT NULL,\
                 first_dropped_ts INTEGER NOT NULL,\
                 last_dropped_ts INTEGER NOT NULL,\
                 dropped_count INTEGER NOT NULL,\
                 reason TEXT NOT NULL\
             );",
        )
        .map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
        enforce_sqlite_sidecars_private(target)?;
        let approx_raw: i64 = conn
            .query_row(
                "SELECT COALESCE(SUM(LENGTH(payload_zstd) + 128), 0) FROM recorder_events",
                [],
                |r| r.get(0),
            )
            .map_err(|err| RecorderError::Sqlite {
                detail: err.to_string(),
            })?;
        let approx_bytes = u64::try_from(approx_raw.max(0)).unwrap_or(0);
        Ok(Self {
            conn,
            db_path: target.to_path_buf(),
            cache_cap_bytes,
            approx_bytes,
        })
    }

    pub fn append_event(
        &mut self,
        ts_unix_s: i64,
        lane: &str,
        kind: &str,
        session_id: &str,
        payload: &[u8],
    ) -> Result<i64, RecorderError> {
        if lane.trim().is_empty() || kind.trim().is_empty() {
            return Err(RecorderError::InvalidArgument {
                detail: "lane and kind cannot be empty".to_string(),
            });
        }
        if session_id.len() > MAX_SESSION_ID_BYTES {
            return Err(RecorderError::InvalidArgument {
                detail: "session_id exceeds maximum byte length".to_string(),
            });
        }
        if payload.len() > MAX_DECOMPRESSED_RECORD_BYTES {
            return Err(RecorderError::InvalidArgument {
                detail: format!(
                    "recorder payload {} exceeds limit {MAX_DECOMPRESSED_RECORD_BYTES}",
                    payload.len()
                ),
            });
        }
        let compressed = compress_zstd_frame(payload)?;
        let added_bytes = u64::try_from(compressed.len())
            .unwrap_or(u64::MAX)
            .saturating_add(128);
        let tx = self
            .conn
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
            .map_err(|err| RecorderError::Sqlite {
                detail: err.to_string(),
            })?;
        tx.execute(
            "INSERT INTO recorder_events (ts_unix_s, lane, kind, session_id, payload_zstd) \
             VALUES (?1, ?2, ?3, ?4, ?5)",
            params![ts_unix_s, lane, kind, session_id, compressed],
        )
        .map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
        let id = tx.last_insert_rowid();
        tx.commit().map_err(|err| RecorderError::Sqlite {
            detail: err.to_string(),
        })?;
        self.approx_bytes = self.approx_bytes.saturating_add(added_bytes);
        enforce_sqlite_sidecars_private(&self.db_path)?;
        enforce_cache_cap_rows(
            &mut self.conn,
            &mut self.approx_bytes,
            self.cache_cap_bytes,
            ts_unix_s,
        )?;
        Ok(id)
    }

    pub fn query_events(
        &self,
        since_unix_s: i64,
        until_unix_s: i64,
        session_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<RecordedEntry>, RecorderError> {
        self.query_events_at_level(
            since_unix_s,
            until_unix_s,
            session_id,
            limit,
            RecorderCaptureLevel::Full,
        )
    }

    pub fn query_events_at_level(
        &self,
        since_unix_s: i64,
        until_unix_s: i64,
        session_id: Option<&str>,
        limit: usize,
        capture_level: RecorderCaptureLevel,
    ) -> Result<Vec<RecordedEntry>, RecorderError> {
        if until_unix_s < since_unix_s {
            return Err(RecorderError::InvalidArgument {
                detail: "until_unix_s must be >= since_unix_s".to_string(),
            });
        }
        if limit == 0 || limit > MAX_QUERY_LIMIT {
            return Err(RecorderError::InvalidArgument {
                detail: format!("query limit {limit} out of 1..={MAX_QUERY_LIMIT}"),
            });
        }
        let lim_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut results = Vec::new();
        let mut cumulative_bytes: usize = 0;

        if let Some(sess) = session_id {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT id, ts_unix_s, lane, kind, session_id, payload_zstd \
                     FROM recorder_events \
                     WHERE ts_unix_s >= ?1 AND ts_unix_s <= ?2 AND session_id = ?3 \
                     ORDER BY ts_unix_s ASC, id ASC LIMIT ?4",
                )
                .map_err(|err| RecorderError::Sqlite {
                    detail: err.to_string(),
                })?;
            let rows = stmt
                .query_map(params![since_unix_s, until_unix_s, sess, lim_i64], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                    ))
                })
                .map_err(|err| RecorderError::Sqlite {
                    detail: err.to_string(),
                })?;
            for row in rows {
                let (id, ts, lane, kind, sess_id, zstd_blob) =
                    row.map_err(|err| RecorderError::Sqlite {
                        detail: err.to_string(),
                    })?;
                if !push_filtered_row(
                    &mut results,
                    &mut cumulative_bytes,
                    capture_level,
                    (id, ts, lane, kind, sess_id, zstd_blob),
                )? {
                    break;
                }
            }
        } else {
            let mut stmt = self
                .conn
                .prepare(
                    "SELECT id, ts_unix_s, lane, kind, session_id, payload_zstd \
                     FROM recorder_events \
                     WHERE ts_unix_s >= ?1 AND ts_unix_s <= ?2 \
                     ORDER BY ts_unix_s ASC, id ASC LIMIT ?3",
                )
                .map_err(|err| RecorderError::Sqlite {
                    detail: err.to_string(),
                })?;
            let rows = stmt
                .query_map(params![since_unix_s, until_unix_s, lim_i64], |r| {
                    Ok((
                        r.get::<_, i64>(0)?,
                        r.get::<_, i64>(1)?,
                        r.get::<_, String>(2)?,
                        r.get::<_, String>(3)?,
                        r.get::<_, String>(4)?,
                        r.get::<_, Vec<u8>>(5)?,
                    ))
                })
                .map_err(|err| RecorderError::Sqlite {
                    detail: err.to_string(),
                })?;
            for row in rows {
                let (id, ts, lane, kind, sess_id, zstd_blob) =
                    row.map_err(|err| RecorderError::Sqlite {
                        detail: err.to_string(),
                    })?;
                if !push_filtered_row(
                    &mut results,
                    &mut cumulative_bytes,
                    capture_level,
                    (id, ts, lane, kind, sess_id, zstd_blob),
                )? {
                    break;
                }
            }
        }
        Ok(results)
    }

    pub fn purge_expired(
        &mut self,
        now_unix_s: i64,
        ttl_secs: i64,
    ) -> Result<Option<RecorderGapEntry>, RecorderError> {
        purge_expired_rows(&mut self.conn, &mut self.approx_bytes, now_unix_s, ttl_secs)
    }

    pub fn list_gaps(&self) -> Result<Vec<RecorderGapEntry>, RecorderError> {
        self.list_gaps_bounded(DEFAULT_MAX_GAP_LIST_LIMIT)
    }

    pub fn list_gaps_bounded(&self, limit: usize) -> Result<Vec<RecorderGapEntry>, RecorderError> {
        if limit == 0 || limit > MAX_QUERY_LIMIT {
            return Err(RecorderError::InvalidArgument {
                detail: format!("gap query limit {limit} out of 1..={MAX_QUERY_LIMIT}"),
            });
        }
        let lim_i64 = i64::try_from(limit).unwrap_or(i64::MAX);
        let mut stmt = self
            .conn
            .prepare(
                "SELECT id, created_at_unix_s, first_dropped_ts, last_dropped_ts, dropped_count, reason \
                 FROM recorder_gaps ORDER BY id ASC LIMIT ?1",
            )
            .map_err(|err| RecorderError::Sqlite {
                detail: err.to_string(),
            })?;
        let rows = stmt
            .query_map(params![lim_i64], |r| {
                let count_i64: i64 = r.get(4)?;
                Ok(RecorderGapEntry {
                    id: r.get(0)?,
                    created_at_unix_s: r.get(1)?,
                    first_dropped_ts: r.get(2)?,
                    last_dropped_ts: r.get(3)?,
                    dropped_count: u64::try_from(count_i64).unwrap_or(0),
                    reason: r.get(5)?,
                })
            })
            .map_err(|err| RecorderError::Sqlite {
                detail: err.to_string(),
            })?;

        let mut gaps = Vec::new();
        for row in rows {
            gaps.push(row.map_err(|err| RecorderError::Sqlite {
                detail: err.to_string(),
            })?);
        }
        Ok(gaps)
    }

    pub fn head_seq(&self) -> Result<u64, RecorderError> {
        let max_id: i64 = self
            .conn
            .query_row(
                "SELECT COALESCE(MAX(id), 0) FROM recorder_events",
                [],
                |r| r.get(0),
            )
            .map_err(|err| RecorderError::Sqlite {
                detail: err.to_string(),
            })?;
        Ok(u64::try_from(max_id).unwrap_or(0))
    }
}

fn push_filtered_row(
    results: &mut Vec<RecordedEntry>,
    cumulative_bytes: &mut usize,
    capture_level: RecorderCaptureLevel,
    row: (i64, i64, String, String, String, Vec<u8>),
) -> Result<bool, RecorderError> {
    let (id, ts, lane, kind, session_id, zstd_blob) = row;
    let payload = match capture_level {
        RecorderCaptureLevel::MetadataOnly => Vec::new(),
        RecorderCaptureLevel::Redacted => {
            let decoded = decompress_zstd_frame(&zstd_blob, MAX_DECOMPRESSED_RECORD_BYTES)?;
            format!("[REDACTED:{}B]", decoded.len()).into_bytes()
        }
        RecorderCaptureLevel::Full => {
            decompress_zstd_frame(&zstd_blob, MAX_DECOMPRESSED_RECORD_BYTES)?
        }
    };
    let next_total = cumulative_bytes.saturating_add(payload.len());
    if !results.is_empty() && next_total > MAX_QUERY_TOTAL_BYTES {
        return Ok(false);
    }
    *cumulative_bytes = next_total;
    results.push(RecordedEntry {
        id,
        ts_unix_s: ts,
        lane,
        kind,
        session_id,
        payload,
    });
    Ok(true)
}
