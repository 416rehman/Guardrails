// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::sync::Arc;

use axum::http::{HeaderValue, StatusCode, header};
use axum::response::{IntoResponse, Response};
use grdr_crypto::sha256_hex;
use jiff::Timestamp;
use serde_json::json;
use tokio::sync::RwLock;

use super::limits::rest_limits;

#[derive(Debug, Clone)]
pub enum IdempotencyEntry {
    InFlight {
        request_hash: String,
        started_unix: i64,
        seq: u64,
    },
    Completed {
        request_hash: String,
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
        completed_unix: i64,
        seq: u64,
    },
}

#[derive(Debug, Clone)]
pub enum IdempotencyLookup {
    Miss,
    Replay {
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    },
    InFlight,
    PayloadConflict,
}

#[derive(Debug, Default)]
struct IdempotencyState {
    next_seq: u64,
    entries: BTreeMap<String, IdempotencyEntry>,
}

#[derive(Debug, Clone, Default)]
pub struct IdempotencyCache {
    state: Arc<RwLock<IdempotencyState>>,
}

impl IdempotencyCache {
    pub fn composite_key(
        tenant_id: &str,
        principal_id: &str,
        method: &str,
        path: &str,
        key: &str,
    ) -> String {
        format!("{tenant_id}|{principal_id}|{method}|{path}|{}", key.trim())
    }

    pub async fn begin(&self, composite_key: String, request_bytes: &[u8]) -> IdempotencyLookup {
        let now = Timestamp::now().as_second();
        let ttl = rest_limits().idempotency_ttl_secs;
        let max_entries = rest_limits().max_cache_entries.max(1);
        let req_hash = sha256_hex(request_bytes);
        let mut guard = self.state.write().await;

        guard.entries.retain(|_, v| match v {
            IdempotencyEntry::InFlight { started_unix, .. } => {
                now.saturating_sub(*started_unix) < ttl
            }
            IdempotencyEntry::Completed { completed_unix, .. } => {
                now.saturating_sub(*completed_unix) < ttl
            }
        });

        match guard.entries.get(&composite_key) {
            Some(IdempotencyEntry::InFlight { request_hash, .. }) => {
                if *request_hash != req_hash {
                    IdempotencyLookup::PayloadConflict
                } else {
                    IdempotencyLookup::InFlight
                }
            }
            Some(IdempotencyEntry::Completed {
                request_hash,
                status,
                content_type,
                body,
                ..
            }) => {
                if *request_hash != req_hash {
                    IdempotencyLookup::PayloadConflict
                } else {
                    IdempotencyLookup::Replay {
                        status: *status,
                        content_type: content_type.clone(),
                        body: body.clone(),
                    }
                }
            }
            None => {
                while guard.entries.len() >= max_entries {
                    let oldest_key = guard
                        .entries
                        .iter()
                        .min_by_key(|(_, entry)| match entry {
                            IdempotencyEntry::InFlight { seq, .. } => *seq,
                            IdempotencyEntry::Completed { seq, .. } => *seq,
                        })
                        .map(|(k, _)| k.clone());
                    let Some(k) = oldest_key else {
                        break;
                    };
                    guard.entries.remove(&k);
                }
                guard.next_seq = guard.next_seq.saturating_add(1);
                let seq = guard.next_seq;
                guard.entries.insert(
                    composite_key,
                    IdempotencyEntry::InFlight {
                        request_hash: req_hash,
                        started_unix: now,
                        seq,
                    },
                );
                IdempotencyLookup::Miss
            }
        }
    }

    pub async fn finish(
        &self,
        composite_key: &str,
        request_bytes: &[u8],
        status: u16,
        content_type: Option<String>,
        body: Vec<u8>,
    ) {
        let now = Timestamp::now().as_second();
        let req_hash = sha256_hex(request_bytes);
        let mut guard = self.state.write().await;
        guard.next_seq = guard.next_seq.saturating_add(1);
        let seq = guard.next_seq;
        guard.entries.insert(
            composite_key.to_owned(),
            IdempotencyEntry::Completed {
                request_hash: req_hash,
                status,
                content_type,
                body,
                completed_unix: now,
                seq,
            },
        );
    }

    pub async fn abort(&self, composite_key: &str) {
        let mut guard = self.state.write().await;
        if matches!(
            guard.entries.get(composite_key),
            Some(IdempotencyEntry::InFlight { .. })
        ) {
            guard.entries.remove(composite_key);
        }
    }
}

pub fn idempotency_error_response(reason: &str, status: StatusCode, message: &str) -> Response {
    let body = json!({
        "code": if status == StatusCode::BAD_REQUEST {
            "invalid_argument"
        } else if status == StatusCode::UNAUTHORIZED {
            "unauthenticated"
        } else {
            "failed_precondition"
        },
        "reason": reason,
        "message": message,
    });
    (status, axum::Json(body)).into_response()
}

pub fn replay_response(status: u16, content_type: Option<String>, body: Vec<u8>) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::OK);
    let mut resp = (code, body).into_response();
    if let Some(ct) = content_type
        && let Ok(hv) = HeaderValue::from_str(&ct)
    {
        resp.headers_mut().insert(header::CONTENT_TYPE, hv);
    }
    resp.headers_mut()
        .insert("idempotent-replay", HeaderValue::from_static("true"));
    resp
}
