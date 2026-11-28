// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, VecDeque};
use std::sync::Arc;

use axum::http::{HeaderMap, HeaderValue, StatusCode};
use axum::response::{IntoResponse, Response};
use jiff::Timestamp;
use serde_json::json;
use tokio::sync::Mutex;

use super::limits::rest_limits;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum TrafficClass {
    Ingest,
    Critical,
    Standard,
    Bulk,
}

#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    pub window_seconds: i64,
    pub default_limit: u32,
}

#[derive(Debug, Clone)]
pub struct RateDecision {
    pub allowed: bool,
    pub limit: u32,
    pub remaining: u32,
    pub reset_seconds: i64,
    pub reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct BucketKey {
    tenant_id: String,
    principal_id: String,
    class: TrafficClass,
}

#[derive(Debug, Clone, Default)]
struct BucketWindow {
    timestamps: VecDeque<i64>,
    last_seen_sec: i64,
}

#[derive(Debug, Clone)]
pub struct TenantRateLimiter {
    config: RateLimitConfig,
    buckets: Arc<Mutex<BTreeMap<BucketKey, BucketWindow>>>,
}

impl Default for RateLimitConfig {
    fn default() -> Self {
        let limits = rest_limits();
        Self {
            window_seconds: limits.rate_limit_window_secs,
            default_limit: limits.rate_limit_default_per_min,
        }
    }
}

impl Default for TenantRateLimiter {
    fn default() -> Self {
        Self::new(RateLimitConfig::default())
    }
}

impl TenantRateLimiter {
    pub fn new(config: RateLimitConfig) -> Self {
        Self {
            config,
            buckets: Arc::new(Mutex::new(BTreeMap::new())),
        }
    }

    pub async fn check(
        &self,
        tenant_id: &str,
        principal_id: &str,
        class: TrafficClass,
    ) -> RateDecision {
        self.check_with_limit(tenant_id, principal_id, class, self.config.default_limit)
            .await
    }

    pub async fn check_with_limit(
        &self,
        tenant_id: &str,
        principal_id: &str,
        class: TrafficClass,
        limit: u32,
    ) -> RateDecision {
        let now = Timestamp::now().as_second();
        if class == TrafficClass::Ingest {
            return RateDecision {
                allowed: true,
                limit,
                remaining: limit,
                reset_seconds: self.config.window_seconds,
                reason: "INGEST_EXEMPT",
            };
        }

        let effective_limit = limit.max(1);
        let window_secs = self.config.window_seconds.max(1);
        let max_buckets = rest_limits().max_cache_entries.max(1);
        let key = BucketKey {
            tenant_id: tenant_id.to_owned(),
            principal_id: principal_id.to_owned(),
            class,
        };

        let mut guard = self.buckets.lock().await;
        if !guard.contains_key(&key) && guard.len() >= max_buckets {
            guard.retain(|_, b| now.saturating_sub(b.last_seen_sec) < window_secs);
            while guard.len() >= max_buckets {
                let oldest = guard
                    .iter()
                    .min_by_key(|(_, b)| b.last_seen_sec)
                    .map(|(k, _)| k.clone());
                let Some(k) = oldest else {
                    break;
                };
                guard.remove(&k);
            }
        }

        let entry = guard.entry(key).or_default();
        while let Some(&front) = entry.timestamps.front() {
            if now.saturating_sub(front) >= window_secs {
                entry.timestamps.pop_front();
            } else {
                break;
            }
        }
        entry.last_seen_sec = now;

        let count = u32::try_from(entry.timestamps.len()).unwrap_or(u32::MAX);
        let oldest_ts = entry.timestamps.front().copied().unwrap_or(now);
        let elapsed = now.saturating_sub(oldest_ts).max(0);
        let reset = window_secs.saturating_sub(elapsed).max(1);

        let shed_threshold = match class {
            TrafficClass::Bulk => effective_limit.saturating_mul(70) / 100,
            TrafficClass::Standard => effective_limit.saturating_mul(90) / 100,
            TrafficClass::Critical | TrafficClass::Ingest => effective_limit,
        };
        let threshold = shed_threshold.max(1);
        if count >= threshold {
            let reason = if count >= effective_limit {
                "RATE_LIMIT_EXCEEDED"
            } else {
                "PRIORITY_SHEDDING"
            };
            return RateDecision {
                allowed: false,
                limit: effective_limit,
                remaining: 0,
                reset_seconds: reset,
                reason,
            };
        }

        entry.timestamps.push_back(now);
        let next_count = u32::try_from(entry.timestamps.len()).unwrap_or(u32::MAX);
        RateDecision {
            allowed: true,
            limit: effective_limit,
            remaining: effective_limit.saturating_sub(next_count),
            reset_seconds: reset,
            reason: "OK",
        }
    }
}

pub fn attach_rate_limit_headers(
    headers: &mut HeaderMap,
    decision: &RateDecision,
    window_secs: i64,
) {
    let policy_val = format!("default;q={};w={window_secs}", decision.limit);
    let state_val = format!(
        "default;r={};t={}",
        decision.remaining, decision.reset_seconds
    );
    if let Ok(v) = HeaderValue::from_str(&policy_val) {
        headers.insert("ratelimit-policy", v);
    }
    if let Ok(v) = HeaderValue::from_str(&state_val) {
        headers.insert("ratelimit", v);
    }
    if !decision.allowed
        && let Ok(v) = HeaderValue::from_str(&decision.reset_seconds.to_string())
    {
        headers.insert("retry-after", v);
    }
}

pub fn rate_limited_response(decision: &RateDecision, window_secs: i64) -> Response {
    let mut resp = (
        StatusCode::TOO_MANY_REQUESTS,
        axum::Json(json!({
            "code": "resource_exhausted",
            "reason": decision.reason,
            "message": "Tenant rate limit reached; retry after the reset window.",
            "retryAfterSeconds": decision.reset_seconds,
        })),
    )
        .into_response();
    attach_rate_limit_headers(resp.headers_mut(), decision, window_secs);
    resp
}
