// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Guardrails proxy runtime: loopback OTLP receiver + upstream shipper, SR-39 explicit base-URL
//! HTTP gateway, `McpRelay`, CONNECT/SOCKS5 TLS peeking + selective MITM policy, SSRF filtering,
//! RFC 9421 Web Bot Auth, and peer-verified `grdr-ipc-os` daemon IPC.

pub mod control_ipc_server;
pub mod cred_inject;
pub mod egress;
pub mod floor_fallback;
pub mod ipc_client;
mod ipc_transport;
pub mod local_control;
pub mod mcp_relay;
mod mcp_relay_sse;
mod mcp_relay_state;
pub mod otlp;
pub mod router;
mod router_http;
mod router_otlp;
pub mod sr39;
pub mod streaming;
mod streaming_policy;
mod tls_hello;
pub mod tls_policy;
pub mod tunnel;
mod tunnel_io;
mod tunnel_socks;
pub mod web_bot_auth;

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;

use axum::http::HeaderMap;
use axum::http::header::{HeaderName, HeaderValue};
use grdr_os_clock::{Clock, SystemClock};
use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::policy::{ReceiptDigestInput, compute_receipt_digest};
use grdr_model::{ActionAttempt, CodedError, DecisionReceipt, Verdict};
use grdr_strings::sanitize_untrusted_text;

pub use ipc_client::IpcProxyDecisionClient;

pub const CODE_PROXY_SR39_REJECTED: &str = "GRDR-PROXY-0001";
pub const CODE_PROXY_SSRF_DENIED: &str = "GRDR-PROXY-0002";
pub const CODE_PROXY_POLICY_DENIED: &str = "GRDR-PROXY-0003";
pub const CODE_PROXY_CREDENTIAL: &str = "GRDR-PROXY-0004";
pub const CODE_PROXY_EGRESS_CUT: &str = "GRDR-PROXY-0005";
pub const CODE_PROXY_TRANSPORT: &str = "GRDR-PROXY-0006";
pub const CODE_PROXY_DEGRADED: &str = "GRDR-PROXY-0007";
pub const CODE_PROXY_SNI_MISMATCH: &str = "GRDR-PROXY-0008";

pub const DEFAULT_DECIDE_TIMEOUT_MS: u64 = 1_500;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ProxyError {
    #[error("GRDR-PROXY-0001: SR-39 request validation failed: {0}")]
    Sr39Rejected(String),
    #[error("GRDR-PROXY-0002: outbound destination blocked by SSRF guard: {0}")]
    SsrfDenied(String),
    #[error("GRDR-PROXY-0003: policy denied outbound action: {0}")]
    PolicyDenied(String),
    #[error("GRDR-PROXY-0004: credential injection rejected: {0}")]
    CredentialDenied(String),
    #[error("GRDR-PROXY-0005: session egress cut (D-30) active for `{0}`")]
    SessionEgressCut(String),
    #[error("GRDR-PROXY-0006: proxy transport or upstream error: {0}")]
    Transport(String),
    #[error("GRDR-PROXY-0007: daemon unavailable; proxy operating fail-closed / floor: {0}")]
    DaemonDegraded(String),
    #[error("GRDR-PROXY-0008: net.sni-mismatch TLS SNI disagrees with CONNECT target: {0}")]
    SniMismatch(String),
}

pub type ProxyDecideFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DecisionReceipt, ProxyError>> + Send + 'a>>;

/// Zero local policy state: all authorization decisions delegate to `grdr-daemon`.
pub trait ProxyDecisionClient: Send + Sync {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a>;
}

/// Authoritative per-route tenant-restriction headers set (never appended) on upstream calls.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct TenantHeaderPolicy {
    pub headers: BTreeMap<String, String>,
}

impl From<ProxyError> for CodedError {
    fn from(err: ProxyError) -> Self {
        let code = match &err {
            ProxyError::Sr39Rejected(_) => CODE_PROXY_SR39_REJECTED,
            ProxyError::SsrfDenied(_) => CODE_PROXY_SSRF_DENIED,
            ProxyError::PolicyDenied(_) => CODE_PROXY_POLICY_DENIED,
            ProxyError::CredentialDenied(_) => CODE_PROXY_CREDENTIAL,
            ProxyError::SessionEgressCut(_) => CODE_PROXY_EGRESS_CUT,
            ProxyError::Transport(_) => CODE_PROXY_TRANSPORT,
            ProxyError::DaemonDegraded(_) => CODE_PROXY_DEGRADED,
            ProxyError::SniMismatch(_) => CODE_PROXY_SNI_MISMATCH,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify instance token, route allowlist, SNI host match, tenant headers, and daemon IPC.",
        )
    }
}

impl TenantHeaderPolicy {
    pub fn insert(
        &mut self,
        name: impl Into<String>,
        value: impl Into<String>,
    ) -> Result<(), ProxyError> {
        let key = name.into().trim().to_ascii_lowercase();
        if key.is_empty() {
            return Err(ProxyError::Sr39Rejected(
                "tenant header name cannot be empty".into(),
            ));
        }
        let val = value.into().trim().to_owned();
        if val.contains('\r') || val.contains('\n') {
            return Err(ProxyError::Sr39Rejected(
                "tenant header value contains CRLF".into(),
            ));
        }
        self.headers.insert(key, val);
        Ok(())
    }

    /// Applies tenant headers by removing all prior values and inserting the single
    /// authoritative value so caller-supplied spoofed values are never appended.
    pub fn apply_overwrite(&self, outbound: &mut HeaderMap) -> Result<(), ProxyError> {
        for (name, val) in &self.headers {
            let hdr_name = HeaderName::from_bytes(name.as_bytes())
                .map_err(|e| ProxyError::Transport(format!("invalid header name `{name}`: {e}")))?;
            let hdr_val = HeaderValue::from_str(val)
                .map_err(|e| ProxyError::Transport(format!("invalid header value: {e}")))?;
            while outbound.remove(&hdr_name).is_some() {}
            outbound.insert(hdr_name, hdr_val);
        }
        Ok(())
    }
}

#[must_use]
pub fn build_proxy_receipt(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: Option<&str>,
    reason: &str,
    receipt_id_override: Option<&str>,
    now: Timestamp,
) -> DecisionReceipt {
    let clean = sanitize_untrusted_text(reason);
    let receipt_id = receipt_id_override
        .map(str::trim)
        .filter(|id| !id.is_empty())
        .map_or_else(|| format!("rcp_{}", Uuid::now_v7().simple()), str::to_owned);
    let digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict,
        rule_id,
        decided_at: now,
    });
    DecisionReceipt {
        receipt_id,
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict,
        would_be: None,
        rule_id: rule_id.map(str::to_owned),
        pack_id: Some("grdr-proxy".into()),
        mode_applied: None,
        grant_id: None,
        reason: clean,
        next_step: "Inspect daemon policy or retry with an approved session.".into(),
        receipt_digest: digest,
        decided_at: now,
        key_id: None,
        signature: None,
        signature_verified: None,
    }
}

#[must_use]
pub fn synthetic_proxy_receipt(
    attempt: &ActionAttempt,
    verdict: Verdict,
    rule_id: Option<&str>,
    reason: &str,
) -> DecisionReceipt {
    let now = SystemClock::new().now_wall().unwrap_or(attempt.timestamp);
    build_proxy_receipt(attempt, verdict, rule_id, reason, None, now)
}

#[must_use]
pub fn fail_closed_proxy_receipt(attempt: &ActionAttempt, reason: &str) -> DecisionReceipt {
    synthetic_proxy_receipt(attempt, Verdict::Deny, Some("proxy.fail-closed"), reason)
}
