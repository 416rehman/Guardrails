// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Guardrails proxy runtime: loopback OTLP receiver, SR-39 explicit base-URL HTTP
//! gateway, CONNECT/SOCKS5 proxy chaining, egress SSRF guard, and inject-mode credentials.

pub mod cred_inject;
pub mod egress;
pub mod otlp;
pub mod router;
mod router_http;
pub mod sr39;
pub mod tunnel;
mod tunnel_io;

use std::collections::BTreeMap;
use std::future::Future;
use std::net::{IpAddr, Ipv4Addr};
use std::pin::Pin;
use std::time::Duration;

use axum::http::HeaderMap;
use axum::http::header::{HeaderName, HeaderValue};
use jiff::Timestamp;
use uuid::Uuid;

use grdr_core::policy::{ReceiptDigestInput, compute_receipt_digest};
use grdr_model::{ActionAttempt, CodedError, DecideInput, DecisionReceipt, Verdict};
use grdr_strings::sanitize_untrusted_text;

pub const CODE_PROXY_SR39_REJECTED: &str = "GRDR-PROXY-0001";
pub const CODE_PROXY_SSRF_DENIED: &str = "GRDR-PROXY-0002";
pub const CODE_PROXY_POLICY_DENIED: &str = "GRDR-PROXY-0003";
pub const CODE_PROXY_CREDENTIAL: &str = "GRDR-PROXY-0004";
pub const CODE_PROXY_EGRESS_CUT: &str = "GRDR-PROXY-0005";
pub const CODE_PROXY_TRANSPORT: &str = "GRDR-PROXY-0006";

pub const DEFAULT_DAEMON_PORT: u16 = 8765;
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
}

pub type ProxyDecideFuture<'a> =
    Pin<Box<dyn Future<Output = Result<DecisionReceipt, ProxyError>> + Send + 'a>>;

/// Zero local policy state: all authorization decisions delegate to `grdr-daemon`.
pub trait ProxyDecisionClient: Send + Sync {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a>;
}

#[derive(Debug, Clone)]
pub struct LoopbackDaemonProxyClient {
    http: reqwest::Client,
    endpoint_url: String,
    timeout: Duration,
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
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify instance token, route allowlist, tenant headers, and daemon health.",
        )
    }
}

impl LoopbackDaemonProxyClient {
    pub fn from_loopback_port(port: u16, timeout_ms: u64) -> Result<Self, ProxyError> {
        let host = IpAddr::V4(Ipv4Addr::LOCALHOST);
        let endpoint_url = format!("http://{host}:{port}/local/v1/decide");
        let bounded_ms = timeout_ms.clamp(50, 15_000);
        let http = reqwest::Client::builder()
            .timeout(Duration::from_millis(bounded_ms))
            .no_proxy()
            .build()
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        Ok(Self {
            http,
            endpoint_url,
            timeout: Duration::from_millis(bounded_ms),
        })
    }
}

impl ProxyDecisionClient for LoopbackDaemonProxyClient {
    fn decide<'a>(&'a self, attempt: &'a ActionAttempt) -> ProxyDecideFuture<'a> {
        Box::pin(async move {
            let input = DecideInput {
                session_id: Some(attempt.session_id.clone()),
                device_id: Some(attempt.device_id.clone()),
                device_name: Some(attempt.device_name.clone()),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                control_point: Some(attempt.control_point),
                target: attempt.target.clone(),
                summary: Some(attempt.summary.clone()),
            };
            let send = self.http.post(&self.endpoint_url).json(&input).send();
            let resp = tokio::time::timeout(self.timeout, send)
                .await
                .map_err(|_| ProxyError::PolicyDenied("daemon decide timed out".into()))?
                .map_err(|e| ProxyError::PolicyDenied(format!("daemon unreachable: {e}")))?;
            if !resp.status().is_success() {
                return Err(ProxyError::PolicyDenied(format!(
                    "daemon returned HTTP {}",
                    resp.status()
                )));
            }
            resp.json::<DecisionReceipt>()
                .await
                .map_err(|e| ProxyError::PolicyDenied(format!("invalid receipt JSON: {e}")))
        })
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
pub fn fail_closed_proxy_receipt(attempt: &ActionAttempt, reason: &str) -> DecisionReceipt {
    let now = Timestamp::now();
    let clean = sanitize_untrusted_text(reason);
    let digest = compute_receipt_digest(&ReceiptDigestInput {
        attempt_id: &attempt.id,
        session_id: &attempt.session_id,
        agent_name: &attempt.agent_name,
        action_class: attempt.action_class,
        target: &attempt.target,
        verdict: Verdict::Deny,
        rule_id: Some("proxy.fail-closed"),
        decided_at: now,
    });
    DecisionReceipt {
        receipt_id: format!("rcp_{}", Uuid::now_v7().simple()),
        attempt_id: attempt.id.clone(),
        session_id: attempt.session_id.clone(),
        device_id: attempt.device_id.clone(),
        agent_name: attempt.agent_name.clone(),
        action_class: attempt.action_class,
        control_point: attempt.control_point,
        target: attempt.target.clone(),
        verdict: Verdict::Deny,
        would_be: None,
        rule_id: Some("proxy.fail-closed".into()),
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
