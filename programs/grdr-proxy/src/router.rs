// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Axum HTTP router serving OTLP loopback ingestion and SR-39 explicit base-URL forwarding.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use jiff::Timestamp;
use tokio::sync::{Mutex, watch};
use uuid::Uuid;

use grdr_llm_proto::parse_llm_request_metadata;
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource, Verdict};
use grdr_strings::sanitize_untrusted_text;

use crate::cred_inject::ProxyCredentialManager;
use crate::egress::{EgressGuardConfig, resolve_and_vet_chained_proxy, resolve_and_vet_target};
use crate::otlp::{OtlpSignalKind, SanitizedOtlpEvent, ingest_otlp_payload};
use crate::router_http::{
    bad_gateway_response, build_upstream_url, copy_safe_outbound_headers, denial_403,
    read_bounded_response,
};
use crate::sr39::InstanceTokenRegistry;
use crate::tunnel::UpstreamProxyConfig;
use crate::{ProxyDecisionClient, ProxyError};

pub const MAX_PROXY_BODY_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_UPSTREAM_RESPONSE_BYTES: usize = 16 * 1024 * 1024;
pub const MAX_RETAINED_OTLP_EVENTS: usize = 1_024;
const MAX_CACHED_HTTP_CLIENTS: usize = 64;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct ClientCacheKey {
    target_host: String,
    target_addr: SocketAddr,
    chain: Option<(String, SocketAddr)>,
}

pub struct ProxyGatewayState<C> {
    pub decision_client: C,
    pub listener_port: u16,
    pub egress_config: EgressGuardConfig,
    pub upstream_chain: Option<UpstreamProxyConfig>,
    pub registry: Mutex<InstanceTokenRegistry>,
    pub credentials: Mutex<ProxyCredentialManager>,
    pub otlp_events: Mutex<VecDeque<SanitizedOtlpEvent>>,
    pub cut_watch: watch::Sender<u64>,
    http_clients: Mutex<BTreeMap<ClientCacheKey, reqwest::Client>>,
}

impl<C: ProxyDecisionClient> ProxyGatewayState<C> {
    pub fn new(
        decision_client: C,
        listener_port: u16,
        egress_config: EgressGuardConfig,
    ) -> Result<Self, ProxyError> {
        let (cut_watch, _) = watch::channel(0_u64);
        Ok(Self {
            decision_client,
            listener_port,
            egress_config,
            upstream_chain: None,
            registry: Mutex::new(InstanceTokenRegistry::new()),
            credentials: Mutex::new(ProxyCredentialManager::default()),
            otlp_events: Mutex::new(VecDeque::new()),
            cut_watch,
            http_clients: Mutex::new(BTreeMap::new()),
        })
    }

    #[must_use]
    pub fn with_upstream_chain(mut self, upstream_chain: Option<UpstreamProxyConfig>) -> Self {
        self.upstream_chain = upstream_chain;
        self
    }

    pub async fn cut_session_egress(&self, session_id: &str) -> usize {
        self.registry.lock().await.cut_session(session_id);
        let revoked = self.credentials.lock().await.revoke_session(session_id);
        let next = self.cut_watch.borrow().saturating_add(1);
        if self.cut_watch.send(next).is_err() {
            tracing::debug!(
                session_id,
                "no active tunnel subscribers on D-30 egress cut"
            );
        }
        revoked
    }

    async fn get_or_build_client(
        &self,
        target_host: &str,
        target_addr: SocketAddr,
        chain: Option<(&UpstreamProxyConfig, SocketAddr)>,
    ) -> Result<reqwest::Client, ProxyError> {
        let key = ClientCacheKey {
            target_host: target_host.to_owned(),
            target_addr,
            chain: chain.map(|(proxy, addr)| (proxy.host.clone(), addr)),
        };
        if let Some(cached) = self.http_clients.lock().await.get(&key).cloned() {
            return Ok(cached);
        }

        let mut builder = reqwest::Client::builder()
            .timeout(Duration::from_secs(15))
            .redirect(reqwest::redirect::Policy::none())
            .resolve(target_host, target_addr);
        if let Some((proxy, proxy_addr)) = chain {
            let proxy_authority = if proxy.host.contains(':') && !proxy.host.starts_with('[') {
                format!("[{}]:{}", proxy.host, proxy.port)
            } else {
                format!("{}:{}", proxy.host, proxy.port)
            };
            let proxy_url = format!("http://{proxy_authority}");
            let req_proxy =
                reqwest::Proxy::all(proxy_url).map_err(|e| ProxyError::Transport(e.to_string()))?;
            builder = builder.proxy(req_proxy).resolve(&proxy.host, proxy_addr);
        } else {
            builder = builder.no_proxy();
        }
        let client = builder
            .build()
            .map_err(|e| ProxyError::Transport(e.to_string()))?;

        let mut cache = self.http_clients.lock().await;
        if cache.len() >= MAX_CACHED_HTTP_CLIENTS
            && let Some(oldest) = cache.keys().next().cloned()
        {
            cache.remove(&oldest);
        }
        cache.insert(key, client.clone());
        Ok(client)
    }
}

pub fn build_proxy_router<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
) -> Router {
    Router::new()
        .route("/v1/traces", post(handle_otlp_traces::<C>))
        .route("/v1/logs", post(handle_otlp_logs::<C>))
        .route("/v1/metrics", post(handle_otlp_metrics::<C>))
        .route("/t/{token}/{route_id}", any(handle_base_url_root::<C>))
        .route(
            "/t/{token}/{route_id}/{*tail}",
            any(handle_base_url_tail::<C>),
        )
        .layer(DefaultBodyLimit::max(MAX_PROXY_BODY_BYTES))
        .with_state(state)
}

async fn handle_otlp_traces<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_otlp(state, headers, OtlpSignalKind::Traces, body).await
}

async fn handle_otlp_logs<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_otlp(state, headers, OtlpSignalKind::Logs, body).await
}

async fn handle_otlp_metrics<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_otlp(state, headers, OtlpSignalKind::Metrics, body).await
}

async fn handle_otlp<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    headers: HeaderMap,
    signal: OtlpSignalKind,
    body: Bytes,
) -> Response {
    let event = match ingest_otlp_payload(&headers, signal, &body) {
        Ok(ev) => ev,
        Err(err) => return denial_403(&err),
    };
    let attempt = event.attempt.clone();
    {
        let mut retained = state.otlp_events.lock().await;
        if retained.len() >= MAX_RETAINED_OTLP_EVENTS {
            drop(retained.pop_front());
        }
        retained.push_back(event);
    }
    if let Err(err) = state.decision_client.decide(&attempt).await {
        tracing::warn!(error = %err, "failed to forward sanitized Claimed OTLP telemetry to daemon");
    }
    (
        StatusCode::OK,
        axum::Json(serde_json::json!({
            "accepted": true,
            "provenance": "claimed"
        })),
    )
        .into_response()
}

async fn handle_base_url_root<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    Path((token, route_id)): Path<(String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_base_url(state, token, route_id, String::new(), method, headers, body).await
}

async fn handle_base_url_tail<C: ProxyDecisionClient + 'static>(
    State(state): State<Arc<ProxyGatewayState<C>>>,
    Path((token, route_id, tail)): Path<(String, String, String)>,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    handle_base_url(state, token, route_id, tail, method, headers, body).await
}

async fn handle_base_url<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    token: String,
    route_id: String,
    tail: String,
    method: Method,
    headers: HeaderMap,
    body: Bytes,
) -> Response {
    if body.len() > MAX_PROXY_BODY_BYTES {
        return denial_403(&ProxyError::Sr39Rejected(
            "request body exceeds proxy limit".into(),
        ));
    }

    let (reg, route) = match state.registry.lock().await.resolve_sr39_route(
        &headers,
        state.listener_port,
        &token,
        &route_id,
        !body.is_empty(),
    ) {
        Ok(found) => found,
        Err(err) => return denial_403(&err),
    };

    let vetted = match resolve_and_vet_target(&route.host, route.port, &state.egress_config).await {
        Ok(v) => v,
        Err(err) => return denial_403(&err),
    };
    let Some(&pinned_addr) = vetted.pinned_addrs.first() else {
        return denial_403(&ProxyError::SsrfDenied(
            "SSRF guard produced empty pinned address list".into(),
        ));
    };

    let target_url = match build_upstream_url(&route.base_url, &tail) {
        Ok(url) => url,
        Err(err) => return denial_403(&err),
    };
    let attempt = build_proxy_attempt(
        &reg.session_id,
        &reg.agent_name,
        &route.provider,
        &target_url,
        &body,
    );

    let receipt = match state.decision_client.decide(&attempt).await {
        Ok(r) => r,
        Err(err) => return denial_403(&err),
    };
    if receipt.verdict != Verdict::Allow {
        return (
            StatusCode::FORBIDDEN,
            axum::Json(serde_json::json!({
                "error": sanitize_untrusted_text(&receipt.reason),
                "code": "GRDR-PROXY-0003",
                "receipt_id": receipt.receipt_id,
                "verdict": format!("{:?}", receipt.verdict),
            })),
        )
            .into_response();
    }

    let mut outbound_headers = copy_safe_outbound_headers(&headers);

    if let Err(err) = route.tenant_headers.apply_overwrite(&mut outbound_headers) {
        return denial_403(&err);
    }

    if let Some(cred_id) = route.credential_id.as_deref() {
        let mut creds = state.credentials.lock().await;
        if let Err(err) = creds.inject_for_route(
            &reg,
            cred_id,
            &route.host,
            &headers,
            &mut outbound_headers,
            Timestamp::now(),
        ) {
            return denial_403(&err);
        }
    }

    let chain_target = if let Some(chain) = state.upstream_chain.as_ref() {
        let chain_vetted = match resolve_and_vet_chained_proxy(&chain.host, chain.port).await {
            Ok(v) => v,
            Err(err) => return denial_403(&err),
        };
        let Some(&chain_addr) = chain_vetted.pinned_addrs.first() else {
            return denial_403(&ProxyError::SsrfDenied(
                "chained proxy produced empty pinned address list".into(),
            ));
        };
        Some((chain, chain_addr))
    } else {
        None
    };

    let pinned_client = match state
        .get_or_build_client(&route.host, pinned_addr, chain_target)
        .await
    {
        Ok(client) => client,
        Err(err) => return denial_403(&err),
    };

    let req_builder = pinned_client
        .request(method, target_url)
        .headers(outbound_headers)
        .body(body.to_vec());

    match req_builder.send().await {
        Ok(upstream_resp) => {
            let status = upstream_resp.status();
            let resp_headers = upstream_resp.headers().clone();
            match read_bounded_response(upstream_resp, MAX_UPSTREAM_RESPONSE_BYTES).await {
                Ok(resp_bytes) => {
                    let mut out = (status, resp_bytes).into_response();
                    if let Some(ctype) = resp_headers.get("content-type") {
                        out.headers_mut().insert("content-type", ctype.clone());
                    }
                    out
                }
                Err(err) => bad_gateway_response(&err),
            }
        }
        Err(err) => bad_gateway_response(&ProxyError::Transport(err.to_string())),
    }
}

fn build_proxy_attempt(
    session_id: &str,
    agent_name: &str,
    provider: &str,
    target_url: &str,
    body: &[u8],
) -> ActionAttempt {
    let body_str = std::str::from_utf8(body).unwrap_or("");
    let (action_class, summary) = match parse_llm_request_metadata(provider, body_str) {
        Ok(meta) => (
            ActionClass::LlmRequest,
            format!(
                "provider={} model={} msgs={}",
                meta.provider,
                meta.model.as_deref().unwrap_or("unspecified"),
                meta.message_count
            ),
        ),
        Err(_) => (
            ActionClass::NetRequest,
            format!("http route request target={target_url}"),
        ),
    };
    ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: session_id.to_owned(),
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: agent_name.to_owned(),
        action_class,
        control_point: ControlPoint::Proxy,
        target: target_url.to_owned(),
        summary: sanitize_untrusted_text(&summary),
        timestamp: Timestamp::now(),
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    }
}
