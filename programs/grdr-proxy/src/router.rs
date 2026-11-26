// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Axum HTTP router serving OTLP loopback ingestion, SR-39 explicit base-URL forwarding,
//! `McpRelay` routes, `Grdr-Session` correlation tags, RFC 9421 signing, and bounded streaming.

use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::extract::{DefaultBodyLimit, Path, State};
use axum::http::header::{HeaderName, HeaderValue};
use axum::http::{HeaderMap, Method, StatusCode};
use axum::response::{IntoResponse, Response};
use axum::routing::{any, post};
use grdr_model::Verdict;
use grdr_os_clock::{Clock, SystemClock};
use grdr_strings::sanitize_untrusted_text;
use grdr_wire::peer_auth::Profile;
use tokio::sync::{Mutex, watch};

use crate::cred_inject::ProxyCredentialManager;
use crate::egress::{EgressGuardConfig, resolve_and_vet_chained_proxy, resolve_and_vet_target};
use crate::mcp_relay::{handle_mcp_relay_root, handle_mcp_relay_tail};
use crate::mcp_relay_state::McpRelayState;
use crate::otlp::{OtlpUpstreamShipper, SanitizedOtlpEvent};
use crate::router_http::{
    ProxyAttemptInput, bad_gateway_response, build_proxy_attempt, build_upstream_url,
    copy_safe_outbound_headers, denial_403,
};
use crate::router_otlp::{handle_otlp_logs, handle_otlp_metrics, handle_otlp_traces};
use crate::sr39::{InstanceTokenRegistry, RouteUpstream, SessionRegistration};
use crate::streaming::{inspect_and_decompress_request_body, stream_upstream_response};
use crate::tls_policy::{
    SwgCoexistenceManifest, SwgDetectionResult, detect_enterprise_swg,
    load_swg_coexistence_manifest,
};
use crate::tunnel::UpstreamProxyConfig;
use crate::web_bot_auth::WebBotAuthSigner;
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
    pub profile: Profile,
    pub decision_client: C,
    pub listener_port: u16,
    pub egress_config: EgressGuardConfig,
    pub upstream_chain: Option<UpstreamProxyConfig>,
    pub registry: Mutex<InstanceTokenRegistry>,
    pub credentials: Mutex<ProxyCredentialManager>,
    pub otlp_events: Mutex<VecDeque<SanitizedOtlpEvent>>,
    pub cut_watch: watch::Sender<u64>,
    pub global_kill_switch: AtomicBool,
    pub otlp_shipper: Mutex<Option<OtlpUpstreamShipper>>,
    pub web_bot_signer: Mutex<Option<WebBotAuthSigner>>,
    pub swg_manifest: SwgCoexistenceManifest,
    pub swg_detection: Mutex<SwgDetectionResult>,
    pub trusted_a2a_keys: Mutex<BTreeMap<String, [u8; 32]>>,
    pub allowed_route_tools: Mutex<BTreeMap<String, BTreeSet<String>>>,
    pub mcp_relay: Mutex<McpRelayState>,
    http_clients: Mutex<BTreeMap<ClientCacheKey, reqwest::Client>>,
}

impl<C: ProxyDecisionClient> ProxyGatewayState<C> {
    pub fn new(
        decision_client: C,
        listener_port: u16,
        egress_config: EgressGuardConfig,
    ) -> Result<Self, ProxyError> {
        Self::new_with_profile(Profile::User, decision_client, listener_port, egress_config)
    }

    pub fn new_with_profile(
        profile: Profile,
        decision_client: C,
        listener_port: u16,
        egress_config: EgressGuardConfig,
    ) -> Result<Self, ProxyError> {
        let (cut_watch, _) = watch::channel(0_u64);
        let swg_manifest = load_swg_coexistence_manifest(profile)?;
        let empty_env = BTreeMap::new();
        let swg_detection = detect_enterprise_swg(&empty_env, &[], None, &swg_manifest);
        Ok(Self {
            profile,
            decision_client,
            listener_port,
            egress_config,
            upstream_chain: None,
            registry: Mutex::new(InstanceTokenRegistry::new()),
            credentials: Mutex::new(ProxyCredentialManager::default()),
            otlp_events: Mutex::new(VecDeque::new()),
            cut_watch,
            global_kill_switch: AtomicBool::new(false),
            otlp_shipper: Mutex::new(None),
            web_bot_signer: Mutex::new(None),
            swg_manifest,
            swg_detection: Mutex::new(swg_detection),
            trusted_a2a_keys: Mutex::new(BTreeMap::new()),
            allowed_route_tools: Mutex::new(BTreeMap::new()),
            mcp_relay: Mutex::new(McpRelayState::new()),
            http_clients: Mutex::new(BTreeMap::new()),
        })
    }

    #[must_use]
    pub fn with_upstream_chain(mut self, upstream_chain: Option<UpstreamProxyConfig>) -> Self {
        self.upstream_chain = upstream_chain;
        self
    }

    #[must_use]
    pub fn with_otlp_shipper(self, shipper: Option<OtlpUpstreamShipper>) -> Self {
        if let Ok(mut slot) = self.otlp_shipper.try_lock() {
            *slot = shipper;
        }
        self
    }

    #[must_use]
    pub fn with_web_bot_signer(self, signer: Option<WebBotAuthSigner>) -> Self {
        if let Ok(mut slot) = self.web_bot_signer.try_lock() {
            *slot = signer;
        }
        self
    }

    #[must_use]
    pub fn with_swg_env(self, env_map: &BTreeMap<String, String>) -> Self {
        let detected = detect_enterprise_swg(env_map, &[], None, &self.swg_manifest);
        if let Ok(mut slot) = self.swg_detection.try_lock() {
            *slot = detected;
        }
        self
    }

    pub fn set_global_kill_switch(&self, active: bool) {
        self.global_kill_switch.store(active, Ordering::SeqCst);
        let next = self.cut_watch.borrow().saturating_add(1);
        let _ = self.cut_watch.send(next);
    }

    #[must_use]
    pub fn is_globally_killed(&self) -> bool {
        self.global_kill_switch.load(Ordering::SeqCst)
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

    pub(crate) async fn build_pinned_route_client(
        &self,
        vetted_host: &str,
        pinned_addr: SocketAddr,
    ) -> Result<(reqwest::Client, SocketAddr), ProxyError> {
        let chain_target = if let Some(chain) = self.upstream_chain.as_ref() {
            let chain_vetted = resolve_and_vet_chained_proxy(&chain.host, chain.port).await?;
            let Some(&chain_addr) = chain_vetted.pinned_addrs.first() else {
                return Err(ProxyError::SsrfDenied(
                    "chained proxy produced empty pinned address list".into(),
                ));
            };
            Some((chain, chain_addr))
        } else {
            None
        };
        let expected_peer = chain_target.map_or(pinned_addr, |(_, addr)| addr);
        let client = self
            .get_or_build_client(vetted_host, pinned_addr, chain_target)
            .await?;
        Ok((client, expected_peer))
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
            .timeout(Duration::from_secs(300))
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
        .route(
            "/mcp-relay/{token}/{route_id}",
            any(handle_mcp_relay_root::<C>),
        )
        .route(
            "/mcp-relay/{token}/{route_id}/{*tail}",
            any(handle_mcp_relay_tail::<C>),
        )
        .layer(DefaultBodyLimit::max(MAX_PROXY_BODY_BYTES))
        .with_state(state)
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
    if state.is_globally_killed() {
        return denial_403(&ProxyError::SessionEgressCut("global-kill-switch".into()));
    }
    let inspected_body = match inspect_and_decompress_request_body(&headers, &body) {
        Ok(b) => b,
        Err(err) => return denial_403(&err),
    };

    let (reg, route) = match state.registry.lock().await.resolve_sr39_route(
        &headers,
        state.listener_port,
        &token,
        &route_id,
        !inspected_body.is_empty(),
    ) {
        Ok(found) => found,
        Err(err) => return denial_403(&err),
    };

    let target_url = match build_upstream_url(&route.base_url, &tail) {
        Ok(url) => url,
        Err(err) => return denial_403(&err),
    };
    let trusted_a2a = state.trusted_a2a_keys.lock().await.clone();
    let attempt = match build_proxy_attempt(ProxyAttemptInput {
        session_id: &reg.session_id,
        agent_name: &reg.agent_name,
        provider: &route.provider,
        route_host: &route.host,
        target_url: &target_url,
        headers: &headers,
        body: &inspected_body,
        trusted_a2a_keys: &trusted_a2a,
    }) {
        Ok(a) => a,
        Err(err) => return denial_403(&err),
    };

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

    execute_pinned_route_request(
        state,
        reg,
        route,
        method,
        target_url,
        headers,
        inspected_body,
    )
    .await
}

pub(crate) async fn execute_pinned_route_request<C: ProxyDecisionClient + 'static>(
    state: Arc<ProxyGatewayState<C>>,
    reg: SessionRegistration,
    route: RouteUpstream,
    method: Method,
    target_url: String,
    inbound_headers: HeaderMap,
    outbound_body: Vec<u8>,
) -> Response {
    let vetted = match resolve_and_vet_target(&route.host, route.port, &state.egress_config).await {
        Ok(v) => v,
        Err(err) => return denial_403(&err),
    };
    let Some(&pinned_addr) = vetted.pinned_addrs.first() else {
        return denial_403(&ProxyError::SsrfDenied(
            "SSRF guard produced empty pinned address list".into(),
        ));
    };

    let mut outbound_headers = copy_safe_outbound_headers(&inbound_headers);
    outbound_headers.insert(
        HeaderName::from_static("accept-encoding"),
        HeaderValue::from_static("identity"),
    );
    if let Err(err) = route.tenant_headers.apply_overwrite(&mut outbound_headers) {
        return denial_403(&err);
    }

    if let Some(cred_id) = route.credential_id.as_deref() {
        let now = match SystemClock::new().now_wall() {
            Ok(t) => t,
            Err(e) => return denial_403(&ProxyError::Transport(format!("clock unavailable: {e}"))),
        };
        let mut creds = state.credentials.lock().await;
        if let Err(err) = creds.inject_for_route(
            &reg,
            cred_id,
            &vetted.host,
            &inbound_headers,
            &mut outbound_headers,
            now,
        ) {
            return denial_403(&err);
        }
    }

    let clean_session = sanitize_untrusted_text(&reg.session_id);
    if let Ok(session_val) = HeaderValue::from_str(&clean_session) {
        outbound_headers.insert(HeaderName::from_static("grdr-session"), session_val);
    }

    if let Some(signer) = state.web_bot_signer.lock().await.as_ref()
        && let Err(err) = signer.sign_outbound_request(
            method.as_str(),
            &target_url,
            &outbound_body,
            &mut outbound_headers,
        )
    {
        return denial_403(&err);
    }

    let (pinned_client, expected_peer) = match state
        .build_pinned_route_client(&vetted.host, pinned_addr)
        .await
    {
        Ok(pair) => pair,
        Err(err) => return denial_403(&err),
    };

    let req_builder = pinned_client
        .request(method, target_url)
        .headers(outbound_headers)
        .body(outbound_body);

    match req_builder.send().await {
        Ok(upstream_resp) => {
            if upstream_resp.remote_addr() != Some(expected_peer) {
                return denial_403(&ProxyError::SsrfDenied(
                    "upstream remote_addr did not match pinned SSRF socket".into(),
                ));
            }
            stream_upstream_response(
                state,
                reg.session_id,
                route.route_id,
                &route.provider,
                upstream_resp,
            )
            .await
        }
        Err(err) => bad_gateway_response(&ProxyError::Transport(err.to_string())),
    }
}
