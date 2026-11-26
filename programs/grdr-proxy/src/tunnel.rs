// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Authenticated CONNECT and SOCKS5 tunnel listener supporting upstream
//! `HTTP_PROXY` chaining, SSRF vetting, daemon authorization, TLS peek enforcement, and D-30 cut.

use std::collections::BTreeMap;
use std::sync::Arc;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource, Verdict};
use grdr_os_clock::{Clock, SystemClock};
use tokio::io::AsyncWriteExt;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

use crate::egress::resolve_and_vet_target;
use crate::router::ProxyGatewayState;
use crate::tls_policy::MitmRoutingDecision;
use crate::tunnel_io::{
    MAX_CONNECT_HEADERS, MAX_CONNECT_LINE_BYTES, TUNNEL_HANDSHAKE_TIMEOUT, connect_via_chain,
    parse_host_port, peek_and_verify_initial_tls, read_bounded_crlf_line, send_tunnel_bytes,
};
use crate::tunnel_socks::handle_socks5;
use crate::{ProxyDecisionClient, ProxyError};

const MAX_CONCURRENT_TUNNELS: usize = 256;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpstreamProxyConfig {
    pub host: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TunnelTarget {
    ConnectHttp {
        host: String,
        port: u16,
        session_id: String,
    },
    Socks5 {
        host: String,
        port: u16,
        session_id: String,
    },
}

struct ParsedConnectHead {
    host: String,
    port: u16,
    presented_token: String,
}

impl UpstreamProxyConfig {
    /// Parses `HTTPS_PROXY` or `HTTP_PROXY` environment variables for proxy chaining (D-16).
    /// Rejects credentialed proxy URLs and non-HTTP schemes that would silently downgrade TLS.
    #[must_use]
    pub fn from_env_map(env_vars: &BTreeMap<String, String>) -> Option<Self> {
        Self::try_from_env_map(env_vars).ok().flatten()
    }

    pub fn try_from_env_map(
        env_vars: &BTreeMap<String, String>,
    ) -> Result<Option<Self>, ProxyError> {
        let Some(raw) = env_vars
            .get("HTTPS_PROXY")
            .or_else(|| env_vars.get("https_proxy"))
            .or_else(|| env_vars.get("HTTP_PROXY"))
            .or_else(|| env_vars.get("http_proxy"))
            .map(String::as_str)
            .map(str::trim)
            .filter(|s| !s.is_empty())
        else {
            return Ok(None);
        };
        let parsed = Url::parse(raw)
            .map_err(|e| ProxyError::Sr39Rejected(format!("invalid upstream proxy URL: {e}")))?;
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return Err(ProxyError::Sr39Rejected(
                "chained proxy URL must not embed credentials".into(),
            ));
        }
        if parsed.scheme() != "http" {
            return Err(ProxyError::Sr39Rejected(format!(
                "chained proxy scheme `{}` unsupported without TLS tunnel wrapper",
                parsed.scheme()
            )));
        }
        let raw_host = parsed
            .host_str()
            .ok_or_else(|| ProxyError::Sr39Rejected("chained proxy missing host".into()))?;
        let host = raw_host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_owned();
        let port = parsed
            .port_or_known_default()
            .ok_or_else(|| ProxyError::Sr39Rejected("chained proxy missing port".into()))?;
        if host.is_empty() || port == 0 {
            return Err(ProxyError::Sr39Rejected(
                "chained proxy host or port invalid".into(),
            ));
        }
        Ok(Some(Self { host, port }))
    }
}

pub async fn run_tunnel_listener<C: ProxyDecisionClient + 'static>(
    listener: TcpListener,
    state: Arc<ProxyGatewayState<C>>,
    upstream_chain: Option<UpstreamProxyConfig>,
) -> Result<(), ProxyError> {
    let sem = Arc::new(Semaphore::new(MAX_CONCURRENT_TUNNELS));
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        let Ok(permit) = Arc::clone(&sem).acquire_owned().await else {
            return Err(ProxyError::Transport("tunnel semaphore closed".into()));
        };
        let state_clone = Arc::clone(&state);
        let chain_clone = upstream_chain.clone();
        tokio::spawn(async move {
            let _permit = permit;
            if let Err(err) = handle_tunnel_connection(stream, state_clone, chain_clone).await {
                tracing::debug!(error = %err, "tunnel connection closed");
            }
        });
    }
}

pub async fn handle_tunnel_connection<C: ProxyDecisionClient + 'static>(
    client: TcpStream,
    state: Arc<ProxyGatewayState<C>>,
    upstream_chain: Option<UpstreamProxyConfig>,
) -> Result<(), ProxyError> {
    let mut first = [0_u8; 1];
    timeout(TUNNEL_HANDSHAKE_TIMEOUT, client.peek(&mut first))
        .await
        .map_err(|_| ProxyError::Sr39Rejected("tunnel protocol peek timed out".into()))?
        .map_err(|e| ProxyError::Transport(e.to_string()))?;

    if first == [0x05] {
        handle_socks5(client, state, upstream_chain).await
    } else {
        handle_http_connect(client, state, upstream_chain).await
    }
}

async fn handle_http_connect<C: ProxyDecisionClient + 'static>(
    mut client: TcpStream,
    state: Arc<ProxyGatewayState<C>>,
    upstream_chain: Option<UpstreamProxyConfig>,
) -> Result<(), ProxyError> {
    let parsed = match timeout(TUNNEL_HANDSHAKE_TIMEOUT, read_connect_head(&mut client)).await {
        Ok(Ok(head)) => head,
        Ok(Err(err)) => {
            if err.to_string().contains("CONNECT or SOCKS5") {
                send_tunnel_bytes(
                    &mut client,
                    b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            } else {
                send_tunnel_bytes(
                    &mut client,
                    b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
            }
            return Err(err);
        }
        Err(_) => {
            send_tunnel_bytes(
                &mut client,
                b"HTTP/1.1 408 Request Timeout\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            return Err(ProxyError::Sr39Rejected(
                "CONNECT handshake timed out".into(),
            ));
        }
    };

    let reg = match state
        .registry
        .lock()
        .await
        .verify_tunnel_token(&parsed.presented_token)
    {
        Ok(reg) => reg,
        Err(err) => {
            send_tunnel_bytes(
                &mut client,
                b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
            )
            .await;
            return Err(err);
        }
    };

    if let Err(err) = authorize_and_vet(&state, &reg.session_id, &parsed.host, parsed.port).await {
        send_tunnel_bytes(
            &mut client,
            b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        return Err(err);
    }

    let Ok(mut upstream_stream) =
        connect_via_chain(&parsed.host, parsed.port, upstream_chain.as_ref(), &state).await
    else {
        send_tunnel_bytes(
            &mut client,
            b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 0\r\n\r\n",
        )
        .await;
        return Err(ProxyError::Transport(
            "upstream tunnel connect failed".into(),
        ));
    };

    client
        .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;

    let tls_decision = peek_and_verify_initial_tls(
        &mut client,
        &mut upstream_stream,
        &parsed.host,
        parsed.port,
        &reg.session_id,
        &state,
    )
    .await?;
    enforce_tunnel_tls_decision(&parsed.host, tls_decision)?;

    bridge_with_egress_cut(client, upstream_stream, &reg.session_id, &state).await
}

pub(crate) fn enforce_tunnel_tls_decision(
    host: &str,
    decision: Option<MitmRoutingDecision>,
) -> Result<(), ProxyError> {
    if let Some(MitmRoutingDecision::InterceptTls {
        provider_family,
        sni_host,
        ..
    }) = decision
    {
        return Err(ProxyError::PolicyDenied(format!(
            "GRDR-PROXY-0003: TLS interception required for {provider_family} ({}); raw CONNECT passthrough forbidden",
            sni_host.as_deref().unwrap_or(host)
        )));
    }
    Ok(())
}

async fn read_connect_head(client: &mut TcpStream) -> Result<ParsedConnectHead, ProxyError> {
    let request_line = read_bounded_crlf_line(client, MAX_CONNECT_LINE_BYTES).await?;
    let mut parts = request_line.split_whitespace();
    let Some(method) = parts.next() else {
        return Err(ProxyError::Sr39Rejected("missing HTTP method".into()));
    };
    let Some(authority) = parts.next() else {
        return Err(ProxyError::Sr39Rejected("missing CONNECT authority".into()));
    };
    let Some(version) = parts.next() else {
        return Err(ProxyError::Sr39Rejected(
            "missing CONNECT HTTP version".into(),
        ));
    };
    if parts.next().is_some()
        || !(version.eq_ignore_ascii_case("HTTP/1.1") || version.eq_ignore_ascii_case("HTTP/1.0"))
    {
        return Err(ProxyError::Sr39Rejected(
            "malformed CONNECT request-line version or trailing tokens".into(),
        ));
    }
    if !method.eq_ignore_ascii_case("CONNECT") {
        return Err(ProxyError::Sr39Rejected(
            "tunnel port supports CONNECT or SOCKS5 only".into(),
        ));
    }
    let (host, port) = parse_host_port(authority)?;

    let mut presented_token: Option<String> = None;
    let mut header_count: usize = 0;
    loop {
        header_count = header_count
            .checked_add(1)
            .ok_or_else(|| ProxyError::Sr39Rejected("CONNECT header count overflow".into()))?;
        if header_count > MAX_CONNECT_HEADERS {
            return Err(ProxyError::Sr39Rejected(
                "CONNECT request exceeded maximum header count".into(),
            ));
        }
        let hdr_line = read_bounded_crlf_line(client, MAX_CONNECT_LINE_BYTES).await?;
        let trimmed = hdr_line.trim();
        if trimmed.is_empty() {
            break;
        }
        let Some((name_raw, val_raw)) = trimmed.split_once(':') else {
            return Err(ProxyError::Sr39Rejected("malformed CONNECT header".into()));
        };
        let name = name_raw.trim();
        let val = val_raw.trim();
        if name.eq_ignore_ascii_case("host") {
            let (hdr_host, hdr_port) = parse_host_port(val)?;
            if !hdr_host.eq_ignore_ascii_case(&host) || hdr_port != port {
                return Err(ProxyError::Sr39Rejected(
                    "CONNECT Host header conflicts with request target".into(),
                ));
            }
        } else if name.eq_ignore_ascii_case("x-grdr-instance-token") {
            record_connect_token(&mut presented_token, val)?;
        } else if name.eq_ignore_ascii_case("proxy-authorization")
            && let Some(bearer) = strip_bearer_prefix(val)
        {
            record_connect_token(&mut presented_token, bearer)?;
        }
    }

    let token = presented_token
        .filter(|t| !t.is_empty())
        .ok_or_else(|| ProxyError::Sr39Rejected("CONNECT requires instance_token".into()))?;
    Ok(ParsedConnectHead {
        host,
        port,
        presented_token: token,
    })
}

fn strip_bearer_prefix(value: &str) -> Option<&str> {
    let mut parts = value.splitn(2, char::is_whitespace);
    let scheme = parts.next()?;
    let rest = parts.next()?.trim();
    if scheme.eq_ignore_ascii_case("Bearer") && !rest.is_empty() {
        Some(rest)
    } else {
        None
    }
}

fn record_connect_token(slot: &mut Option<String>, candidate: &str) -> Result<(), ProxyError> {
    if slot.is_some() {
        return Err(ProxyError::Sr39Rejected(
            "duplicate tunnel authentication headers rejected".into(),
        ));
    }
    *slot = Some(candidate.to_owned());
    Ok(())
}

pub(crate) async fn authorize_and_vet<C: ProxyDecisionClient + 'static>(
    state: &ProxyGatewayState<C>,
    session_id: &str,
    host: &str,
    port: u16,
) -> Result<(), ProxyError> {
    if state.is_globally_killed() || state.registry.lock().await.is_session_cut(session_id) {
        return Err(ProxyError::SessionEgressCut(session_id.to_owned()));
    }
    resolve_and_vet_target(host, port, &state.egress_config).await?;
    let now = SystemClock::new()
        .now_wall()
        .map_err(|e| ProxyError::Transport(format!("wall clock unavailable: {e}")))?;
    let attempt = ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: session_id.to_owned(),
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: "proxy-tunnel".into(),
        action_class: ActionClass::NetConnect,
        control_point: ControlPoint::Proxy,
        target: format!("{host}:{port}"),
        summary: format!("CONNECT/SOCKS5 tunnel to {host}:{port}"),
        timestamp: now,
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    };
    let receipt = state.decision_client.decide(&attempt).await?;
    if receipt.verdict != Verdict::Allow {
        return Err(ProxyError::PolicyDenied(receipt.reason));
    }
    Ok(())
}

pub(crate) async fn bridge_with_egress_cut<C: ProxyDecisionClient + 'static>(
    mut client: TcpStream,
    mut upstream: TcpStream,
    session_id: &str,
    state: &ProxyGatewayState<C>,
) -> Result<(), ProxyError> {
    let mut watch_rx = state.cut_watch.subscribe();
    let session_owned = session_id.to_owned();
    tokio::select! {
        res = tokio::io::copy_bidirectional(&mut client, &mut upstream) => {
            res.map(|_| ()).map_err(|e| ProxyError::Transport(e.to_string()))
        }
        _ = async {
            loop {
                if state.is_globally_killed()
                    || state.registry.lock().await.is_session_cut(&session_owned)
                {
                    break;
                }
                if watch_rx.changed().await.is_err() {
                    break;
                }
            }
        } => {
            if let Err(err) = client.shutdown().await {
                tracing::debug!(error = %err, "client shutdown error on egress cut");
            }
            if let Err(err) = upstream.shutdown().await {
                tracing::debug!(error = %err, "upstream shutdown error on egress cut");
            }
            Err(ProxyError::SessionEgressCut(session_owned))
        }
    }
}
