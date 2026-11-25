// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Authenticated CONNECT and SOCKS5 tunnel listener supporting upstream
//! `HTTP_PROXY`/`HTTPS_PROXY` chaining, SSRF vetting, daemon authorization, and D-30 cut.

use std::collections::BTreeMap;
use std::sync::Arc;

use jiff::Timestamp;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;
use url::Url;
use uuid::Uuid;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource, Verdict};

use crate::egress::resolve_and_vet_target;
use crate::router::ProxyGatewayState;
use crate::tunnel_io::{
    MAX_CONNECT_HEADERS, MAX_CONNECT_LINE_BYTES, TUNNEL_HANDSHAKE_TIMEOUT, connect_via_chain,
    parse_host_port, read_bounded_crlf_line, read_socks5_rfc1929_token, send_tunnel_bytes,
};
use crate::{ProxyDecisionClient, ProxyError};

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
    /// Parses `HTTPS_PROXY` or `HTTP_PROXY` environment variables for proxy chaining (D-16)
    /// without mutating host OS proxy settings.
    #[must_use]
    pub fn from_env_map(env_vars: &BTreeMap<String, String>) -> Option<Self> {
        let raw = env_vars
            .get("HTTPS_PROXY")
            .or_else(|| env_vars.get("https_proxy"))
            .or_else(|| env_vars.get("HTTP_PROXY"))
            .or_else(|| env_vars.get("http_proxy"))?
            .trim();
        if raw.is_empty() {
            return None;
        }
        let parsed = Url::parse(raw).ok()?;
        let host = parsed.host_str()?.to_owned();
        let port = parsed.port_or_known_default()?;
        if host.is_empty() || port == 0 {
            return None;
        }
        Some(Self { host, port })
    }
}

pub async fn run_tunnel_listener<C: ProxyDecisionClient + 'static>(
    listener: TcpListener,
    state: Arc<ProxyGatewayState<C>>,
    upstream_chain: Option<UpstreamProxyConfig>,
) -> Result<(), ProxyError> {
    loop {
        let (stream, _) = listener
            .accept()
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        let state_clone = Arc::clone(&state);
        let chain_clone = upstream_chain.clone();
        tokio::spawn(async move {
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

    let Ok(upstream_stream) =
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

    bridge_with_egress_cut(client, upstream_stream, &reg.session_id, &state).await
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

async fn handle_socks5<C: ProxyDecisionClient + 'static>(
    mut client: TcpStream,
    state: Arc<ProxyGatewayState<C>>,
    upstream_chain: Option<UpstreamProxyConfig>,
) -> Result<(), ProxyError> {
    let (reg, host, port) = timeout(
        TUNNEL_HANDSHAKE_TIMEOUT,
        socks5_handshake(&mut client, &state),
    )
    .await
    .map_err(|_| ProxyError::Sr39Rejected("SOCKS5 handshake timed out".into()))??;

    if let Err(err) = authorize_and_vet(&state, &reg.session_id, &host, port).await {
        send_tunnel_bytes(&mut client, &[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(err);
    }

    let Ok(upstream_stream) = connect_via_chain(&host, port, upstream_chain.as_ref(), &state).await
    else {
        send_tunnel_bytes(&mut client, &[0x05, 0x05, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(ProxyError::Transport(
            "upstream SOCKS5 connect failed".into(),
        ));
    };

    client
        .write_all(&[0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;

    bridge_with_egress_cut(client, upstream_stream, &reg.session_id, &state).await
}

async fn socks5_handshake<C: ProxyDecisionClient + 'static>(
    client: &mut TcpStream,
    state: &ProxyGatewayState<C>,
) -> Result<(crate::sr39::SessionRegistration, String, u16), ProxyError> {
    let mut greeting = [0_u8; 2];
    client
        .read_exact(&mut greeting)
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;
    let [greet_ver, raw_n_methods] = greeting;
    if greet_ver != 0x05 || raw_n_methods == 0 {
        return Err(ProxyError::Sr39Rejected(
            "expected valid SOCKS5 greeting".into(),
        ));
    }
    let n_methods = usize::from(raw_n_methods);
    let mut methods = vec![0_u8; n_methods];
    client
        .read_exact(&mut methods)
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;
    if !methods.contains(&0x02) {
        send_tunnel_bytes(client, &[0x05, 0xff]).await;
        return Err(ProxyError::Sr39Rejected(
            "SOCKS5 requires RFC 1929 token authentication (0x02)".into(),
        ));
    }
    client
        .write_all(&[0x05, 0x02])
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;

    let token = read_socks5_rfc1929_token(client).await?;
    let reg = match state.registry.lock().await.verify_tunnel_token(&token) {
        Ok(reg) => {
            client
                .write_all(&[0x01, 0x00])
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            reg
        }
        Err(err) => {
            send_tunnel_bytes(client, &[0x01, 0x01]).await;
            return Err(err);
        }
    };

    let mut req_head = [0_u8; 4];
    client
        .read_exact(&mut req_head)
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;
    let [req_ver, req_cmd, _rsv, req_atyp] = req_head;
    if req_ver != 0x05 || req_cmd != 0x01 {
        send_tunnel_bytes(client, &[0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(ProxyError::Sr39Rejected(
            "SOCKS5 supports CONNECT (0x01) command only".into(),
        ));
    }

    let host = match req_atyp {
        0x01 => {
            let mut ip = [0_u8; 4];
            client
                .read_exact(&mut ip)
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            std::net::Ipv4Addr::from(ip).to_string()
        }
        0x03 => {
            let mut len_b = [0_u8; 1];
            client
                .read_exact(&mut len_b)
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            let [domain_len_u8] = len_b;
            let domain_len = usize::from(domain_len_u8);
            let mut domain = vec![0_u8; domain_len];
            client
                .read_exact(&mut domain)
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            String::from_utf8(domain)
                .map_err(|_| ProxyError::Sr39Rejected("invalid UTF-8 SOCKS5 host".into()))?
        }
        0x04 => {
            let mut ip = [0_u8; 16];
            client
                .read_exact(&mut ip)
                .await
                .map_err(|e| ProxyError::Transport(e.to_string()))?;
            std::net::Ipv6Addr::from(ip).to_string()
        }
        _ => {
            send_tunnel_bytes(client, &[0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
            return Err(ProxyError::Sr39Rejected(
                "unsupported SOCKS5 address type".into(),
            ));
        }
    };

    let mut port_bytes = [0_u8; 2];
    client
        .read_exact(&mut port_bytes)
        .await
        .map_err(|e| ProxyError::Transport(e.to_string()))?;
    let port = u16::from_be_bytes(port_bytes);
    if host.is_empty() || port == 0 {
        send_tunnel_bytes(client, &[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(ProxyError::Sr39Rejected(
            "SOCKS5 target host or port invalid".into(),
        ));
    }
    Ok((reg, host, port))
}

async fn authorize_and_vet<C: ProxyDecisionClient + 'static>(
    state: &ProxyGatewayState<C>,
    session_id: &str,
    host: &str,
    port: u16,
) -> Result<(), ProxyError> {
    if state.registry.lock().await.is_session_cut(session_id) {
        return Err(ProxyError::SessionEgressCut(session_id.to_owned()));
    }
    resolve_and_vet_target(host, port, &state.egress_config).await?;
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
        timestamp: Timestamp::now(),
        provenance: ProvenanceSource::Mediated,
        ..Default::default()
    };
    let receipt = state.decision_client.decide(&attempt).await?;
    if receipt.verdict != Verdict::Allow {
        return Err(ProxyError::PolicyDenied(receipt.reason));
    }
    Ok(())
}

async fn bridge_with_egress_cut<C: ProxyDecisionClient + 'static>(
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
                if state.registry.lock().await.is_session_cut(&session_owned) {
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
