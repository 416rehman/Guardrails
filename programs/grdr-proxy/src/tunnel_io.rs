// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded wire framing, RFC 1929 auth parsing, chained CONNECT dialing, and TLS ClientHello peeking.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::{Duration, Instant};

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::egress::{resolve_and_vet_chained_proxy, resolve_and_vet_target};
use crate::router::ProxyGatewayState;
use crate::tls_hello::{expected_tls_record_total_len, peek_tls_client_hello};
use crate::tls_policy::{
    CallerClass, EchPolicy, LocalCaTrust, MitmDenyReason, MitmRoutingDecision, PinningHealth,
    SelectiveMitmInput, SwgOverrideMode, evaluate_selective_mitm_policy,
};
use crate::tunnel::UpstreamProxyConfig;
use crate::{ProxyDecisionClient, ProxyError};

pub const MAX_CONNECT_LINE_BYTES: usize = 4_096;
pub const MAX_CONNECT_HEADERS: usize = 64;
pub const MAX_CHAIN_RESPONSE_HEAD_BYTES: usize = 8_192;
pub const TUNNEL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const TLS_PEEK_CAP_BYTES: usize = 16_384;

pub async fn read_bounded_crlf_line(
    stream: &mut TcpStream,
    max_bytes: usize,
) -> Result<String, ProxyError> {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if buf.len() >= max_bytes {
            return Err(ProxyError::Sr39Rejected(
                "CONNECT header line exceeds bounded byte limit".into(),
            ));
        }
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| ProxyError::Sr39Rejected(format!("CONNECT handshake read error: {e}")))?;
        let [b] = byte;
        buf.push(b);
        if b == b'\n' {
            break;
        }
    }
    String::from_utf8(buf)
        .map_err(|_| ProxyError::Sr39Rejected("invalid UTF-8 in CONNECT header line".into()))
}

pub async fn read_socks5_rfc1929_token(stream: &mut TcpStream) -> Result<String, ProxyError> {
    let mut head = [0_u8; 2];
    stream
        .read_exact(&mut head)
        .await
        .map_err(|e| ProxyError::Sr39Rejected(format!("RFC 1929 header read failed: {e}")))?;
    let [auth_ver, raw_ulen] = head;
    if auth_ver != 0x01 {
        return Err(ProxyError::Sr39Rejected(
            "expected RFC 1929 subnegotiation version 0x01".into(),
        ));
    }
    let ulen = usize::from(raw_ulen);
    let mut uname = vec![0_u8; ulen];
    stream
        .read_exact(&mut uname)
        .await
        .map_err(|e| ProxyError::Sr39Rejected(format!("RFC 1929 username read failed: {e}")))?;

    let mut plen_buf = [0_u8; 1];
    stream
        .read_exact(&mut plen_buf)
        .await
        .map_err(|e| ProxyError::Sr39Rejected(format!("RFC 1929 password length failed: {e}")))?;
    let [raw_plen] = plen_buf;
    let plen = usize::from(raw_plen);
    let mut passwd = vec![0_u8; plen];
    stream
        .read_exact(&mut passwd)
        .await
        .map_err(|e| ProxyError::Sr39Rejected(format!("RFC 1929 password read failed: {e}")))?;

    let raw_bytes = if passwd.is_empty() { uname } else { passwd };
    let text = String::from_utf8(raw_bytes)
        .map_err(|_| ProxyError::Sr39Rejected("RFC 1929 token must be valid UTF-8".into()))?;
    Ok(text.trim().to_owned())
}

pub async fn connect_via_chain<C: ProxyDecisionClient + 'static>(
    target_host: &str,
    target_port: u16,
    chain: Option<&UpstreamProxyConfig>,
    state: &ProxyGatewayState<C>,
) -> Result<TcpStream, ProxyError> {
    if target_host.is_empty()
        || target_port == 0
        || target_host.chars().any(|c| {
            c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '\\' | '?' | '#')
        })
    {
        return Err(ProxyError::Sr39Rejected(
            "target host or port invalid for tunnel".into(),
        ));
    }
    if let Some(proxy) = chain {
        let vetted = resolve_and_vet_chained_proxy(&proxy.host, proxy.port).await?;
        let mut upstream = connect_pinned(&vetted.pinned_addrs).await?;
        let authority = format_authority(target_host, target_port);
        let req = format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n");
        upstream
            .write_all(req.as_bytes())
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        let head = timeout(
            TUNNEL_HANDSHAKE_TIMEOUT,
            read_http_head_exact(&mut upstream, MAX_CHAIN_RESPONSE_HEAD_BYTES),
        )
        .await
        .map_err(|_| ProxyError::Transport("upstream chained proxy CONNECT timed out".into()))??;
        if !is_http_200_status(&head) {
            return Err(ProxyError::Transport(
                "upstream chained proxy refused CONNECT".into(),
            ));
        }
        return Ok(upstream);
    }

    let vetted = resolve_and_vet_target(target_host, target_port, &state.egress_config).await?;
    connect_pinned(&vetted.pinned_addrs).await
}

async fn read_http_head_exact(
    stream: &mut TcpStream,
    max_bytes: usize,
) -> Result<String, ProxyError> {
    let mut buf = Vec::new();
    let mut byte = [0_u8; 1];
    loop {
        if buf.len() >= max_bytes {
            return Err(ProxyError::Transport(
                "upstream chained proxy response header exceeds limit".into(),
            ));
        }
        stream
            .read_exact(&mut byte)
            .await
            .map_err(|e| ProxyError::Transport(e.to_string()))?;
        let [b] = byte;
        buf.push(b);
        if buf.ends_with(b"\r\n\r\n") {
            break;
        }
    }
    String::from_utf8(buf)
        .map_err(|_| ProxyError::Transport("invalid UTF-8 from upstream chained proxy".into()))
}

pub fn is_http_200_status(head: &str) -> bool {
    let Some(status_line) = head.lines().next() else {
        return false;
    };
    let mut parts = status_line.split_ascii_whitespace();
    let Some(proto) = parts.next() else {
        return false;
    };
    let Some(code) = parts.next() else {
        return false;
    };
    (proto.eq_ignore_ascii_case("HTTP/1.1") || proto.eq_ignore_ascii_case("HTTP/1.0"))
        && code == "200"
}

pub async fn connect_pinned(addrs: &[SocketAddr]) -> Result<TcpStream, ProxyError> {
    for addr in addrs {
        if let Ok(stream) = TcpStream::connect(addr).await {
            return Ok(stream);
        }
    }
    Err(ProxyError::Transport(
        "failed to connect to vetted pinned address".into(),
    ))
}

pub async fn send_tunnel_bytes(stream: &mut TcpStream, bytes: &[u8]) {
    if let Err(err) = stream.write_all(bytes).await {
        tracing::debug!(error = %err, "failed to write tunnel status bytes");
    }
}

pub fn parse_host_port(authority: &str) -> Result<(String, u16), ProxyError> {
    let trimmed = authority.trim();
    if trimmed
        .chars()
        .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '\\' | '?' | '#'))
    {
        return Err(ProxyError::Sr39Rejected(
            "CONNECT authority contains disallowed character".into(),
        ));
    }
    if let Some(rest) = trimmed.strip_prefix('[') {
        let Some((ip6, tail)) = rest.split_once("]:") else {
            return Err(ProxyError::Sr39Rejected(
                "IPv6 CONNECT authority requires port".into(),
            ));
        };
        if ip6.parse::<Ipv6Addr>().is_err() {
            return Err(ProxyError::Sr39Rejected(
                "CONNECT authority has invalid IPv6 literal".into(),
            ));
        }
        let port = tail
            .parse::<u16>()
            .map_err(|_| ProxyError::Sr39Rejected("invalid port".into()))?;
        if ip6.is_empty() || port == 0 {
            return Err(ProxyError::Sr39Rejected("empty host or zero port".into()));
        }
        return Ok((ip6.to_owned(), port));
    }
    let Some((host, port_str)) = trimmed.rsplit_once(':') else {
        return Err(ProxyError::Sr39Rejected(
            "CONNECT authority must include :port".into(),
        ));
    };
    let port = port_str
        .parse::<u16>()
        .map_err(|_| ProxyError::Sr39Rejected("invalid port".into()))?;
    if host.is_empty() || port == 0 {
        return Err(ProxyError::Sr39Rejected("empty host or zero port".into()));
    }
    Ok((host.to_owned(), port))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Peeks the complete initial TLS ClientHello record (up to 16 KiB) before bridging,
/// rejecting SNI mismatches, ECH violations, truncated ClientHellos, and un-terminated MITM hosts.
pub async fn peek_and_verify_initial_tls<C: ProxyDecisionClient + 'static>(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    connect_host: &str,
    connect_port: u16,
    session_id: &str,
    state: &ProxyGatewayState<C>,
) -> Result<Option<MitmRoutingDecision>, ProxyError> {
    let mut watch_rx = state.cut_watch.subscribe();
    let deadline = Instant::now()
        .checked_add(TUNNEL_HANDSHAKE_TIMEOUT)
        .unwrap_or_else(Instant::now);
    let mut peek_buf = vec![0_u8; TLS_PEEK_CAP_BYTES];

    loop {
        if state.is_globally_killed() || state.registry.lock().await.is_session_cut(session_id) {
            let _ = client.shutdown().await;
            let _ = upstream.shutdown().await;
            return Err(ProxyError::SessionEgressCut(session_id.to_owned()));
        }
        let rem = deadline
            .checked_duration_since(Instant::now())
            .filter(|d| !d.is_zero())
            .ok_or_else(|| ProxyError::Sr39Rejected("TLS ClientHello peek timed out".into()))?;

        let n = tokio::select! {
            changed = watch_rx.changed() => {
                if changed.is_err()
                    || state.is_globally_killed()
                    || state.registry.lock().await.is_session_cut(session_id)
                {
                    let _ = client.shutdown().await;
                    let _ = upstream.shutdown().await;
                    return Err(ProxyError::SessionEgressCut(session_id.to_owned()));
                }
                continue;
            }
            step = timeout(rem, client.peek(&mut peek_buf)) => {
                let res = step.map_err(|_| {
                    ProxyError::Sr39Rejected("TLS ClientHello peek timed out".into())
                })?;
                res.map_err(|e| ProxyError::Transport(e.to_string()))?
            }
        };

        if n == 0 || peek_buf.first().copied() != Some(0x16) {
            if connect_port == 443 || connect_port == 8443 {
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Err(ProxyError::Sr39Rejected(format!(
                    "GRDR-PROXY-0008: unencrypted non-TLS traffic forbidden on port {connect_port}"
                )));
            }
            let swg = state.swg_detection.lock().await.clone();
            let non_tls_decision = evaluate_selective_mitm_policy(
                &SelectiveMitmInput {
                    connect_host: connect_host.to_owned(),
                    caller_class: CallerClass::ManagedAgent,
                    local_ca_trust: LocalCaTrust::Trusted,
                    pinning_health: PinningHealth::Healthy,
                    ech_policy: EchPolicy::PassthroughOnEch,
                    swg_override: SwgOverrideMode::RespectStandDown,
                    swg,
                    client_hello: None,
                },
                &state.swg_manifest,
            );
            if let MitmRoutingDecision::Deny(_, msg) = non_tls_decision {
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Err(ProxyError::PolicyDenied(msg));
            }
            return Ok(None);
        }
        let slice = peek_buf.get(..n).unwrap_or(&[]);
        let need_more = match expected_tls_record_total_len(slice) {
            Some(total) if total <= TLS_PEEK_CAP_BYTES => n < total,
            None => n < 5,
            Some(_) => false,
        };
        if need_more {
            tokio::time::sleep(Duration::from_millis(5)).await;
            continue;
        }
        let Some(hello) = peek_tls_client_hello(slice)? else {
            return Ok(None);
        };
        let swg = state.swg_detection.lock().await.clone();
        let decision = evaluate_selective_mitm_policy(
            &SelectiveMitmInput {
                connect_host: connect_host.to_owned(),
                caller_class: CallerClass::ManagedAgent,
                local_ca_trust: LocalCaTrust::Trusted,
                pinning_health: PinningHealth::Healthy,
                ech_policy: EchPolicy::PassthroughOnEch,
                swg_override: SwgOverrideMode::RespectStandDown,
                swg,
                client_hello: Some(hello),
            },
            &state.swg_manifest,
        );
        match &decision {
            MitmRoutingDecision::Deny(MitmDenyReason::SniMismatch, msg) => {
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Err(ProxyError::SniMismatch(msg.clone()));
            }
            MitmRoutingDecision::Deny(
                MitmDenyReason::EchBlocked | MitmDenyReason::NonTlsTrafficRequired,
                msg,
            ) => {
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Err(ProxyError::PolicyDenied(msg.clone()));
            }
            MitmRoutingDecision::InterceptTls {
                provider_family,
                alpn_protocols,
                ..
            } => {
                tracing::warn!(
                    session_id,
                    host = connect_host,
                    provider = %provider_family,
                    alpn_count = alpn_protocols.len(),
                    "blocking raw CONNECT passthrough on InterceptTls-required LLM host"
                );
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Ok(Some(decision));
            }
            MitmRoutingDecision::Passthrough(_) => return Ok(Some(decision)),
        }
    }
}
