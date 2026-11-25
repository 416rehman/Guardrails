// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Bounded wire framing, RFC 1929 auth parsing, and chained CONNECT dialing for `grdr-proxy`.

use std::net::{Ipv6Addr, SocketAddr};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::egress::{resolve_and_vet_chained_proxy, resolve_and_vet_target};
use crate::router::ProxyGatewayState;
use crate::tunnel::UpstreamProxyConfig;
use crate::{ProxyDecisionClient, ProxyError};

pub const MAX_CONNECT_LINE_BYTES: usize = 4_096;
pub const MAX_CONNECT_HEADERS: usize = 64;
pub const MAX_CHAIN_RESPONSE_HEAD_BYTES: usize = 8_192;
pub const TUNNEL_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

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
