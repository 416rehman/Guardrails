// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::Arc;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::time::timeout;

use crate::router::ProxyGatewayState;
use crate::tunnel::UpstreamProxyConfig;
use crate::tunnel_io::{
    TUNNEL_HANDSHAKE_TIMEOUT, connect_via_chain, peek_and_verify_initial_tls,
    read_socks5_rfc1929_token, send_tunnel_bytes,
};
use crate::{ProxyDecisionClient, ProxyError};

pub(crate) async fn handle_socks5<C: ProxyDecisionClient + 'static>(
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

    if let Err(err) = crate::tunnel::authorize_and_vet(&state, &reg.session_id, &host, port).await {
        send_tunnel_bytes(&mut client, &[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(err);
    }

    let Ok(mut upstream_stream) =
        connect_via_chain(&host, port, upstream_chain.as_ref(), &state).await
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

    let tls_decision = peek_and_verify_initial_tls(
        &mut client,
        &mut upstream_stream,
        &host,
        port,
        &reg.session_id,
        &state,
    )
    .await?;
    crate::tunnel::enforce_tunnel_tls_decision(&host, tls_decision)?;

    crate::tunnel::bridge_with_egress_cut(client, upstream_stream, &reg.session_id, &state).await
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
    if host.is_empty()
        || port == 0
        || host.chars().any(|c| {
            matches!(c, '@' | '/' | '\\' | '?' | '#') || c.is_whitespace() || c.is_control()
        })
    {
        send_tunnel_bytes(client, &[0x05, 0x02, 0x00, 0x01, 0, 0, 0, 0, 0, 0]).await;
        return Err(ProxyError::Sr39Rejected(
            "SOCKS5 target host or port invalid".into(),
        ));
    }
    Ok((reg, host, port))
}
