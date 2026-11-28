// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::Read;
use std::net::{TcpStream, ToSocketAddrs};
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::WebPkiServerVerifier;
use rustls::crypto::aws_lc_rs::default_provider;
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use rustls_platform_verifier::ConfigVerifierExt;

use crate::server_preflight::cert_probes::load_pem_certs_strict;
use crate::server_preflight::probe_types::{
    ErrCodeSlot, ProbeOutcomeKind, RawProbeResult, parse_host_and_optional_port,
};

const TLS_CONNECT_TIMEOUT_MS: u64 = 1_500;
const TLS_READ_TIMEOUT_MS: u64 = 1_500;

fn collect_root_certs(cert_files: &[PathBuf]) -> Result<RootCertStore, String> {
    let mut store = RootCertStore::empty();
    for der in webpki_root_certs::TLS_SERVER_ROOT_CERTS {
        store
            .add(der.clone())
            .map_err(|e| format!("Failed loading built-in root CA certificate: {e}"))?;
    }
    for path in cert_files {
        for der in load_pem_certs_strict(path)? {
            store.add(der).map_err(|e| {
                format!(
                    "Invalid root certificate in `{}` for TLS trust store: {e}",
                    path.display()
                )
            })?;
        }
    }
    if let Ok(ssl_file) = std::env::var("SSL_CERT_FILE")
        && !ssl_file.trim().is_empty()
    {
        let ssl_path = PathBuf::from(ssl_file.trim());
        for der in load_pem_certs_strict(&ssl_path)? {
            store.add(der).map_err(|e| {
                format!(
                    "Invalid root certificate in `{}` for SSL_CERT_FILE trust store: {e}",
                    ssl_path.display()
                )
            })?;
        }
    }
    Ok(store)
}

pub fn build_rustls_client_config(cert_files: &[PathBuf]) -> Result<Arc<ClientConfig>, String> {
    let provider = Arc::new(default_provider());
    let has_custom = !cert_files.is_empty()
        || std::env::var("SSL_CERT_FILE")
            .ok()
            .is_some_and(|v| !v.trim().is_empty());

    let cfg = if !has_custom {
        ClientConfig::with_platform_verifier()
            .map_err(|e| format!("Failed initializing platform TLS verifier: {e}"))?
    } else {
        let store = collect_root_certs(cert_files)?;
        let verifier =
            WebPkiServerVerifier::builder_with_provider(Arc::new(store), provider.clone())
                .build()
                .map_err(|e| format!("Failed building webpki TLS verifier: {e}"))?;
        ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| format!("Failed setting TLS protocol versions: {e}"))?
            .with_webpki_verifier(verifier)
            .with_no_client_auth()
    };
    Ok(Arc::new(cfg))
}

pub fn connect_tls_on_tcp(
    host: &str,
    mut tcp: TcpStream,
    cert_files: &[PathBuf],
) -> Result<StreamOwned<ClientConnection, TcpStream>, String> {
    tcp.set_read_timeout(Some(Duration::from_millis(TLS_READ_TIMEOUT_MS)))
        .map_err(|e| format!("Failed setting TLS read timeout: {e}"))?;
    tcp.set_write_timeout(Some(Duration::from_millis(TLS_READ_TIMEOUT_MS)))
        .map_err(|e| format!("Failed setting TLS write timeout: {e}"))?;
    let cfg = build_rustls_client_config(cert_files)?;
    let sni = ServerName::try_from(host.to_string())
        .map_err(|_| format!("Invalid TLS server name `{host}`."))?;
    let mut conn =
        ClientConnection::new(cfg, sni).map_err(|e| format!("TLS connection setup failed: {e}"))?;
    while conn.is_handshaking() {
        conn.complete_io(&mut tcp)
            .map_err(|e| format!("TLS handshake failed: {e}"))?;
    }
    Ok(StreamOwned::new(conn, tcp))
}

pub fn probe_nats_tls(server_url: &str, cert_files: &[PathBuf]) -> RawProbeResult {
    let Some(authority) = server_url.strip_prefix("tls://") else {
        return RawProbeResult {
            id: "PF-03",
            name: "nats_tls_handshake",
            kind: ProbeOutcomeKind::Fail,
            err_slot: ErrCodeSlot::NatsTcp,
            detail: format!("NATS URL `{server_url}` must use tls:// scheme."),
            remedy: Some("Configure GRDR_NATS_URL=tls://host:4222."),
        };
    };
    let (host, port_opt) = match parse_host_and_optional_port(authority, true) {
        Ok(hp) => hp,
        Err(msg) => {
            return RawProbeResult {
                id: "PF-03",
                name: "nats_tls_handshake",
                kind: ProbeOutcomeKind::Fail,
                err_slot: ErrCodeSlot::NatsTcp,
                detail: msg,
                remedy: None,
            };
        }
    };
    let port = port_opt.unwrap_or(4222);
    let dial_target = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let addrs: Vec<_> = match dial_target.to_socket_addrs() {
        Ok(it) => it.collect(),
        Err(e) => {
            return RawProbeResult {
                id: "PF-03",
                name: "nats_tls_handshake",
                kind: ProbeOutcomeKind::Fail,
                err_slot: ErrCodeSlot::NatsTcp,
                detail: format!("Failed resolving NATS TLS endpoint `{dial_target}`: {e}"),
                remedy: None,
            };
        }
    };
    let timeout = Duration::from_millis(TLS_CONNECT_TIMEOUT_MS);
    let mut last_err = String::from("no addresses");
    for addr in addrs {
        match TcpStream::connect_timeout(&addr, timeout) {
            Ok(tcp) => match connect_tls_on_tcp(&host, tcp, cert_files) {
                Ok(mut tls_stream) => {
                    if let Err(e) = tls_stream
                        .get_mut()
                        .set_read_timeout(Some(Duration::from_millis(250)))
                    {
                        last_err = format!("Failed configuring NATS TLS socket read timeout: {e}");
                        continue;
                    }
                    let mut buf = [0u8; 512];
                    match tls_stream.read(&mut buf) {
                        Ok(0) => {
                            last_err =
                                "NATS peer closed TLS connection immediately after handshake"
                                    .into();
                            continue;
                        }
                        Ok(n) => {
                            let banner = String::from_utf8_lossy(buf.get(..n).unwrap_or(&[]));
                            if banner.starts_with("HTTP/") {
                                last_err =
                                    "Peer responded HTTP instead of NATS TLS protocol".into();
                                continue;
                            }
                        }
                        Err(e)
                            if matches!(
                                e.kind(),
                                std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                            ) => {}
                        Err(e) => {
                            last_err = format!("TLS post-handshake alert: {e}");
                            continue;
                        }
                    }
                    return RawProbeResult {
                        id: "PF-03",
                        name: "nats_tls_handshake",
                        kind: ProbeOutcomeKind::Pass,
                        err_slot: ErrCodeSlot::None,
                        detail: format!(
                            "Verified NATS TLS handshake and certificate chain on `{dial_target}`."
                        ),
                        remedy: None,
                    };
                }
                Err(e) => last_err = e,
            },
            Err(e) => last_err = e.to_string(),
        }
    }
    RawProbeResult {
        id: "PF-03",
        name: "nats_tls_handshake",
        kind: ProbeOutcomeKind::Fail,
        err_slot: ErrCodeSlot::NatsTcp,
        detail: format!("NATS TLS handshake failed on `{dial_target}`: {last_err}"),
        remedy: Some("Verify NATS TLS listener, SANs, and --cert / SSL_CERT_FILE trust chain."),
    }
}
