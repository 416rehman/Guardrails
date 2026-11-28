// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;

use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName};
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};

use grdr_model::CodedError;

use crate::config::{CODE_NATS_CONFIG, CODE_NATS_WIRE};

#[derive(Debug)]
pub(crate) enum NatsStream {
    Plain(TcpStream),
    Tls(Box<StreamOwned<ClientConnection, TcpStream>>),
    Closed,
}

#[derive(Debug, Clone)]
pub(crate) struct NatsTlsContext {
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

impl NatsStream {
    pub(crate) fn is_tls(&self) -> bool {
        matches!(self, Self::Tls(_))
    }

    pub(crate) fn shutdown(&mut self) {
        if let Self::Tls(stream) = self {
            stream.conn.send_close_notify();
            let _ = stream.conn.complete_io(&mut stream.sock);
        }
    }
}

impl Read for NatsStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(sock) => sock.read(buf),
            Self::Tls(stream) => stream.read(buf),
            Self::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed")),
        }
    }
}

impl Write for NatsStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(sock) => sock.write(buf),
            Self::Tls(stream) => stream.write(buf),
            Self::Closed => Err(io::Error::new(io::ErrorKind::NotConnected, "stream closed")),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(sock) => sock.flush(),
            Self::Tls(stream) => stream.flush(),
            Self::Closed => Ok(()),
        }
    }
}

impl NatsTlsContext {
    pub(crate) fn build(hostport: &str, ca_cert_pem: Option<&str>) -> Result<Self, CodedError> {
        let host = extract_host(hostport)?;
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
            CodedError::new(
                CODE_NATS_CONFIG,
                format!("Invalid NATS TLS hostname `{host}`: {e}"),
                "Provide a valid hostname or IP address in the NATS server URL.",
            )
        })?;
        let roots = load_root_store(ca_cert_pem)?;
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let client_config = ClientConfig::builder_with_provider(provider)
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                CodedError::new(
                    CODE_NATS_WIRE,
                    format!("Failed initializing NATS TLS protocol versions: {e}"),
                    "Check rustls cryptographic provider.",
                )
            })?
            .with_root_certificates(roots)
            .with_no_client_auth();
        Ok(Self {
            client_config: Arc::new(client_config),
            server_name,
        })
    }
}

pub(crate) fn wrap_nats_tls(
    tcp: TcpStream,
    ctx: &NatsTlsContext,
) -> Result<NatsStream, CodedError> {
    let conn = ClientConnection::new(Arc::clone(&ctx.client_config), ctx.server_name.clone())
        .map_err(|e| {
            CodedError::new(
                CODE_NATS_WIRE,
                format!("Failed creating NATS TLS client session: {e}"),
                "Verify NATS TLS server name and trust anchors.",
            )
        })?;
    let mut tls_stream = StreamOwned::new(conn, tcp);
    while tls_stream.conn.is_handshaking() {
        tls_stream
            .conn
            .complete_io(&mut tls_stream.sock)
            .map_err(|e| {
                CodedError::new(
                    CODE_NATS_WIRE,
                    format!("NATS TLS handshake failed: {e}"),
                    "Verify NATS server certificate trust chain, SAN hostname, and TLS 1.2/1.3.",
                )
            })?;
    }
    Ok(NatsStream::Tls(Box::new(tls_stream)))
}

pub(crate) fn validate_ca_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, CodedError> {
    let mut certs = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = item.map_err(|e| {
            CodedError::new(
                CODE_NATS_CONFIG,
                format!("Invalid PEM certificate in NATS CA bundle: {e}"),
                "Provide valid PEM-encoded X.509 CA certificates.",
            )
        })?;
        certs.push(cert.into_owned());
    }
    if certs.is_empty() {
        return Err(CodedError::new(
            CODE_NATS_CONFIG,
            "NATS CA PEM bundle contained zero certificates.",
            "Provide at least one PEM CA certificate.",
        ));
    }
    Ok(certs)
}

fn load_root_store(ca_cert_pem: Option<&str>) -> Result<RootCertStore, CodedError> {
    let mut store = RootCertStore::empty();
    if let Some(pem) = ca_cert_pem {
        for cert in validate_ca_pem(pem)? {
            store.add(cert).map_err(|e| {
                CodedError::new(
                    CODE_NATS_CONFIG,
                    format!("Failed adding custom NATS CA certificate: {e}"),
                    "Verify NATS CA PEM certificate encoding.",
                )
            })?;
        }
        return Ok(store);
    }

    let _ =
        store.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    for cert in rustls_native_certs::load_native_certs().certs {
        let _ = store.add(cert);
    }
    if store.is_empty() {
        return Err(CodedError::new(
            CODE_NATS_CONFIG,
            "No TLS root trust anchors available for NATS connection.",
            "Configure tls_ca_pem or install system CA certificates.",
        ));
    }
    Ok(store)
}

fn extract_host(hostport: &str) -> Result<&str, CodedError> {
    let trimmed = hostport.trim();
    if let Some(after_open) = trimmed.strip_prefix('[')
        && let Some((host, _)) = after_open.split_once(']')
        && !host.is_empty()
    {
        return Ok(host);
    }
    if let Some((host, _port)) = trimmed.rsplit_once(':')
        && !host.is_empty()
    {
        return Ok(host);
    }
    if trimmed.is_empty() {
        return Err(CodedError::new(
            CODE_NATS_CONFIG,
            "NATS TLS endpoint host cannot be empty.",
            "Provide a valid host:port NATS endpoint.",
        ));
    }
    Ok(trimmed)
}
