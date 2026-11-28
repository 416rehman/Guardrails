// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::{self, Read, Write};
use std::net::TcpStream;
use std::sync::Arc;
use std::time::Duration;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::client::{WebPkiServerVerifier, verify_server_cert_signed_by_trust_anchor};
use rustls::crypto::{WebPkiSupportedAlgorithms, verify_tls12_signature, verify_tls13_signature};
use rustls::pki_types::pem::PemObject;
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::server::ParsedCertificate;
use rustls::{
    ClientConfig, ClientConnection, DigitallySignedStruct, Error as RustlsError, RootCertStore,
    SignatureScheme, StreamOwned, SupportedCipherSuite,
};

use grdr_crypto::sha256_digest;
use grdr_model::CodedError;

use crate::config::{CODE_PG_CONFIG, CODE_PG_WIRE, MAX_CA_PEM_BYTES, PostgresSslMode};
use crate::tls_hash::sha512_digest;
use crate::wire_codec::wire_io_err;

const OID_SHA384_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0c];
const OID_SHA512_RSA: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0d];
const OID_ECDSA_SHA384: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x03];
const OID_ECDSA_SHA512: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x04];
const OID_RSASSA_PSS: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0a];
const OID_SHA384_DIGEST: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x02];
const OID_SHA512_DIGEST: &[u8] = &[0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x03];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum TlsVerificationPolicy {
    CaChainOnly,
    FullHostnameAndCa,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum EndPointDigestAlg {
    Sha256,
    Sha384,
    Sha512,
}

#[derive(Debug, Clone)]
pub(crate) struct PostgresTlsContext {
    client_config: Arc<ClientConfig>,
    server_name: ServerName<'static>,
}

#[derive(Debug)]
struct CaOnlyServerCertVerifier {
    roots: Arc<RootCertStore>,
    supported_algs: WebPkiSupportedAlgorithms,
}

#[derive(Debug)]
pub(crate) enum PgStream {
    Plain(TcpStream),
    Tls {
        stream: Box<StreamOwned<ClientConnection, TcpStream>>,
        peer_cert_binding: Option<Vec<u8>>,
    },
}

impl ServerCertVerifier for CaOnlyServerCertVerifier {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, RustlsError> {
        let cert = ParsedCertificate::try_from(end_entity)?;
        verify_server_cert_signed_by_trust_anchor(
            &cert,
            &self.roots,
            intermediates,
            now,
            self.supported_algs.all,
        )?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls12_signature(message, cert, dss, &self.supported_algs)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, RustlsError> {
        verify_tls13_signature(message, cert, dss, &self.supported_algs)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.supported_algs.supported_schemes()
    }
}

impl PostgresTlsContext {
    pub(crate) fn build(
        ssl_mode: PostgresSslMode,
        endpoint: &str,
        ca_cert_pem: Option<&str>,
    ) -> Result<Option<Self>, CodedError> {
        let policy = match ssl_mode {
            PostgresSslMode::Disable => return Ok(None),
            PostgresSslMode::Prefer | PostgresSslMode::VerifyFull => {
                TlsVerificationPolicy::FullHostnameAndCa
            }
            PostgresSslMode::Require | PostgresSslMode::VerifyCa => {
                TlsVerificationPolicy::CaChainOnly
            }
        };

        let host = extract_host_from_endpoint(endpoint)?;
        let server_name = ServerName::try_from(host.to_string()).map_err(|e| {
            CodedError::new(
                CODE_PG_CONFIG,
                format!("Invalid PostgreSQL TLS server name `{host}`: {e}"),
                "Specify a valid DNS hostname or IP address in the PostgreSQL DSN.",
            )
        })?;

        let roots = Arc::new(load_root_store(ca_cert_pem)?);
        let provider = Arc::new(rustls::crypto::aws_lc_rs::default_provider());
        let supported_algs = provider.signature_verification_algorithms;
        let builder = ClientConfig::builder_with_provider(Arc::clone(&provider))
            .with_safe_default_protocol_versions()
            .map_err(|e| {
                CodedError::new(
                    CODE_PG_WIRE,
                    format!("Failed configuring PostgreSQL TLS protocol versions: {e}"),
                    "Verify rustls cryptographic provider initialization.",
                )
            })?;

        let client_config = match policy {
            TlsVerificationPolicy::FullHostnameAndCa => {
                let verifier = WebPkiServerVerifier::builder_with_provider(roots, provider)
                    .build()
                    .map_err(|e| {
                        CodedError::new(
                            CODE_PG_CONFIG,
                            format!("Failed initializing PostgreSQL TLS certificate verifier: {e}"),
                            "Verify system trust anchors or configure sslrootcert.",
                        )
                    })?;
                builder
                    .dangerous()
                    .with_custom_certificate_verifier(verifier)
                    .with_no_client_auth()
            }
            TlsVerificationPolicy::CaChainOnly => builder
                .dangerous()
                .with_custom_certificate_verifier(Arc::new(CaOnlyServerCertVerifier {
                    roots,
                    supported_algs,
                }))
                .with_no_client_auth(),
        };

        Ok(Some(Self {
            client_config: Arc::new(client_config),
            server_name,
        }))
    }
}

impl PgStream {
    pub(crate) fn peer_leaf_cert_binding(&self) -> Option<&[u8]> {
        match self {
            Self::Plain(_) => None,
            Self::Tls {
                peer_cert_binding, ..
            } => peer_cert_binding.as_deref(),
        }
    }

    pub(crate) fn set_timeouts(&mut self, timeout: Duration) -> Result<(), CodedError> {
        let sock = match self {
            Self::Plain(sock) => sock,
            Self::Tls { stream, .. } => &mut stream.sock,
        };
        sock.set_read_timeout(Some(timeout)).map_err(wire_io_err)?;
        sock.set_write_timeout(Some(timeout)).map_err(wire_io_err)?;
        Ok(())
    }

    pub(crate) fn shutdown(&mut self) {
        if let Self::Tls { stream, .. } = self {
            stream.conn.send_close_notify();
            let _ = stream.conn.complete_io(&mut stream.sock);
        }
    }
}

impl Read for PgStream {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        match self {
            Self::Plain(sock) => sock.read(buf),
            Self::Tls { stream, .. } => stream.read(buf),
        }
    }
}

impl Write for PgStream {
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        match self {
            Self::Plain(sock) => sock.write(buf),
            Self::Tls { stream, .. } => stream.write(buf),
        }
    }

    fn flush(&mut self) -> io::Result<()> {
        match self {
            Self::Plain(sock) => sock.flush(),
            Self::Tls { stream, .. } => stream.flush(),
        }
    }
}

pub(crate) fn wrap_tls_stream(
    tcp: TcpStream,
    ctx: &PostgresTlsContext,
) -> Result<PgStream, CodedError> {
    let conn = ClientConnection::new(Arc::clone(&ctx.client_config), ctx.server_name.clone())
        .map_err(|e| {
            CodedError::new(
                CODE_PG_WIRE,
                format!("Failed creating PostgreSQL TLS client session: {e}"),
                "Verify PostgreSQL TLS hostname and CA trust configuration.",
            )
        })?;
    let mut tls_stream = StreamOwned::new(conn, tcp);
    while tls_stream.conn.is_handshaking() {
        tls_stream
            .conn
            .complete_io(&mut tls_stream.sock)
            .map_err(|e| {
                CodedError::new(
                    CODE_PG_WIRE,
                    format!("PostgreSQL TLS handshake failed: {e}"),
                    "Verify server certificate trust chain, SAN hostname, and TLS 1.2/1.3 support.",
                )
            })?;
    }
    let peer_cert_binding = tls_stream
        .conn
        .peer_certificates()
        .and_then(|certs| certs.first())
        .map(|leaf| tls_server_end_point_binding(leaf.as_ref()));
    Ok(PgStream::Tls {
        stream: Box::new(tls_stream),
        peer_cert_binding,
    })
}

pub(crate) fn tls_server_end_point_binding(leaf_der: &[u8]) -> Vec<u8> {
    match detect_cert_endpoint_digest(leaf_der) {
        EndPointDigestAlg::Sha384 => sha384_binding(leaf_der),
        EndPointDigestAlg::Sha512 => sha512_digest(leaf_der).to_vec(),
        EndPointDigestAlg::Sha256 => sha256_digest(leaf_der).to_vec(),
    }
}

fn sha384_binding(input: &[u8]) -> Vec<u8> {
    match rustls::crypto::aws_lc_rs::cipher_suite::TLS13_AES_256_GCM_SHA384 {
        SupportedCipherSuite::Tls13(suite) => {
            suite.common.hash_provider.hash(input).as_ref().to_vec()
        }
        SupportedCipherSuite::Tls12(suite) => {
            suite.common.hash_provider.hash(input).as_ref().to_vec()
        }
    }
}

fn detect_cert_endpoint_digest(leaf_der: &[u8]) -> EndPointDigestAlg {
    let Some((0x30, cert_body, _)) = read_der_tlv(leaf_der) else {
        return EndPointDigestAlg::Sha256;
    };
    let Some((0x30, _tbs, after_tbs)) = read_der_tlv(cert_body) else {
        return EndPointDigestAlg::Sha256;
    };
    let Some((0x30, sig_alg_body, _)) = read_der_tlv(after_tbs) else {
        return EndPointDigestAlg::Sha256;
    };
    let Some((0x06, oid, params)) = read_der_tlv(sig_alg_body) else {
        return EndPointDigestAlg::Sha256;
    };
    if oid == OID_SHA384_RSA || oid == OID_ECDSA_SHA384 {
        return EndPointDigestAlg::Sha384;
    }
    if oid == OID_SHA512_RSA || oid == OID_ECDSA_SHA512 {
        return EndPointDigestAlg::Sha512;
    }
    if oid == OID_RSASSA_PSS {
        return detect_pss_digest(params);
    }
    EndPointDigestAlg::Sha256
}

fn detect_pss_digest(params: &[u8]) -> EndPointDigestAlg {
    let Some((0x30, mut pss_seq, _)) = read_der_tlv(params) else {
        return EndPointDigestAlg::Sha256;
    };
    while let Some((tag, body, rest)) = read_der_tlv(pss_seq) {
        if tag == 0xa0 {
            if let Some((0x30, alg_body, _)) = read_der_tlv(body)
                && let Some((0x06, hash_oid, _)) = read_der_tlv(alg_body)
            {
                if hash_oid == OID_SHA384_DIGEST {
                    return EndPointDigestAlg::Sha384;
                }
                if hash_oid == OID_SHA512_DIGEST {
                    return EndPointDigestAlg::Sha512;
                }
            }
            return EndPointDigestAlg::Sha256;
        }
        pss_seq = rest;
    }
    EndPointDigestAlg::Sha256
}

fn read_der_tlv(input: &[u8]) -> Option<(u8, &[u8], &[u8])> {
    let tag = *input.first()?;
    let len_byte = *input.get(1)?;
    let (len, hdr_len) = if len_byte < 0x80 {
        (usize::from(len_byte), 2usize)
    } else {
        let num_octets = usize::from(len_byte & 0x7f);
        if num_octets == 0 || num_octets > 4 {
            return None;
        }
        let len_end = 2usize.checked_add(num_octets)?;
        let octets = input.get(2..len_end)?;
        let mut len_val = 0usize;
        for &b in octets {
            len_val = (len_val << 8) | usize::from(b);
        }
        (len_val, len_end)
    };
    let end = hdr_len.checked_add(len)?;
    let body = input.get(hdr_len..end)?;
    let rest = input.get(end..).unwrap_or(&[]);
    Some((tag, body, rest))
}

pub(crate) fn validate_ca_pem(pem: &str) -> Result<Vec<CertificateDer<'static>>, CodedError> {
    if pem.len() > MAX_CA_PEM_BYTES {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            format!("PostgreSQL CA PEM bundle exceeds {MAX_CA_PEM_BYTES} byte limit."),
            "Provide a concise PEM CA bundle.",
        ));
    }
    let mut out = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = item.map_err(|e| {
            CodedError::new(
                CODE_PG_CONFIG,
                format!("Invalid PEM certificate in PostgreSQL CA bundle: {e}"),
                "Provide valid X.509 CERTIFICATE blocks in sslrootcert.",
            )
        })?;
        out.push(cert.into_owned());
    }
    if out.is_empty() {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            "PostgreSQL CA PEM bundle contained zero certificates.",
            "Provide at least one PEM-encoded X.509 CA certificate.",
        ));
    }
    Ok(out)
}

fn load_root_store(ca_cert_pem: Option<&str>) -> Result<RootCertStore, CodedError> {
    let mut store = RootCertStore::empty();
    if let Some(pem) = ca_cert_pem {
        let certs = validate_ca_pem(pem)?;
        for cert in certs {
            store.add(cert).map_err(|e| {
                CodedError::new(
                    CODE_PG_CONFIG,
                    format!("Failed adding custom PostgreSQL CA certificate: {e}"),
                    "Verify that sslrootcert contains valid X.509 root certificates.",
                )
            })?;
        }
        return Ok(store);
    }

    let _ =
        store.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = store.add(cert);
    }
    if store.is_empty() {
        return Err(CodedError::new(
            CODE_PG_CONFIG,
            "No TLS root trust anchors available for PostgreSQL.",
            "Configure sslrootcert or install system CA certificates.",
        ));
    }
    Ok(store)
}

fn extract_host_from_endpoint(endpoint: &str) -> Result<&str, CodedError> {
    let trimmed = endpoint.trim();
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
            CODE_PG_CONFIG,
            "PostgreSQL endpoint host cannot be empty.",
            "Provide a valid host:port endpoint.",
        ));
    }
    Ok(trimmed)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_tlv(tag: u8, payload: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(payload.len().saturating_add(4));
        out.push(tag);
        if payload.len() < 128 {
            out.push(u8::try_from(payload.len()).unwrap_or(0));
        } else {
            out.push(0x82);
            let be = u16::try_from(payload.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes();
            out.extend_from_slice(&be);
        }
        out.extend_from_slice(payload);
        out
    }

    fn test_cert_with_sig_alg(sig_alg_inner: &[u8]) -> Vec<u8> {
        let tbs = test_tlv(0x30, &[0x02, 0x01, 0x01]);
        let alg = test_tlv(0x30, sig_alg_inner);
        let sig = test_tlv(0x03, &[0x00, 0xaa]);
        let mut inner = Vec::new();
        inner.extend_from_slice(&tbs);
        inner.extend_from_slice(&alg);
        inner.extend_from_slice(&sig);
        test_tlv(0x30, &inner)
    }

    #[test]
    fn rfc5929_tls_server_end_point_matches_cert_hash_algorithm() {
        let sha384_cert = test_cert_with_sig_alg(&test_tlv(0x06, OID_SHA384_RSA));
        let b384 = tls_server_end_point_binding(&sha384_cert);
        assert_eq!(b384.len(), 48);
        assert_eq!(b384, sha384_binding(&sha384_cert));

        let sha512_cert = test_cert_with_sig_alg(&test_tlv(0x06, OID_ECDSA_SHA512));
        let b512 = tls_server_end_point_binding(&sha512_cert);
        assert_eq!(b512.len(), 64);
        assert_eq!(b512, sha512_digest(&sha512_cert).to_vec());

        let pss_hash_alg = test_tlv(0x30, &test_tlv(0x06, OID_SHA512_DIGEST));
        let pss_ctx0 = test_tlv(0xa0, &pss_hash_alg);
        let pss_params = test_tlv(0x30, &pss_ctx0);
        let mut pss_alg_inner = test_tlv(0x06, OID_RSASSA_PSS);
        pss_alg_inner.extend_from_slice(&pss_params);
        let pss_cert = test_cert_with_sig_alg(&pss_alg_inner);
        assert_eq!(
            tls_server_end_point_binding(&pss_cert),
            sha512_digest(&pss_cert).to_vec()
        );

        let sha1_oid = [0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x05];
        let sha1_cert = test_cert_with_sig_alg(&test_tlv(0x06, &sha1_oid));
        let b256 = tls_server_end_point_binding(&sha1_cert);
        assert_eq!(b256.len(), 32);
        assert_eq!(b256, sha256_digest(&sha1_cert).to_vec());
    }
}
