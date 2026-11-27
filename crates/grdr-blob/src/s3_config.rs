// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;
use std::net::IpAddr;

use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use url::Url;
use zeroize::Zeroizing;

use grdr_model::CodedError;
use grdr_ports::{CODE_BLOB_INVALID_PATH, CODE_BLOB_IO};

const MAX_BUCKET_LEN: usize = 63;
const MIN_BUCKET_LEN: usize = 3;
const MAX_CA_PEM_BYTES: usize = 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum S3AddressingStyle {
    #[default]
    PathStyle,
    VirtualHosted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum S3TransportSecurity {
    #[default]
    RequireTls,
    AllowInsecureLoopbackHttp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum S3LifecycleMode {
    #[default]
    BucketManaged,
    ServerManaged,
}

#[derive(Clone, PartialEq, Eq)]
pub struct S3Credentials {
    pub access_key_id: String,
    pub secret_access_key: Zeroizing<String>,
    pub session_token: Option<Zeroizing<String>>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct S3BlobConfig {
    pub endpoint: String,
    pub bucket: String,
    pub region: String,
    pub key_prefix: Option<String>,
    pub addressing: S3AddressingStyle,
    pub security: S3TransportSecurity,
    pub lifecycle_mode: S3LifecycleMode,
    pub credentials: S3Credentials,
    pub ca_cert_pem: Option<String>,
    pub connect_timeout_ms: u64,
    pub request_timeout_ms: u64,
}

impl fmt::Debug for S3Credentials {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("S3Credentials")
            .field("access_key_id", &self.access_key_id)
            .field("secret_access_key", &"[REDACTED]")
            .field(
                "session_token",
                &self.session_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

impl S3Credentials {
    pub fn new(access_key_id: impl Into<String>, secret_access_key: impl Into<String>) -> Self {
        Self {
            access_key_id: access_key_id.into(),
            secret_access_key: Zeroizing::new(secret_access_key.into()),
            session_token: None,
        }
    }

    pub fn with_session_token(mut self, token: impl Into<String>) -> Self {
        self.session_token = Some(Zeroizing::new(token.into()));
        self
    }
}

impl S3BlobConfig {
    pub fn new(
        endpoint: impl Into<String>,
        bucket: impl Into<String>,
        region: impl Into<String>,
        credentials: S3Credentials,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            bucket: bucket.into(),
            region: region.into(),
            key_prefix: None,
            addressing: S3AddressingStyle::PathStyle,
            security: S3TransportSecurity::RequireTls,
            lifecycle_mode: S3LifecycleMode::BucketManaged,
            credentials,
            ca_cert_pem: None,
            connect_timeout_ms: 5_000,
            request_timeout_ms: 30_000,
        }
    }

    pub fn with_addressing(mut self, addressing: S3AddressingStyle) -> Self {
        self.addressing = addressing;
        self
    }

    pub fn with_key_prefix(mut self, prefix: impl Into<String>) -> Self {
        self.key_prefix = Some(prefix.into());
        self
    }

    pub fn with_ca_cert_pem(mut self, pem: impl Into<String>) -> Self {
        self.ca_cert_pem = Some(pem.into());
        self
    }

    pub fn with_allow_insecure_loopback_http(mut self) -> Self {
        self.security = S3TransportSecurity::AllowInsecureLoopbackHttp;
        self
    }

    pub fn with_lifecycle_mode(mut self, mode: S3LifecycleMode) -> Self {
        self.lifecycle_mode = mode;
        self
    }

    pub fn with_timeouts_ms(mut self, connect_ms: u64, request_ms: u64) -> Self {
        self.connect_timeout_ms = connect_ms.max(100);
        self.request_timeout_ms = request_ms.max(100);
        self
    }

    pub fn validate(&self) -> Result<(), CodedError> {
        let parsed = Url::parse(self.endpoint.trim()).map_err(|e| {
            CodedError::new(
                CODE_BLOB_INVALID_PATH,
                format!("Invalid S3 endpoint URL `{}`: {e}", self.endpoint),
                "Provide a valid https:// S3 endpoint URL.",
            )
        })?;
        match parsed.scheme() {
            "https" => {}
            "http" => {
                if self.security != S3TransportSecurity::AllowInsecureLoopbackHttp {
                    return Err(CodedError::new(
                        CODE_BLOB_IO,
                        "Refusing unencrypted http:// S3 endpoint when TLS is required.",
                        "Use an https:// S3 endpoint.",
                    ));
                }
                let host = parsed.host_str().unwrap_or("");
                if !is_loopback_host(host) {
                    return Err(CodedError::new(
                        CODE_BLOB_IO,
                        format!(
                            "Refusing unencrypted http:// S3 endpoint on non-loopback host `{host}`."
                        ),
                        "Plaintext S3 HTTP is permitted only on loopback addresses for local tests.",
                    ));
                }
            }
            other => {
                return Err(CodedError::new(
                    CODE_BLOB_INVALID_PATH,
                    format!("Unsupported S3 endpoint URL scheme `{other}`."),
                    "Use https:// (or http:// on loopback only).",
                ));
            }
        }
        if parsed.host_str().is_none_or(str::is_empty) {
            return Err(CodedError::new(
                CODE_BLOB_INVALID_PATH,
                "S3 endpoint URL must include a hostname.",
                "Specify a valid S3 hostname.",
            ));
        }
        if !parsed.username().is_empty()
            || parsed.password().is_some()
            || parsed.query().is_some()
            || parsed.fragment().is_some()
        {
            return Err(CodedError::new(
                CODE_BLOB_INVALID_PATH,
                "S3 endpoint URL cannot contain userinfo, query string, or #fragment.",
                "Specify a clean S3 scheme://host[:port][/prefix] base URL.",
            ));
        }

        validate_bucket_name(&self.bucket)?;
        validate_sigv4_scope_token("region", &self.region)?;
        validate_sigv4_scope_token("access_key_id", &self.credentials.access_key_id)?;
        if self.credentials.secret_access_key.trim().is_empty()
            || self
                .credentials
                .secret_access_key
                .chars()
                .any(|c| c == '\0' || c.is_control())
        {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                "S3 secret_access_key must be non-empty without control characters.",
                "Configure valid S3 SigV4 credentials.",
            ));
        }
        if let Some(ref token) = self.credentials.session_token
            && token
                .chars()
                .any(|c| matches!(c, '\r' | '\n' | '\0') || c.is_control())
        {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                "S3 session_token contains forbidden control characters.",
                "Configure a valid S3 STS session token.",
            ));
        }
        if let Some(ref prefix) = self.key_prefix {
            validate_key_prefix(prefix)?;
        }
        if let Some(ref pem) = self.ca_cert_pem {
            let _ = parse_ca_pem_certs(pem)?;
        }
        Ok(())
    }

    pub(crate) fn normalized_prefix(&self) -> String {
        self.key_prefix
            .as_deref()
            .map(|p| p.trim().trim_matches('/').to_string())
            .filter(|p| !p.is_empty())
            .unwrap_or_default()
    }
}

pub(crate) fn parse_ca_pem_certs(pem: &str) -> Result<Vec<Vec<u8>>, CodedError> {
    if pem.len() > MAX_CA_PEM_BYTES {
        return Err(CodedError::new(
            CODE_BLOB_IO,
            format!("S3 CA PEM bundle exceeds {MAX_CA_PEM_BYTES} byte limit."),
            "Provide a concise PEM CA bundle.",
        ));
    }
    let mut certs = Vec::new();
    for item in CertificateDer::pem_slice_iter(pem.as_bytes()) {
        let cert = item.map_err(|e| {
            CodedError::new(
                CODE_BLOB_IO,
                format!("Invalid PEM certificate in S3 CA bundle: {e}"),
                "Provide valid PEM-encoded X.509 CA certificates.",
            )
        })?;
        certs.push(cert.as_ref().to_vec());
    }
    if certs.is_empty() {
        return Err(CodedError::new(
            CODE_BLOB_IO,
            "S3 CA PEM bundle contained zero certificates.",
            "Provide at least one PEM CA certificate.",
        ));
    }
    Ok(certs)
}

fn validate_bucket_name(bucket: &str) -> Result<(), CodedError> {
    if !(MIN_BUCKET_LEN..=MAX_BUCKET_LEN).contains(&bucket.len()) {
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            format!("S3 bucket name `{bucket}` length must be between 3 and 63 characters."),
            "Use a DNS-compliant S3 bucket name.",
        ));
    }
    let valid_chars = bucket
        .bytes()
        .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || b == b'.');
    let starts_ends_alnum = bucket
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric())
        && bucket
            .bytes()
            .last()
            .is_some_and(|b| b.is_ascii_alphanumeric());
    if !valid_chars || !starts_ends_alnum || bucket.contains("..") {
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            format!("Invalid S3 bucket name `{bucket}`."),
            "Use lowercase alphanumeric characters, hyphens, and non-adjacent dots.",
        ));
    }
    Ok(())
}

fn validate_key_prefix(prefix: &str) -> Result<(), CodedError> {
    let trimmed = prefix.trim().trim_matches('/');
    if trimmed.contains('\0') || trimmed.split('/').any(|seg| seg == ".." || seg == ".") {
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            "S3 key_prefix contains forbidden traversal or NUL segments.",
            "Provide a clean relative S3 key prefix.",
        ));
    }
    Ok(())
}

fn validate_sigv4_scope_token(field: &str, value: &str) -> Result<(), CodedError> {
    if value.trim().is_empty()
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | ',' | '=' | '\0'))
    {
        return Err(CodedError::new(
            CODE_BLOB_INVALID_PATH,
            format!("S3 {field} contains empty or forbidden scope characters."),
            "Remove whitespace, control chars, '/', ',', and '=' from S3 region and access_key_id.",
        ));
    }
    Ok(())
}

fn is_loopback_host(host: &str) -> bool {
    let trimmed = host.trim_start_matches('[').trim_end_matches(']');
    if trimmed.eq_ignore_ascii_case("localhost") {
        return true;
    }
    trimmed.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback())
}
