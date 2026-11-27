// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::mpsc::{self, Sender, SyncSender};
use std::thread::{self, JoinHandle};
use std::time::Duration;

use jiff::Timestamp;
use reqwest::header::{HeaderMap, HeaderName, HeaderValue};
use reqwest::{Certificate, Client, Method, redirect};
use url::Url;

use grdr_model::CodedError;
use grdr_ports::CODE_BLOB_IO;

use crate::s3_config::{S3AddressingStyle, S3BlobConfig, S3TransportSecurity, parse_ca_pem_certs};
use crate::s3_sigv4::{
    SigV4SignInput, aws_uri_encode, build_canonical_query_string, is_reserved_sigv4_header,
    sign_s3_request,
};

const MAX_S3_RESPONSE_BYTES: usize = 64 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S3HttpMethod {
    Get,
    Put,
    Head,
    Delete,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum S3ResponseStatus {
    Ok,
    PartialContent,
    NoContent,
    NotFound,
    PreconditionFailed,
    Conflict,
    RangeNotSatisfiable,
    Other(u16),
}

#[derive(Debug)]
pub(crate) struct S3HttpRequest {
    pub(crate) method: S3HttpMethod,
    pub(crate) key: Option<String>,
    pub(crate) query: Vec<(String, String)>,
    pub(crate) extra_headers: Vec<(String, String)>,
    pub(crate) body: Vec<u8>,
}

#[derive(Debug)]
pub(crate) struct S3HttpResponse {
    pub(crate) status: S3ResponseStatus,
    pub(crate) etag: Option<String>,
    pub(crate) version_id: Option<String>,
    pub(crate) content_length: u64,
    pub(crate) body: Vec<u8>,
}

#[derive(Debug)]
struct WorkerTask {
    req: S3HttpRequest,
    reply: SyncSender<Result<S3HttpResponse, CodedError>>,
}

#[derive(Debug)]
pub(crate) struct S3HttpClient {
    config: S3BlobConfig,
    sender: Option<Sender<WorkerTask>>,
    worker: Option<JoinHandle<()>>,
}

impl S3ResponseStatus {
    pub(crate) fn from_code(code: u16) -> Self {
        match code {
            200 => Self::Ok,
            204 => Self::NoContent,
            206 => Self::PartialContent,
            404 => Self::NotFound,
            409 => Self::Conflict,
            412 => Self::PreconditionFailed,
            416 => Self::RangeNotSatisfiable,
            other => Self::Other(other),
        }
    }

    pub(crate) fn code(self) -> u16 {
        match self {
            Self::Ok => 200,
            Self::NoContent => 204,
            Self::PartialContent => 206,
            Self::NotFound => 404,
            Self::Conflict => 409,
            Self::PreconditionFailed => 412,
            Self::RangeNotSatisfiable => 416,
            Self::Other(c) => c,
        }
    }

    pub(crate) fn is_error(self) -> bool {
        self.code() >= 400
    }
}

impl S3HttpMethod {
    fn as_str(self) -> &'static str {
        match self {
            Self::Get => "GET",
            Self::Put => "PUT",
            Self::Head => "HEAD",
            Self::Delete => "DELETE",
        }
    }

    fn to_reqwest(self) -> Method {
        match self {
            Self::Get => Method::GET,
            Self::Put => Method::PUT,
            Self::Head => Method::HEAD,
            Self::Delete => Method::DELETE,
        }
    }
}

impl S3HttpClient {
    pub(crate) fn new(config: S3BlobConfig) -> Result<Self, CodedError> {
        config.validate()?;
        let worker_cfg = config.clone();
        let (tx, rx) = mpsc::channel::<WorkerTask>();
        let (init_tx, init_rx) = mpsc::sync_channel::<Result<(), CodedError>>(1);

        let worker = thread::Builder::new()
            .name("grdr-s3-http".into())
            .spawn(move || {
                let rt = match tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                {
                    Ok(rt) => rt,
                    Err(e) => {
                        let _ = init_tx.send(Err(CodedError::new(
                            CODE_BLOB_IO,
                            format!("Failed creating S3 HTTP runtime: {e}"),
                            "Check OS thread and socket resources.",
                        )));
                        return;
                    }
                };
                let client = match build_reqwest_client(&worker_cfg) {
                    Ok(c) => c,
                    Err(e) => {
                        let _ = init_tx.send(Err(e));
                        return;
                    }
                };
                let _ = init_tx.send(Ok(()));

                while let Ok(task) = rx.recv() {
                    let res = rt.block_on(execute_single_request(&client, &worker_cfg, task.req));
                    let _ = task.reply.send(res);
                }
            })
            .map_err(|e| {
                CodedError::new(
                    CODE_BLOB_IO,
                    format!("Failed spawning S3 HTTP worker thread: {e}"),
                    "Verify OS thread limits.",
                )
            })?;

        let init_res = init_rx.recv().map_err(|_| {
            CodedError::new(
                CODE_BLOB_IO,
                "S3 HTTP worker terminated during initialization.",
                "Check TLS configuration and certificates.",
            )
        })?;
        init_res?;

        Ok(Self {
            config,
            sender: Some(tx),
            worker: Some(worker),
        })
    }

    pub(crate) fn config(&self) -> &S3BlobConfig {
        &self.config
    }

    pub(crate) fn execute(&self, req: S3HttpRequest) -> Result<S3HttpResponse, CodedError> {
        let Some(sender) = &self.sender else {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                "S3 HTTP worker already shut down.",
                "Recreate S3BlobStore.",
            ));
        };
        let (reply_tx, reply_rx) = mpsc::sync_channel(1);
        sender
            .send(WorkerTask {
                req,
                reply: reply_tx,
            })
            .map_err(|_| {
                CodedError::new(
                    CODE_BLOB_IO,
                    "S3 HTTP worker channel closed.",
                    "Recreate S3BlobStore.",
                )
            })?;
        reply_rx.recv().map_err(|_| {
            CodedError::new(
                CODE_BLOB_IO,
                "S3 HTTP worker dropped response.",
                "Inspect S3 endpoint reachability.",
            )
        })?
    }
}

impl Drop for S3HttpClient {
    fn drop(&mut self) {
        self.sender.take();
        if let Some(handle) = self.worker.take() {
            let _ = handle.join();
        }
    }
}

fn build_reqwest_client(config: &S3BlobConfig) -> Result<Client, CodedError> {
    let mut builder = Client::builder()
        .tls_backend_rustls()
        .tls_version_min(reqwest::tls::Version::TLS_1_2)
        .redirect(redirect::Policy::none())
        .no_proxy()
        .connect_timeout(Duration::from_millis(config.connect_timeout_ms))
        .timeout(Duration::from_millis(config.request_timeout_ms));

    if config.security == S3TransportSecurity::RequireTls {
        builder = builder.https_only(true);
    }

    if let Some(ref pem) = config.ca_cert_pem {
        let ders = parse_ca_pem_certs(pem)?;
        let mut certs = Vec::with_capacity(ders.len());
        for der in ders {
            let cert = Certificate::from_der(&der).map_err(|e| {
                CodedError::new(
                    CODE_BLOB_IO,
                    format!("Invalid DER certificate in S3 CA bundle: {e}"),
                    "Provide valid X.509 PEM certificates.",
                )
            })?;
            certs.push(cert);
        }
        builder = builder.tls_certs_only(certs);
    }

    builder.build().map_err(|e| {
        CodedError::new(
            CODE_BLOB_IO,
            format!("Failed building S3 HTTPS client: {e}"),
            "Check S3 TLS and timeout configuration.",
        )
    })
}

async fn execute_single_request(
    client: &Client,
    config: &S3BlobConfig,
    req: S3HttpRequest,
) -> Result<S3HttpResponse, CodedError> {
    let (full_url, canonical_uri, host_header) = build_s3_target(config, req.key.as_deref())?;
    let query_refs: Vec<(&str, &str)> = req
        .query
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let canonical_qs = build_canonical_query_string(&query_refs);
    let url_with_query = if canonical_qs.is_empty() {
        full_url
    } else {
        format!("{full_url}?{canonical_qs}")
    };

    let extra_refs: Vec<(&str, &str)> = req
        .extra_headers
        .iter()
        .map(|(k, v)| (k.as_str(), v.as_str()))
        .collect();
    let signed = sign_s3_request(&SigV4SignInput {
        method: req.method.as_str(),
        canonical_uri: &canonical_uri,
        query_params: &query_refs,
        host_header: &host_header,
        extra_headers: &extra_refs,
        payload: &req.body,
        credentials: &config.credentials,
        region: &config.region,
        now: Timestamp::now(),
    })?;

    let mut headers = HeaderMap::new();
    insert_header(&mut headers, "host", &host_header)?;
    insert_header(&mut headers, "x-amz-date", &signed.amz_date)?;
    insert_header(&mut headers, "x-amz-content-sha256", &signed.content_sha256)?;
    insert_header(&mut headers, "authorization", &signed.authorization)?;
    if let Some(ref token) = config.credentials.session_token {
        let trimmed = token.trim();
        if !trimmed.is_empty() {
            insert_header(&mut headers, "x-amz-security-token", trimmed)?;
        }
    }
    for (k, v) in &req.extra_headers {
        let lower = k.trim().to_ascii_lowercase();
        if is_reserved_sigv4_header(&lower) {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                format!("Forbidden override of reserved S3 header `{lower}`."),
                "Do not override host, authorization, or x-amz-* headers.",
            ));
        }
        insert_header(&mut headers, k, v)?;
    }

    let mut builder = client
        .request(req.method.to_reqwest(), &url_with_query)
        .headers(headers);
    if !req.body.is_empty() {
        builder = builder.body(req.body);
    }

    let mut resp = builder.send().await.map_err(|e| {
        CodedError::new(
            CODE_BLOB_IO,
            format!("S3 HTTP request failed: {e}"),
            "Verify S3 endpoint, TLS trust chain, and connectivity.",
        )
    })?;
    let status_raw = resp.status();
    if status_raw.is_redirection() {
        return Err(CodedError::new(
            CODE_BLOB_IO,
            format!(
                "Refused S3 HTTP redirect status {} to prevent credential forwarding.",
                status_raw.as_u16()
            ),
            "Configure the authoritative S3 regional endpoint directly.",
        ));
    }

    let etag = resp
        .headers()
        .get("etag")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.trim_matches('"').to_string());
    let version_id = resp
        .headers()
        .get("x-amz-version-id")
        .and_then(|v| v.to_str().ok())
        .map(ToString::to_string);
    let content_length_hdr = resp
        .headers()
        .get(reqwest::header::CONTENT_LENGTH)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.trim().parse::<u64>().ok());

    if content_length_hdr.is_some_and(|n| n > MAX_S3_RESPONSE_BYTES as u64) {
        return Err(CodedError::new(
            CODE_BLOB_IO,
            format!("S3 HTTP Content-Length exceeded {MAX_S3_RESPONSE_BYTES} byte limit."),
            "Use ByteRange reads for objects exceeding 64 MiB.",
        ));
    }
    let mut body = Vec::new();
    while let Some(chunk) = resp.chunk().await.map_err(|e| {
        CodedError::new(
            CODE_BLOB_IO,
            format!("Failed reading S3 HTTP response chunk: {e}"),
            "Retry S3 operation.",
        )
    })? {
        let next_len = body.len().checked_add(chunk.len()).ok_or_else(|| {
            CodedError::new(
                CODE_BLOB_IO,
                "S3 HTTP response body size overflow.",
                "Use ByteRange reads.",
            )
        })?;
        if next_len > MAX_S3_RESPONSE_BYTES {
            return Err(CodedError::new(
                CODE_BLOB_IO,
                format!("S3 HTTP response body exceeded {MAX_S3_RESPONSE_BYTES} byte limit."),
                "Use ByteRange reads for objects exceeding 64 MiB.",
            ));
        }
        body.extend_from_slice(&chunk);
    }

    let content_length =
        content_length_hdr.unwrap_or_else(|| u64::try_from(body.len()).unwrap_or(0));
    Ok(S3HttpResponse {
        status: S3ResponseStatus::from_code(status_raw.as_u16()),
        etag,
        version_id,
        content_length,
        body,
    })
}

fn build_s3_target(
    config: &S3BlobConfig,
    key: Option<&str>,
) -> Result<(String, String, String), CodedError> {
    let base = Url::parse(config.endpoint.trim()).map_err(|e| {
        CodedError::new(
            CODE_BLOB_IO,
            format!("Invalid S3 endpoint `{}`: {e}", config.endpoint),
            "Provide a valid S3 URL.",
        )
    })?;
    let scheme = base.scheme();
    let host = base.host_str().unwrap_or("");
    let port_suffix = match base.port() {
        Some(p) => format!(":{p}"),
        None => String::new(),
    };
    let base_path = base.path().trim_end_matches('/');

    let encoded_key = key.map(|k| aws_uri_encode(k.trim_start_matches('/'), false));
    match config.addressing {
        S3AddressingStyle::PathStyle => {
            let host_hdr = format!("{host}{port_suffix}");
            let canonical_uri = match encoded_key {
                Some(ref k) if !k.is_empty() => format!("{base_path}/{}/{k}", config.bucket),
                _ => format!("{base_path}/{}", config.bucket),
            };
            let full_url = format!("{scheme}://{host_hdr}{canonical_uri}");
            Ok((full_url, canonical_uri, host_hdr))
        }
        S3AddressingStyle::VirtualHosted => {
            let vhost = format!("{}.{host}{port_suffix}", config.bucket);
            let canonical_uri = match encoded_key {
                Some(ref k) if !k.is_empty() => format!("{base_path}/{k}"),
                _ => {
                    if base_path.is_empty() {
                        "/".to_string()
                    } else {
                        base_path.to_string()
                    }
                }
            };
            let full_url = format!("{scheme}://{vhost}{canonical_uri}");
            Ok((full_url, canonical_uri, vhost))
        }
    }
}

fn insert_header(headers: &mut HeaderMap, name: &str, value: &str) -> Result<(), CodedError> {
    let hname = HeaderName::from_bytes(name.as_bytes()).map_err(|e| {
        CodedError::new(
            CODE_BLOB_IO,
            format!("Invalid S3 header name `{name}`: {e}"),
            "Check S3 header formatting.",
        )
    })?;
    let hval = HeaderValue::from_str(value).map_err(|e| {
        CodedError::new(
            CODE_BLOB_IO,
            format!("Invalid S3 header value for `{name}`: {e}"),
            "Strip control characters from S3 headers.",
        )
    })?;
    headers.insert(hname, hval);
    Ok(())
}
