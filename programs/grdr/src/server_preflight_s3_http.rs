// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::io::Read;
use std::path::PathBuf;
use std::time::Duration;

use reqwest::Certificate;
use reqwest::blocking::Client;
use reqwest::redirect::Policy;

use crate::fs_safe;
use crate::server_preflight::probe_types::{
    ErrCodeSlot, PreflightThresholds, ProbeOutcomeKind, RawProbeResult,
};
use crate::server_preflight::s3_auth::{S3Credentials, sign_aws_sigv4_headers};

const PROBE_HTTP_TIMEOUT_S: u64 = 3;
const MAX_S3_RESPONSE_BYTES: usize = 65_536;
const MAX_CERT_PEM_BYTES: u64 = 1_048_576;

pub(super) fn s3_res(
    id: &'static str,
    name: &'static str,
    kind: ProbeOutcomeKind,
    detail: String,
    remedy: Option<&'static str>,
) -> RawProbeResult {
    let err_slot = match (kind, id) {
        (ProbeOutcomeKind::Pass, _) => ErrCodeSlot::None,
        (_, "PF-08") => ErrCodeSlot::Storage,
        _ => ErrCodeSlot::ObjectStore,
    };
    RawProbeResult {
        id,
        name,
        kind,
        err_slot,
        detail,
        remedy,
    }
}

pub(super) fn build_s3_client(cert_files: &[PathBuf]) -> Result<Client, String> {
    let mut builder = Client::builder()
        .use_rustls_tls()
        .connect_timeout(Duration::from_secs(PROBE_HTTP_TIMEOUT_S))
        .timeout(Duration::from_secs(PROBE_HTTP_TIMEOUT_S))
        .redirect(Policy::none())
        .user_agent("grdr-preflight");

    for path in cert_files {
        let bytes = fs_safe::read_bounded_regular(path, MAX_CERT_PEM_BYTES)
            .map_err(|e| format!("Failed reading TLS CA file `{}`: {e}", path.display()))?;
        let certs = Certificate::from_pem_bundle(&bytes).map_err(|e| {
            format!(
                "Invalid PEM certificate bundle in `{}`: {e}",
                path.display()
            )
        })?;
        for cert in certs {
            builder = builder.add_root_certificate(cert);
        }
    }
    builder
        .build()
        .map_err(|e| format!("Failed initializing rustls HTTP client for S3 probe: {e}"))
}

pub(super) fn execute_signed_get(
    client: &Client,
    url: &str,
    creds: Option<&S3Credentials>,
    now_unix_s: i64,
) -> Result<(u16, String), String> {
    let resp = send_signed_request(client, "GET", url, creds, now_unix_s)?;
    let status = resp.status().as_u16();
    let cap = u64::try_from(MAX_S3_RESPONSE_BYTES)
        .unwrap_or(65_536)
        .saturating_add(1);
    let mut buf = Vec::new();
    resp.take(cap)
        .read_to_end(&mut buf)
        .map_err(|e| format!("Failed reading S3 HTTP response body: {e}"))?;
    if buf.len() > MAX_S3_RESPONSE_BYTES {
        return Err(format!(
            "S3 XML response exceeded bounded {MAX_S3_RESPONSE_BYTES}-byte limit."
        ));
    }
    let body = String::from_utf8(buf).map_err(|_| "S3 response body is not valid UTF-8.")?;
    Ok((status, body))
}

pub(super) fn probe_http_date_skew(
    client: &Client,
    endpoint: &str,
    creds: Option<&S3Credentials>,
    thresholds: &PreflightThresholds,
    now_unix_s: i64,
    out: &mut Vec<RawProbeResult>,
) {
    let resp = send_signed_request(client, "HEAD", endpoint, creds, now_unix_s)
        .or_else(|_| send_signed_request(client, "GET", endpoint, creds, now_unix_s));
    let r = match resp {
        Ok(r) => r,
        Err(err) => {
            out.push(s3_res(
                "PF-04",
                "object_store_endpoint_reachability",
                ProbeOutcomeKind::Fail,
                format!("Failed connecting to S3 endpoint: {err}"),
                Some("Verify network policy, DNS, and TLS trust for object store endpoint."),
            ));
            return;
        }
    };
    out.push(s3_res(
        "PF-04",
        "object_store_endpoint_reachability",
        ProbeOutcomeKind::Pass,
        format!(
            "Object store endpoint responded HTTP {}.",
            r.status().as_u16()
        ),
        None,
    ));
    let Some(date_hdr) = r
        .headers()
        .get(reqwest::header::DATE)
        .and_then(|v| v.to_str().ok())
    else {
        out.push(s3_res(
            "PF-08",
            "http_clock_skew",
            ProbeOutcomeKind::Fail,
            "Object store response omitted required RFC 2822 Date header.".into(),
            Some("Ensure S3 gateway returns an authoritative Date header."),
        ));
        return;
    };
    match jiff::fmt::rfc2822::parse(date_hdr.trim()) {
        Ok(dt) => {
            let skew_s = now_unix_s
                .saturating_sub(dt.timestamp().as_second())
                .unsigned_abs();
            let (kind, detail, remedy) = if skew_s >= thresholds.clock_skew_http_fail_s {
                (
                    ProbeOutcomeKind::Fail,
                    format!(
                        "HTTP Date skew against object store is {skew_s}s (fail limit {}s).",
                        thresholds.clock_skew_http_fail_s
                    ),
                    Some("Synchronize host NTP/Chrony or w32time against site time source."),
                )
            } else if skew_s >= thresholds.clock_skew_http_warn_s {
                (
                    ProbeOutcomeKind::Warn,
                    format!(
                        "HTTP Date skew against object store is {skew_s}s (warn threshold {}s).",
                        thresholds.clock_skew_http_warn_s
                    ),
                    Some("Verify NTP daemon drift before enrolling or renewing leases."),
                )
            } else {
                (
                    ProbeOutcomeKind::Pass,
                    format!(
                        "HTTP Date skew against object store is {skew_s}s (within {}s).",
                        thresholds.clock_skew_http_warn_s
                    ),
                    None,
                )
            };
            out.push(s3_res("PF-08", "http_clock_skew", kind, detail, remedy));
        }
        Err(_) => out.push(s3_res(
            "PF-08",
            "http_clock_skew",
            ProbeOutcomeKind::Fail,
            "Object store returned unparseable HTTP Date header.".into(),
            Some("Ensure S3 gateway Date header uses valid RFC 2822 format."),
        )),
    }
}

fn send_signed_request(
    client: &Client,
    method: &str,
    url: &str,
    creds: Option<&S3Credentials>,
    now_unix_s: i64,
) -> Result<reqwest::blocking::Response, String> {
    let mut req = match method {
        "HEAD" => client.head(url),
        _ => client.get(url),
    };
    if let Some(c) = creds {
        for (name, val) in sign_aws_sigv4_headers(method, url, c, now_unix_s)? {
            req = req.header(name, val);
        }
    }
    req.send().map_err(|e| e.to_string())
}
