// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_crypto::{encode_lower_hex, hmac_sha256, sha256_hex};
use url::Url;
use zeroize::Zeroize;

use crate::server_preflight::probe_types::{S3AddressingStyle, is_loopback_hostport};

const EMPTY_SHA256_HEX: &str = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";

#[derive(Clone)]
pub struct S3Credentials {
    pub access_key: String,
    pub secret_key: String,
    pub session_token: Option<String>,
    pub region: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum LifecycleAssessment {
    Valid,
    Invalid(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObjectLockAssessment {
    Valid { mode: &'static str, days: u64 },
    Invalid(String),
}

impl Drop for S3Credentials {
    fn drop(&mut self) {
        self.access_key.zeroize();
        self.secret_key.zeroize();
        if let Some(tok) = &mut self.session_token {
            tok.zeroize();
        }
    }
}

impl S3Credentials {
    pub fn from_env() -> Result<Option<Self>, String> {
        let access_key =
            read_first_non_empty(&["GRDR_OBJECT_STORE_ACCESS_KEY", "AWS_ACCESS_KEY_ID"]);
        let secret_key =
            read_first_non_empty(&["GRDR_OBJECT_STORE_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"]);
        let session_token =
            read_first_non_empty(&["GRDR_OBJECT_STORE_SESSION_TOKEN", "AWS_SESSION_TOKEN"]);
        let region = read_first_non_empty(&[
            "GRDR_OBJECT_STORE_REGION",
            "AWS_REGION",
            "AWS_DEFAULT_REGION",
        ])
        .unwrap_or_else(|| "us-east-1".to_string());

        match (access_key, secret_key) {
            (Some(ak), Some(sk)) => Ok(Some(Self {
                access_key: ak,
                secret_key: sk,
                session_token,
                region,
            })),
            (None, None) => Ok(None),
            _ => Err(
                "Partial S3 credentials configured; provide both access key and secret key.".into(),
            ),
        }
    }
}

fn read_first_non_empty(keys: &[&str]) -> Option<String> {
    for key in keys {
        if let Ok(val) = std::env::var(key) {
            let trimmed = val.trim();
            if !trimmed.is_empty() {
                return Some(trimmed.to_string());
            }
        }
    }
    None
}

pub fn sign_aws_sigv4_headers(
    method: &str,
    url_str: &str,
    creds: &S3Credentials,
    now_unix_s: i64,
) -> Result<Vec<(String, String)>, String> {
    let url = Url::parse(url_str).map_err(|e| format!("Invalid S3 URL for signing: {e}"))?;
    let host = url
        .host_str()
        .ok_or_else(|| "S3 URL missing host for SigV4.".to_string())?;
    let host_header = match url.port() {
        Some(port) => format!("{host}:{port}"),
        None => host.to_string(),
    };

    let ts = jiff::Timestamp::from_second(now_unix_s)
        .map_err(|e| format!("Invalid timestamp for SigV4 signing: {e}"))?;
    let utc = jiff::tz::TimeZone::UTC.to_datetime(ts);
    let date_stamp = format!("{:04}{:02}{:02}", utc.year(), utc.month(), utc.day());
    let amz_date = format!(
        "{date_stamp}T{:02}{:02}{:02}Z",
        utc.hour(),
        utc.minute(),
        utc.second()
    );

    let canonical_uri = if url.path().is_empty() {
        "/"
    } else {
        url.path()
    };
    let canonical_query = canonicalize_query(url.query());

    let mut headers = vec![
        ("host".to_string(), host_header),
        (
            "x-amz-content-sha256".to_string(),
            EMPTY_SHA256_HEX.to_string(),
        ),
        ("x-amz-date".to_string(), amz_date.clone()),
    ];
    if let Some(tok) = &creds.session_token {
        headers.push(("x-amz-security-token".to_string(), tok.clone()));
    }
    headers.sort_by(|a, b| a.0.cmp(&b.0));

    let canonical_headers: String = headers
        .iter()
        .map(|(k, v)| format!("{k}:{}\n", v.trim()))
        .collect();
    let signed_headers: String = headers
        .iter()
        .map(|(k, _)| k.as_str())
        .collect::<Vec<_>>()
        .join(";");
    let canonical_request = format!(
        "{}\n{}\n{}\n{}\n{}\n{}",
        method.to_ascii_uppercase(),
        canonical_uri,
        canonical_query,
        canonical_headers,
        signed_headers,
        EMPTY_SHA256_HEX
    );

    let credential_scope = format!("{date_stamp}/{}/s3/aws4_request", creds.region);
    let string_to_sign = format!(
        "AWS4-HMAC-SHA256\n{amz_date}\n{credential_scope}\n{}",
        sha256_hex(canonical_request.as_bytes())
    );

    let mut k_secret = format!("AWS4{}", creds.secret_key);
    let k_date = hmac_sha256(k_secret.as_bytes(), date_stamp.as_bytes());
    k_secret.zeroize();
    let k_region = hmac_sha256(&k_date, creds.region.as_bytes());
    let k_service = hmac_sha256(&k_region, b"s3");
    let k_signing = hmac_sha256(&k_service, b"aws4_request");
    let sig_hex = encode_lower_hex(&hmac_sha256(&k_signing, string_to_sign.as_bytes()));

    let auth_header = format!(
        "AWS4-HMAC-SHA256 Credential={}/{credential_scope}, SignedHeaders={signed_headers}, Signature={sig_hex}",
        creds.access_key
    );

    let mut out = Vec::with_capacity(4);
    out.push(("x-amz-date".to_string(), amz_date));
    out.push((
        "x-amz-content-sha256".to_string(),
        EMPTY_SHA256_HEX.to_string(),
    ));
    if let Some(tok) = &creds.session_token {
        out.push(("x-amz-security-token".to_string(), tok.clone()));
    }
    out.push(("Authorization".to_string(), auth_header));
    Ok(out)
}

fn canonicalize_query(raw_query: Option<&str>) -> String {
    let Some(q) = raw_query else {
        return String::new();
    };
    let mut pairs: Vec<(String, String)> = q
        .split('&')
        .filter(|seg| !seg.is_empty())
        .map(|seg| match seg.split_once('=') {
            Some((k, v)) => (pct_encode(k), pct_encode(v)),
            None => (pct_encode(seg), String::new()),
        })
        .collect();
    pairs.sort();
    pairs
        .into_iter()
        .map(|(k, v)| format!("{k}={v}"))
        .collect::<Vec<_>>()
        .join("&")
}

fn pct_encode(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    for byte in input.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push('%');
            out.push(hex_upper(byte >> 4));
            out.push(hex_upper(byte & 0x0f));
        }
    }
    out
}

fn hex_upper(nibble: u8) -> char {
    match nibble {
        0..=9 => char::from(b'0'.saturating_add(nibble)),
        10..=15 => char::from(b'A'.saturating_add(nibble.saturating_sub(10))),
        _ => '0',
    }
}

pub fn sanitize_s3_xml(xml: &str) -> Result<String, String> {
    let lower = xml.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err("S3 XML response contains forbidden DTD/ENTITY declaration.".into());
    }
    let mut stripped = String::with_capacity(xml.len());
    let mut rest = xml;
    while let Some(start) = rest.find("<!--") {
        let Some(before) = rest.get(..start) else {
            break;
        };
        stripped.push_str(before);
        let Some(after_open) = rest.get(start.saturating_add(4)..) else {
            return Err("Malformed unclosed XML comment in S3 response.".into());
        };
        let Some(end) = after_open.find("-->") else {
            return Err("Malformed unclosed XML comment in S3 response.".into());
        };
        rest = after_open.get(end.saturating_add(3)..).unwrap_or("");
    }
    stripped.push_str(rest);
    if stripped.contains("<!") {
        return Err("S3 XML response contains unsupported markup declaration.".into());
    }
    Ok(stripped)
}

pub fn xml_tag_values<'a>(xml: &'a str, tag: &str) -> Vec<&'a str> {
    let mut out = Vec::new();
    let prefix = format!("<{tag}");
    let close = format!("</{tag}>");
    let mut rest = xml;
    while let Some(start) = rest.find(&prefix) {
        let Some(after_tag) = rest.get(start.saturating_add(prefix.len())..) else {
            break;
        };
        let next_ch = after_tag.chars().next();
        if !matches!(
            next_ch,
            Some('>') | Some(' ') | Some('\t') | Some('\r') | Some('\n')
        ) {
            rest = after_tag;
            continue;
        }
        let Some(gt_offset) = after_tag.find('>') else {
            break;
        };
        if after_tag
            .get(..gt_offset)
            .is_some_and(|attrs| attrs.ends_with('/'))
        {
            rest = after_tag.get(gt_offset.saturating_add(1)..).unwrap_or("");
            continue;
        }
        let Some(after_open) = after_tag.get(gt_offset.saturating_add(1)..) else {
            break;
        };
        let Some(end) = after_open.find(&close) else {
            break;
        };
        if let Some(inner) = after_open.get(..end) {
            out.push(inner.trim());
        }
        let Some(next) = after_open.get(end.saturating_add(close.len())..) else {
            break;
        };
        rest = next;
    }
    out
}

pub fn xml_contains_tag_value(xml: &str, tag: &str, expected: &str) -> bool {
    xml_tag_values(xml, tag).contains(&expected)
}

pub fn assess_lifecycle_xml(raw_xml: &str) -> LifecycleAssessment {
    let clean = match sanitize_s3_xml(raw_xml) {
        Ok(c) => c,
        Err(e) => return LifecycleAssessment::Invalid(e),
    };
    if !clean.contains("<LifecycleConfiguration") {
        return LifecycleAssessment::Invalid(
            "Missing <LifecycleConfiguration> root element.".into(),
        );
    }
    let rules = xml_tag_values(&clean, "Rule");
    if rules.is_empty() {
        return LifecycleAssessment::Invalid(
            "Lifecycle configuration contains zero <Rule> elements.".into(),
        );
    }
    for rule in rules {
        if !xml_contains_tag_value(rule, "Status", "Enabled") {
            continue;
        }
        let has_current_exp = xml_tag_values(rule, "Expiration").into_iter().any(|exp| {
            xml_tag_values(exp, "Days")
                .into_iter()
                .any(|d| d.parse::<u64>().is_ok_and(|n| n > 0))
                || !xml_tag_values(exp, "Date").is_empty()
        });
        let has_noncurrent_exp = xml_tag_values(rule, "NoncurrentVersionExpiration")
            .into_iter()
            .any(|nc| {
                xml_tag_values(nc, "NoncurrentDays")
                    .into_iter()
                    .any(|d| d.parse::<u64>().is_ok_and(|n| n > 0))
                    || xml_tag_values(nc, "NewerNoncurrentVersions")
                        .into_iter()
                        .any(|d| d.parse::<u64>().is_ok_and(|n| n > 0))
            });
        if has_current_exp || has_noncurrent_exp {
            return LifecycleAssessment::Valid;
        }
    }
    LifecycleAssessment::Invalid(
        "No Enabled lifecycle rule defines Expiration or NoncurrentVersionExpiration.".into(),
    )
}

pub fn assess_object_lock_xml(raw_xml: &str, min_retention_days: u64) -> ObjectLockAssessment {
    let clean = match sanitize_s3_xml(raw_xml) {
        Ok(c) => c,
        Err(e) => return ObjectLockAssessment::Invalid(e),
    };
    if !xml_contains_tag_value(&clean, "ObjectLockEnabled", "Enabled") {
        return ObjectLockAssessment::Invalid(
            "Bucket does not report <ObjectLockEnabled>Enabled</ObjectLockEnabled>.".into(),
        );
    }
    let default_blocks = xml_tag_values(&clean, "DefaultRetention");
    let Some(retention_xml) = default_blocks.first().copied() else {
        return ObjectLockAssessment::Invalid(
            "Object Lock is enabled without <DefaultRetention> policy.".into(),
        );
    };
    if !xml_contains_tag_value(retention_xml, "Mode", "COMPLIANCE") {
        return ObjectLockAssessment::Invalid(
            "Object Lock <DefaultRetention> Mode must be COMPLIANCE (GOVERNANCE refused).".into(),
        );
    }
    let days = xml_tag_values(retention_xml, "Days")
        .first()
        .and_then(|s| s.parse::<u64>().ok())
        .or_else(|| {
            xml_tag_values(retention_xml, "Years")
                .first()
                .and_then(|s| s.parse::<u64>().ok())
                .map(|y| y.saturating_mul(365))
        });
    let Some(ret_days) = days.filter(|&d| d > 0) else {
        return ObjectLockAssessment::Invalid(
            "Object Lock <DefaultRetention> lacks positive <Days> or <Years>.".into(),
        );
    };
    if ret_days < min_retention_days {
        return ObjectLockAssessment::Invalid(format!(
            "Object Lock COMPLIANCE retention ({ret_days}d) is shorter than pitr_window_days ({min_retention_days}d)."
        ));
    }
    ObjectLockAssessment::Valid {
        mode: "COMPLIANCE",
        days: ret_days,
    }
}

pub fn validate_bucket_name(bucket: &str) -> Result<&str, &'static str> {
    let clean = bucket.trim();
    if clean.len() < 3 || clean.len() > 63 {
        return Err("S3 bucket name must be 3..=63 characters.");
    }
    if clean.contains("..")
        || !clean
            .bytes()
            .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'.'))
    {
        return Err("S3 bucket name contains invalid characters.");
    }
    let starts_ok = clean
        .bytes()
        .next()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    let ends_ok = clean
        .bytes()
        .last()
        .is_some_and(|b| b.is_ascii_alphanumeric());
    if !starts_ok || !ends_ok {
        return Err("S3 bucket name must start and end with lowercase alphanumeric ASCII.");
    }
    Ok(clean)
}

pub fn validate_s3_endpoint_url(endpoint: &str) -> Result<(), &'static str> {
    let trimmed = endpoint.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_whitespace) {
        return Err("S3 endpoint URL must be non-empty without whitespace.");
    }
    let parsed = Url::parse(trimmed).map_err(|_| "S3 endpoint URL could not be parsed.")?;
    if !parsed.username().is_empty() || parsed.password().is_some() || trimmed.contains('@') {
        return Err("S3 endpoint URL must not embed credentials or userinfo (@).");
    }
    if parsed.query().is_some() || parsed.fragment().is_some() {
        return Err("S3 endpoint URL must not contain query parameters or fragments.");
    }
    let Some(host) = parsed.host_str() else {
        return Err("S3 endpoint URL is missing a hostname.");
    };
    let host_port = match parsed.port() {
        Some(p) => format!("{host}:{p}"),
        None => host.to_string(),
    };
    match parsed.scheme() {
        "https" => Ok(()),
        "http" if is_loopback_hostport(&host_port) => Ok(()),
        "http" => Err("Non-loopback S3 endpoint must use https:// (plaintext http:// prohibited)."),
        _ => Err("S3 endpoint URL must use https:// (or loopback http:// for local dev)."),
    }
}

pub fn build_bucket_url(
    endpoint: &str,
    bucket: &str,
    style: S3AddressingStyle,
) -> Result<String, String> {
    validate_s3_endpoint_url(endpoint).map_err(str::to_string)?;
    let clean_bucket = validate_bucket_name(bucket)?;
    let mut url = Url::parse(endpoint.trim())
        .map_err(|_| "S3 endpoint URL could not be parsed.".to_string())?;
    match style {
        S3AddressingStyle::PathStyle => {
            let base = url.path().trim_end_matches('/');
            let new_path = if base.is_empty() {
                format!("/{clean_bucket}")
            } else {
                format!("{base}/{clean_bucket}")
            };
            url.set_path(&new_path);
            Ok(url.to_string())
        }
        S3AddressingStyle::VirtualHosted => {
            let Some(host_kind) = url.host() else {
                return Err("S3 endpoint URL is missing a hostname.".to_string());
            };
            if matches!(host_kind, url::Host::Ipv4(_) | url::Host::Ipv6(_)) {
                return Err(
                    "Virtual-hosted S3 addressing requires a DNS hostname; pass --object-store-path-style for IP endpoints."
                        .to_string(),
                );
            }
            let host = url
                .host_str()
                .ok_or_else(|| "S3 endpoint URL is missing a hostname.".to_string())?;
            url.set_host(Some(&format!("{clean_bucket}.{host}")))
                .map_err(|_| {
                    "Failed applying virtual-hosted bucket prefix to S3 endpoint.".to_string()
                })?;
            Ok(url.to_string().trim_end_matches('/').to_string())
        }
    }
}
