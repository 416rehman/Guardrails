// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use grdr_model::error::CODE_INVALID_INPUT;
use reqwest::header::{CONTENT_TYPE, HeaderMap, HeaderValue};
use tokio::net::lookup_host;

use crate::connect_error::ApiError;

use super::limits::rest_limits;

#[derive(Debug, Clone)]
pub struct ValidatedWebhookTarget {
    pub scheme: String,
    pub host: String,
    pub port: u16,
    pub path_and_query: String,
}

#[derive(Debug, Clone)]
pub struct SignedWebhookHeaders {
    pub webhook_id: String,
    pub webhook_timestamp: i64,
    pub webhook_signature: String,
    pub body: Vec<u8>,
}

pub fn validate_webhook_url(raw: &str) -> Result<ValidatedWebhookTarget, ApiError> {
    if raw
        .chars()
        .any(|c| c.is_control() || c.is_whitespace() || c == '\\')
    {
        return Err(ssrf_error(
            "Webhook URL must not contain control characters, whitespace, or backslashes.",
        ));
    }
    let trimmed = raw.trim();
    let (scheme, rest) = if let Some(r) = trimmed.strip_prefix("https://") {
        ("https".to_owned(), r)
    } else if let Some(r) = trimmed.strip_prefix("http://") {
        ("http".to_owned(), r)
    } else {
        return Err(ssrf_error(
            "Webhook URL must use https:// or http:// scheme.",
        ));
    };

    let (authority, path_and_query) = match rest.find(['/', '?', '#']) {
        Some(idx) => {
            if rest.as_bytes().get(idx) == Some(&b'#') {
                return Err(ssrf_error("Webhook URL must not include fragments."));
            }
            (
                rest.get(..idx).unwrap_or(""),
                rest.get(idx..).unwrap_or("/"),
            )
        }
        None => (rest, "/"),
    };
    if authority.is_empty() || authority.contains('@') {
        return Err(ssrf_error(
            "Webhook URL must contain a host without userinfo.",
        ));
    }
    if path_and_query.contains('#') {
        return Err(ssrf_error("Webhook URL must not include fragments."));
    }

    let (host, port) = parse_host_and_port(authority, &scheme)?;
    if host.is_empty() || host.contains('%') || host.ends_with('.') {
        return Err(ssrf_error(
            "Webhook URL host must not contain IPv6 zone IDs or trailing dots.",
        ));
    }
    let lower_host = host.to_ascii_lowercase();
    if lower_host == "localhost"
        || lower_host.ends_with(".localhost")
        || lower_host.ends_with(".local")
        || lower_host.ends_with(".internal")
        || lower_host == "metadata.google.internal"
    {
        return Err(ssrf_error(
            "Webhook URL host is restricted (local/metadata hostname).",
        ));
    }

    if is_ambiguous_numeric_ipv4(&host) {
        return Err(ssrf_error(
            "Webhook URL must not use octal, hex, integer, or short-form IPv4 notation.",
        ));
    }
    if let Some(ip) = parse_ip_or_numeric_host(&host)
        && !is_globally_routable_ip(ip)
    {
        return Err(ssrf_error(
            "Webhook target IP address is private, loopback, or reserved (SSRF blocked).",
        ));
    }

    Ok(ValidatedWebhookTarget {
        scheme,
        host,
        port,
        path_and_query: path_and_query.to_owned(),
    })
}

pub async fn deliver_webhook_ssrf_safe(
    target_url: &str,
    signed: &SignedWebhookHeaders,
) -> Result<u16, ApiError> {
    let target = validate_webhook_url(target_url)?;
    if target.scheme != "https" && target.scheme != "http" {
        return Err(ssrf_error("Unsupported webhook URL scheme."));
    }
    let resolved = lookup_host((target.host.as_str(), target.port))
        .await
        .map_err(|e| ssrf_error(&format!("DNS resolution failed: {e}")))?;
    let mut public_addr: Option<SocketAddr> = None;
    for addr in resolved {
        if !is_globally_routable_ip(addr.ip()) {
            return Err(ssrf_error(
                "Webhook hostname resolved to non-public IP address (SSRF blocked).",
            ));
        }
        if public_addr.is_none() {
            public_addr = Some(addr);
        }
    }
    let addr = public_addr.ok_or_else(|| ssrf_error("Webhook hostname did not resolve."))?;

    let timeout = Duration::from_millis(rest_limits().webhook_timeout_ms);
    let client = reqwest::Client::builder()
        .timeout(timeout)
        .connect_timeout(timeout)
        .redirect(reqwest::redirect::Policy::none())
        .no_proxy()
        .resolve(&target.host, addr)
        .build()
        .map_err(|e| ssrf_error(&format!("Webhook TLS/HTTP client init failed: {e}")))?;

    let authority_host = if target.host.contains(':') && !target.host.starts_with('[') {
        format!("[{}]", target.host)
    } else {
        target.host.clone()
    };
    let clean_url = format!(
        "{}://{}:{}{}",
        target.scheme, authority_host, target.port, target.path_and_query
    );

    let mut headers = HeaderMap::new();
    headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
    let wh_id = HeaderValue::from_str(&signed.webhook_id)
        .map_err(|_| ssrf_error("Invalid webhook-id header value."))?;
    let wh_ts = HeaderValue::from_str(&signed.webhook_timestamp.to_string())
        .map_err(|_| ssrf_error("Invalid webhook-timestamp header value."))?;
    let wh_sig = HeaderValue::from_str(&signed.webhook_signature)
        .map_err(|_| ssrf_error("Invalid webhook-signature header value."))?;
    headers.insert("webhook-id", wh_id);
    headers.insert("webhook-timestamp", wh_ts);
    headers.insert("webhook-signature", wh_sig);

    let resp = client
        .post(clean_url)
        .headers(headers)
        .body(signed.body.clone())
        .send()
        .await
        .map_err(|e| ssrf_error(&format!("Webhook delivery failed: {e}")))?;

    Ok(resp.status().as_u16())
}

pub fn is_globally_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_globally_routable_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_globally_routable_v4(mapped);
            }
            let seg = v6.segments();
            let is_v4_compat = seg[0..6] == [0, 0, 0, 0, 0, 0];
            if v6.is_loopback() || v6.is_unspecified() || v6.is_multicast() || is_v4_compat {
                return false;
            }
            let is_ula = (seg[0] & 0xfe00) == 0xfc00;
            let is_link_local = (seg[0] & 0xffc0) == 0xfe80;
            let is_site_local = (seg[0] & 0xffc0) == 0xfec0;
            let is_doc = seg[0] == 0x2001 && seg[1] == 0x0db8;
            let is_teredo = seg[0] == 0x2001 && seg[1] == 0x0000;
            let is_benchmark = seg[0] == 0x2001 && seg[1] == 0x0002 && seg[2] == 0;
            let is_6to4 = seg[0] == 0x2002;
            let is_discard = seg[0] == 0x0100 && seg[1] == 0 && seg[2] == 0 && seg[3] == 0;
            let is_nat64_wk = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2..6] == [0, 0, 0, 0];
            let is_nat64_local = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001;
            !(is_ula
                || is_link_local
                || is_site_local
                || is_doc
                || is_teredo
                || is_benchmark
                || is_6to4
                || is_discard
                || is_nat64_wk
                || is_nat64_local)
        }
    }
}

fn is_globally_routable_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    let is_cgnat = o[0] == 100 && (o[1] & 0b1100_0000) == 64;
    let is_benchmark = o[0] == 198 && (o[1] == 18 || o[1] == 19);
    let is_doc1 = o[0] == 192 && o[1] == 0 && o[2] == 2;
    let is_doc2 = o[0] == 198 && o[1] == 51 && o[2] == 100;
    let is_doc3 = o[0] == 203 && o[1] == 0 && o[2] == 113;
    let is_reserved = o[0] >= 240;
    !(v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_unspecified()
        || o[0] == 0
        || is_cgnat
        || is_benchmark
        || is_doc1
        || is_doc2
        || is_doc3
        || is_reserved)
}

fn is_ambiguous_numeric_ipv4(host: &str) -> bool {
    if host.is_empty() || host.contains(':') {
        return false;
    }
    let parts: Vec<&str> = host.split('.').collect();
    if parts.is_empty() || parts.len() > 4 {
        return false;
    }
    let all_numeric_radices = parts.iter().all(|part| {
        if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
            !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit())
        } else {
            !part.is_empty() && part.chars().all(|c| c.is_ascii_digit())
        }
    });
    if !all_numeric_radices {
        return false;
    }
    let has_non_canonical_prefix = parts.iter().any(|part| {
        part.starts_with("0x")
            || part.starts_with("0X")
            || (part.len() > 1 && part.starts_with('0'))
    });
    parts.len() != 4 || has_non_canonical_prefix
}

fn parse_host_and_port(authority: &str, scheme: &str) -> Result<(String, u16), ApiError> {
    let default_port = if scheme == "https" { 443 } else { 80 };
    if let Some(after_open) = authority.strip_prefix('[') {
        let Some((ipv6_part, rest)) = after_open.split_once(']') else {
            return Err(ssrf_error("Malformed bracketed IPv6 host."));
        };
        let port = if let Some(p_str) = rest.strip_prefix(':') {
            p_str
                .parse::<u16>()
                .map_err(|_| ssrf_error("Invalid URL port."))?
        } else if rest.is_empty() {
            default_port
        } else {
            return Err(ssrf_error("Invalid authority suffix."));
        };
        return Ok((ipv6_part.to_owned(), port));
    }
    if let Some((host, port_str)) = authority.rsplit_once(':')
        && !host.contains(':')
    {
        let port = port_str
            .parse::<u16>()
            .map_err(|_| ssrf_error("Invalid URL port."))?;
        return Ok((host.to_owned(), port));
    }
    Ok((authority.to_owned(), default_port))
}

fn parse_ip_or_numeric_host(host: &str) -> Option<IpAddr> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Some(ip);
    }
    if let Ok(v6) = host.parse::<Ipv6Addr>() {
        return Some(IpAddr::V6(v6));
    }
    if let Some(hex_digits) = host.strip_prefix("0x").or_else(|| host.strip_prefix("0X"))
        && let Ok(num) = u32::from_str_radix(hex_digits, 16)
    {
        return Some(IpAddr::V4(Ipv4Addr::from(num)));
    }
    if host.chars().all(|c| c.is_ascii_digit())
        && let Ok(num) = host.parse::<u32>()
    {
        return Some(IpAddr::V4(Ipv4Addr::from(num)));
    }
    None
}

fn ssrf_error(msg: &str) -> ApiError {
    ApiError::invalid_argument(
        CODE_INVALID_INPUT,
        "WEBHOOK_SSRF_BLOCKED",
        msg,
        "Provide a public HTTPS/HTTP webhook endpoint URL.",
    )
}
