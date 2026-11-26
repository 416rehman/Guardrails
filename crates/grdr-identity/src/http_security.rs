// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::time::Duration;

use reqwest::{Client, Response};
use url::{Host, Url};
use zeroize::Zeroizing;

use crate::IdentityError;

pub(crate) const DEFAULT_HTTP_TIMEOUT_SECS: u64 = 10;
pub(crate) const MAX_HTTP_RESPONSE_BYTES: usize = 1_048_576;

pub(crate) async fn read_bounded_response_text(
    mut resp: Response,
    label: &str,
) -> Result<Zeroizing<String>, IdentityError> {
    let max_u64 = u64::try_from(MAX_HTTP_RESPONSE_BYTES).unwrap_or(u64::MAX);
    if let Some(len) = resp.content_length()
        && len > max_u64
    {
        return Err(IdentityError::SecretStore(format!(
            "{label} response exceeds 1MiB cap"
        )));
    }
    let mut buf = Zeroizing::new(Vec::new());
    while let Some(chunk) = resp
        .chunk()
        .await
        .map_err(|e| IdentityError::SecretStore(format!("{label} response read failed: {e}")))?
    {
        if buf.len().saturating_add(chunk.len()) > MAX_HTTP_RESPONSE_BYTES {
            return Err(IdentityError::SecretStore(format!(
                "{label} response body exceeds 1MiB cap"
            )));
        }
        buf.extend_from_slice(&chunk);
    }
    let raw_bytes = std::mem::take(&mut *buf);
    let text = String::from_utf8(raw_bytes)
        .map_err(|e| IdentityError::SecretStore(format!("{label} response invalid UTF-8: {e}")))?;
    Ok(Zeroizing::new(text))
}

pub(crate) fn validate_single_segment(label: &str, value: &str) -> Result<(), IdentityError> {
    if value.is_empty()
        || value.len() > 64
        || !value
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '-' | '.'))
        || value.contains("..")
    {
        return Err(IdentityError::InvalidHttpEndpoint(format!(
            "invalid {label} path segment"
        )));
    }
    Ok(())
}

pub(crate) fn validate_endpoint_url(
    raw: &str,
    allow_insecure_loopback: bool,
) -> Result<Url, IdentityError> {
    let mut url = validate_exact_endpoint_url(raw, allow_insecure_loopback)?;
    if !url.path().ends_with('/') {
        let new_path = format!("{}/", url.path());
        url.set_path(&new_path);
    }
    Ok(url)
}

pub(crate) fn validate_exact_endpoint_url(
    raw: &str,
    allow_insecure_loopback: bool,
) -> Result<Url, IdentityError> {
    let url = Url::parse(raw)
        .map_err(|e| IdentityError::InvalidHttpEndpoint(format!("invalid endpoint URL: {e}")))?;
    if !url.username().is_empty() || url.password().is_some() {
        return Err(IdentityError::InvalidHttpEndpoint(
            "endpoint URL must not embed credentials".to_string(),
        ));
    }
    if url.query().is_some() || url.fragment().is_some() {
        return Err(IdentityError::InvalidHttpEndpoint(
            "endpoint URL must not contain query or fragment".to_string(),
        ));
    }
    let Some(host) = url.host() else {
        return Err(IdentityError::InvalidHttpEndpoint(
            "endpoint URL missing host".to_string(),
        ));
    };
    if is_forbidden_metadata_or_unspecified_host(&host) {
        return Err(IdentityError::InvalidHttpEndpoint(
            "endpoint host is unspecified, link-local metadata, or multicast".to_string(),
        ));
    }
    let loopback = is_loopback_host(&host);
    if loopback && !allow_insecure_loopback {
        return Err(IdentityError::InvalidHttpEndpoint(
            "endpoint loopback host requires explicit allow_insecure_loopback".to_string(),
        ));
    }
    let is_https = url.scheme() == "https";
    let is_loopback_http = allow_insecure_loopback && url.scheme() == "http" && loopback;
    if !is_https && !is_loopback_http {
        return Err(IdentityError::InvalidHttpEndpoint(
            "endpoint must use https (or explicit loopback http in test)".to_string(),
        ));
    }
    Ok(url)
}

pub(crate) fn is_forbidden_ip_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_forbidden_ipv4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped() {
                return is_forbidden_ipv4(mapped);
            }
            let first = *v6.segments().first().unwrap_or(&0);
            let is_link_local = (first & 0xffc0) == 0xfe80;
            v6.is_unspecified() || is_link_local || v6.is_multicast()
        }
    }
}

pub(crate) fn validate_resolved_ips(
    addrs: &[SocketAddr],
    allow_insecure_loopback: bool,
) -> Result<(), IdentityError> {
    if addrs.is_empty() {
        return Err(IdentityError::InvalidHttpEndpoint(
            "endpoint DNS lookup returned no addresses".to_string(),
        ));
    }
    for addr in addrs {
        if is_forbidden_ip_addr(addr.ip())
            || (!allow_insecure_loopback && is_loopback_ip(addr.ip()))
        {
            return Err(IdentityError::InvalidHttpEndpoint(
                "endpoint host resolves to forbidden metadata, loopback, or unspecified address"
                    .to_string(),
            ));
        }
    }
    Ok(())
}

pub(crate) async fn pinned_client_for_url(
    url: &Url,
    fallback: &Client,
    allow_insecure_loopback: bool,
) -> Result<Client, IdentityError> {
    let Some(Host::Domain(domain)) = url.host() else {
        return Ok(fallback.clone());
    };
    if allow_insecure_loopback && domain.eq_ignore_ascii_case("localhost") {
        return Ok(fallback.clone());
    }
    let port = url.port_or_known_default().unwrap_or(443);
    let resolved: Vec<SocketAddr> = tokio::net::lookup_host((domain, port))
        .await
        .map_err(|e| IdentityError::InvalidHttpEndpoint(format!("endpoint DNS resolution: {e}")))?
        .collect();
    validate_resolved_ips(&resolved, allow_insecure_loopback)?;
    Client::builder()
        .https_only(!allow_insecure_loopback)
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .timeout(Duration::from_secs(DEFAULT_HTTP_TIMEOUT_SECS))
        .resolve_to_addrs(domain, &resolved)
        .build()
        .map_err(|e| {
            IdentityError::InvalidHttpEndpoint(format!("pinned HTTP client init failed: {e}"))
        })
}

fn is_loopback_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            v6.is_loopback() || v6.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
    }
}

fn is_forbidden_ipv4(ip: Ipv4Addr) -> bool {
    ip.is_unspecified() || ip.is_link_local() || ip.is_multicast() || ip.is_broadcast()
}

fn is_loopback_host(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => ip.is_loopback(),
        Host::Ipv6(ip) => {
            ip.is_loopback() || ip.to_ipv4_mapped().is_some_and(|v4| v4.is_loopback())
        }
        Host::Domain(d) => d.eq_ignore_ascii_case("localhost"),
    }
}

fn is_forbidden_metadata_or_unspecified_host(host: &Host<&str>) -> bool {
    match host {
        Host::Ipv4(ip) => is_forbidden_ipv4(*ip),
        Host::Ipv6(ip) => is_forbidden_ip_addr(IpAddr::V6(*ip)),
        Host::Domain(d) => {
            d.eq_ignore_ascii_case("metadata.google.internal")
                || d.eq_ignore_ascii_case("metadata")
                || d.eq_ignore_ascii_case("instance-data")
        }
    }
}
