// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::time::Duration;

use reqwest::redirect::Policy;
use tokio::net::lookup_host;
use url::Url;

use crate::McpBrokerError;

const FORBIDDEN_HOSTNAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "169.254.169.254",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SsrfPolicy {
    StrictPublicOnly,
    AllowLoopbackTestOnly,
}

#[derive(Debug, Clone)]
pub struct VettedUpstream {
    pub url: Url,
    pub host: String,
    pub pinned_addr: SocketAddr,
}

pub async fn resolve_and_vet_upstream(
    raw_url: &str,
    policy: SsrfPolicy,
) -> Result<VettedUpstream, McpBrokerError> {
    let parsed = Url::parse(raw_url.trim())
        .map_err(|e| McpBrokerError::OAuthOrSsrf(format!("invalid upstream MCP URL: {e}")))?;
    let scheme = parsed.scheme();
    if scheme != "https" && !(policy == SsrfPolicy::AllowLoopbackTestOnly && scheme == "http") {
        return Err(McpBrokerError::OAuthOrSsrf(
            "upstream MCP URL must use HTTPS".to_string(),
        ));
    }
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err(McpBrokerError::OAuthOrSsrf(
            "upstream MCP URL must not contain userinfo".to_string(),
        ));
    }
    let raw_host = parsed
        .host_str()
        .map(str::trim)
        .filter(|h| !h.is_empty())
        .ok_or_else(|| McpBrokerError::OAuthOrSsrf("upstream MCP URL missing host".to_string()))?;
    let host = strip_exact_ipv6_brackets(raw_host)?
        .trim_end_matches('.')
        .to_string();
    if host.is_empty() {
        return Err(McpBrokerError::OAuthOrSsrf(
            "upstream MCP URL empty host".to_string(),
        ));
    }
    let port = parsed
        .port_or_known_default()
        .ok_or_else(|| McpBrokerError::OAuthOrSsrf("upstream MCP URL missing port".to_string()))?;

    let addrs: Vec<SocketAddr> = if let Ok(ip) = host.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        if is_forbidden_hostname(&host, policy) {
            return Err(McpBrokerError::OAuthOrSsrf(format!(
                "hostname `{host}` is restricted by SSRF guard"
            )));
        }
        lookup_host((host.as_str(), port))
            .await
            .map_err(|e| McpBrokerError::OAuthOrSsrf(format!("DNS resolution failed: {e}")))?
            .collect()
    };
    if addrs.is_empty() {
        return Err(McpBrokerError::OAuthOrSsrf(
            "upstream DNS returned no addresses".to_string(),
        ));
    }
    for addr in &addrs {
        if !is_ip_allowed(addr.ip(), policy) {
            return Err(McpBrokerError::OAuthOrSsrf(format!(
                "blocked disallowed upstream IP `{}`",
                addr.ip()
            )));
        }
        if scheme == "http" && !is_loopback_canonical(addr.ip()) {
            return Err(McpBrokerError::OAuthOrSsrf(
                "plain HTTP upstream allowed only for loopback targets".to_string(),
            ));
        }
    }
    let pinned_addr = addrs
        .first()
        .copied()
        .ok_or_else(|| McpBrokerError::OAuthOrSsrf("no pinned address".to_string()))?;
    Ok(VettedUpstream {
        url: parsed,
        host,
        pinned_addr,
    })
}

pub fn build_pinned_http_client(
    vetted: &VettedUpstream,
    timeout: Duration,
) -> Result<reqwest::Client, McpBrokerError> {
    reqwest::Client::builder()
        .resolve(&vetted.host, vetted.pinned_addr)
        .redirect(Policy::none())
        .no_proxy()
        .timeout(timeout)
        .build()
        .map_err(|e| McpBrokerError::Transport(format!("failed building pinned HTTP client: {e}")))
}

fn strip_exact_ipv6_brackets(raw: &str) -> Result<&str, McpBrokerError> {
    if raw.starts_with('[') || raw.ends_with(']') {
        let inner = raw
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .filter(|s| s.parse::<Ipv6Addr>().is_ok())
            .ok_or_else(|| McpBrokerError::OAuthOrSsrf("malformed bracketed IPv6 host".into()))?;
        return Ok(inner);
    }
    Ok(raw)
}

fn is_loopback_canonical(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => v4.is_loopback(),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                mapped.is_loopback()
            } else {
                v6.is_loopback()
            }
        }
    }
}

fn is_ip_allowed(ip: IpAddr, policy: SsrfPolicy) -> bool {
    if is_metadata_ip(ip) {
        return false;
    }
    match ip {
        IpAddr::V4(v4) => is_v4_allowed(v4, policy),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return !is_metadata_v4(mapped_v4) && is_v4_allowed(mapped_v4, policy);
            }
            if v6.is_loopback() {
                return policy == SsrfPolicy::AllowLoopbackTestOnly;
            }
            !is_disallowed_ipv6(v6)
        }
    }
}

fn is_v4_allowed(v4: Ipv4Addr, policy: SsrfPolicy) -> bool {
    if v4.is_loopback() {
        return policy == SsrfPolicy::AllowLoopbackTestOnly;
    }
    let [a, b, c, _] = v4.octets();
    let is_cgnat = a == 100 && (b & 0xc0) == 64;
    let is_zero_net = a == 0;
    let is_ietf_proto = a == 192 && b == 0 && c == 0;
    let is_benchmark = a == 198 && (b == 18 || b == 19);
    let is_reserved_high = a >= 240;
    !(v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || is_cgnat
        || is_zero_net
        || is_ietf_proto
        || is_benchmark
        || is_reserved_high)
}

fn is_disallowed_ipv6(v6: Ipv6Addr) -> bool {
    let [s0, s1, s2, s3, s4, s5, _, _] = v6.segments();
    let is_ula = (s0 & 0xfe00) == 0xfc00;
    let is_link_local = (s0 & 0xffc0) == 0xfe80;
    let is_site_local = (s0 & 0xffc0) == 0xfec0;
    let is_nat64_wellknown =
        s0 == 0x0064 && s1 == 0xff9b && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0;
    let is_nat64_local = s0 == 0x0064 && s1 == 0xff9b && s2 == 1;
    let is_6to4 = s0 == 0x2002;
    let is_teredo = s0 == 0x2001 && s1 == 0x0000;
    let is_benchmarking = s0 == 0x2001 && s1 == 0x0002 && s2 == 0x0000;
    let is_doc = s0 == 0x2001 && s1 == 0x0db8;
    let is_discard = s0 == 0x0100 && s1 == 0 && s2 == 0 && s3 == 0;
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || is_ula
        || is_link_local
        || is_site_local
        || is_nat64_wellknown
        || is_nat64_local
        || is_6to4
        || is_teredo
        || is_benchmarking
        || is_doc
        || is_discard
}

fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_metadata_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_metadata_v4(mapped);
            }
            v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

const fn is_metadata_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, d] = v4.octets();
    (a == 169 && b == 254) || (a == 100 && b == 100 && c == 100 && d == 200)
}

fn is_forbidden_hostname(host: &str, policy: SsrfPolicy) -> bool {
    let lower = host.to_ascii_lowercase();
    if FORBIDDEN_HOSTNAMES.contains(&lower.as_str())
        || lower.ends_with(".internal")
        || lower.ends_with(".local")
    {
        return true;
    }
    policy == SsrfPolicy::StrictPublicOnly
        && (lower == "localhost" || lower.ends_with(".localhost"))
}
