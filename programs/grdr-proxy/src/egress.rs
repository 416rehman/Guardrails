// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Egress SSRF guard performing single vetted DNS resolution, IPv4-mapped IPv6
//! normalization, metadata IP blocking, and anti-rebinding socket pinning.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use tokio::net::lookup_host;

use crate::ProxyError;

const FORBIDDEN_HOSTNAMES: &[&str] = &[
    "metadata.google.internal",
    "metadata.goog",
    "instance-data",
    "169.254.169.254",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LoopbackUpstreamPolicy {
    DenyAll,
    AllowExplicitLoopbackUpstreams,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct EgressGuardConfig {
    pub loopback_policy: LoopbackUpstreamPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VettedEndpoint {
    pub host: String,
    pub port: u16,
    pub pinned_addrs: Vec<SocketAddr>,
}

impl Default for EgressGuardConfig {
    fn default() -> Self {
        Self {
            loopback_policy: LoopbackUpstreamPolicy::DenyAll,
        }
    }
}

/// Resolves `(host, port)` ONCE and inspects every resolved address against SSRF
/// ranges (after normalizing IPv4-mapped IPv6 addresses), returning pinned `SocketAddr`s
/// so outbound connections never re-resolve via DNS (anti-DNS-rebinding).
pub async fn resolve_and_vet_target(
    host: &str,
    port: u16,
    config: &EgressGuardConfig,
) -> Result<VettedEndpoint, ProxyError> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() || port == 0 {
        return Err(ProxyError::SsrfDenied("empty host or zero port".into()));
    }

    let stripped = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);

    if let Ok(ip) = stripped.parse::<IpAddr>() {
        validate_ip(ip, config)?;
        return Ok(VettedEndpoint {
            host: stripped.to_owned(),
            port,
            pinned_addrs: vec![SocketAddr::new(ip, port)],
        });
    }

    if is_forbidden_hostname(stripped, config.loopback_policy) {
        return Err(ProxyError::SsrfDenied(format!(
            "hostname `{stripped}` is restricted by SSRF guard"
        )));
    }

    let resolved: Vec<SocketAddr> = lookup_host((stripped, port))
        .await
        .map_err(|e| {
            ProxyError::SsrfDenied(format!("DNS resolution failed for `{stripped}`: {e}"))
        })?
        .collect();

    if resolved.is_empty() {
        return Err(ProxyError::SsrfDenied(format!(
            "DNS returned zero addresses for `{stripped}`"
        )));
    }

    for addr in &resolved {
        validate_ip(addr.ip(), config)?;
    }

    Ok(VettedEndpoint {
        host: stripped.to_owned(),
        port,
        pinned_addrs: resolved,
    })
}

pub fn validate_ip(raw_ip: IpAddr, config: &EgressGuardConfig) -> Result<(), ProxyError> {
    if is_metadata_ip(raw_ip) {
        return Err(ProxyError::SsrfDenied(format!(
            "cloud metadata IP `{raw_ip}` is always denied"
        )));
    }

    match raw_ip {
        IpAddr::V4(v4) => validate_v4(v4, config),
        IpAddr::V6(v6) => {
            if let Some(mapped_v4) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                if is_metadata_v4(mapped_v4) {
                    return Err(ProxyError::SsrfDenied(format!(
                        "IPv4-embedded metadata IP `{raw_ip}` is always denied"
                    )));
                }
                return validate_v4(mapped_v4, config);
            }
            validate_v6(v6, config)
        }
    }
}

/// Validates a customer-configured corporate chained proxy (`HTTPS_PROXY` / `HTTP_PROXY`):
/// permits RFC1918/private corporate hosts while strictly denying metadata and unspecified IPs.
pub async fn resolve_and_vet_chained_proxy(
    host: &str,
    port: u16,
) -> Result<VettedEndpoint, ProxyError> {
    let trimmed = host.trim().trim_end_matches('.');
    if trimmed.is_empty() || port == 0 {
        return Err(ProxyError::SsrfDenied(
            "chained proxy host or port invalid".into(),
        ));
    }
    let stripped = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    if FORBIDDEN_HOSTNAMES.contains(&stripped.to_ascii_lowercase().as_str()) {
        return Err(ProxyError::SsrfDenied(format!(
            "chained proxy cannot target restricted metadata host `{stripped}`"
        )));
    }
    let addrs: Vec<SocketAddr> = if let Ok(ip) = stripped.parse::<IpAddr>() {
        vec![SocketAddr::new(ip, port)]
    } else {
        lookup_host((stripped, port))
            .await
            .map_err(|e| ProxyError::SsrfDenied(format!("chained proxy DNS failed: {e}")))?
            .collect()
    };
    if addrs.is_empty() {
        return Err(ProxyError::SsrfDenied(
            "chained proxy resolved zero addresses".into(),
        ));
    }
    for addr in &addrs {
        if is_metadata_ip(addr.ip()) || addr.ip().is_unspecified() || addr.ip().is_multicast() {
            return Err(ProxyError::SsrfDenied(format!(
                "chained proxy IP `{}` denied",
                addr.ip()
            )));
        }
    }
    Ok(VettedEndpoint {
        host: stripped.to_owned(),
        port,
        pinned_addrs: addrs,
    })
}

fn validate_v4(v4: Ipv4Addr, config: &EgressGuardConfig) -> Result<(), ProxyError> {
    let [a, b, c, _] = v4.octets();
    let is_cgnat = a == 100 && (b & 0xc0) == 64;
    let is_zero_net = a == 0;
    let is_ietf_proto = a == 192 && b == 0 && c == 0;
    let is_benchmark = a == 198 && (b == 18 || b == 19);
    let is_reserved_high = a >= 240;
    if v4.is_loopback() {
        if config.loopback_policy == LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams {
            return Ok(());
        }
        return Err(ProxyError::SsrfDenied(format!(
            "loopback IPv4 `{v4}` denied"
        )));
    }
    if v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || is_cgnat
        || is_zero_net
        || is_ietf_proto
        || is_benchmark
        || is_reserved_high
    {
        return Err(ProxyError::SsrfDenied(format!(
            "non-public IPv4 `{v4}` denied by SSRF guard"
        )));
    }
    Ok(())
}

fn validate_v6(v6: Ipv6Addr, config: &EgressGuardConfig) -> Result<(), ProxyError> {
    if v6.is_loopback() {
        if config.loopback_policy == LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams {
            return Ok(());
        }
        return Err(ProxyError::SsrfDenied(format!(
            "loopback IPv6 `{v6}` denied"
        )));
    }
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
    if v6.is_unspecified()
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
    {
        return Err(ProxyError::SsrfDenied(format!(
            "non-public IPv6 `{v6}` denied by SSRF guard"
        )));
    }
    Ok(())
}

fn is_metadata_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_metadata_v4(v4),
        IpAddr::V6(v6) => {
            if let Some(mapped) = v6.to_ipv4_mapped().or_else(|| v6.to_ipv4()) {
                return is_metadata_v4(mapped);
            }
            // AWS IMDSv6 fd00:ec2::254
            v6.segments() == [0xfd00, 0x0ec2, 0, 0, 0, 0, 0, 0x0254]
        }
    }
}

const fn is_metadata_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, d] = v4.octets();
    (a == 169 && b == 254) || (a == 100 && b == 100 && c == 100 && d == 200)
}

fn is_forbidden_hostname(host: &str, loopback: LoopbackUpstreamPolicy) -> bool {
    let lower = host.to_ascii_lowercase();
    if FORBIDDEN_HOSTNAMES.contains(&lower.as_str())
        || lower.ends_with(".internal")
        || lower.ends_with(".local")
    {
        return true;
    }
    if loopback == LoopbackUpstreamPolicy::DenyAll
        && (lower == "localhost" || lower.ends_with(".localhost"))
    {
        return true;
    }
    false
}
