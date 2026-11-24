// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::IntegrationError;

const DISALLOWED_HOST_EXACT: &[&str] = &[
    "localhost",
    "localhost.localdomain",
    "ip6-localhost",
    "ip6-loopback",
    "metadata",
    "metadata.google.internal",
];

const DISALLOWED_HOST_SUFFIXES: &[&str] =
    &[".localhost", ".local", ".internal", ".localdomain", ".arpa"];

#[must_use]
pub fn is_valid_dns_suffix(suffix: &str) -> bool {
    let trimmed = suffix.strip_prefix('.').unwrap_or(suffix);
    if trimmed.is_empty() || trimmed.ends_with('.') || trimmed.contains("..") {
        return false;
    }
    trimmed.split('.').all(is_valid_dns_label)
}

pub fn validate_egress_url(
    base_url: &str,
    host_constraints: &[String],
    allow_private_ranges: bool,
) -> Result<(), IntegrationError> {
    if base_url.is_empty()
        || base_url.chars().any(|c| {
            c.is_ascii_control() || c.is_ascii_whitespace() || matches!(c, '\\' | '?' | '#')
        })
    {
        return Err(IntegrationError::EgressDenied(
            "egress URL contains forbidden whitespace, control, query, or fragment characters"
                .into(),
        ));
    }

    let rest = if let Some(https) = base_url.strip_prefix("https://") {
        https
    } else if allow_private_ranges {
        base_url
            .strip_prefix("http://")
            .ok_or_else(|| IntegrationError::EgressDenied("URL must use https://".into()))?
    } else {
        return Err(IntegrationError::EgressDenied(
            "egress URL must use https://".into(),
        ));
    };

    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') {
        return Err(IntegrationError::EgressDenied(
            "egress URL has invalid authority".into(),
        ));
    }
    let host = parse_host_from_authority(authority)?;

    if !allow_private_ranges && is_disallowed_host(host) {
        return Err(IntegrationError::EgressDenied(format!(
            "private, loopback, or metadata address `{host}` is forbidden"
        )));
    }

    if !host_constraints.is_empty()
        && !host_constraints
            .iter()
            .any(|suffix| matches_dns_suffix(host, suffix))
    {
        return Err(IntegrationError::EgressDenied(format!(
            "host `{host}` does not satisfy manifest host_constraints"
        )));
    }
    Ok(())
}

fn parse_host_from_authority(authority: &str) -> Result<&str, IntegrationError> {
    if let Some(after_open) = authority.strip_prefix('[') {
        let Some((ip_part, rest)) = after_open.split_once(']') else {
            return Err(IntegrationError::EgressDenied(
                "unclosed IPv6 host bracket".into(),
            ));
        };
        if ip_part.is_empty() || ip_part.contains('%') || ip_part.parse::<Ipv6Addr>().is_err() {
            return Err(IntegrationError::EgressDenied(
                "invalid IPv6 host in egress URL".into(),
            ));
        }
        if !rest.is_empty() {
            let Some(port_str) = rest.strip_prefix(':') else {
                return Err(IntegrationError::EgressDenied(
                    "invalid port separator after IPv6 host".into(),
                ));
            };
            validate_port(port_str)?;
        }
        return Ok(ip_part);
    }

    let (host, port_opt) = match authority.split_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (authority, None),
    };
    if let Some(port_str) = port_opt {
        if port_str.contains(':') {
            return Err(IntegrationError::EgressDenied(
                "unbracketed IPv6 or extra colons in authority".into(),
            ));
        }
        validate_port(port_str)?;
    }

    if host.is_empty() || host.ends_with('.') {
        return Err(IntegrationError::EgressDenied(
            "egress URL host is empty or ends with trailing dot".into(),
        ));
    }
    if host.parse::<Ipv4Addr>().is_err()
        && !is_obfuscated_ip_host(host)
        && !host.split('.').all(is_valid_dns_label)
    {
        return Err(IntegrationError::EgressDenied(format!(
            "invalid host syntax `{host}`"
        )));
    }
    Ok(host)
}

fn validate_port(port_str: &str) -> Result<(), IntegrationError> {
    let port = port_str
        .parse::<u16>()
        .map_err(|_| IntegrationError::EgressDenied("invalid port in egress URL".into()))?;
    if port == 0 {
        return Err(IntegrationError::EgressDenied(
            "port 0 is forbidden in egress URL".into(),
        ));
    }
    Ok(())
}

fn is_valid_dns_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
}

fn is_obfuscated_ip_host(host: &str) -> bool {
    if host.parse::<u128>().is_ok() {
        return true;
    }
    if host
        .strip_prefix("0x")
        .or_else(|| host.strip_prefix("0X"))
        .is_some_and(|hex| !hex.is_empty() && hex.chars().all(|c| c.is_ascii_hexdigit()))
    {
        return true;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.is_empty() || labels.len() > 4 {
        return false;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && (label.chars().all(|c| c.is_ascii_digit())
                || label
                    .strip_prefix("0x")
                    .or_else(|| label.strip_prefix("0X"))
                    .is_some_and(|h| !h.is_empty() && h.chars().all(|c| c.is_ascii_hexdigit())))
    })
}

fn is_disallowed_host(host: &str) -> bool {
    let lower = host.to_ascii_lowercase();
    if DISALLOWED_HOST_EXACT.contains(&lower.as_str())
        || DISALLOWED_HOST_SUFFIXES.iter().any(|s| lower.ends_with(s))
    {
        return true;
    }
    if is_obfuscated_ip_host(host) && host.parse::<Ipv4Addr>().is_err() {
        return true;
    }
    if let Ok(ip) = host.parse::<IpAddr>() {
        return is_disallowed_ip(ip);
    }
    false
}

fn is_disallowed_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_ipv4(v4),
        IpAddr::V6(v6) => is_disallowed_ipv6(v6),
    }
}

fn is_disallowed_ipv4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || v4.is_documentation()
        || o[0] == 0
        || (o[0] == 100 && (64..=127).contains(&o[1]))
        || (o[0] == 192 && o[1] == 0 && o[2] == 0)
        || (o[0] == 198 && (18..=19).contains(&o[1]))
        || o[0] >= 240
}

fn is_disallowed_ipv6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_disallowed_ipv4(mapped);
    }
    if let Some(compat) = v6.to_ipv4() {
        return is_disallowed_ipv4(compat);
    }
    let seg = v6.segments();
    let is_unicast_link_local = (seg[0] & 0xffc0) == 0xfe80;
    let is_doc = seg[0] == 0x2001 && seg[1] == 0x0db8;
    let is_teredo = seg[0] == 0x2001 && seg[1] == 0x0000;
    let is_6to4 = seg[0] == 0x2002;
    let is_nat64_local = seg[0] == 0x0064 && seg[1] == 0xff9b && seg[2] == 0x0001;
    let is_nat64_wk = seg[0] == 0x0064
        && seg[1] == 0xff9b
        && seg[2] == 0
        && seg[3] == 0
        && seg[4] == 0
        && seg[5] == 0;
    if is_nat64_wk {
        let embedded = Ipv4Addr::new(
            u8::try_from(seg[6] >> 8).unwrap_or(0),
            u8::try_from(seg[6] & 0xff).unwrap_or(0),
            u8::try_from(seg[7] >> 8).unwrap_or(0),
            u8::try_from(seg[7] & 0xff).unwrap_or(0),
        );
        return is_disallowed_ipv4(embedded);
    }
    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_unique_local()
        || v6.is_multicast()
        || is_unicast_link_local
        || is_doc
        || is_teredo
        || is_6to4
        || is_nat64_local
}

fn matches_dns_suffix(host: &str, suffix: &str) -> bool {
    if !is_valid_dns_suffix(suffix) {
        return false;
    }
    let h = host.to_ascii_lowercase();
    let s = suffix.to_ascii_lowercase();
    let trimmed = s.trim_start_matches('.');
    h == trimmed || h.ends_with(&format!(".{trimmed}"))
}
