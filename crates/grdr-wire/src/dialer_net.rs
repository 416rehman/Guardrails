// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Host canonicalization, PAC URL validation, and special-use/SSRF IP filters for `dialer`.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::dialer::EgressRouteError;

pub(crate) struct NormalizedHost {
    pub(crate) canonical: String,
    pub(crate) ip: Option<IpAddr>,
}

pub(crate) fn validate_pac_url(raw: &str) -> Result<(), EgressRouteError> {
    if raw.is_empty() || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(EgressRouteError::PolicyBlocked(
            "PAC URL must not be empty or contain control/whitespace chars".into(),
        ));
    }
    let rest = if let Some(after) = raw.strip_prefix("https://") {
        after
    } else if raw.starts_with("http://") {
        return Err(EgressRouteError::InsecureScheme(
            "PAC URL must use https://".into(),
        ));
    } else {
        return Err(EgressRouteError::PolicyBlocked(
            "PAC URL must start with https://".into(),
        ));
    };

    let pre_slash = rest.split('/').next().unwrap_or("");
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    if authority.is_empty() || pre_slash.contains('@') || pre_slash.contains('\\') {
        return Err(EgressRouteError::PolicyBlocked(
            "malformed authority in PAC URL".into(),
        ));
    }
    let (host_part, port_opt) = if authority.starts_with('[') {
        match authority.split_once(']') {
            Some((bracketed, "")) => (format!("{bracketed}]"), None),
            Some((bracketed, after)) => {
                let port_raw = after.strip_prefix(':').ok_or_else(|| {
                    EgressRouteError::PolicyBlocked("malformed IPv6 authority in PAC URL".into())
                })?;
                (format!("{bracketed}]"), Some(port_raw))
            }
            None => {
                return Err(EgressRouteError::PolicyBlocked(
                    "unclosed IPv6 literal in PAC URL".into(),
                ));
            }
        }
    } else if let Some((h, p)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return Err(EgressRouteError::PolicyBlocked(
                "unbracketed IPv6 literal with port in PAC URL".into(),
            ));
        }
        (h.to_owned(), Some(p))
    } else {
        (authority.to_owned(), None)
    };

    if let Some(port_raw) = port_opt {
        let parsed: u16 = port_raw.parse().map_err(|_| {
            EgressRouteError::PolicyBlocked(format!("invalid PAC TCP port `{port_raw}`"))
        })?;
        if parsed == 0 {
            return Err(EgressRouteError::PolicyBlocked(
                "PAC TCP port must be 1..=65535".into(),
            ));
        }
    }
    let _ = normalize_host(&host_part, "PAC proxy")?;
    Ok(())
}

pub(crate) fn normalize_host(raw: &str, label: &str) -> Result<NormalizedHost, EgressRouteError> {
    if raw.is_empty() || raw.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return Err(EgressRouteError::PolicyBlocked(format!(
            "{label} host `{raw}` must not be empty or contain whitespace/control chars"
        )));
    }
    if raw.contains('@')
        || raw.contains('/')
        || raw.contains('?')
        || raw.contains('#')
        || raw.contains('\\')
        || raw.contains('%')
    {
        return Err(EgressRouteError::PolicyBlocked(format!(
            "{label} host contains forbidden authority characters"
        )));
    }

    if let Some(rest) = raw.strip_prefix('[') {
        let Some((inner, after)) = rest.split_once(']') else {
            return Err(EgressRouteError::PolicyBlocked(format!(
                "unclosed bracketed IPv6 literal in {label} host"
            )));
        };
        if !after.is_empty() || inner.contains('[') || inner.contains(']') {
            return Err(EgressRouteError::PolicyBlocked(format!(
                "ambiguous bracketed IPv6 literal in {label} host"
            )));
        }
        let v6: Ipv6Addr = inner.parse().map_err(|_| {
            EgressRouteError::PolicyBlocked(format!("invalid bracketed IPv6 literal in {label}"))
        })?;
        let ip = IpAddr::V6(v6);
        if is_non_public_ip(ip) {
            return Err(EgressRouteError::PrivateAddressDenied(format!(
                "{label} host `{raw}` rejected"
            )));
        }
        return Ok(NormalizedHost {
            canonical: v6.to_string(),
            ip: Some(ip),
        });
    }

    if raw.contains('[') || raw.contains(']') {
        return Err(EgressRouteError::PolicyBlocked(format!(
            "stray brackets in {label} host"
        )));
    }

    if raw.contains(':') {
        let v6: Ipv6Addr = raw.parse().map_err(|_| {
            EgressRouteError::PolicyBlocked(format!(
                "unbracketed IPv6 or port suffix in {label} host `{raw}`"
            ))
        })?;
        let ip = IpAddr::V6(v6);
        if is_non_public_ip(ip) {
            return Err(EgressRouteError::PrivateAddressDenied(format!(
                "{label} host `{raw}` rejected"
            )));
        }
        return Ok(NormalizedHost {
            canonical: v6.to_string(),
            ip: Some(ip),
        });
    }

    let lower = raw.to_ascii_lowercase();
    let stripped_trailing = lower.trim_end_matches('.');
    if stripped_trailing == "localhost" || stripped_trailing.ends_with(".localhost") {
        return Err(EgressRouteError::PrivateAddressDenied(format!(
            "{label} host `{raw}` rejected"
        )));
    }

    if let Ok(v4) = lower.parse::<Ipv4Addr>() {
        let ip = IpAddr::V4(v4);
        if is_non_public_ip(ip) {
            return Err(EgressRouteError::PrivateAddressDenied(format!(
                "{label} host `{raw}` rejected"
            )));
        }
        return Ok(NormalizedHost {
            canonical: v4.to_string(),
            ip: Some(ip),
        });
    }

    if is_non_canonical_ip_literal(&lower) {
        return Err(EgressRouteError::PrivateAddressDenied(format!(
            "non-canonical IP literal disallowed in {label} host `{raw}`"
        )));
    }

    if lower.starts_with('.') || lower.ends_with('.') || lower.contains("..") || lower.len() > 253 {
        return Err(EgressRouteError::PolicyBlocked(format!(
            "malformed DNS hostname in {label} host `{raw}`"
        )));
    }

    for part in lower.split('.') {
        if part.is_empty()
            || part.len() > 63
            || part.starts_with('-')
            || part.ends_with('-')
            || !part.chars().all(|c| c.is_ascii_alphanumeric() || c == '-')
        {
            return Err(EgressRouteError::PolicyBlocked(format!(
                "malformed DNS label in {label} host `{raw}`"
            )));
        }
    }

    Ok(NormalizedHost {
        canonical: lower,
        ip: None,
    })
}

fn is_non_canonical_ip_literal(host: &str) -> bool {
    let trimmed = host.trim_end_matches('.');
    if trimmed.is_empty() {
        return true;
    }
    trimmed.split('.').all(|label| {
        !label.is_empty() && (label.starts_with("0x") || label.bytes().all(|b| b.is_ascii_digit()))
    })
}

#[must_use]
pub const fn is_non_public_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_non_public_v4(v4),
        IpAddr::V6(v6) => is_non_public_v6(v6),
    }
}

const fn is_non_public_v4(v4: Ipv4Addr) -> bool {
    let [a, b, c, _] = v4.octets();
    let zero_net = a == 0;
    let cgnat = a == 100 && (b & 0b1100_0000) == 64;
    let ietf_proto = a == 192 && b == 0 && c == 0;
    let test_net_1 = a == 192 && b == 0 && c == 2;
    let benchmark_net = a == 198 && (b == 18 || b == 19);
    let test_net_2 = a == 198 && b == 51 && c == 100;
    let test_net_3 = a == 203 && b == 0 && c == 113;
    let reserved_or_broadcast = a >= 240;

    zero_net
        || v4.is_loopback()
        || v4.is_private()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || cgnat
        || ietf_proto
        || test_net_1
        || benchmark_net
        || test_net_2
        || test_net_3
        || reserved_or_broadcast
}

const fn is_non_public_v6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_non_public_v4(mapped);
    }
    if let Some(compat) = v6.to_ipv4()
        && is_non_public_v4(compat)
    {
        return true;
    }
    let [s0, s1, s2, s3, s4, s5, _, _] = v6.segments();
    let ipv4_compat_96 = s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0;
    let ipv4_translated = s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0xffff && s5 == 0;
    let nat64_well_known = s0 == 0x0064 && s1 == 0xff9b && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0;
    let nat64_local = s0 == 0x0064 && s1 == 0xff9b && s2 == 0x0001;
    let discard_net = s0 == 0x0100 && s1 == 0 && s2 == 0 && s3 == 0;
    let teredo = s0 == 0x2001 && s1 == 0x0000;
    let orchid_v2 = s0 == 0x2001 && (s1 & 0xfff0) == 0x0020;
    let doc_net = s0 == 0x2001 && s1 == 0x0db8;
    let six_to_four = s0 == 0x2002;
    let unique_local = (s0 & 0xfe00) == 0xfc00;
    let link_local = (s0 & 0xffc0) == 0xfe80;
    let site_local = (s0 & 0xffc0) == 0xfec0;

    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || ipv4_compat_96
        || ipv4_translated
        || nat64_well_known
        || nat64_local
        || discard_net
        || teredo
        || orchid_v2
        || doc_net
        || six_to_four
        || unique_local
        || link_local
        || site_local
}
