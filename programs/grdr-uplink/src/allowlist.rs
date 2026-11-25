// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Egress allow-list rules (`CIDR v4/v6`, strict subdomain DNS matching), HTTPS authority
//! validation, non-canonical IP rejection, and complete private/special-use SSRF guards (`P16`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

use crate::error::UplinkError;

/// Allow-list matcher in `Isolated` mode (`network.mode = "isolated"`).
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AllowEntry {
    CidrV4 { network: u32, prefix_len: u8 },
    CidrV6 { network: u128, prefix_len: u8 },
    DnsSuffix { suffix: String },
}

/// Private/special-use egress guard in `Standard` mode (`#cfg(test)` permits loopback harness only).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivateAddressPolicy {
    BlockPrivateAndLinkLocal,
    #[cfg(test)]
    AllowLoopbackForLocalRelay,
}

/// Parsed HTTPS authority extracted without unsafe indexing or parser confusion.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ParsedHttpsTarget {
    pub host: String,
    pub port: u16,
    pub host_ip: Option<IpAddr>,
}

/// Validated explicit proxy host normalized without brackets and checked for non-canonical IP literals.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidatedProxyHost {
    pub host: String,
    pub host_ip: Option<IpAddr>,
}

impl AllowEntry {
    /// Parse an allow-list rule (`CIDR v4/v6`, bare IP literal, `*.domain`, or exact host).
    pub fn parse(raw: &str) -> Result<Self, UplinkError> {
        let trimmed = raw.trim();
        if trimmed.is_empty() {
            return Err(UplinkError::InvalidEndpoint {
                detail: "empty allow_list entry".to_string(),
            });
        }

        if let Some((ip_part, prefix_part)) = trimmed.split_once('/') {
            let ip: IpAddr = ip_part.parse().map_err(|_| UplinkError::InvalidEndpoint {
                detail: format!("invalid CIDR address '{ip_part}'"),
            })?;
            let prefix_len: u8 = prefix_part
                .parse()
                .map_err(|_| UplinkError::InvalidEndpoint {
                    detail: format!("invalid CIDR prefix '{prefix_part}'"),
                })?;
            return Self::from_cidr(ip, prefix_len);
        }

        if let Ok(ip) = trimmed.parse::<IpAddr>() {
            return match ip {
                IpAddr::V4(v4) => Ok(Self::CidrV4 {
                    network: u32::from(v4),
                    prefix_len: 32,
                }),
                IpAddr::V6(v6) => Ok(Self::CidrV6 {
                    network: u128::from(v6),
                    prefix_len: 128,
                }),
            };
        }

        let normalized = trimmed.to_ascii_lowercase();
        if is_non_canonical_ip_literal(&normalized) {
            return Err(UplinkError::InvalidEndpoint {
                detail: format!("non-canonical IP literal disallowed in allow_list '{trimmed}'"),
            });
        }
        let domain_part = if let Some(rest) = normalized.strip_prefix("*.") {
            rest
        } else if let Some(rest) = normalized.strip_prefix('.') {
            rest
        } else {
            normalized.as_str()
        };
        if domain_part.is_empty()
            || domain_part.contains('*')
            || domain_part.contains("..")
            || domain_part.starts_with('.')
            || domain_part.ends_with('.')
            || !domain_part
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
        {
            return Err(UplinkError::InvalidEndpoint {
                detail: format!("invalid DNS suffix '{trimmed}'"),
            });
        }
        Ok(Self::DnsSuffix { suffix: normalized })
    }

    fn from_cidr(ip: IpAddr, prefix_len: u8) -> Result<Self, UplinkError> {
        match ip {
            IpAddr::V4(v4) => {
                if prefix_len > 32 {
                    return Err(UplinkError::InvalidEndpoint {
                        detail: format!("IPv4 prefix length {prefix_len} > 32"),
                    });
                }
                let mask = ipv4_mask(prefix_len);
                Ok(Self::CidrV4 {
                    network: u32::from(v4) & mask,
                    prefix_len,
                })
            }
            IpAddr::V6(v6) => {
                if prefix_len > 128 {
                    return Err(UplinkError::InvalidEndpoint {
                        detail: format!("IPv6 prefix length {prefix_len} > 128"),
                    });
                }
                let mask = ipv6_mask(prefix_len);
                Ok(Self::CidrV6 {
                    network: u128::from(v6) & mask,
                    prefix_len,
                })
            }
        }
    }

    /// Check whether a lowercase hostname matches this rule (`*.domain` matches proper subdomains only).
    #[must_use]
    pub fn matches_host(&self, host: &str) -> bool {
        let host_lc = host.trim_end_matches('.').to_ascii_lowercase();
        match self {
            Self::DnsSuffix { suffix } => {
                if let Some(domain) = suffix.strip_prefix("*.") {
                    host_lc.ends_with(&format!(".{domain}"))
                } else if let Some(domain) = suffix.strip_prefix('.') {
                    host_lc.ends_with(&format!(".{domain}"))
                } else {
                    host_lc == *suffix
                }
            }
            Self::CidrV4 { .. } | Self::CidrV6 { .. } => host_lc
                .parse::<IpAddr>()
                .is_ok_and(|ip| self.matches_ip(ip)),
        }
    }

    /// Check whether an IP address falls inside this rule.
    #[must_use]
    pub fn matches_ip(&self, ip: IpAddr) -> bool {
        match (self, ip) {
            (
                Self::CidrV4 {
                    network,
                    prefix_len,
                },
                IpAddr::V4(v4),
            ) => (u32::from(v4) & ipv4_mask(*prefix_len)) == *network,
            (
                Self::CidrV6 {
                    network,
                    prefix_len,
                },
                IpAddr::V6(v6),
            ) => (u128::from(v6) & ipv6_mask(*prefix_len)) == *network,
            _ => false,
        }
    }
}

/// Parse an `https://host[:port]/...` endpoint cleanly without authority/parser confusion.
pub fn parse_https_target(uri: &str) -> Result<ParsedHttpsTarget, UplinkError> {
    let trimmed = uri.trim();
    let rest = trimmed
        .strip_prefix("https://")
        .ok_or_else(|| UplinkError::InvalidEndpoint {
            detail: format!("target URI must use https scheme: '{trimmed}'"),
        })?;
    let pre_slash = rest.split('/').next().unwrap_or("");
    let authority = rest.split(['/', '?', '#', '\\']).next().unwrap_or("");
    if authority.is_empty()
        || pre_slash.contains('@')
        || pre_slash.contains('\\')
        || authority
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(UplinkError::InvalidEndpoint {
            detail: format!("invalid target authority in '{trimmed}'"),
        });
    }

    let (host, port) = if let Some(bracketed) = authority.strip_prefix('[') {
        let (v6, after_bracket) =
            bracketed
                .split_once(']')
                .ok_or_else(|| UplinkError::InvalidEndpoint {
                    detail: format!("unclosed IPv6 literal in '{trimmed}'"),
                })?;
        if v6.parse::<Ipv6Addr>().is_err() {
            return Err(UplinkError::InvalidEndpoint {
                detail: format!("invalid IPv6 literal in '{trimmed}'"),
            });
        }
        let port = if after_bracket.is_empty() {
            443
        } else if let Some(port_str) = after_bracket.strip_prefix(':') {
            parse_nonzero_port(port_str)?
        } else {
            return Err(UplinkError::InvalidEndpoint {
                detail: format!("malformed IPv6 authority in '{trimmed}'"),
            });
        };
        (v6.to_ascii_lowercase(), port)
    } else if let Some((h, port_str)) = authority.rsplit_once(':') {
        if h.contains(':') {
            return Err(UplinkError::InvalidEndpoint {
                detail: format!("unbracketed IPv6 literal in '{trimmed}'"),
            });
        }
        (h.to_ascii_lowercase(), parse_nonzero_port(port_str)?)
    } else {
        (authority.to_ascii_lowercase(), 443)
    };

    if is_non_canonical_ip_literal(&host) {
        return Err(UplinkError::InvalidEndpoint {
            detail: format!("invalid or non-canonical host in '{trimmed}'"),
        });
    }
    let host_ip = host.parse::<IpAddr>().ok();
    validate_normalized_host(&host, host_ip.is_some(), trimmed)?;
    Ok(ParsedHttpsTarget {
        host,
        port,
        host_ip,
    })
}

/// Normalize and validate an explicit proxy host or bracketed IPv6 literal.
pub fn parse_proxy_host(raw: &str) -> Result<ValidatedProxyHost, UplinkError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.contains('@')
        || trimmed.contains('/')
        || trimmed.contains('?')
        || trimmed.contains('#')
        || trimmed.contains('\\')
        || trimmed.chars().any(|c| c.is_whitespace() || c.is_control())
    {
        return Err(UplinkError::InvalidEndpoint {
            detail: format!("invalid proxy host '{raw}'"),
        });
    }

    let host = if let Some(inner) = trimmed.strip_prefix('[') {
        let (v6, after) = inner
            .split_once(']')
            .ok_or_else(|| UplinkError::InvalidEndpoint {
                detail: format!("unclosed IPv6 literal in proxy host '{raw}'"),
            })?;
        if !after.is_empty() || v6.parse::<Ipv6Addr>().is_err() {
            return Err(UplinkError::InvalidEndpoint {
                detail: format!("invalid IPv6 literal in proxy host '{raw}'"),
            });
        }
        v6.to_ascii_lowercase()
    } else if trimmed.contains(':') {
        return Err(UplinkError::InvalidEndpoint {
            detail: format!("unbracketed IPv6 or port in proxy host '{raw}'"),
        });
    } else {
        trimmed.to_ascii_lowercase()
    };

    if is_non_canonical_ip_literal(&host) {
        return Err(UplinkError::InvalidEndpoint {
            detail: format!("non-canonical IP literal disallowed in proxy host '{raw}'"),
        });
    }
    let host_ip = host.parse::<IpAddr>().ok();
    validate_normalized_host(&host, host_ip.is_some(), trimmed)?;
    Ok(ValidatedProxyHost { host, host_ip })
}

fn validate_normalized_host(host: &str, is_ip: bool, raw: &str) -> Result<(), UplinkError> {
    if host.is_empty() {
        return Err(UplinkError::InvalidEndpoint {
            detail: format!("empty hostname in '{raw}'"),
        });
    }
    if !is_ip
        && (!host
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-'))
            || host.contains("..")
            || host.starts_with('.')
            || host.ends_with('.'))
    {
        return Err(UplinkError::InvalidEndpoint {
            detail: format!("malformed hostname '{host}'"),
        });
    }
    Ok(())
}

/// Reject decimal integer (`2130706433`), shortened (`127.1`), hex (`0x7f.1`), or leading-zero octal IPs.
#[must_use]
pub fn is_non_canonical_ip_literal(host: &str) -> bool {
    if host.parse::<IpAddr>().is_ok() {
        return false;
    }
    let labels: Vec<&str> = host.split('.').collect();
    if labels.is_empty() {
        return true;
    }
    labels.iter().all(|label| {
        !label.is_empty()
            && (label.starts_with("0x")
                || label.starts_with("0X")
                || label.bytes().all(|b| b.is_ascii_digit()))
    })
}

/// Return true if `ip` belongs to private, loopback, link-local, special-use, transition, or multicast ranges.
#[must_use]
pub fn is_disallowed_private_or_link_local(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => is_disallowed_v4(v4),
        IpAddr::V6(v6) => is_disallowed_v6(v6),
    }
}

fn parse_nonzero_port(raw: &str) -> Result<u16, UplinkError> {
    let port: u16 = raw.parse().map_err(|_| UplinkError::InvalidEndpoint {
        detail: format!("invalid TCP port '{raw}'"),
    })?;
    if port == 0 {
        return Err(UplinkError::InvalidEndpoint {
            detail: "TCP port must be 1..=65535".to_string(),
        });
    }
    Ok(port)
}

fn ipv4_mask(prefix_len: u8) -> u32 {
    if prefix_len == 0 {
        0
    } else {
        let shift = 32u8.saturating_sub(prefix_len);
        u32::MAX.checked_shl(u32::from(shift)).unwrap_or(0)
    }
}

fn ipv6_mask(prefix_len: u8) -> u128 {
    if prefix_len == 0 {
        0
    } else {
        let shift = 128u8.saturating_sub(prefix_len);
        u128::MAX.checked_shl(u32::from(shift)).unwrap_or(0)
    }
}

fn is_disallowed_v4(v4: Ipv4Addr) -> bool {
    let o = v4.octets();
    let zero_net = o.first().copied() == Some(0);
    let carrier_nat = o.first().copied() == Some(100)
        && o.get(1).copied().is_some_and(|b| (64..=127).contains(&b));
    let ietf_proto = o.first().copied() == Some(192)
        && o.get(1).copied() == Some(0)
        && o.get(2).copied() == Some(0);
    let test_net_1 = o.first().copied() == Some(192)
        && o.get(1).copied() == Some(0)
        && o.get(2).copied() == Some(2);
    let benchmark_net =
        o.first().copied() == Some(198) && o.get(1).copied().is_some_and(|b| b == 18 || b == 19);
    let test_net_2 = o.first().copied() == Some(198)
        && o.get(1).copied() == Some(51)
        && o.get(2).copied() == Some(100);
    let test_net_3 = o.first().copied() == Some(203)
        && o.get(1).copied() == Some(0)
        && o.get(2).copied() == Some(113);
    let reserved_high = o.first().copied().is_some_and(|b| b >= 240);

    zero_net
        || v4.is_private()
        || v4.is_loopback()
        || v4.is_link_local()
        || v4.is_unspecified()
        || v4.is_broadcast()
        || v4.is_multicast()
        || carrier_nat
        || ietf_proto
        || benchmark_net
        || test_net_1
        || test_net_2
        || test_net_3
        || reserved_high
}

fn is_disallowed_v6(v6: Ipv6Addr) -> bool {
    if let Some(mapped) = v6.to_ipv4_mapped() {
        return is_disallowed_v4(mapped);
    }
    if let Some(compat) = v6.to_ipv4()
        && !v6.is_unspecified()
        && !v6.is_loopback()
    {
        return is_disallowed_v4(compat);
    }
    let segs = v6.segments();
    let s0 = segs.first().copied().unwrap_or(0);
    let s1 = segs.get(1).copied().unwrap_or(0);
    let s2 = segs.get(2).copied().unwrap_or(0);
    let s3 = segs.get(3).copied().unwrap_or(0);
    let s4 = segs.get(4).copied().unwrap_or(0);
    let s5 = segs.get(5).copied().unwrap_or(0);

    let link_local = (s0 & 0xffc0) == 0xfe80;
    let site_local = (s0 & 0xffc0) == 0xfec0;
    let unique_local = (s0 & 0xfe00) == 0xfc00;
    let doc_net = s0 == 0x2001 && s1 == 0x0db8;
    let teredo = s0 == 0x2001 && s1 == 0x0000;
    let six_to_four = s0 == 0x2002;
    let nat64_well_known = s0 == 0x0064 && s1 == 0xff9b && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0;
    let nat64_local = s0 == 0x0064 && s1 == 0xff9b && s2 == 0x0001;

    v6.is_loopback()
        || v6.is_unspecified()
        || v6.is_multicast()
        || link_local
        || site_local
        || unique_local
        || doc_net
        || teredo
        || six_to_four
        || nat64_well_known
        || nat64_local
}
