// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Non-canonical IPv4, embedded IPv6, and IP exposure classification helpers (`D-10`).

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpExposureClass {
    Loopback,
    CloudMetadataLinkLocal,
    PrivateRfc1918,
    PublicRoutable,
}

/// Extracts an IPv4 address from mapped, compatible, SIIT, NAT64, 6to4, or Teredo IPv6 forms.
#[must_use]
pub(crate) fn extract_embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let segs = v6.segments();
    let s0 = *segs.first()?;
    let s1 = *segs.get(1)?;
    let s2 = *segs.get(2)?;
    let s3 = *segs.get(3)?;
    let s4 = *segs.get(4)?;
    let s5 = *segs.get(5)?;
    let s6 = *segs.get(6)?;
    let s7 = *segs.get(7)?;

    if s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 {
        if s6 == 0 && (s7 == 0 || s7 == 1) {
            return None;
        }
        return Some(u16_pair_to_ipv4(s6, s7));
    }
    if s0 == 0 && s1 == 0 && s2 == 0 && s3 == 0 && s4 == 0xFFFF && s5 == 0 {
        return Some(u16_pair_to_ipv4(s6, s7));
    }
    if s0 == 0x0064 && s1 == 0xFF9B && s2 == 0 && s3 == 0 && s4 == 0 && s5 == 0 {
        return Some(u16_pair_to_ipv4(s6, s7));
    }
    if s0 == 0x0064 && s1 == 0xFF9B && s2 == 1 && !(s6 == 0 && s7 <= 1) {
        return Some(u16_pair_to_ipv4(s6, s7));
    }
    if s0 == 0x2002 {
        return Some(u16_pair_to_ipv4(s1, s2));
    }
    if s0 == 0x2001 && s1 == 0x0000 && segs != [0x2001, 0, 0, 0, 0, 0, 0, 0] {
        return Some(u16_pair_to_ipv4(s6 ^ 0xFFFF, s7 ^ 0xFFFF));
    }
    None
}

/// Parses dotted 1/2/3/4-part decimal, octal, and hex IPv4 literals using WHATWG/`inet_aton` rules.
#[must_use]
pub(crate) fn parse_non_canonical_ipv4(raw: &str) -> Option<Ipv4Addr> {
    if let Ok(ip) = raw.parse::<Ipv4Addr>() {
        return Some(ip);
    }
    let parts: Vec<&str> = raw.split('.').collect();
    match parts.as_slice() {
        [single] => parse_ip_part(single).map(Ipv4Addr::from),
        [a, b] => {
            let p0 = u8::try_from(parse_ip_part(a)?).ok()?;
            let tail = parse_ip_part(b)?;
            if tail > 0x00FF_FFFF {
                return None;
            }
            Some(Ipv4Addr::from((u32::from(p0) << 24) | tail))
        }
        [a, b, c] => {
            let p0 = u8::try_from(parse_ip_part(a)?).ok()?;
            let p1 = u8::try_from(parse_ip_part(b)?).ok()?;
            let tail = parse_ip_part(c)?;
            if tail > 0xFFFF {
                return None;
            }
            Some(Ipv4Addr::from(
                (u32::from(p0) << 24) | (u32::from(p1) << 16) | tail,
            ))
        }
        [a, b, c, d] => {
            let p0 = u8::try_from(parse_ip_part(a)?).ok()?;
            let p1 = u8::try_from(parse_ip_part(b)?).ok()?;
            let p2 = u8::try_from(parse_ip_part(c)?).ok()?;
            let p3 = u8::try_from(parse_ip_part(d)?).ok()?;
            Some(Ipv4Addr::new(p0, p1, p2, p3))
        }
        _ => None,
    }
}

/// Classifies IP addresses conservatively so unspecified, link-local, CGNAT, multicast, and reserved never appear public.
#[must_use]
pub(crate) fn classify_v6_effective_exposure(v6: Ipv6Addr) -> IpExposureClass {
    let v6_class = classify_v6_exposure(v6);
    if let Some(v4) = extract_embedded_ipv4(v6) {
        classify_v4_exposure(v4).min(v6_class)
    } else {
        v6_class
    }
}

#[must_use]
pub(crate) fn classify_ip_exposure(ip: IpAddr) -> IpExposureClass {
    match ip {
        IpAddr::V4(v4) => classify_v4_exposure(v4),
        IpAddr::V6(v6) => classify_v6_exposure(v6),
    }
}

fn classify_v4_exposure(v4: Ipv4Addr) -> IpExposureClass {
    let octets = v4.octets();
    let [first, second, third, _] = octets;
    if v4.is_loopback() || first == 0 {
        return IpExposureClass::Loopback;
    }
    if octets == [169, 254, 169, 254]
        || octets == [169, 254, 170, 2]
        || octets == [100, 100, 100, 200]
        || v4.is_link_local()
    {
        return IpExposureClass::CloudMetadataLinkLocal;
    }
    let is_cgnat = first == 100 && (64..=127).contains(&second);
    let is_special_non_public = (first == 192 && second == 0 && (third == 0 || third == 2))
        || (first == 198 && (second == 18 || second == 19))
        || (first == 198 && second == 51 && third == 100)
        || (first == 203 && second == 0 && third == 113);
    let is_reserved_or_bcast = first >= 240;
    if v4.is_private()
        || is_cgnat
        || is_special_non_public
        || v4.is_multicast()
        || is_reserved_or_bcast
    {
        IpExposureClass::PrivateRfc1918
    } else {
        IpExposureClass::PublicRoutable
    }
}

fn classify_v6_exposure(v6: Ipv6Addr) -> IpExposureClass {
    let [s0, s1, s2, s3, ..] = v6.segments();
    if v6.is_loopback() || v6.is_unspecified() {
        return IpExposureClass::Loopback;
    }
    if v6 == Ipv6Addr::new(0xFD00, 0x0EC2, 0, 0, 0, 0, 0, 0x0254)
        || v6 == Ipv6Addr::new(0xFD20, 0x00CE, 0, 0, 0, 0, 0, 0x0254)
        || (s0 & 0xFFC0) == 0xFE80
    {
        return IpExposureClass::CloudMetadataLinkLocal;
    }
    let is_site_local_deprecated = (s0 & 0xFFC0) == 0xFEC0;
    let is_nat64_local = s0 == 0x0064 && s1 == 0xFF9B && s2 == 1;
    let is_special_non_public = (s0 == 0x0100 && s1 == 0 && s2 == 0 && s3 == 0)
        || (s0 == 0x2001 && s1 == 0x0002 && s2 == 0)
        || (s0 == 0x2001 && s1 == 0x0DB8)
        || (s0 == 0x3FFF && (s1 & 0xF000) == 0);
    if v6.is_unique_local()
        || v6.is_multicast()
        || is_site_local_deprecated
        || is_nat64_local
        || is_special_non_public
    {
        IpExposureClass::PrivateRfc1918
    } else {
        IpExposureClass::PublicRoutable
    }
}

fn u16_pair_to_ipv4(hi: u16, lo: u16) -> Ipv4Addr {
    Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo))
}

fn parse_ip_part(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if hex.is_empty() {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    } else if part.len() > 1 && part.starts_with('0') {
        if !part.bytes().all(|b| (b'0'..=b'7').contains(&b)) {
            return None;
        }
        u32::from_str_radix(part, 8).ok()
    } else if part.bytes().all(|b| b.is_ascii_digit()) {
        part.parse::<u32>().ok()
    } else {
        None
    }
}
