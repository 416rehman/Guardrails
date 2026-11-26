// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Observable canonicalization, IP/IDNA/URL/PURL normalization, and guard/public filters (`docs/design/14`).

use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use url::Url;

use crate::IntelError;
use crate::record::ObservableKind;
use crate::validators::{
    canonicalize_strict_dns_domain, validate_observable_syntax, validate_purl_syntax,
};

const MAX_PUBLIC_ARTEFACT_BYTES: usize = 4_096;

const PRIVATE_HOST_SUFFIXES: &[&str] = &[
    "localhost",
    "local",
    "internal",
    "corp",
    "lan",
    "home",
    "arpa",
    "intranet",
    "localdomain",
];

/// Canonicalizes an observable into a normalized `(kind:value)` key.
#[must_use]
pub fn normalize_observable(kind: ObservableKind, raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(char::is_control) {
        return String::new();
    }
    let body = match kind {
        ObservableKind::Domain => canonicalize_domain(trimmed),
        ObservableKind::IpAddress => canonicalize_ip_or_fallback(trimmed),
        ObservableKind::Url => canonicalize_url_or_fallback(trimmed),
        ObservableKind::PackagePurl => canonicalize_purl(trimmed),
        ObservableKind::Sha256 | ObservableKind::SignerFingerprint => trimmed.to_ascii_lowercase(),
        ObservableKind::Cve | ObservableKind::Ghsa => trimmed.to_ascii_lowercase(),
    };
    if body.is_empty() {
        String::new()
    } else {
        format!("{kind:?}:{body}")
    }
}

/// Splits a canonicalized `PackagePurl` into `(base_index_key, Option<version>)`.
/// Other observable kinds return `(canonical_key, None)`.
#[must_use]
pub fn canonical_index_key_and_version(
    kind: ObservableKind,
    raw: &str,
) -> (String, Option<String>) {
    let full = normalize_observable(kind, raw);
    if full.is_empty() || kind != ObservableKind::PackagePurl {
        return (full, None);
    }
    let prefix = format!("{kind:?}:");
    let body = full.strip_prefix(&prefix).unwrap_or(&full);
    let (base, ver) = split_purl_body_and_version(body);
    (format!("{prefix}{base}"), ver.map(str::to_owned))
}

/// Normalizes a domain name using UTS-46 IDNA ASCII conversion and strict DNS label checks.
#[must_use]
pub fn canonicalize_domain(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return String::new();
    }
    let ip_candidate = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if let Some(ip) = parse_canonical_ip(ip_candidate) {
        return ip.to_string();
    }
    canonicalize_strict_dns_domain(trimmed).unwrap_or_default()
}

/// Canonicalizes IPv4 (including octal/hex/decimal integer forms) and IPv6
/// (including IPv4-mapped `::ffff:a.b.c.d`, IPv4-compatible, and NAT64 forms).
#[must_use]
pub fn parse_canonical_ip(raw: &str) -> Option<IpAddr> {
    let clean = raw.trim().trim_start_matches('[').trim_end_matches(']');
    if let Ok(v4) = clean.parse::<Ipv4Addr>() {
        return Some(IpAddr::V4(v4));
    }
    if let Some(v4) = parse_non_canonical_ipv4(clean) {
        return Some(IpAddr::V4(v4));
    }
    if let Ok(v6) = clean.parse::<Ipv6Addr>() {
        if let Some(mapped) = extract_embedded_ipv4(v6) {
            return Some(IpAddr::V4(mapped));
        }
        return Some(IpAddr::V6(v6));
    }
    None
}

/// Extracts and canonicalizes the host component of a URL or domain observable.
#[must_use]
pub fn extract_canonical_host(kind: ObservableKind, raw_or_canonical: &str) -> Option<String> {
    let bare = strip_kind_prefix(kind, raw_or_canonical);
    match kind {
        ObservableKind::Domain => {
            let host = canonicalize_domain(bare);
            if host.is_empty() { None } else { Some(host) }
        }
        ObservableKind::IpAddress => parse_canonical_ip(bare).map(|ip| ip.to_string()),
        ObservableKind::Url => {
            let parsed = Url::parse(bare).ok()?;
            let host_str = parsed.host_str()?;
            let clean = host_str.trim_matches(|c| c == '[' || c == ']');
            if let Some(ip) = parse_canonical_ip(clean) {
                return Some(ip.to_string());
            }
            let dom = canonicalize_domain(clean);
            if dom.is_empty() { None } else { Some(dom) }
        }
        _ => None,
    }
}

/// Checks whether a canonical observable exactly matches a configured guard-list domain/host.
/// Subdomains of multi-tenant hosts (e.g. `evil.s3.amazonaws.com`) do NOT match `s3.amazonaws.com`.
#[must_use]
pub fn is_guard_listed_host(
    kind: ObservableKind,
    raw_or_canonical: &str,
    guard_domains: &BTreeSet<String>,
) -> bool {
    if guard_domains.is_empty() {
        return false;
    }
    let Some(host) = extract_canonical_host(kind, raw_or_canonical) else {
        return false;
    };
    guard_domains.contains(&host)
}

/// Validates that an observable refers to a structurally public artefact suitable for
/// privacy-preserving `k=5` sightings (rejecting internal URLs, credentials, and private IPs/domains).
pub fn validate_public_artefact(kind: ObservableKind, raw: &str) -> Result<String, IntelError> {
    let trimmed = raw.trim();
    if trimmed.is_empty()
        || trimmed.len() > MAX_PUBLIC_ARTEFACT_BYTES
        || trimmed.chars().any(char::is_control)
    {
        return Err(IntelError::SightingRejected(
            "empty, oversized, or control-character observable cannot be recorded".into(),
        ));
    }
    match kind {
        ObservableKind::Url => {
            let parsed = Url::parse(trimmed).map_err(|_| {
                IntelError::SightingRejected("sighting URL failed strict WHATWG parsing".into())
            })?;
            if parsed.scheme() != "https" && parsed.scheme() != "http" {
                return Err(IntelError::SightingRejected(
                    "only http/https public URLs are eligible for sightings".into(),
                ));
            }
            if !parsed.username().is_empty() || parsed.password().is_some() {
                return Err(IntelError::SightingRejected(
                    "URLs with embedded credentials cannot enter sightings".into(),
                ));
            }
            let host = extract_canonical_host(ObservableKind::Url, trimmed).ok_or_else(|| {
                IntelError::SightingRejected("sighting URL missing valid host".into())
            })?;
            ensure_public_host(&host)?;
        }
        ObservableKind::Domain => {
            let host = canonicalize_strict_dns_domain(trimmed).ok_or_else(|| {
                IntelError::SightingRejected("invalid domain syntax for sighting".into())
            })?;
            if !host.contains('.') {
                return Err(IntelError::SightingRejected(
                    "single-label or empty domain cannot enter sightings".into(),
                ));
            }
            ensure_public_host(&host)?;
        }
        ObservableKind::IpAddress => {
            let ip = parse_canonical_ip(trimmed).ok_or_else(|| {
                IntelError::SightingRejected("invalid IP address for sighting".into())
            })?;
            if !is_globally_routable_ip(ip) {
                return Err(IntelError::SightingRejected(
                    "private or non-routable IP cannot enter sightings".into(),
                ));
            }
        }
        ObservableKind::PackagePurl => {
            validate_purl_syntax(trimmed)
                .map_err(|msg| IntelError::SightingRejected(msg.into()))?;
            let lower = canonicalize_purl(trimmed);
            if lower.starts_with("pkg:local/") || lower.starts_with("pkg:generic/") {
                return Err(IntelError::SightingRejected(
                    "private or generic package coordinates cannot enter sightings".into(),
                ));
            }
        }
        ObservableKind::Sha256 => {
            if trimmed.len() != 64 || !trimmed.bytes().all(|b| b.is_ascii_hexdigit()) {
                return Err(IntelError::SightingRejected(
                    "invalid SHA-256 digest for sighting".into(),
                ));
            }
        }
        ObservableKind::SignerFingerprint | ObservableKind::Cve | ObservableKind::Ghsa => {
            validate_observable_syntax(kind, trimmed, MAX_PUBLIC_ARTEFACT_BYTES)
                .map_err(|msg| IntelError::SightingRejected(msg.into()))?;
        }
    }

    let key = normalize_observable(kind, trimmed);
    if key.is_empty() {
        return Err(IntelError::SightingRejected(
            "observable failed canonicalization".into(),
        ));
    }
    Ok(key)
}

fn ensure_public_host(host: &str) -> Result<(), IntelError> {
    if let Some(ip) = parse_canonical_ip(host) {
        if !is_globally_routable_ip(ip) {
            return Err(IntelError::SightingRejected(
                "private or non-routable IP host rejected from sightings".into(),
            ));
        }
        return Ok(());
    }
    let strict_host = canonicalize_strict_dns_domain(host)
        .ok_or_else(|| IntelError::SightingRejected("invalid host syntax for sighting".into()))?;
    if !strict_host.contains('.') {
        return Err(IntelError::SightingRejected(
            "single-label internal host rejected from sightings".into(),
        ));
    }
    for suffix in PRIVATE_HOST_SUFFIXES {
        if strict_host == *suffix || strict_host.ends_with(&format!(".{suffix}")) {
            return Err(IntelError::SightingRejected(format!(
                "internal host suffix `.{suffix}` rejected from sightings"
            )));
        }
    }
    Ok(())
}

pub(crate) fn is_globally_routable_ip(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let oct = v4.octets();
            let [o0, o1, o2, _] = oct;
            let is_zero_net = o0 == 0;
            let is_cgnat = o0 == 100 && (64..=127).contains(&o1);
            let is_ietf_protocol = o0 == 192 && o1 == 0 && o2 == 0;
            let is_doc_1 = o0 == 192 && o1 == 0 && o2 == 2;
            let is_benchmarking = o0 == 198 && (18..=19).contains(&o1);
            let is_doc_2 = o0 == 198 && o1 == 51 && o2 == 100;
            let is_doc_3 = o0 == 203 && o1 == 0 && o2 == 113;
            let is_reserved_240 = o0 >= 240;
            !(v4.is_loopback()
                || v4.is_private()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_broadcast()
                || v4.is_unspecified()
                || is_zero_net
                || is_cgnat
                || is_ietf_protocol
                || is_doc_1
                || is_benchmarking
                || is_doc_2
                || is_doc_3
                || is_reserved_240)
        }
        IpAddr::V6(v6) => {
            let segs = v6.segments();
            let seg0 = segs.first().copied().unwrap_or(0);
            let seg1 = segs.get(1).copied().unwrap_or(0);
            let seg2 = segs.get(2).copied().unwrap_or(0);
            let seg3 = segs.get(3).copied().unwrap_or(0);
            let seg4 = segs.get(4).copied().unwrap_or(0);
            let seg5 = segs.get(5).copied().unwrap_or(0);
            let is_ula = (seg0 & 0xFE00) == 0xFC00;
            let is_link_local = (seg0 & 0xFFC0) == 0xFE80;
            let is_site_local = (seg0 & 0xFFC0) == 0xFEC0;
            let is_doc = seg0 == 0x2001 && seg1 == 0x0DB8;
            let is_doc_rfc9637 = seg0 == 0x3FFF && (seg1 & 0xF000) == 0x0000;
            let is_bmwg = seg0 == 0x2001 && seg1 == 0x0002 && seg2 == 0x0000;
            let is_orchid = seg0 == 0x2001 && (seg1 & 0xFFF0) == 0x0010;
            let is_orchid_v2 = seg0 == 0x2001 && (seg1 & 0xFFF0) == 0x0020;
            let is_nat64_local = seg0 == 0x0064 && seg1 == 0xFF9B && seg2 == 0x0001;
            let is_discard = seg0 == 0x0100 && seg1 == 0 && seg2 == 0 && seg3 == 0;
            let is_v4_translated =
                seg0 == 0 && seg1 == 0 && seg2 == 0 && seg3 == 0 && seg4 == 0xFFFF && seg5 == 0;
            let is_v4_mapped_non_routable = v6
                .to_ipv4_mapped()
                .is_some_and(|v4| !is_globally_routable_ip(IpAddr::V4(v4)));
            let is_6to4_non_routable = seg0 == 0x2002
                && !is_globally_routable_ip(IpAddr::V4(Ipv4Addr::from(
                    (u32::from(seg1) << 16) | u32::from(seg2),
                )));
            !(v6.is_loopback()
                || v6.is_multicast()
                || v6.is_unspecified()
                || is_ula
                || is_link_local
                || is_site_local
                || is_doc
                || is_doc_rfc9637
                || is_bmwg
                || is_orchid
                || is_orchid_v2
                || is_nat64_local
                || is_discard
                || is_v4_translated
                || is_v4_mapped_non_routable
                || is_6to4_non_routable)
        }
    }
}

fn canonicalize_ip_or_fallback(raw: &str) -> String {
    parse_canonical_ip(raw).map_or_else(|| raw.trim().to_ascii_lowercase(), |ip| ip.to_string())
}

fn canonicalize_url_or_fallback(raw: &str) -> String {
    let Ok(mut parsed) = Url::parse(raw) else {
        return raw.trim().to_ascii_lowercase();
    };
    if parsed.cannot_be_a_base() {
        if !parsed.username().is_empty() || parsed.password().is_some() {
            return String::new();
        }
    } else if parsed.set_username("").is_err() || parsed.set_password(None).is_err() {
        return String::new();
    }
    if let Some(host_str) = parsed.host_str() {
        let clean = host_str.trim_matches(|c| c == '[' || c == ']');
        let set_res = if let Some(ip) = parse_canonical_ip(clean) {
            let formatted = match ip {
                IpAddr::V4(v4) => v4.to_string(),
                IpAddr::V6(v6) => format!("[{v6}]"),
            };
            parsed.set_host(Some(&formatted))
        } else {
            let dom = canonicalize_domain(clean);
            if dom.is_empty() {
                return String::new();
            }
            parsed.set_host(Some(&dom))
        };
        if set_res.is_err() {
            return String::new();
        }
    }
    parsed.set_fragment(None);
    parsed.to_string()
}

pub(crate) fn canonicalize_purl(raw: &str) -> String {
    let trimmed = raw.trim();
    let without_frag = trimmed.split('#').next().unwrap_or(trimmed);
    let without_qual = without_frag.split('?').next().unwrap_or(without_frag);
    let lower = without_qual.to_ascii_lowercase();
    if let Some(slash_idx) = lower.rfind('/')
        && let (Some(prefix), Some(tail)) = (lower.get(..slash_idx), lower.get(slash_idx..))
    {
        return format!("{}{}", prefix.replace("%40", "@"), tail);
    }
    lower.replace("%40", "@")
}

pub(crate) fn split_purl_body_and_version(body: &str) -> (&str, Option<&str>) {
    let Some(slash_idx) = body.rfind('/') else {
        return (body, None);
    };
    let tail = body.get(slash_idx..).unwrap_or("");
    let Some(rel_at) = tail.rfind('@') else {
        return (body, None);
    };
    let abs_at = slash_idx.saturating_add(rel_at);
    let base = body.get(..abs_at).unwrap_or(body);
    let ver = body.get(abs_at.saturating_add(1)..).unwrap_or("");
    if ver.is_empty() {
        (base, None)
    } else {
        (base, Some(ver))
    }
}

fn strip_kind_prefix(kind: ObservableKind, raw_or_canonical: &str) -> &str {
    let prefix = format!("{kind:?}:");
    raw_or_canonical
        .strip_prefix(&prefix)
        .unwrap_or(raw_or_canonical)
}

fn extract_embedded_ipv4(v6: Ipv6Addr) -> Option<Ipv4Addr> {
    if let Some(v4) = v6.to_ipv4_mapped() {
        return Some(v4);
    }
    let segs = v6.segments();
    let is_nat64 = segs.first() == Some(&0x0064)
        && segs.get(1) == Some(&0xFF9B)
        && segs.get(2) == Some(&0)
        && segs.get(3) == Some(&0)
        && segs.get(4) == Some(&0)
        && segs.get(5) == Some(&0);
    if is_nat64 && let (Some(&hi), Some(&lo)) = (segs.get(6), segs.get(7)) {
        return Some(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    let is_compat = segs.first() == Some(&0)
        && segs.get(1) == Some(&0)
        && segs.get(2) == Some(&0)
        && segs.get(3) == Some(&0)
        && segs.get(4) == Some(&0)
        && segs.get(5) == Some(&0)
        && !(segs.get(6) == Some(&0) && matches!(segs.get(7), Some(&0) | Some(&1)));
    if is_compat && let (Some(&hi), Some(&lo)) = (segs.get(6), segs.get(7)) {
        return Some(Ipv4Addr::from((u32::from(hi) << 16) | u32::from(lo)));
    }
    None
}

fn parse_non_canonical_ipv4(raw: &str) -> Option<Ipv4Addr> {
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

fn parse_ip_part(part: &str) -> Option<u32> {
    if part.is_empty() {
        return None;
    }
    if let Some(hex) = part.strip_prefix("0x").or_else(|| part.strip_prefix("0X")) {
        if hex.is_empty() || !hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return None;
        }
        u32::from_str_radix(hex, 16).ok()
    } else if part.len() > 1
        && part.starts_with('0')
        && part.bytes().all(|b| (b'0'..=b'7').contains(&b))
    {
        u32::from_str_radix(part, 8).ok()
    } else if part.bytes().all(|b| b.is_ascii_digit()) {
        part.parse::<u32>().ok()
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round6_validate_public_artefact_validates_cve_ghsa_signer_and_byte_cap() {
        assert_eq!(
            validate_public_artefact(ObservableKind::Cve, " CVE-2026-12345 ").unwrap(),
            "Cve:cve-2026-12345"
        );
        assert_eq!(
            validate_public_artefact(ObservableKind::Ghsa, "GHSA-aaaa-bbbb-cccc").unwrap(),
            "Ghsa:ghsa-aaaa-bbbb-cccc"
        );
        assert_eq!(
            validate_public_artefact(ObservableKind::SignerFingerprint, "SHA256:ABCDEF0123456789")
                .unwrap(),
            "SignerFingerprint:sha256:abcdef0123456789"
        );

        for (kind, bad) in [
            (ObservableKind::Cve, "not-a-cve"),
            (ObservableKind::Cve, "CVE-1990-1234"),
            (ObservableKind::Ghsa, "GHSA-bad"),
            (ObservableKind::Ghsa, "ghsa-111-2222-3333"),
            (ObservableKind::SignerFingerprint, "fp with space"),
        ] {
            assert!(
                validate_public_artefact(kind, bad).is_err(),
                "expected {kind:?}={bad:?} to fail public validation"
            );
        }

        let over_fp = "f".repeat(MAX_PUBLIC_ARTEFACT_BYTES + 1);
        assert!(validate_public_artefact(ObservableKind::SignerFingerprint, &over_fp).is_err());

        let over_url = format!(
            "https://public.example/{}",
            "a".repeat(MAX_PUBLIC_ARTEFACT_BYTES)
        );
        assert!(validate_public_artefact(ObservableKind::Url, &over_url).is_err());
    }
}
