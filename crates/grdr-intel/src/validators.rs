// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Shared syntax validators for threat intel observables, URLs, domains, CVEs, GHSAs, and PURLs.

use idna::domain_to_ascii;
use url::Url;

use crate::canonical::{canonicalize_purl, parse_canonical_ip, split_purl_body_and_version};
use crate::record::ObservableKind;

const MAX_DNS_BYTES: usize = 253;
const MAX_DNS_LABEL_BYTES: usize = 63;
const MAX_PURL_BYTES: usize = 512;
const MAX_PURL_VERSION_BYTES: usize = 128;
const MIN_CVE_YEAR: u16 = 1999;

pub(crate) fn validate_sha256_syntax(raw: &str) -> Result<(), &'static str> {
    if raw.len() == 64 && raw.bytes().all(|b| b.is_ascii_hexdigit()) {
        Ok(())
    } else {
        Err("SHA-256 observable must be 64 hex chars")
    }
}

pub(crate) fn validate_cve_syntax(cve: &str) -> Result<(), &'static str> {
    if cve != cve.trim() || cve.chars().any(char::is_control) {
        return Err("invalid CVE identifier");
    }
    let Some(rest) = cve
        .strip_prefix("CVE-")
        .or_else(|| cve.strip_prefix("cve-"))
    else {
        return Err("CVE must start with `CVE-` or `cve-`");
    };
    let Some((year_s, seq_s)) = rest.split_once('-') else {
        return Err("CVE missing sequence separator");
    };
    if year_s.len() != 4
        || !year_s.bytes().all(|b| b.is_ascii_digit())
        || year_s.parse::<u16>().is_ok_and(|y| y < MIN_CVE_YEAR)
    {
        return Err("invalid CVE year");
    }
    if !(4..=10).contains(&seq_s.len()) || !seq_s.bytes().all(|b| b.is_ascii_digit()) {
        return Err("invalid CVE sequence number");
    }
    Ok(())
}

pub(crate) fn validate_ghsa_syntax(ghsa: &str) -> Result<(), &'static str> {
    if ghsa != ghsa.trim() || ghsa.len() != 19 || ghsa.chars().any(char::is_control) {
        return Err("invalid GHSA identifier format");
    }
    let Some(rest) = ghsa
        .strip_prefix("GHSA-")
        .or_else(|| ghsa.strip_prefix("ghsa-"))
    else {
        return Err("GHSA must start with `GHSA-` or `ghsa-`");
    };
    let parts: Vec<&str> = rest.split('-').collect();
    if parts.len() != 3
        || !parts
            .iter()
            .all(|p| p.len() == 4 && p.bytes().all(|b| b.is_ascii_alphanumeric()))
    {
        return Err("invalid GHSA segment format");
    }
    Ok(())
}

pub(crate) fn validate_http_https_url(raw: &str, max_bytes: usize) -> Result<Url, &'static str> {
    if raw.trim().is_empty()
        || raw != raw.trim()
        || raw.len() > max_bytes
        || raw.chars().any(char::is_control)
    {
        return Err("URL must be non-empty, control-free, and within byte bound");
    }
    let parsed = Url::parse(raw).map_err(|_| "invalid HTTP(S) URL syntax")?;
    if !matches!(parsed.scheme(), "http" | "https") {
        return Err("URL scheme must be http or https");
    }
    let Some(host_str) = parsed.host_str().filter(|h| !h.is_empty()) else {
        return Err("URL missing host");
    };
    if !parsed.username().is_empty() || parsed.password().is_some() {
        return Err("URL cannot contain embedded credentials");
    }
    let clean_host = host_str.trim_matches(|c| c == '[' || c == ']');
    if parse_canonical_ip(clean_host).is_none()
        && canonicalize_strict_dns_domain(clean_host).is_none()
    {
        return Err("URL host is not a valid IP or DNS domain");
    }
    Ok(parsed)
}

pub(crate) fn canonicalize_strict_dns_domain(raw: &str) -> Option<String> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c.is_control() || c.is_whitespace()) {
        return None;
    }
    let without_dot = trimmed.strip_suffix('.').unwrap_or(trimmed);
    if without_dot.is_empty() || without_dot.len() > MAX_DNS_BYTES {
        return None;
    }
    let ascii = domain_to_ascii(without_dot).ok()?;
    if ascii.is_empty() || ascii.len() > MAX_DNS_BYTES {
        return None;
    }
    if ascii.split('.').any(|lbl| {
        lbl.is_empty()
            || lbl.len() > MAX_DNS_LABEL_BYTES
            || lbl.starts_with('-')
            || lbl.ends_with('-')
            || !lbl.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
    }) {
        return None;
    }
    Some(ascii.to_ascii_lowercase())
}

pub(crate) fn validate_purl_syntax(raw: &str) -> Result<(), &'static str> {
    if raw.trim().is_empty()
        || raw != raw.trim()
        || raw.len() > MAX_PURL_BYTES
        || raw.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err("invalid PURL field");
    }
    let lower = canonicalize_purl(raw);
    let Some(rest) = lower.strip_prefix("pkg:") else {
        return Err("PURL must start with `pkg:`");
    };
    let Some((eco, rest_name)) = rest.split_once('/') else {
        return Err("PURL missing ecosystem/name");
    };
    if eco.is_empty()
        || !eco
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'.' | b'+'))
        || rest_name.is_empty()
    {
        return Err("PURL missing ecosystem or package name");
    }
    let (base, ver) = split_purl_body_and_version(&lower);
    if ver.is_none() && rest_name.ends_with('@') {
        return Err("PURL has empty version suffix");
    }
    if let Some(version) = ver
        && !is_valid_purl_version(version)
    {
        return Err("invalid PURL version suffix");
    }
    let base_name = base
        .strip_prefix("pkg:")
        .and_then(|s| s.split_once('/'))
        .map_or("", |(_, n)| n);
    if base_name.is_empty() || base_name.starts_with('/') || base_name.ends_with('/') {
        return Err("PURL missing package name");
    }
    if base_name.starts_with('@') {
        if !base_name.split_once('/').is_some_and(|(scope, pkg)| {
            scope.len() > 1
                && !scope.strip_prefix('@').is_some_and(|s| s.contains('@'))
                && !pkg.is_empty()
                && !pkg.contains('/')
                && !pkg.contains('@')
        }) {
            return Err("invalid scoped PURL package name");
        }
    } else if base_name.contains('@') || base_name.split('/').any(str::is_empty) {
        return Err("invalid PURL path segment");
    }
    Ok(())
}

pub(crate) fn validate_observable_syntax(
    kind: ObservableKind,
    val: &str,
    max_bytes: usize,
) -> Result<(), &'static str> {
    if val.trim().is_empty() || val.len() > max_bytes || val.chars().any(char::is_control) {
        return Err("observable value is empty, oversized, or contains control characters");
    }
    match kind {
        ObservableKind::Sha256 => validate_sha256_syntax(val),
        ObservableKind::IpAddress => parse_canonical_ip(val)
            .map(|_| ())
            .ok_or("invalid IP address observable"),
        ObservableKind::Domain => canonicalize_strict_dns_domain(val)
            .map(|_| ())
            .ok_or("invalid domain observable"),
        ObservableKind::Url => validate_http_https_url(val, max_bytes).map(|_| ()),
        ObservableKind::PackagePurl => validate_purl_syntax(val),
        ObservableKind::Cve => validate_cve_syntax(val),
        ObservableKind::Ghsa => validate_ghsa_syntax(val),
        ObservableKind::SignerFingerprint => {
            if val != val.trim() || val.chars().any(char::is_whitespace) {
                Err("invalid signer fingerprint observable")
            } else {
                Ok(())
            }
        }
    }
}

fn is_valid_purl_version(ver: &str) -> bool {
    !ver.is_empty()
        && ver.len() <= MAX_PURL_VERSION_BYTES
        && !ver.chars().any(|c| {
            c.is_control()
                || c.is_whitespace()
                || matches!(c, ',' | '|' | '<' | '>' | '=' | '!' | '~' | '^' | '@' | '/')
        })
}
