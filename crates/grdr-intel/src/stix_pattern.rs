// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strict STIX 2.1 pattern encoding, grammar parsing, and observable validation.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use grdr_crypto::{encode_lower_hex, sha256_digest};

use crate::IntelError;
use crate::record::{GrdrIntelId, IntelObservable, ObservableKind};
use crate::validators::{
    canonicalize_strict_dns_domain, validate_cve_syntax, validate_http_https_url,
    validate_sha256_syntax,
};

pub(crate) fn fallback_stix_id(
    org_id: &str,
    idx: usize,
    pattern: &str,
) -> Result<GrdrIntelId, IntelError> {
    let input = format!("{org_id}:{idx}:{pattern}");
    let digest = sha256_digest(input.as_bytes());
    let year_raw =
        u16::from_le_bytes([*digest.first().unwrap_or(&0), *digest.get(1).unwrap_or(&0)]);
    let year_off = year_raw % 7_976;
    let year = 2024_u16.saturating_add(year_off);
    let seq_raw = u32::from_le_bytes([
        *digest.get(2).unwrap_or(&0),
        *digest.get(3).unwrap_or(&0),
        *digest.get(4).unwrap_or(&0),
        *digest.get(5).unwrap_or(&0),
    ]);
    let seq = (seq_raw % 99_999).saturating_add(1);
    GrdrIntelId::parse(&format!("GRDRI-{year:04}-{seq:05}"))
}

pub(crate) fn stix_pattern_for_observable(obs: &IntelObservable) -> Option<String> {
    let escaped = escape_stix_single_quoted(&obs.value);
    match obs.kind {
        ObservableKind::Sha256 => Some(format!("[file:hashes.'SHA-256' = '{escaped}']")),
        ObservableKind::Domain => Some(format!("[domain-name:value = '{escaped}']")),
        ObservableKind::Url => Some(format!("[url:value = '{escaped}']")),
        ObservableKind::IpAddress => {
            if obs.value.trim().parse::<Ipv6Addr>().is_ok() {
                Some(format!("[ipv6-addr:value = '{escaped}']"))
            } else {
                Some(format!("[ipv4-addr:value = '{escaped}']"))
            }
        }
        _ => None,
    }
}

fn escape_stix_single_quoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '\'' => out.push_str("\\'"),
            other => out.push(other),
        }
    }
    out
}

pub(crate) fn parse_stix_pattern(pattern: &str) -> Result<IntelObservable, IntelError> {
    let trimmed = pattern.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
        .ok_or_else(|| {
            IntelError::CodecParse("STIX pattern must be a single `[...]` block".into())
        })?;
    let (lhs_raw, rhs_raw) = inner
        .split_once('=')
        .ok_or_else(|| IntelError::CodecParse("invalid STIX equality pattern".into()))?;
    let lhs = lhs_raw.trim();
    if lhs.ends_with('!') || lhs.ends_with('<') || lhs.ends_with('>') {
        return Err(IntelError::CodecParse(
            "unsupported STIX comparison operator".into(),
        ));
    }
    let val = parse_stix_single_quoted_rhs(rhs_raw.trim())?;
    let lower_lhs = lhs.to_ascii_lowercase();
    let kind = match lower_lhs.as_str() {
        "file:hashes.'sha-256'" | "file:hashes.\"sha-256\"" | "file:hashes.sha-256" => {
            ObservableKind::Sha256
        }
        "domain-name:value" => ObservableKind::Domain,
        "url:value" => ObservableKind::Url,
        "ipv4-addr:value" => {
            if val.parse::<Ipv4Addr>().is_err() {
                return Err(IntelError::CodecParse(
                    "invalid IPv4 literal in STIX".into(),
                ));
            }
            ObservableKind::IpAddress
        }
        "ipv6-addr:value" => {
            if val.parse::<Ipv6Addr>().is_err() {
                return Err(IntelError::CodecParse(
                    "invalid IPv6 literal in STIX".into(),
                ));
            }
            ObservableKind::IpAddress
        }
        _ => {
            return Err(IntelError::CodecParse(
                "unsupported STIX pattern observable".into(),
            ));
        }
    };
    validate_observable_value(kind, &val)?;
    Ok(IntelObservable {
        kind,
        value: val,
        version_range: None,
    })
}

fn parse_stix_single_quoted_rhs(rhs: &str) -> Result<String, IntelError> {
    let rest = rhs
        .strip_prefix('\'')
        .ok_or_else(|| IntelError::CodecParse("STIX literal must start with `'`".into()))?;
    let mut out = String::new();
    let mut chars = rest.chars();
    let mut closed = false;
    while let Some(ch) = chars.next() {
        match ch {
            '\\' => {
                let escaped = chars.next().ok_or_else(|| {
                    IntelError::CodecParse("dangling escape in STIX literal".into())
                })?;
                if escaped != '\\' && escaped != '\'' {
                    return Err(IntelError::CodecParse(
                        "unsupported escape in STIX literal".into(),
                    ));
                }
                out.push(escaped);
            }
            '\'' => {
                closed = true;
                break;
            }
            other => out.push(other),
        }
    }
    if !closed || !chars.as_str().trim().is_empty() {
        return Err(IntelError::CodecParse(
            "unclosed or compound trailing STIX pattern".into(),
        ));
    }
    Ok(out)
}

pub(crate) fn validate_observable_value(kind: ObservableKind, val: &str) -> Result<(), IntelError> {
    if val.trim().is_empty() || val.chars().any(char::is_control) {
        return Err(IntelError::CodecParse(
            "empty or control-character observable".into(),
        ));
    }
    match kind {
        ObservableKind::Sha256 => {
            validate_sha256_syntax(val).map_err(|msg| IntelError::CodecParse(msg.into()))?;
        }
        ObservableKind::IpAddress => {
            if val.parse::<IpAddr>().is_err() {
                return Err(IntelError::CodecParse("invalid IP address".into()));
            }
        }
        ObservableKind::Url => {
            validate_http_https_url(val, 4_096)
                .map_err(|msg| IntelError::CodecParse(msg.into()))?;
        }
        ObservableKind::Domain => {
            let trimmed = val.strip_suffix('.').unwrap_or(val);
            if trimmed.is_empty()
                || val != val.trim()
                || val
                    .chars()
                    .any(|c| c.is_whitespace() || matches!(c, '\'' | '"' | '[' | ']' | '\\' | ';'))
                || canonicalize_strict_dns_domain(val).is_none()
            {
                return Err(IntelError::CodecParse("invalid domain observable".into()));
            }
        }
        ObservableKind::Cve => {
            validate_cve_syntax(val).map_err(|msg| IntelError::CodecParse(msg.into()))?;
        }
        _ => {}
    }
    Ok(())
}

pub(crate) fn deterministic_stix_uuid(record_id: &str, idx: usize) -> String {
    let mut digest = sha256_digest(format!("{record_id}:{idx}").as_bytes());
    if let Some(ver) = digest.get_mut(6) {
        *ver = (*ver & 0x0F) | 0x50;
    }
    if let Some(var) = digest.get_mut(8) {
        *var = (*var & 0x3F) | 0x80;
    }
    let hex = encode_lower_hex(&digest);
    let p1 = hex.get(0..8).unwrap_or("00000000");
    let p2 = hex.get(8..12).unwrap_or("0000");
    let p3 = hex.get(12..16).unwrap_or("5000");
    let p4 = hex.get(16..20).unwrap_or("8000");
    let p5 = hex.get(20..32).unwrap_or("000000000000");
    format!("{p1}-{p2}-{p3}-{p4}-{p5}")
}
