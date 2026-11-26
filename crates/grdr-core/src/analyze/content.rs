// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Deterministic binary-safe secret & PII recognisers (`D-10`, `D-28`) returning spans and keyed HMAC digests.

use std::cmp::Reverse;

use serde::{Deserialize, Serialize};

use crate::analyze::content_rules::scan_layer_bytes;
use crate::analyze::decode::{DecodeStatus, decode_payload_layers_checked};
use crate::analyze::types::{AnalyzeFact, AnalyzeLimits, FactOriginTag, Span};

pub use crate::analyze::content_rules::{iban_valid, luhn_valid};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum FindingDetectorKind {
    Secret,
    Pii,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentFindingMatch {
    pub detector_kind: FindingDetectorKind,
    pub label: String,
    pub span: Span,
    pub sha256_hex: String,
    pub origin: FactOriginTag,
    pub decoded_layer: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContentScanReport {
    pub matches: Vec<ContentFindingMatch>,
    pub facts: Vec<AnalyzeFact>,
    pub decoded_layers: u8,
}

/// Scans input plus up to 3 decoded layers for deterministic secrets and checksum-validated PII.
/// Omits unkeyed digests when called without a caller secret key so low-entropy PII is never brute-forceable (`P8`).
#[must_use]
pub fn scan_deterministic_content(raw: &[u8]) -> ContentScanReport {
    scan_deterministic_content_internal(raw, None)
}

/// Scans input with a caller-supplied HMAC key and schema scan-byte ceiling.
#[must_use]
pub fn scan_deterministic_content_with_key(raw: &[u8], hmac_key: &[u8]) -> ContentScanReport {
    scan_deterministic_content_internal(raw, Some(hmac_key))
}

fn scan_deterministic_content_internal(raw: &[u8], hmac_key: Option<&[u8]>) -> ContentScanReport {
    let limits = AnalyzeLimits::from_schema();
    let max_scan = limits.content_max_scan_bytes;
    let bounded = raw.get(..raw.len().min(max_scan)).unwrap_or(&[]);
    let mut matches = Vec::new();
    let mut facts = Vec::new();

    if raw.len() > max_scan {
        facts.push(AnalyzeFact {
            key: "content.truncated".into(),
            value: raw.len().to_string(),
            origin: FactOriginTag::Deterministic,
            span: None,
        });
    }

    scan_layer_bytes(bounded, 0, 0, hmac_key, &mut matches, &mut facts);

    let (layers, decoded_variants, decode_err) = decode_payload_layers_checked(bounded);
    for (idx, variant) in decoded_variants.iter().enumerate() {
        let layer_num = u8::try_from(idx.saturating_add(1)).unwrap_or(u8::MAX);
        let var_bounded = variant.get(..variant.len().min(max_scan)).unwrap_or(&[]);
        scan_layer_bytes(
            var_bounded,
            0,
            layer_num,
            hmac_key,
            &mut matches,
            &mut facts,
        );
    }
    match decode_err {
        Some(DecodeStatus::LimitExceeded) => facts.push(AnalyzeFact {
            key: "content.decode_truncated".into(),
            value: "true".into(),
            origin: FactOriginTag::Deterministic,
            span: None,
        }),
        Some(DecodeStatus::Malformed) => facts.push(AnalyzeFact {
            key: "content.decode_malformed".into(),
            value: "true".into(),
            origin: FactOriginTag::Deterministic,
            span: None,
        }),
        _ => {}
    }

    ContentScanReport {
        matches,
        facts,
        decoded_layers: layers,
    }
}

/// Redacts deterministic secret and PII spans across the full text using `[REDACTED:<label>:redacted]`.
#[must_use]
pub fn redact_sensitive_text(raw: &str) -> String {
    redact_sensitive_text_internal(raw, None)
}

/// Redacts deterministic secret and PII spans across chunk boundaries without leaking digest prefixes.
#[must_use]
pub fn redact_sensitive_text_with_key(raw: &str, hmac_key: &[u8]) -> String {
    redact_sensitive_text_internal(raw, Some(hmac_key))
}

fn redact_sensitive_text_internal(raw: &str, hmac_key: Option<&[u8]>) -> String {
    if raw.is_empty() {
        return String::new();
    }
    let chunk_size = AnalyzeLimits::from_schema()
        .content_max_scan_bytes
        .max(1024);
    let mut matches = Vec::new();
    let mut facts = Vec::new();
    let mut start_off: usize = 0;

    while start_off < raw.len() {
        let mut end_off = start_off.saturating_add(chunk_size).min(raw.len());
        while end_off > start_off && !raw.is_char_boundary(end_off) {
            end_off = end_off.saturating_sub(1);
        }
        if end_off == start_off {
            break;
        }
        if let Some(chunk) = raw.as_bytes().get(start_off..end_off) {
            scan_layer_bytes(chunk, start_off, 0, hmac_key, &mut matches, &mut facts);
        }
        if end_off >= raw.len() {
            break;
        }
        let overlap = chunk_size / 8;
        let mut next_start = end_off.saturating_sub(overlap);
        while next_start < end_off && !raw.is_char_boundary(next_start) {
            next_start = next_start.saturating_add(1);
        }
        if next_start <= start_off {
            next_start = end_off;
        }
        start_off = next_start;
    }

    let merged = merge_redaction_spans(raw, &mut matches);
    if merged.is_empty() {
        return raw.to_owned();
    }

    let mut out = String::with_capacity(raw.len());
    let mut cursor: usize = 0;
    for (start, end, label) in merged {
        if let Some(prefix) = raw.get(cursor..start) {
            out.push_str(prefix);
        }
        out.push_str(&format!("[REDACTED:{label}:redacted]"));
        cursor = end;
    }
    if let Some(tail) = raw.get(cursor..) {
        out.push_str(tail);
    }
    out
}

/// Computes Shannon entropy in milli-bits on ASCII tokens; heuristic only.
#[must_use]
pub fn token_entropy_milli_bits(token: &str) -> u32 {
    let bytes = token.as_bytes();
    let total = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    if total == 0 {
        return 0;
    }
    let mut counts = [0_u32; 256];
    for &b in bytes {
        if let Some(slot) = counts.get_mut(usize::from(b)) {
            *slot = slot.saturating_add(1);
        }
    }
    let total_f = f64::from(total);
    let mut entropy = 0.0_f64;
    for &c in &counts {
        if c > 0 {
            let p = f64::from(c) / total_f;
            entropy -= p * p.log2();
        }
    }
    round_milli_bits_to_u32(entropy * 1000.0)
}

fn merge_redaction_spans(
    raw: &str,
    matches: &mut [ContentFindingMatch],
) -> Vec<(usize, usize, String)> {
    matches.sort_by_key(|m| (m.span.start, Reverse(m.span.end)));
    let mut merged: Vec<(usize, usize, String)> = Vec::new();
    for item in matches {
        let start = usize::try_from(item.span.start).unwrap_or(0);
        let end = usize::try_from(item.span.end).unwrap_or(0);
        if end > raw.len()
            || start >= end
            || !raw.is_char_boundary(start)
            || !raw.is_char_boundary(end)
        {
            continue;
        }
        if let Some(prev) = merged.last_mut()
            && start <= prev.1
        {
            if end > prev.1 {
                prev.1 = end;
            }
            continue;
        }
        merged.push((start, end, item.label.clone()));
    }
    merged
}

fn round_milli_bits_to_u32(val: f64) -> u32 {
    if !val.is_finite() || val <= 0.0 {
        return 0;
    }
    let mut lo = 0_u32;
    let mut hi = 8_000_u32;
    while lo < hi {
        let mid = lo.saturating_add(hi.saturating_sub(lo).div_ceil(2));
        if f64::from(mid) - 0.5 <= val {
            lo = mid;
        } else {
            hi = mid.saturating_sub(1);
        }
    }
    lo
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scans_binary_bytes_pem_blocks_and_new_secret_formats() {
        let mut payload = vec![0xFF, 0xFE, b' '];
        payload.extend_from_slice(
            concat!(
                "-----BEGIN ",
                "RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEAtestbody\n-----END ",
                "RSA PRIVATE KEY-----\n"
            )
            .as_bytes(),
        );
        payload.extend_from_slice(
            concat!(
                " aws_secret_access_key=",
                "wJalrXUtn",
                "FEMI/K7MDENG/",
                "bPxRfiCYEXAMPLEKEY"
            )
            .as_bytes(),
        );
        payload.extend_from_slice(
            concat!(
                " token=",
                "glpat-",
                "abcdefghijklmnopqr1234 ",
                "hf_",
                "ABCDEFGHIJKLMNOPQRST"
            )
            .as_bytes(),
        );

        let report = scan_deterministic_content(&payload);
        assert!(report.matches.iter().any(|m| m.label == "private_key_pem"));
        assert!(report.matches.iter().any(|m| m.label == "aws_secret_key"));
        assert!(report.matches.iter().any(|m| m.label == "gitlab_token"));
        assert!(
            report
                .matches
                .iter()
                .any(|m| m.label == "huggingface_token")
        );
    }

    #[test]
    fn redacts_full_pem_body_past_truncation_without_leaking_hash_prefix() {
        let text = format!(
            "{} {}PRIVATE KEY-----\nSECRET_KEY_BODY_LINE\n{}PRIVATE KEY----- 4111111111111111 12",
            "x".repeat(600_000),
            "-----BEGIN ",
            "-----END ",
        );
        let redacted = redact_sensitive_text(&text);
        assert!(!redacted.contains("SECRET_KEY_BODY_LINE"));
        assert!(!redacted.contains("4111111111111111"));
        assert!(redacted.ends_with("[REDACTED:credit_card_pan:redacted] 12"));

        let trunc = scan_deterministic_content(text.as_bytes());
        assert!(trunc.facts.iter().any(|f| f.key == "content.truncated"));
    }

    #[test]
    fn uses_hmac_digest_and_rejects_raw_sha256_correlation() {
        let ssn = b"123-45-6789";
        let r1 = scan_deterministic_content_with_key(ssn, b"key-one");
        let r2 = scan_deterministic_content_with_key(ssn, b"key-two");
        assert_ne!(r1.matches[0].sha256_hex, r2.matches[0].sha256_hex);
        assert_ne!(r1.matches[0].sha256_hex, grdr_crypto::sha256_hex(ssn));
    }

    #[test]
    fn detects_spaced_iban_and_stripped_anthropic_key() {
        assert!(
            !scan_deterministic_content(b"DE89 3704 0044 0532 0130 00")
                .matches
                .is_empty()
        );
        assert!(
            scan_deterministic_content(
                concat!(
                    "key=",
                    "api03-",
                    "abcdefghijkl",
                    "mnopqrstuvwxyz",
                    "0123456789"
                )
                .as_bytes()
            )
            .matches
            .iter()
            .any(|m| m.label == "anthropic_api_key")
        );

        let quoted_aws = concat!(
            r#"{"aws_secret_access_key": ""#,
            "wJalrXUtn",
            "FEMI/K7MDENG/",
            r#"bPxRfiCYEXAMPLEKEY"}"#,
        )
        .as_bytes();
        let aws_rep = scan_deterministic_content(quoted_aws);
        assert!(aws_rep.matches.iter().any(|m| m.label == "aws_secret_key"));
        assert!(aws_rep.matches[0].sha256_hex.is_empty());

        let anth = scan_deterministic_content(
            concat!(
                "sk-ant-", "api03-", "ABCDEFGH", "IJKLMNOP", "QRSTUVWX", "YZ012345"
            )
            .as_bytes(),
        );
        assert!(anth.matches.iter().any(|m| m.label == "anthropic_api_key"));
        assert!(!anth.matches.iter().any(|m| m.label == "openai_api_key"));

        let trunc_b64 = "c2st".repeat(400_000);
        let b64_rep = scan_deterministic_content(trunc_b64.as_bytes());
        assert!(
            b64_rep
                .facts
                .iter()
                .any(|f| f.key == "content.decode_truncated" || f.key == "content.truncated")
        );
    }

    #[test]
    fn round4_truncated_pem_pgp_aws_paren_and_anthropic_tokens() {
        let long_b64 = "QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVowMTIzNDU2Nzg5".repeat(8);
        let trunc_pem = format!(
            "{}PRIVATE KEY-----\n{long_b64}\n\ntrailing ok",
            "-----BEGIN "
        );
        let red_pem = redact_sensitive_text(&trunc_pem);
        assert!(!red_pem.contains(&long_b64));
        assert!(red_pem.contains("[REDACTED:private_key_pem:redacted]"));
        assert!(red_pem.ends_with("\n\ntrailing ok"));

        let trunc_pgp = format!("{}PGP PRIVATE KEY BLOCK-----\n\n{long_b64}", "-----BEGIN ");
        let red_pgp = redact_sensitive_text(&trunc_pgp);
        assert!(!red_pgp.contains(&long_b64));
        assert!(red_pgp.contains("[REDACTED:private_key_pem:redacted]"));

        let indented_pem = concat!(
            "  -----BEGIN ",
            "RSA PRIVATE KEY-----\n  MIIEowIBAAKCAQEAtestbody"
        );
        let red_indented = redact_sensitive_text(indented_pem);
        assert!(!red_indented.contains("MIIEowIBAAKCAQEAtestbody"));
        assert!(red_indented.contains("[REDACTED:private_key_pem:redacted]"));

        let paren_aws = concat!(
            "set(aws_secret_access_key=",
            "wJalrXUtn",
            "FEMI/K7MDENG/",
            "bPxRfiCYEXAMPLEKEY)"
        )
        .as_bytes();
        assert!(
            scan_deterministic_content(paren_aws)
                .matches
                .iter()
                .any(|m| m.label == "aws_secret_key")
        );

        for tok in [
            concat!(
                "sk-ant-", "admin01-", "ABCDEFGH", "IJKLMNOP", "QRSTUVWX", "YZ012345"
            )
            .as_bytes(),
            concat!(
                "sk-ant-", "oat01-", "ABCDEFGH", "IJKLMNOP", "QRSTUVWX", "YZ012345"
            )
            .as_bytes(),
        ] {
            let rep = scan_deterministic_content(tok);
            assert!(
                rep.matches.iter().any(|m| m.label == "anthropic_api_key"),
                "expected anthropic_api_key for {:?}",
                String::from_utf8_lossy(tok)
            );
        }
    }

    #[test]
    fn round5_pem_trailing_banner_spaces_and_long_pgp_armor_headers() {
        let trailing_ws_pem = concat!(
            "-----BEGIN ",
            "PRIVATE KEY-----   \t \nMIIEowIBAAKCAQEAtestbody"
        );
        let red_ws = redact_sensitive_text(trailing_ws_pem);
        assert!(!red_ws.contains("MIIEowIBAAKCAQEAtestbody"));
        assert!(red_ws.contains("[REDACTED:private_key_pem:redacted]"));

        let long_comment = "a".repeat(1_200);
        let long_pgp = format!(
            "{}PGP PRIVATE KEY BLOCK-----  \nVersion: GnuPG v2\nComment: {long_comment}\n\nMIIEowIBAAKCAQEAtestbody   \t",
            "-----BEGIN "
        );
        let red_pgp = redact_sensitive_text(&long_pgp);
        assert!(!red_pgp.contains("MIIEowIBAAKCAQEAtestbody"));
        assert!(!red_pgp.contains(&long_comment));
        assert!(red_pgp.contains("[REDACTED:private_key_pem:redacted]"));
    }
}
