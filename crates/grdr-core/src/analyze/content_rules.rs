// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Deterministic byte-level secret and PII recogniser rules (`D-10`, `D-28`).

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};

use crate::analyze::content::{ContentFindingMatch, FindingDetectorKind};
use crate::analyze::pack_lists::{
    CompiledRecogniser, ContentRecogniserCatalog, RecogniserPostValidator,
    default_content_recognisers,
};
use crate::analyze::types::{AnalyzeFact, FactOriginTag, Span};

const FINDING_HMAC_DOMAIN: &str = "grdr.analyze.finding.v1";

/// Scans raw bytes for secret and PII findings at `layer` using signed YAML recognisers.
pub(crate) fn scan_layer_bytes(
    data: &[u8],
    offset_base: usize,
    layer: u8,
    hmac_key: Option<&[u8]>,
    matches: &mut Vec<ContentFindingMatch>,
    facts: &mut Vec<AnalyzeFact>,
) -> Result<(), &'static str> {
    let catalog = default_content_recognisers()?;
    scan_layer_bytes_with_catalog(data, offset_base, layer, hmac_key, catalog, matches, facts);
    Ok(())
}

/// Scans raw bytes against an explicit dynamically loaded `ContentRecogniserCatalog`.
pub(crate) fn scan_layer_bytes_with_catalog(
    data: &[u8],
    offset_base: usize,
    layer: u8,
    hmac_key: Option<&[u8]>,
    catalog: &ContentRecogniserCatalog,
    matches: &mut Vec<ContentFindingMatch>,
    facts: &mut Vec<AnalyzeFact>,
) {
    let mut pem_ranges: Vec<(usize, usize)> = Vec::new();
    for rule in &catalog.rules {
        apply_recogniser(
            rule,
            data,
            offset_base,
            layer,
            hmac_key,
            &mut pem_ranges,
            matches,
            facts,
        );
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_recogniser(
    rule: &CompiledRecogniser,
    data: &[u8],
    offset_base: usize,
    layer: u8,
    hmac_key: Option<&[u8]>,
    pem_ranges: &mut Vec<(usize, usize)>,
    matches: &mut Vec<ContentFindingMatch>,
    facts: &mut Vec<AnalyzeFact>,
) {
    match rule.post_validator {
        RecogniserPostValidator::PemBlock => {
            for m in rule.regex.find_iter(data) {
                pem_ranges.push((m.start(), m.end()));
                push_finding(
                    rule.detector_kind,
                    &rule.rule_kind,
                    offset_base.saturating_add(m.start()),
                    offset_base.saturating_add(m.end()),
                    m.as_bytes(),
                    layer,
                    hmac_key,
                    matches,
                    facts,
                );
            }
        }
        RecogniserPostValidator::PemHeaderUncovered => {
            for m in rule.regex.find_iter(data) {
                let covered = pem_ranges
                    .iter()
                    .any(|&(s, e)| m.start() >= s && m.start() < e);
                if !covered {
                    push_finding(
                        rule.detector_kind,
                        &rule.rule_kind,
                        offset_base.saturating_add(m.start()),
                        offset_base.saturating_add(m.end()),
                        m.as_bytes(),
                        layer,
                        hmac_key,
                        matches,
                        facts,
                    );
                }
            }
        }
        RecogniserPostValidator::LuhnSubranges => {
            for m in rule.regex.find_iter(data) {
                let slice = m.as_bytes();
                for (rel_s, rel_e) in extract_card_subranges(slice) {
                    if let Some(cand) = slice.get(rel_s..rel_e) {
                        push_finding(
                            rule.detector_kind,
                            &rule.rule_kind,
                            offset_base.saturating_add(m.start()).saturating_add(rel_s),
                            offset_base.saturating_add(m.start()).saturating_add(rel_e),
                            cand,
                            layer,
                            hmac_key,
                            matches,
                            facts,
                        );
                    }
                }
            }
        }
        RecogniserPostValidator::IbanMod97 => {
            for m in rule.regex.find_iter(data) {
                if let Ok(text) = std::str::from_utf8(m.as_bytes())
                    && iban_valid(text)
                {
                    push_finding(
                        rule.detector_kind,
                        &rule.rule_kind,
                        offset_base.saturating_add(m.start()),
                        offset_base.saturating_add(m.end()),
                        m.as_bytes(),
                        layer,
                        hmac_key,
                        matches,
                        facts,
                    );
                }
            }
        }
        RecogniserPostValidator::UsSsnBounds => {
            for m in rule.regex.find_iter(data) {
                if ssn_bytes_valid(m.as_bytes()) {
                    push_finding(
                        rule.detector_kind,
                        &rule.rule_kind,
                        offset_base.saturating_add(m.start()),
                        offset_base.saturating_add(m.end()),
                        m.as_bytes(),
                        layer,
                        hmac_key,
                        matches,
                        facts,
                    );
                }
            }
        }
        RecogniserPostValidator::None => {
            if rule.capture_group > 0 {
                for caps in rule.regex.captures_iter(data) {
                    if let Some(m) = caps.get(rule.capture_group) {
                        push_finding(
                            rule.detector_kind,
                            &rule.rule_kind,
                            offset_base.saturating_add(m.start()),
                            offset_base.saturating_add(m.end()),
                            m.as_bytes(),
                            layer,
                            hmac_key,
                            matches,
                            facts,
                        );
                    }
                }
                return;
            }
            for m in rule.regex.find_iter(data) {
                if rule
                    .exclude_prefix
                    .as_deref()
                    .is_some_and(|prefix| m.as_bytes().starts_with(prefix))
                {
                    continue;
                }
                push_finding(
                    rule.detector_kind,
                    &rule.rule_kind,
                    offset_base.saturating_add(m.start()),
                    offset_base.saturating_add(m.end()),
                    m.as_bytes(),
                    layer,
                    hmac_key,
                    matches,
                    facts,
                );
            }
        }
    }
}

#[must_use]
pub fn luhn_valid(digits: &[u8]) -> bool {
    if digits.len() < 13 || digits.len() > 19 || digits.iter().all(|&d| d == 0) {
        return false;
    }
    let mut sum: u32 = 0;
    let mut alt = false;
    for &digit in digits.iter().rev() {
        if digit > 9 {
            return false;
        }
        let mut val = u32::from(digit);
        if alt {
            val = val.saturating_mul(2);
            if val > 9 {
                val = val.saturating_sub(9);
            }
        }
        sum = sum.saturating_add(val);
        alt = !alt;
    }
    sum.is_multiple_of(10)
}

#[must_use]
pub fn iban_valid(raw: &str) -> bool {
    let clean: Vec<u8> = raw
        .bytes()
        .filter(|b| b.is_ascii_alphanumeric())
        .map(|b| b.to_ascii_uppercase())
        .collect();
    if clean.len() < 15 || clean.len() > 34 {
        return false;
    }
    let Some(tail) = clean.get(4..) else {
        return false;
    };
    let Some(head) = clean.get(..4) else {
        return false;
    };
    let mut rem: u32 = 0;
    for &b in tail.iter().chain(head.iter()) {
        if b.is_ascii_digit() {
            rem = (rem
                .saturating_mul(10)
                .saturating_add(u32::from(b.saturating_sub(b'0'))))
                % 97;
        } else if b.is_ascii_uppercase() {
            let val = u32::from(b.saturating_sub(b'A')).saturating_add(10);
            rem = (rem.saturating_mul(100).saturating_add(val)) % 97;
        } else {
            return false;
        }
    }
    rem == 1
}

fn extract_card_subranges(slice: &[u8]) -> Vec<(usize, usize)> {
    let mut group_starts = vec![0usize];
    for (idx, &b) in slice.iter().enumerate() {
        if (b == b' ' || b == b'-') && idx.saturating_add(1) < slice.len() {
            group_starts.push(idx.saturating_add(1));
        }
    }
    let mut group_ends = Vec::with_capacity(group_starts.len());
    for (idx, &b) in slice.iter().enumerate() {
        if b == b' ' || b == b'-' {
            group_ends.push(idx);
        }
    }
    group_ends.push(slice.len());

    let mut out = Vec::new();
    let mut gi = 0usize;
    while gi < group_starts.len() {
        let mut matched_end: Option<(usize, usize)> = None;
        for (gj, &end_pos) in group_ends.iter().enumerate().skip(gi) {
            let start_pos = *group_starts.get(gi).unwrap_or(&0);
            let Some(sub) = slice.get(start_pos..end_pos) else {
                continue;
            };
            let digits: Vec<u8> = sub
                .iter()
                .copied()
                .filter(u8::is_ascii_digit)
                .map(|b| b.saturating_sub(b'0'))
                .collect();
            if digits.len() > 19 {
                break;
            }
            if digits.len() >= 13 && luhn_valid(&digits) {
                matched_end = Some((gj, end_pos));
            }
        }
        if let Some((gj, end_pos)) = matched_end {
            let start_pos = *group_starts.get(gi).unwrap_or(&0);
            out.push((start_pos, end_pos));
            gi = gj.saturating_add(1);
        } else {
            gi = gi.saturating_add(1);
        }
    }
    out
}

#[allow(clippy::too_many_arguments)]
fn push_finding(
    detector_kind: FindingDetectorKind,
    label: &str,
    start: usize,
    end: usize,
    matched_bytes: &[u8],
    layer: u8,
    hmac_key: Option<&[u8]>,
    matches: &mut Vec<ContentFindingMatch>,
    facts: &mut Vec<AnalyzeFact>,
) {
    let span = Span::from_usize(start, end);
    let digest = match hmac_key {
        Some(key) => {
            let mac = domain_hmac_sha256(key, FINDING_HMAC_DOMAIN, matched_bytes);
            encode_lower_hex(&mac)
        }
        None => String::new(),
    };
    matches.push(ContentFindingMatch {
        detector_kind,
        label: label.to_owned(),
        span,
        sha256_hex: digest,
        origin: FactOriginTag::Deterministic,
        decoded_layer: layer,
    });
    match detector_kind {
        FindingDetectorKind::Secret => {
            facts.push(AnalyzeFact {
                key: "content.secret".into(),
                value: label.to_owned(),
                origin: FactOriginTag::Deterministic,
                span: Some(span),
            });
            facts.push(AnalyzeFact {
                key: "secret.type".into(),
                value: label.to_owned(),
                origin: FactOriginTag::Deterministic,
                span: Some(span),
            });
        }
        FindingDetectorKind::Pii => {
            facts.push(AnalyzeFact {
                key: "pii.class".into(),
                value: label.to_owned(),
                origin: FactOriginTag::Deterministic,
                span: Some(span),
            });
        }
    }
}

fn ssn_bytes_valid(raw: &[u8]) -> bool {
    let digits: Vec<u8> = raw
        .iter()
        .copied()
        .filter(u8::is_ascii_digit)
        .map(|b| b.saturating_sub(b'0'))
        .collect();
    if digits.len() != 9 {
        return false;
    }
    let area = u16::from(*digits.first().unwrap_or(&0))
        .saturating_mul(100)
        .saturating_add(u16::from(*digits.get(1).unwrap_or(&0)).saturating_mul(10))
        .saturating_add(u16::from(*digits.get(2).unwrap_or(&0)));
    let group = u16::from(*digits.get(3).unwrap_or(&0))
        .saturating_mul(10)
        .saturating_add(u16::from(*digits.get(4).unwrap_or(&0)));
    let serial = u16::from(*digits.get(5).unwrap_or(&0))
        .saturating_mul(1000)
        .saturating_add(u16::from(*digits.get(6).unwrap_or(&0)).saturating_mul(100))
        .saturating_add(u16::from(*digits.get(7).unwrap_or(&0)).saturating_mul(10))
        .saturating_add(u16::from(*digits.get(8).unwrap_or(&0)));
    area != 0 && area != 666 && area < 900 && group != 0 && serial != 0
}
