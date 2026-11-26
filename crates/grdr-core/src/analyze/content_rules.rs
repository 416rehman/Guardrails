// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Deterministic byte-level secret and PII recogniser rules (`D-10`, `D-28`).

use std::sync::LazyLock;

use regex::bytes::{Regex as BytesRegex, RegexBuilder as BytesRegexBuilder};

use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};

use crate::analyze::content::{ContentFindingMatch, FindingDetectorKind};
use crate::analyze::types::{AnalyzeFact, FactOriginTag, Span};

const FINDING_HMAC_DOMAIN: &str = "grdr.analyze.finding.v1";
const CONTENT_REGEX_DFA_SIZE_LIMIT: usize = 256 * 1024;

static RE_OPENAI: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{24,}\b"));
static RE_ANTHROPIC: LazyLock<Option<BytesRegex>> = LazyLock::new(|| {
    compile_bytes_regex(
        r"\b(?:sk-ant-(?:api|admin|oat|sid)\d{0,2}-|(?:ant-)?api\d{2}-)[A-Za-z0-9_-]{24,}\b",
    )
});
static RE_GITHUB: LazyLock<Option<BytesRegex>> = LazyLock::new(|| {
    compile_bytes_regex(
        r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b",
    )
});
static RE_GITLAB: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\bglpat-[A-Za-z0-9_-]{20,}\b"));
static RE_HUGGINGFACE: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\bhf_[A-Za-z0-9]{20,}\b"));
static RE_NPM: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\bnpm_[A-Za-z0-9]{20,}\b"));
static RE_AWS_KEY: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\b(?:AKIA|ASIA|AROA|ABIA|ACCA)[0-9A-Z]{16}\b"));
static RE_AWS_SECRET_CTX: LazyLock<Option<BytesRegex>> = LazyLock::new(|| {
    compile_bytes_regex(
        r#"(?i)(?:aws_secret_access_key|aws_secret_key|secret_access_key|secretaccesskey)["']?\s*[:=]\s*["']?([A-Za-z0-9/+=]{40})(?:["'\s,;\}\]\)]|$)"#,
    )
});
static RE_STRIPE: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"));
static RE_SLACK: LazyLock<Option<BytesRegex>> = LazyLock::new(|| {
    compile_bytes_regex(
        r"\bxox[bpasor]-[0-9A-Za-z-]{16,}\b|\bxapp-\d+-[A-Za-z0-9-]{16,}\b|\bxoxe\.xox[bp]-\d+-[A-Za-z0-9_-]{16,}\b",
    )
});
static RE_GCP: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\bAIza[0-9A-Za-z_-]{35}\b"));
static RE_JWT: LazyLock<Option<BytesRegex>> = LazyLock::new(|| {
    compile_bytes_regex(r"\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b")
});
static RE_PEM_KEY_BLOCK: LazyLock<Option<BytesRegex>> = LazyLock::new(|| {
    compile_bytes_regex(concat!(
        r"-----BEGIN ",
        r"[A-Z0-9 ]*PRIVATE KEY-----(?s:.*?)-----END ",
        r"[A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN ",
        r"PGP PRIVATE KEY BLOCK-----(?s:.*?)-----END ",
        r"PGP PRIVATE KEY BLOCK-----",
    ))
});
static RE_PEM_KEY_HEADER: LazyLock<Option<BytesRegex>> = LazyLock::new(|| {
    compile_bytes_regex(concat!(
        r"(?:-----BEGIN ",
        r"[A-Z0-9 ]*PRIVATE KEY-----|-----BEGIN ",
        r"PGP PRIVATE KEY BLOCK-----)",
        r"[ \t]*(?:\r?\n[ \t]*[A-Za-z][A-Za-z0-9-]{0,31}:[ \t]*[^\r\n]*)*(?:(?:\r?\n[ \t]*)?(?:\r?\n[ \t]*[A-Za-z0-9+/=]+[ \t]*)+)?",
    ))
});
static RE_CARD_CANDIDATE: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\b\d+(?:[ -]\d+)*\b"));
static RE_IBAN: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"(?i)\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]){11,30}\b"));
static RE_SSN: LazyLock<Option<BytesRegex>> =
    LazyLock::new(|| compile_bytes_regex(r"\b\d{3}-\d{2}-\d{4}\b"));

fn compile_bytes_regex(pattern: &str) -> Option<BytesRegex> {
    BytesRegexBuilder::new(pattern)
        .dfa_size_limit(CONTENT_REGEX_DFA_SIZE_LIMIT)
        .build()
        .ok()
}

/// Scans raw bytes for secret and PII findings at `layer` using `offset_base` for layer-0 chunking.
pub(crate) fn scan_layer_bytes(
    data: &[u8],
    offset_base: usize,
    layer: u8,
    hmac_key: Option<&[u8]>,
    matches: &mut Vec<ContentFindingMatch>,
    facts: &mut Vec<AnalyzeFact>,
) {
    let secret_rules: [(&Option<BytesRegex>, &str); 12] = [
        (&RE_OPENAI, "openai_api_key"),
        (&RE_ANTHROPIC, "anthropic_api_key"),
        (&RE_GITHUB, "github_token"),
        (&RE_GITLAB, "gitlab_token"),
        (&RE_HUGGINGFACE, "huggingface_token"),
        (&RE_NPM, "npm_token"),
        (&RE_AWS_KEY, "aws_access_key"),
        (&RE_STRIPE, "stripe_live_key"),
        (&RE_SLACK, "slack_token"),
        (&RE_GCP, "google_api_key"),
        (&RE_JWT, "jwt_token"),
        (&RE_AWS_SECRET_CTX, "aws_secret_key"),
    ];

    let mut pem_ranges: Vec<(usize, usize)> = Vec::new();
    if let Some(re) = &*RE_PEM_KEY_BLOCK {
        for m in re.find_iter(data) {
            pem_ranges.push((m.start(), m.end()));
            push_finding(
                FindingDetectorKind::Secret,
                "private_key_pem",
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
    if let Some(re) = &*RE_PEM_KEY_HEADER {
        for m in re.find_iter(data) {
            let covered = pem_ranges
                .iter()
                .any(|&(s, e)| m.start() >= s && m.start() < e);
            if !covered {
                push_finding(
                    FindingDetectorKind::Secret,
                    "private_key_pem",
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

    for (opt_re, kind) in secret_rules {
        let Some(re) = opt_re else {
            continue;
        };
        if kind == "aws_secret_key" {
            for caps in re.captures_iter(data) {
                if let Some(m) = caps.get(1) {
                    push_finding(
                        FindingDetectorKind::Secret,
                        kind,
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
            continue;
        }
        for m in re.find_iter(data) {
            if kind == "openai_api_key" && m.as_bytes().starts_with(b"sk-ant-") {
                continue;
            }
            push_finding(
                FindingDetectorKind::Secret,
                kind,
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

    scan_credit_cards(data, offset_base, layer, hmac_key, matches, facts);
    scan_iban_and_ssn(data, offset_base, layer, hmac_key, matches, facts);
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

fn scan_credit_cards(
    data: &[u8],
    offset_base: usize,
    layer: u8,
    hmac_key: Option<&[u8]>,
    matches: &mut Vec<ContentFindingMatch>,
    facts: &mut Vec<AnalyzeFact>,
) {
    let Some(re) = &*RE_CARD_CANDIDATE else {
        return;
    };
    for m in re.find_iter(data) {
        let slice = m.as_bytes();
        let ranges = extract_card_subranges(slice);
        for (rel_s, rel_e) in ranges {
            if let Some(cand) = slice.get(rel_s..rel_e) {
                push_finding(
                    FindingDetectorKind::Pii,
                    "credit_card_pan",
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

fn scan_iban_and_ssn(
    data: &[u8],
    offset_base: usize,
    layer: u8,
    hmac_key: Option<&[u8]>,
    matches: &mut Vec<ContentFindingMatch>,
    facts: &mut Vec<AnalyzeFact>,
) {
    if let Some(re) = &*RE_IBAN {
        for m in re.find_iter(data) {
            if let Ok(text) = std::str::from_utf8(m.as_bytes())
                && iban_valid(text)
            {
                push_finding(
                    FindingDetectorKind::Pii,
                    "iban",
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
    if let Some(re) = &*RE_SSN {
        for m in re.find_iter(data) {
            if ssn_bytes_valid(m.as_bytes()) {
                push_finding(
                    FindingDetectorKind::Pii,
                    "us_ssn",
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
