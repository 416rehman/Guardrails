// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Multi-layer recursive payload peeling across base64, hex, URL-percent, UTF-16LE, and gzip (`D-10`).

use crate::analyze::decode::{
    DecodeBudget, DecodeKind, DecodeOutcome, DecodeStatus, MIN_AUTO_B64_CHARS, MIN_HEX_RUN_BYTES,
    decode_base64_with_budget, decode_hex_with_budget, decode_strict_utf16le,
    decode_url_percent_once_bytes,
};
use crate::analyze::deflate::{GunzipErr, gunzip_bounded};

pub fn decode_payload_layers(raw: &[u8]) -> (u8, Vec<Vec<u8>>) {
    let (layers, variants, _) = decode_payload_layers_checked(raw);
    (layers, variants)
}

pub(crate) fn decode_payload_layers_checked(
    raw: &[u8],
) -> (u8, Vec<Vec<u8>>, Option<DecodeStatus>) {
    let mut budget = DecodeBudget::from_schema();
    if raw.len() > budget.remaining_bytes {
        return (0, Vec::new(), Some(DecodeStatus::LimitExceeded));
    }
    let mut variants = Vec::new();
    let mut current = raw.to_vec();
    let mut layers: u8 = 0;

    while layers < budget.max_layers {
        match peel_one_layer(&current, &mut budget) {
            Ok(Some(decoded)) if decoded != current => {
                layers = layers.saturating_add(1);
                variants.push(decoded.clone());
                current = decoded;
            }
            Ok(_) => break,
            Err(status) => return (layers, variants, Some(status)),
        }
    }
    (layers, variants, None)
}

pub fn decode_payload_layers_with_budget(
    raw: &[u8],
    budget: &mut DecodeBudget,
) -> Result<(u8, Vec<Vec<u8>>), DecodeStatus> {
    if raw.len() > budget.remaining_bytes {
        return Err(DecodeStatus::LimitExceeded);
    }
    let mut variants = Vec::new();
    let mut current = raw.to_vec();
    let mut layers: u8 = 0;

    while layers < budget.max_layers {
        let next = peel_one_layer(&current, budget)?;
        let Some(decoded) = next else {
            break;
        };
        if decoded == current {
            break;
        }
        layers = layers.saturating_add(1);
        variants.push(decoded.clone());
        current = decoded;
    }
    Ok((layers, variants))
}

pub(super) fn bytes_to_peeled_text(
    bytes: &[u8],
    budget: &mut DecodeBudget,
    outcome: &mut DecodeOutcome,
) -> String {
    match decode_payload_layers_with_budget(bytes, budget) {
        Ok((extra, variants)) if extra > 0 => {
            outcome.layers = outcome
                .layers
                .max(1_u8.saturating_add(extra).min(budget.max_layers));
            for v in variants {
                outcome
                    .decoded_payloads
                    .push(String::from_utf8_lossy(&v).into_owned());
            }
        }
        Err(status) => outcome.status = outcome.status.merge(status),
        _ => {}
    }
    String::from_utf8_lossy(bytes).into_owned()
}

pub(super) fn recursively_peel_payload(
    decoded: &str,
    current_layer: u8,
    budget: &mut DecodeBudget,
    outcome: &mut DecodeOutcome,
) {
    if current_layer >= budget.max_layers {
        return;
    }
    match decode_payload_layers_with_budget(decoded.as_bytes(), budget) {
        Ok((extra_layers, variants)) if extra_layers > 0 => {
            outcome.layers = outcome.layers.max(
                current_layer
                    .saturating_add(extra_layers)
                    .min(budget.max_layers),
            );
            for v in variants {
                outcome
                    .decoded_payloads
                    .push(String::from_utf8_lossy(&v).into_owned());
            }
        }
        Err(status) => outcome.status = outcome.status.merge(status),
        _ => {}
    }
}

pub(super) fn decode_base64_payload_layers(
    b64: &str,
    budget: &mut DecodeBudget,
) -> Result<(u8, Vec<DecodeKind>, Vec<String>), DecodeStatus> {
    let first = decode_base64_with_budget(b64, budget)?;
    let mut kinds = vec![DecodeKind::Base64Utf8];
    let mut decoded_texts = Vec::new();
    let mut current = first;
    let mut layers: u8 = 1;

    while layers < budget.max_layers {
        if current.starts_with(&[0x1F, 0x8B]) {
            current = gunzip_bounded(&current, budget.remaining_bytes).map_err(map_gunzip_err)?;
            budget.consume_bytes(current.len())?;
            kinds.push(DecodeKind::Gzip);
            layers = layers.saturating_add(1);
            continue;
        }
        if looks_like_clean_utf16le(&current)
            && let Ok(text) = decode_strict_utf16le(&current)
        {
            budget.consume_bytes(text.len())?;
            current = text.into_bytes();
            kinds.push(DecodeKind::Base64Utf16Le);
            layers = layers.saturating_add(1);
            continue;
        }
        if let Some(next) = peel_one_layer(&current, budget)?
            && next != current
        {
            decoded_texts.push(String::from_utf8_lossy(&current).into_owned());
            current = next;
            kinds.push(DecodeKind::Base64Utf8);
            layers = layers.saturating_add(1);
            continue;
        }
        break;
    }
    decoded_texts.push(String::from_utf8_lossy(&current).into_owned());
    Ok((layers, kinds, decoded_texts))
}

fn peel_one_layer(
    current: &[u8],
    budget: &mut DecodeBudget,
) -> Result<Option<Vec<u8>>, DecodeStatus> {
    if current.starts_with(&[0x1F, 0x8B]) {
        let gunzipped = gunzip_bounded(current, budget.remaining_bytes).map_err(map_gunzip_err)?;
        budget.consume_bytes(gunzipped.len())?;
        return Ok(Some(gunzipped));
    }
    if looks_like_clean_utf16le(current)
        && let Ok(text) = decode_strict_utf16le(current)
    {
        budget.consume_bytes(text.len())?;
        return Ok(Some(text.into_bytes()));
    }
    let Ok(text) = std::str::from_utf8(current) else {
        return Ok(None);
    };
    let trimmed = text.trim();
    let hex_body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    if hex_body.len() >= MIN_HEX_RUN_BYTES.saturating_mul(2)
        && hex_body.len().is_multiple_of(2)
        && hex_body.bytes().all(|b| b.is_ascii_hexdigit())
    {
        return decode_hex_with_budget(trimmed, budget).map(Some);
    }
    if trimmed.len() >= MIN_AUTO_B64_CHARS
        && trimmed.len() % 4 != 1
        && trimmed.bytes().all(is_b64_char)
    {
        match decode_base64_with_budget(trimmed, budget) {
            Ok(decoded) if is_plausible_b64_payload(&decoded) => return Ok(Some(decoded)),
            Err(DecodeStatus::LimitExceeded) => return Err(DecodeStatus::LimitExceeded),
            _ => {}
        }
    }
    if trimmed.contains('%') {
        let pct = decode_url_percent_once_bytes(trimmed.as_bytes());
        if pct != trimmed.as_bytes() {
            budget.consume_bytes(pct.len())?;
            return Ok(Some(pct));
        }
    }
    Ok(None)
}

fn is_plausible_b64_payload(decoded: &[u8]) -> bool {
    if decoded.starts_with(&[0x1F, 0x8B]) || looks_like_clean_utf16le(decoded) {
        return true;
    }
    std::str::from_utf8(decoded).is_ok_and(|s| {
        !s.contains('\0')
            && s.bytes()
                .all(|b| !b.is_ascii_control() || matches!(b, b'\n' | b'\r' | b'\t'))
    })
}

fn looks_like_clean_utf16le(bytes: &[u8]) -> bool {
    if bytes.len() < 4 || !bytes.len().is_multiple_of(2) {
        return false;
    }
    let pairs = bytes.as_chunks::<2>().0;
    pairs.iter().all(|p| {
        let lo = p.first().copied().unwrap_or(0);
        let hi = p.get(1).copied().unwrap_or(1);
        hi == 0 && (lo.is_ascii_graphic() || matches!(lo, b' ' | b'\n' | b'\r' | b'\t'))
    })
}

fn map_gunzip_err(err: GunzipErr) -> DecodeStatus {
    match err {
        GunzipErr::Malformed => DecodeStatus::Malformed,
        GunzipErr::LimitExceeded => DecodeStatus::LimitExceeded,
    }
}

const fn is_b64_char(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=' || b == b'-' || b == b'_'
}
