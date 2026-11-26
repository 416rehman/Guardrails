// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strict TLS `ClientHello` inspection without socket consumption or silent truncation.

use crate::ProxyError;
use crate::tls_policy::ClientHelloMetadata;

const TLS_CONTENT_TYPE_HANDSHAKE: u8 = 0x16;
const TLS_HANDSHAKE_CLIENT_HELLO: u8 = 0x01;
const TLS_EXT_SERVER_NAME: u16 = 0x0000;
const TLS_EXT_ALPN: u16 = 0x0010;
const TLS_EXT_ECH: u16 = 0xfe0d;
const MAX_SNI_HOST_BYTES: usize = 255;
const MAX_TLS_RECORD_BYTES: usize = 16_384;

/// Inspects an initial peeked buffer without consuming socket bytes.
/// Returns `Ok(None)` only when the record does not begin with a TLS Handshake (`0x16`).
pub fn peek_tls_client_hello(buf: &[u8]) -> Result<Option<ClientHelloMetadata>, ProxyError> {
    let Some(&record_type) = buf.first() else {
        return Ok(None);
    };
    if record_type != TLS_CONTENT_TYPE_HANDSHAKE {
        return Ok(None);
    }
    let Some(header) = buf.get(0..5) else {
        return Err(ProxyError::Sr39Rejected(
            "truncated TLS record header during ClientHello peek".into(),
        ));
    };
    let rec_ver = (
        header.get(1).copied().unwrap_or(0),
        header.get(2).copied().unwrap_or(0),
    );
    if rec_ver.0 != 0x03 {
        return Err(ProxyError::Sr39Rejected(
            "invalid TLS record legacy version".into(),
        ));
    }
    let rec_len = usize::from(u16::from_be_bytes([
        header.get(3).copied().unwrap_or(0),
        header.get(4).copied().unwrap_or(0),
    ]));
    if rec_len > MAX_TLS_RECORD_BYTES {
        return Err(ProxyError::Sr39Rejected(
            "TLS ClientHello record exceeds 16 KiB bound".into(),
        ));
    }
    let record_end = 5usize
        .checked_add(rec_len)
        .ok_or_else(|| ProxyError::Sr39Rejected("TLS record length overflow".into()))?;
    if buf.len() < record_end {
        return Err(ProxyError::Sr39Rejected(
            "truncated TLS ClientHello record payload".into(),
        ));
    }
    let record_payload = buf
        .get(5..record_end)
        .ok_or_else(|| ProxyError::Sr39Rejected("TLS record payload out of bounds".into()))?;
    if record_payload.len() < 4 {
        return Err(ProxyError::Sr39Rejected(
            "truncated TLS handshake header".into(),
        ));
    }
    if record_payload.first().copied() != Some(TLS_HANDSHAKE_CLIENT_HELLO) {
        return Err(ProxyError::Sr39Rejected(
            "expected TLS ClientHello handshake record".into(),
        ));
    }
    let hs_len = (usize::from(record_payload.get(1).copied().unwrap_or(0)) << 16)
        | (usize::from(record_payload.get(2).copied().unwrap_or(0)) << 8)
        | usize::from(record_payload.get(3).copied().unwrap_or(0));
    let hs_end = 4usize
        .checked_add(hs_len)
        .ok_or_else(|| ProxyError::Sr39Rejected("TLS ClientHello length overflow".into()))?;
    if record_payload.len() < hs_end {
        return Err(ProxyError::Sr39Rejected(
            "truncated TLS ClientHello handshake body".into(),
        ));
    }
    let body = record_payload
        .get(4..hs_end)
        .ok_or_else(|| ProxyError::Sr39Rejected("truncated TLS ClientHello body".into()))?;

    parse_client_hello_body(rec_ver, body).map(Some)
}

pub(crate) fn expected_tls_record_total_len(buf: &[u8]) -> Option<usize> {
    if buf.first().copied() != Some(TLS_CONTENT_TYPE_HANDSHAKE) {
        return None;
    }
    let header = buf.get(0..5)?;
    let rec_len = usize::from(u16::from_be_bytes([
        header.get(3).copied().unwrap_or(0),
        header.get(4).copied().unwrap_or(0),
    ]));
    5usize.checked_add(rec_len)
}

fn parse_client_hello_body(
    rec_ver: (u8, u8),
    body: &[u8],
) -> Result<ClientHelloMetadata, ProxyError> {
    let mut pos = 34usize;
    let hello_ver = (
        *body
            .first()
            .ok_or_else(|| ProxyError::Sr39Rejected("truncated TLS ClientHello version".into()))?,
        *body
            .get(1)
            .ok_or_else(|| ProxyError::Sr39Rejected("truncated TLS ClientHello version".into()))?,
    );
    let sid_len =
        usize::from(*body.get(pos).ok_or_else(|| {
            ProxyError::Sr39Rejected("truncated TLS ClientHello session_id".into())
        })?);
    pos = pos
        .checked_add(1)
        .and_then(|p| p.checked_add(sid_len))
        .ok_or_else(|| ProxyError::Sr39Rejected("TLS session_id overflow".into()))?;
    if pos > body.len() {
        return Err(ProxyError::Sr39Rejected("truncated TLS session_id".into()));
    }

    let cs_len = usize::from(read_u16(body, pos)?);
    pos = pos
        .checked_add(2)
        .and_then(|p| p.checked_add(cs_len))
        .ok_or_else(|| ProxyError::Sr39Rejected("TLS cipher_suites overflow".into()))?;
    if pos > body.len() {
        return Err(ProxyError::Sr39Rejected(
            "truncated TLS cipher_suites".into(),
        ));
    }

    let comp_len = usize::from(
        *body
            .get(pos)
            .ok_or_else(|| ProxyError::Sr39Rejected("truncated TLS compression_methods".into()))?,
    );
    pos = pos
        .checked_add(1)
        .and_then(|p| p.checked_add(comp_len))
        .ok_or_else(|| ProxyError::Sr39Rejected("TLS compression_methods overflow".into()))?;
    if pos > body.len() {
        return Err(ProxyError::Sr39Rejected(
            "truncated TLS compression_methods".into(),
        ));
    }

    let mut sni_host = None;
    let mut seen_sni_ext = false;
    let mut alpn_protocols = Vec::new();
    let mut has_ech = false;

    if pos < body.len() {
        let ext_total_len = usize::from(read_u16(body, pos)?);
        pos = pos.saturating_add(2);
        let ext_end = pos
            .checked_add(ext_total_len)
            .ok_or_else(|| ProxyError::Sr39Rejected("TLS extensions length overflow".into()))?;
        if ext_end > body.len() {
            return Err(ProxyError::Sr39Rejected(
                "truncated TLS ClientHello extensions".into(),
            ));
        }
        while pos < ext_end {
            if pos.saturating_add(4) > ext_end {
                return Err(ProxyError::Sr39Rejected(
                    "truncated TLS extension header".into(),
                ));
            }
            let ext_type = read_u16(body, pos)?;
            let ext_len = usize::from(read_u16(body, pos.saturating_add(2))?);
            let data_start = pos.saturating_add(4);
            let data_end = data_start
                .checked_add(ext_len)
                .ok_or_else(|| ProxyError::Sr39Rejected("TLS extension overflow".into()))?;
            if data_end > ext_end {
                return Err(ProxyError::Sr39Rejected(
                    "truncated TLS extension payload".into(),
                ));
            }
            let ext_bytes = body
                .get(data_start..data_end)
                .ok_or_else(|| ProxyError::Sr39Rejected("TLS extension slice oob".into()))?;
            match ext_type {
                TLS_EXT_SERVER_NAME => {
                    if seen_sni_ext {
                        return Err(ProxyError::Sr39Rejected(
                            "duplicate TLS server_name extension rejected".into(),
                        ));
                    }
                    seen_sni_ext = true;
                    sni_host = parse_sni_extension(ext_bytes)?;
                }
                TLS_EXT_ALPN => {
                    alpn_protocols = parse_alpn_extension(ext_bytes)?;
                }
                TLS_EXT_ECH => {
                    has_ech = true;
                }
                _ => {}
            }
            pos = data_end;
        }
    }

    Ok(ClientHelloMetadata {
        record_version: rec_ver,
        hello_version: hello_ver,
        sni_host,
        alpn_protocols,
        has_ech,
    })
}

fn read_u16(buf: &[u8], offset: usize) -> Result<u16, ProxyError> {
    let hi = *buf
        .get(offset)
        .ok_or_else(|| ProxyError::Sr39Rejected("truncated u16 in TLS ClientHello".into()))?;
    let lo = *buf
        .get(offset.saturating_add(1))
        .ok_or_else(|| ProxyError::Sr39Rejected("truncated u16 in TLS ClientHello".into()))?;
    Ok(u16::from_be_bytes([hi, lo]))
}

fn parse_sni_extension(ext: &[u8]) -> Result<Option<String>, ProxyError> {
    if ext.is_empty() {
        return Ok(None);
    }
    if ext.len() < 5 {
        return Err(ProxyError::Sr39Rejected(
            "malformed TLS server_name extension".into(),
        ));
    }
    let list_len = usize::from(read_u16(ext, 0)?);
    let end = 2usize.saturating_add(list_len);
    if end != ext.len() {
        return Err(ProxyError::Sr39Rejected(
            "TLS server_name list length disagrees with extension size".into(),
        ));
    }
    let mut pos = 2usize;
    let mut host_out: Option<String> = None;
    while pos < end {
        if pos.saturating_add(3) > end {
            return Err(ProxyError::Sr39Rejected(
                "truncated TLS server_name entry".into(),
            ));
        }
        let name_type = *ext.get(pos).unwrap_or(&0xff);
        let name_len = usize::from(read_u16(ext, pos.saturating_add(1))?);
        let name_start = pos.saturating_add(3);
        let name_end = name_start
            .checked_add(name_len)
            .ok_or_else(|| ProxyError::Sr39Rejected("TLS SNI entry overflow".into()))?;
        if name_end > end || name_type != 0x00 || name_len == 0 || name_len > MAX_SNI_HOST_BYTES {
            return Err(ProxyError::Sr39Rejected(
                "invalid TLS SNI host_name entry".into(),
            ));
        }
        if host_out.is_some() {
            return Err(ProxyError::Sr39Rejected(
                "multiple TLS SNI entries rejected".into(),
            ));
        }
        let raw = ext
            .get(name_start..name_end)
            .ok_or_else(|| ProxyError::Sr39Rejected("TLS SNI slice oob".into()))?;
        let host = std::str::from_utf8(raw).map_err(|_| {
            ProxyError::Sr39Rejected("TLS ClientHello SNI hostname is not valid UTF-8".into())
        })?;
        let lower = host.trim().to_ascii_lowercase();
        if lower.is_empty() || lower.chars().any(|c| c.is_control() || c.is_whitespace()) {
            return Err(ProxyError::Sr39Rejected(
                "TLS ClientHello SNI hostname invalid".into(),
            ));
        }
        host_out = Some(lower);
        pos = name_end;
    }
    Ok(host_out)
}

fn parse_alpn_extension(ext: &[u8]) -> Result<Vec<String>, ProxyError> {
    if ext.len() < 3 {
        return Err(ProxyError::Sr39Rejected(
            "malformed TLS ALPN extension".into(),
        ));
    }
    let list_len = usize::from(read_u16(ext, 0)?);
    let end = 2usize.saturating_add(list_len);
    if end != ext.len() {
        return Err(ProxyError::Sr39Rejected(
            "TLS ALPN list length disagrees with extension size".into(),
        ));
    }
    let mut out = Vec::new();
    let mut pos = 2usize;
    while pos < end {
        let len = usize::from(*ext.get(pos).unwrap_or(&0));
        let start = pos.saturating_add(1);
        let next = start
            .checked_add(len)
            .ok_or_else(|| ProxyError::Sr39Rejected("TLS ALPN entry overflow".into()))?;
        if len == 0 || next > end {
            return Err(ProxyError::Sr39Rejected("invalid TLS ALPN length".into()));
        }
        let proto_bytes = ext
            .get(start..next)
            .ok_or_else(|| ProxyError::Sr39Rejected("TLS ALPN slice oob".into()))?;
        let proto = std::str::from_utf8(proto_bytes)
            .map_err(|_| ProxyError::Sr39Rejected("non-UTF8 TLS ALPN protocol".into()))?;
        out.push(proto.to_string());
        pos = next;
    }
    Ok(out)
}
