// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! AWS EventStream binary decoder with prelude/message CRC32 verification and strict header bounds.

use std::collections::BTreeSet;

use crate::error::ProtoError;
use crate::inflate::crc32_ieee;
use crate::strict_json::MAX_SSE_EVENT_BYTES;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AwsEventStreamFrame {
    pub event_type: String,
    pub content_type: String,
    pub payload: Vec<u8>,
}

pub fn decode_aws_eventstream_frames(
    bytes: &[u8],
    max_frame_bytes: usize,
) -> Result<(Vec<AwsEventStreamFrame>, usize), ProtoError> {
    let mut offset: usize = 0;
    let mut frames = Vec::new();
    let cap = max_frame_bytes.min(MAX_SSE_EVENT_BYTES);
    while bytes.len().saturating_sub(offset) >= 12 {
        let total_len = usize::try_from(read_be_u32(bytes, offset)?).unwrap_or(usize::MAX);
        let headers_len =
            usize::try_from(read_be_u32(bytes, offset.saturating_add(4))?).unwrap_or(usize::MAX);
        let expected_prelude_crc = read_be_u32(bytes, offset.saturating_add(8))?;
        let prelude_slice = bytes
            .get(offset..offset.saturating_add(8))
            .ok_or_else(|| ProtoError::Parse("eventstream prelude oob".to_string()))?;
        if crc32_ieee(prelude_slice) != expected_prelude_crc {
            return Err(ProtoError::Parse(
                "aws eventstream prelude crc32 mismatch".to_string(),
            ));
        }
        if total_len > cap || total_len < 16 {
            return Err(ProtoError::PayloadTooLarge);
        }
        if bytes.len().saturating_sub(offset) < total_len {
            break;
        }
        let hdr_start = offset.saturating_add(12);
        let hdr_end = hdr_start
            .checked_add(headers_len)
            .ok_or_else(|| ProtoError::Parse("eventstream header length overflow".to_string()))?;
        let frame_end = offset
            .checked_add(total_len)
            .ok_or_else(|| ProtoError::Parse("eventstream frame length overflow".to_string()))?;
        let payload_end = frame_end.saturating_sub(4);
        if hdr_end > payload_end {
            return Err(ProtoError::Parse(
                "aws eventstream header exceeds frame".to_string(),
            ));
        }
        let message_body = bytes
            .get(offset..payload_end)
            .ok_or_else(|| ProtoError::Parse("eventstream body oob".to_string()))?;
        let expected_msg_crc = read_be_u32(bytes, payload_end)?;
        if crc32_ieee(message_body) != expected_msg_crc {
            return Err(ProtoError::Parse(
                "aws eventstream message crc32 mismatch".to_string(),
            ));
        }

        let hdr_bytes = bytes
            .get(hdr_start..hdr_end)
            .ok_or_else(|| ProtoError::Parse("eventstream header oob".to_string()))?;
        let payload = bytes
            .get(hdr_end..payload_end)
            .ok_or_else(|| ProtoError::Parse("eventstream payload oob".to_string()))?
            .to_vec();
        let (event_type, content_type) = parse_eventstream_headers(hdr_bytes)?;
        frames.push(AwsEventStreamFrame {
            event_type,
            content_type,
            payload,
        });
        offset = frame_end;
    }
    Ok((frames, offset))
}

fn parse_eventstream_headers(bytes: &[u8]) -> Result<(String, String), ProtoError> {
    let (mut pos, mut event_type, mut content_type) = (0usize, String::new(), String::new());
    let mut seen_reserved: BTreeSet<String> = BTreeSet::new();
    while pos < bytes.len() {
        let name_len = usize::from(
            bytes
                .get(pos)
                .copied()
                .ok_or_else(|| ProtoError::Parse("eventstream header name len".to_string()))?,
        );
        pos = pos.saturating_add(1);
        if name_len == 0 {
            return Err(ProtoError::Parse(
                "empty eventstream header name".to_string(),
            ));
        }
        let name_end = pos
            .checked_add(name_len)
            .filter(|&end| end <= bytes.len())
            .ok_or_else(|| ProtoError::Parse("eventstream header name oob".to_string()))?;
        let name_bytes = bytes
            .get(pos..name_end)
            .ok_or_else(|| ProtoError::Parse("eventstream header name oob".to_string()))?;
        let name = std::str::from_utf8(name_bytes)
            .map_err(|_| ProtoError::Parse("non-UTF8 eventstream header name".to_string()))?;
        if name.starts_with(':') && !seen_reserved.insert(name.to_owned()) {
            return Err(ProtoError::Parse(format!(
                "duplicate reserved eventstream header `{name}`"
            )));
        }
        pos = name_end;
        let val_type = bytes
            .get(pos)
            .copied()
            .ok_or_else(|| ProtoError::Parse("eventstream header type".to_string()))?;
        pos = pos.saturating_add(1);
        match val_type {
            7 => {
                let vlen = read_be_u16_len(bytes, pos)?;
                pos = pos.saturating_add(2);
                let vend = pos
                    .checked_add(vlen)
                    .filter(|&end| end <= bytes.len())
                    .ok_or_else(|| ProtoError::Parse("eventstream str val oob".to_string()))?;
                let val_bytes = bytes
                    .get(pos..vend)
                    .ok_or_else(|| ProtoError::Parse("eventstream str val".to_string()))?;
                let val = std::str::from_utf8(val_bytes)
                    .map_err(|_| ProtoError::Parse("non-UTF8 eventstream header val".to_string()))?
                    .to_owned();
                if name == ":event-type" {
                    event_type = val;
                } else if name == ":content-type" {
                    content_type = val;
                }
                pos = vend;
            }
            0 | 1 => {}
            2 => pos = advance_checked(pos, 1, bytes.len())?,
            3 => pos = advance_checked(pos, 2, bytes.len())?,
            4 => pos = advance_checked(pos, 4, bytes.len())?,
            5 | 8 => pos = advance_checked(pos, 8, bytes.len())?,
            9 => pos = advance_checked(pos, 16, bytes.len())?,
            6 => {
                let vlen = read_be_u16_len(bytes, pos)?;
                let after_len = advance_checked(pos, 2, bytes.len())?;
                pos = advance_checked(after_len, vlen, bytes.len())?;
            }
            _ => {
                return Err(ProtoError::Parse(
                    "unknown eventstream header type".to_string(),
                ));
            }
        }
    }
    if pos != bytes.len() {
        return Err(ProtoError::Parse(
            "eventstream headers did not terminate at exact boundary".to_string(),
        ));
    }
    Ok((event_type, content_type))
}

fn advance_checked(pos: usize, delta: usize, max_len: usize) -> Result<usize, ProtoError> {
    let next = pos
        .checked_add(delta)
        .filter(|&end| end <= max_len)
        .ok_or_else(|| ProtoError::Parse("eventstream header value out of bounds".to_string()))?;
    Ok(next)
}

fn read_be_u16_len(bytes: &[u8], pos: usize) -> Result<usize, ProtoError> {
    let slice = bytes
        .get(pos..pos.saturating_add(2))
        .ok_or_else(|| ProtoError::Parse("eventstream u16 len".to_string()))?;
    Ok(usize::from(u16::from_be_bytes([
        slice.first().copied().unwrap_or(0),
        slice.get(1).copied().unwrap_or(0),
    ])))
}

fn read_be_u32(bytes: &[u8], offset: usize) -> Result<u32, ProtoError> {
    let slice = bytes
        .get(offset..offset.saturating_add(4))
        .ok_or_else(|| ProtoError::Parse("eventstream u32 oob".to_string()))?;
    Ok(u32::from_be_bytes([
        slice.first().copied().unwrap_or(0),
        slice.get(1).copied().unwrap_or(0),
        slice.get(2).copied().unwrap_or(0),
        slice.get(3).copied().unwrap_or(0),
    ]))
}
