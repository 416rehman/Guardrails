// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};
use serde_json::Value;

use crate::error::ProtoError;
use crate::strict_json::{
    MAX_JSON_DEPTH, MAX_SSE_EVENT_BYTES, MAX_TOOL_CALLS, parse_strict_json_bytes,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WsOpcode {
    Continuation,
    Text,
    Binary,
    Close,
    Ping,
    Pong,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WsFrame {
    pub fin: bool,
    pub opcode: WsOpcode,
    pub masked: bool,
    pub payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RealtimeEventMeta {
    pub event_type: String,
    pub model: Option<String>,
    pub tools: Vec<String>,
    pub function_call_name: Option<String>,
    pub function_call_id: Option<String>,
    pub modalities: Vec<String>,
    pub instructions_present: bool,
}

pub fn parse_ws_frames(
    buf: &[u8],
    max_frame_bytes: usize,
) -> Result<(Vec<WsFrame>, usize), ProtoError> {
    let cap = max_frame_bytes.min(MAX_SSE_EVENT_BYTES);
    let mut offset: usize = 0;
    let mut frames = Vec::new();
    while buf.len().saturating_sub(offset) >= 2 {
        let Some((frame, frame_len)) =
            try_parse_one_ws_frame(buf.get(offset..).unwrap_or_default(), cap)?
        else {
            break;
        };
        frames.push(frame);
        offset = offset.saturating_add(frame_len);
    }
    Ok((frames, offset))
}

fn try_parse_one_ws_frame(
    slice: &[u8],
    cap: usize,
) -> Result<Option<(WsFrame, usize)>, ProtoError> {
    let b0 = slice
        .first()
        .copied()
        .ok_or_else(|| ProtoError::Parse("ws hdr b0".to_string()))?;
    let b1 = slice
        .get(1)
        .copied()
        .ok_or_else(|| ProtoError::Parse("ws hdr b1".to_string()))?;
    if b0 & 0x70 != 0 {
        return Err(ProtoError::Parse(
            "unsupported websocket RSV bits".to_string(),
        ));
    }
    let fin = (b0 & 0x80) != 0;
    let opcode = match b0 & 0x0F {
        0 => WsOpcode::Continuation,
        1 => WsOpcode::Text,
        2 => WsOpcode::Binary,
        8 => WsOpcode::Close,
        9 => WsOpcode::Ping,
        10 => WsOpcode::Pong,
        _ => {
            return Err(ProtoError::Parse(
                "unsupported websocket opcode".to_string(),
            ));
        }
    };
    let masked = (b1 & 0x80) != 0;
    let len7 = b1 & 0x7F;
    let Some((payload_len, hdr_len)) = decode_ws_payload_len(slice, len7)? else {
        return Ok(None);
    };
    if matches!(opcode, WsOpcode::Close | WsOpcode::Ping | WsOpcode::Pong)
        && (payload_len > 125 || !fin)
    {
        return Err(ProtoError::Parse(
            "invalid websocket control frame".to_string(),
        ));
    }
    if payload_len > cap {
        return Err(ProtoError::PayloadTooLarge);
    }
    let mask_offset = hdr_len;
    let payload_offset = mask_offset.saturating_add(if masked { 4 } else { 0 });
    let total_len = payload_offset.saturating_add(payload_len);
    if slice.len() < total_len {
        return Ok(None);
    }
    let raw_payload = slice
        .get(payload_offset..total_len)
        .ok_or_else(|| ProtoError::Parse("ws payload oob".to_string()))?;
    let payload = if masked {
        let mask = slice
            .get(mask_offset..mask_offset.saturating_add(4))
            .ok_or_else(|| ProtoError::Parse("ws mask oob".to_string()))?;
        raw_payload
            .iter()
            .enumerate()
            .map(|(i, &b)| b ^ mask.get(i % 4).copied().unwrap_or(0))
            .collect()
    } else {
        raw_payload.to_vec()
    };
    Ok(Some((
        WsFrame {
            fin,
            opcode,
            masked,
            payload,
        },
        total_len,
    )))
}

fn decode_ws_payload_len(slice: &[u8], len7: u8) -> Result<Option<(usize, usize)>, ProtoError> {
    match len7 {
        0..=125 => Ok(Some((usize::from(len7), 2))),
        126 => {
            if slice.len() < 4 {
                return Ok(None);
            }
            let hi = u16::from(slice.get(2).copied().unwrap_or(0));
            let lo = u16::from(slice.get(3).copied().unwrap_or(0));
            Ok(Some((usize::from((hi << 8) | lo), 4)))
        }
        _ => {
            let Some(ext) = slice.get(2..10) else {
                return Ok(None);
            };
            let mut val: u64 = 0;
            for &b in ext {
                val = (val << 8) | u64::from(b);
            }
            if val >> 63 != 0 {
                return Err(ProtoError::Parse(
                    "invalid websocket MSB in 64-bit length".to_string(),
                ));
            }
            let as_usize = usize::try_from(val).map_err(|_| ProtoError::PayloadTooLarge)?;
            Ok(Some((as_usize, 10)))
        }
    }
}

pub fn parse_realtime_frame_json(payload: &[u8]) -> Result<RealtimeEventMeta, ProtoError> {
    let val = parse_strict_json_bytes(payload, MAX_SSE_EVENT_BYTES, MAX_JSON_DEPTH)?;
    let obj = val
        .as_object()
        .ok_or_else(|| ProtoError::Parse("realtime frame must be JSON object".to_string()))?;
    let event_type = obj
        .get("type")
        .and_then(Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .ok_or_else(|| ProtoError::Parse("realtime frame missing type".to_string()))?
        .to_string();
    let session = obj.get("session");
    let response = obj.get("response");
    let item = obj.get("item");
    let model = obj
        .get("model")
        .or_else(|| session.and_then(|s| s.get("model")))
        .or_else(|| response.and_then(|r| r.get("model")))
        .and_then(Value::as_str)
        .map(str::to_string);
    let mut tools = Vec::new();
    for arr in [
        obj.get("tools").and_then(Value::as_array),
        session
            .and_then(|s| s.get("tools"))
            .and_then(Value::as_array),
        response
            .and_then(|r| r.get("tools"))
            .and_then(Value::as_array),
    ]
    .into_iter()
    .flatten()
    {
        if tools.len().saturating_add(arr.len()) > MAX_TOOL_CALLS {
            return Err(ProtoError::PayloadTooLarge);
        }
        for t in arr {
            if let Some(n) = t.get("name").and_then(Value::as_str) {
                tools.push(n.to_string());
            }
        }
    }
    let function_call_name = obj
        .get("name")
        .or_else(|| item.and_then(|i| i.get("name")))
        .and_then(Value::as_str)
        .map(str::to_string);
    let function_call_id = obj
        .get("call_id")
        .or_else(|| item.and_then(|i| i.get("call_id")))
        .and_then(Value::as_str)
        .map(str::to_string);
    let modalities = session
        .and_then(|s| s.get("modalities"))
        .or_else(|| response.and_then(|r| r.get("modalities")))
        .and_then(Value::as_array)
        .map(|arr| {
            arr.iter()
                .filter_map(Value::as_str)
                .map(str::to_string)
                .collect()
        })
        .unwrap_or_default();
    let instructions_present = session
        .and_then(|s| s.get("instructions"))
        .or_else(|| response.and_then(|r| r.get("instructions")))
        .and_then(Value::as_str)
        .is_some_and(|s| !s.trim().is_empty());
    Ok(RealtimeEventMeta {
        event_type,
        model,
        tools,
        function_call_name,
        function_call_id,
        modalities,
        instructions_present,
    })
}
