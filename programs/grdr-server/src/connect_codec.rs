// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use axum::body::Bytes;
use axum::http::{HeaderMap, HeaderValue, Method, StatusCode, Uri, header};
use axum::response::{IntoResponse, Response};
use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD_NO_PAD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use prost::Message;
use serde::Serialize;
use serde::de::DeserializeOwned;
use uuid::Uuid;

use grdr_proto::common::{ErrorClass, IdempotencyLevel, MethodDescriptor};

use crate::aip::revision::etag_matches;
use crate::connect_error::{
    ApiError, ApiErrorInner, CODE_API_BAD_REQUEST, CODE_API_INTERNAL, CODE_API_UNSUPPORTED_MEDIA,
    ConnectCode, REQUEST_ID_HEADER, WireEncoding, apply_common_headers, encode_connect_error,
    wrap_connect_frame,
};

pub fn extract_request_id(headers: &HeaderMap) -> String {
    if let Some(raw) = headers.get(REQUEST_ID_HEADER).and_then(|v| v.to_str().ok()) {
        let trimmed = raw.trim();
        if !trimmed.is_empty() && trimmed.len() <= 96 {
            return trimmed.to_string();
        }
    }
    format!("req_{}", Uuid::now_v7().simple())
}

pub fn negotiate_encoding(
    method: &Method,
    headers: &HeaderMap,
    uri: &Uri,
) -> Result<WireEncoding, ApiError> {
    if method == Method::GET {
        let query = uri.query().unwrap_or("");
        let encoding = query_param(query, "encoding").unwrap_or_else(|| "json".into());
        return match encoding.to_ascii_lowercase().as_str() {
            "json" => Ok(WireEncoding::Json),
            "proto" => Ok(WireEncoding::Proto),
            other => Err(ApiError::invalid_argument(
                CODE_API_UNSUPPORTED_MEDIA,
                "UNSUPPORTED_ENCODING",
                format!("Unsupported Connect GET encoding '{other}'."),
                "Use encoding=json or encoding=proto.",
            )),
        };
    }

    if let Some(proto_ver) = headers
        .get("connect-protocol-version")
        .and_then(|v| v.to_str().ok())
        && proto_ver.trim() != "1"
    {
        return Err(ApiError::invalid_argument(
            CODE_API_BAD_REQUEST,
            "UNSUPPORTED_CONNECT_PROTOCOL",
            format!("Unsupported Connect-Protocol-Version '{proto_ver}'."),
            "Send Connect-Protocol-Version: 1.",
        ));
    }

    let raw_ct = headers
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("application/json");
    let media = raw_ct
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();
    match media.as_str() {
        "" | "application/json" => Ok(WireEncoding::Json),
        "application/proto" | "application/protobuf" => Ok(WireEncoding::Proto),
        "application/connect+json" => Ok(WireEncoding::ConnectJson),
        "application/connect+proto" => Ok(WireEncoding::ConnectProto),
        _ => Err(ApiError::invalid_argument(
            CODE_API_UNSUPPORTED_MEDIA,
            "UNSUPPORTED_MEDIA_TYPE",
            format!("Unsupported Content-Type '{media}'."),
            "Use application/json, application/proto, application/connect+json, or application/connect+proto.",
        )),
    }
}

pub fn decode_connect_request<M>(
    desc: &MethodDescriptor,
    http_method: &Method,
    headers: &HeaderMap,
    uri: &Uri,
    body: &Bytes,
) -> Result<(WireEncoding, M), ApiError>
where
    M: Message + DeserializeOwned + Default,
{
    let encoding = negotiate_encoding(http_method, headers, uri)?;

    if http_method == Method::GET {
        if desc.idempotency != IdempotencyLevel::NoSideEffects {
            return Err(ApiError::invalid_argument(
                CODE_API_BAD_REQUEST,
                "METHOD_NOT_IDEMPOTENT",
                format!("Method {} does not support HTTP GET.", desc.path),
                "Invoke mutating RPC methods with HTTP POST.",
            ));
        }
        let query = uri.query().unwrap_or("");
        let msg_raw = query_param(query, "message").unwrap_or_default();
        if msg_raw.trim().is_empty() {
            return Ok((encoding, M::default()));
        }
        let is_b64 = query_param(query, "base64").as_deref() == Some("1");
        let payload = if is_b64 {
            B64_URL
                .decode(msg_raw.as_bytes())
                .or_else(|_| B64_STD.decode(msg_raw.as_bytes()))
                .map_err(|e| {
                    ApiError::invalid_argument(
                        CODE_API_BAD_REQUEST,
                        "INVALID_GET_MESSAGE",
                        format!("Invalid base64 message query parameter: {e}"),
                        "Provide valid base64url encoded message bytes.",
                    )
                })?
        } else {
            msg_raw.into_bytes()
        };
        let parsed = decode_payload::<M>(encoding, &payload)?;
        return Ok((encoding, parsed));
    }

    if http_method != Method::POST {
        return Err(ApiError::invalid_argument(
            CODE_API_BAD_REQUEST,
            "METHOD_NOT_ALLOWED",
            format!("HTTP {http_method} is not supported on Connect endpoint."),
            "Use HTTP POST, or HTTP GET for NO_SIDE_EFFECTS methods.",
        ));
    }

    let payload = if encoding.is_framed() {
        unwrap_connect_frame(body)?
    } else {
        body.as_ref()
    };
    let parsed = decode_payload::<M>(encoding, payload)?;
    Ok((encoding, parsed))
}

pub fn encode_connect_response<M: Message + Serialize>(
    encoding: WireEncoding,
    http_method: &Method,
    headers: &HeaderMap,
    request_id: &str,
    etag: Option<&str>,
    msg: &M,
) -> Response {
    if http_method == Method::GET
        && let Some(tag) = etag
        && etag_matches(
            headers
                .get(header::IF_NONE_MATCH)
                .and_then(|v| v.to_str().ok()),
            tag,
        )
    {
        let mut resp = StatusCode::NOT_MODIFIED.into_response();
        apply_common_headers(resp.headers_mut(), request_id, Some(tag));
        return resp;
    }

    let payload = match encoding {
        WireEncoding::Json | WireEncoding::ConnectJson => match serde_json::to_vec(msg) {
            Ok(v) => v,
            Err(e) => {
                return encode_connect_error(
                    encoding,
                    request_id,
                    &ApiError::new(ApiErrorInner {
                        code: ConnectCode::Internal,
                        grdr_code: CODE_API_INTERNAL.into(),
                        reason: "SERIALIZATION_FAILED".into(),
                        class: ErrorClass::Internal,
                        message: format!("Response JSON serialization failed: {e}"),
                        fix: "Inspect server logs.".into(),
                        metadata: BTreeMap::new(),
                    }),
                );
            }
        },
        WireEncoding::Proto | WireEncoding::ConnectProto => msg.encode_to_vec(),
    };

    let wire_bytes = if encoding.is_framed() {
        wrap_connect_frame(0, &payload)
    } else {
        payload
    };

    let mut resp = (StatusCode::OK, wire_bytes).into_response();
    if let Ok(ct) = HeaderValue::from_str(encoding.content_type()) {
        resp.headers_mut().insert(header::CONTENT_TYPE, ct);
    }
    apply_common_headers(resp.headers_mut(), request_id, etag);
    resp
}

fn decode_payload<M: Message + DeserializeOwned + Default>(
    encoding: WireEncoding,
    payload: &[u8],
) -> Result<M, ApiError> {
    match encoding {
        WireEncoding::Json | WireEncoding::ConnectJson => {
            if payload.is_empty() {
                return Ok(M::default());
            }
            serde_json::from_slice(payload).map_err(|e| {
                ApiError::invalid_argument(
                    CODE_API_BAD_REQUEST,
                    "INVALID_JSON_PAYLOAD",
                    format!("Invalid Connect JSON request payload: {e}"),
                    "Verify request JSON fields against the service schema.",
                )
            })
        }
        WireEncoding::Proto | WireEncoding::ConnectProto => M::decode(payload).map_err(|e| {
            ApiError::invalid_argument(
                CODE_API_BAD_REQUEST,
                "INVALID_PROTO_PAYLOAD",
                format!("Invalid Protobuf wire payload: {e}"),
                "Verify request binary payload against the .proto schema.",
            )
        }),
    }
}

fn unwrap_connect_frame(body: &[u8]) -> Result<&[u8], ApiError> {
    let Some(len_bytes) = body.get(1..5) else {
        return Err(ApiError::invalid_argument(
            CODE_API_BAD_REQUEST,
            "INVALID_CONNECT_FRAME",
            "Missing 5-byte Connect envelope header.",
            "Prefix payload with [flags:1][u32_be_len:4].",
        ));
    };
    let len_arr: [u8; 4] = len_bytes.try_into().map_err(|_| {
        ApiError::invalid_argument(
            CODE_API_BAD_REQUEST,
            "INVALID_CONNECT_FRAME",
            "Invalid Connect frame length header.",
            "Prefix payload with [flags:1][u32_be_len:4].",
        )
    })?;
    let expected_len = usize::try_from(u32::from_be_bytes(len_arr)).unwrap_or(usize::MAX);
    let Some(payload) = body.get(5..5usize.saturating_add(expected_len)) else {
        return Err(ApiError::invalid_argument(
            CODE_API_BAD_REQUEST,
            "INVALID_CONNECT_FRAME",
            "Truncated Connect frame payload.",
            "Ensure full frame bytes match header length.",
        ));
    };
    Ok(payload)
}

fn query_param(query: &str, key: &str) -> Option<String> {
    for pair in query.split('&') {
        let Some((k, v)) = pair.split_once('=') else {
            continue;
        };
        if k == key {
            return Some(percent_decode(v));
        }
    }
    None
}

fn percent_decode(raw: &str) -> String {
    let bytes = raw.as_bytes();
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while let Some(b) = bytes.get(i).copied() {
        if b == b'+' {
            out.push(b' ');
            i = i.saturating_add(1);
        } else if b == b'%'
            && let (Some(h1), Some(h2)) = (
                bytes.get(i.saturating_add(1)),
                bytes.get(i.saturating_add(2)),
            )
            && let (Some(n1), Some(n2)) = (hex_val(*h1), hex_val(*h2))
        {
            out.push((n1 << 4) | n2);
            i = i.saturating_add(3);
        } else {
            out.push(b);
            i = i.saturating_add(1);
        }
    }
    String::from_utf8_lossy(&out).into_owned()
}

fn hex_val(b: u8) -> Option<u8> {
    match b {
        b'0'..=b'9' => Some(b.saturating_sub(b'0')),
        b'a'..=b'f' => Some(b.saturating_sub(b'a').saturating_add(10)),
        b'A'..=b'F' => Some(b.saturating_sub(b'A').saturating_add(10)),
        _ => None,
    }
}
