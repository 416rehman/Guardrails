// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![no_main]

use axum::http::{HeaderMap, HeaderName, HeaderValue};
use grdr_proxy::otlp::{OtlpSignalKind, ingest_otlp_payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    if data.is_empty() || data.len() > 65_536 {
        return;
    }
    let Some((&first, body)) = data.split_first() else {
        return;
    };
    let mut headers = HeaderMap::new();
    let content_type = if first % 3 == 0 {
        "application/json"
    } else if first % 3 == 1 {
        "application/x-protobuf"
    } else {
        "text/plain"
    };
    headers.insert(
        HeaderName::from_static("content-type"),
        HeaderValue::from_static(content_type),
    );
    if first & 0x80 != 0 {
        headers.insert(
            HeaderName::from_static("origin"),
            HeaderValue::from_static("https://evil.example"),
        );
    }
    let signal = match (first >> 2) % 3 {
        0 => OtlpSignalKind::Traces,
        1 => OtlpSignalKind::Logs,
        _ => OtlpSignalKind::Metrics,
    };
    let _ = ingest_otlp_payload(&headers, signal, body);
});
