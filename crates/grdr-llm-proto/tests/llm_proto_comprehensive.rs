// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_llm_proto::ProtoError;
use grdr_llm_proto::a2a::{
    A2aMethodKind, parse_a2a_agent_card, parse_a2a_request, parse_jws_compact,
};
use grdr_llm_proto::bedrock_stream::decode_aws_eventstream_frames;
use grdr_llm_proto::compression::{
    ContentEncodingKind, decompress_bounded, parse_content_encoding_header,
};
use grdr_llm_proto::providers::{
    SigV4PayloadHashKind, StreamDeliveryKind, inspect_llm_http_request,
};
use grdr_llm_proto::realtime::{WsOpcode, parse_realtime_frame_json, parse_ws_frames};
use grdr_llm_proto::schema::{ProviderFamily, ProviderSchemaRegistry};
use grdr_llm_proto::stream::LlmStreamInspector;
use grdr_llm_proto::strict_json::{MAX_JSON_DEPTH, parse_strict_json_str};

fn encode_gzip_stored_block(raw: &[u8]) -> Vec<u8> {
    let mut out = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF];
    let len = raw.len() as u16;
    let nlen = !len;
    out.push(0x01); // BFINAL=1, BTYPE=00 (stored)
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&nlen.to_le_bytes());
    out.extend_from_slice(raw);
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in raw {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    out.extend_from_slice(&(!crc).to_le_bytes());
    out.extend_from_slice(&(raw.len() as u32).to_le_bytes());
    out
}

fn encode_gzip_fixed_huffman_zeros(count: usize) -> Vec<u8> {
    // Emit a single compressed fixed-Huffman stream representing repeated zero bytes via
    // literal 0x00 (bits: 00110000 MSB-first -> byte 0x0C LSB-first) and length=258 dist=1
    // until count bytes are emitted cleanly inside an authentic RFC 1952 gzip container.
    let mut bits: u64 = 0;
    let mut bit_len: u8 = 0;
    let mut deflate = Vec::new();
    let push_bits = |val: u32, n: u8, b: &mut u64, bl: &mut u8, out: &mut Vec<u8>| {
        *b |= u64::from(val) << *bl;
        *bl += n;
        while *bl >= 8 {
            out.push((*b & 0xFF) as u8);
            *b >>= 8;
            *bl -= 8;
        }
    };
    let push_huff = |code_msb: u32, n: u8, b: &mut u64, bl: &mut u8, out: &mut Vec<u8>| {
        let mut rev = 0u32;
        for i in 0..n {
            if (code_msb >> i) & 1 != 0 {
                rev |= 1 << (n - 1 - i);
            }
        }
        push_bits(rev, n, b, bl, out);
    };
    // BFINAL=1, BTYPE=01 (fixed)
    push_bits(0b011, 3, &mut bits, &mut bit_len, &mut deflate);
    // Literal 0 -> 8-bit fixed code 0b00110000 (48)
    push_huff(0b0011_0000, 8, &mut bits, &mut bit_len, &mut deflate);
    let mut emitted = 1usize;
    while emitted < count {
        let step = (count - emitted).min(258);
        if step >= 3 {
            // Symbol 285 -> 258 bytes, or use symbol 257+0 for 3 bytes cleanly
            if step == 258 {
                // Sym 285 (code 285-280+192 = 197, 8 bits: 11000101), extra 0
                push_huff(0b1100_0101, 8, &mut bits, &mut bit_len, &mut deflate);
                // Dist 0 -> 5 bits 00000
                push_huff(0, 5, &mut bits, &mut bit_len, &mut deflate);
                emitted += 258;
            } else {
                push_huff(0b0011_0000, 8, &mut bits, &mut bit_len, &mut deflate);
                emitted += 1;
            }
        } else {
            push_huff(0b0011_0000, 8, &mut bits, &mut bit_len, &mut deflate);
            emitted += 1;
        }
    }
    // End of block sym 256 -> 7 bits 0000000
    push_huff(0, 7, &mut bits, &mut bit_len, &mut deflate);
    if bit_len > 0 {
        deflate.push((bits & 0xFF) as u8);
    }

    let payload = vec![0u8; count];
    let mut crc: u32 = 0xFFFF_FFFF;
    for &b in &payload {
        crc ^= u32::from(b);
        for _ in 0..8 {
            let mask = (crc & 1).wrapping_neg();
            crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
        }
    }
    let mut out = vec![0x1F, 0x8B, 0x08, 0x00, 0, 0, 0, 0, 0, 0xFF];
    out.extend_from_slice(&deflate);
    out.extend_from_slice(&(!crc).to_le_bytes());
    out.extend_from_slice(&(count as u32).to_le_bytes());
    out
}

#[test]
fn strict_json_rejects_duplicate_keys_escaped_keys_and_excess_depth() {
    let dup = r#"{"model":"gpt-5","model":"gpt-4"}"#;
    let err = parse_strict_json_str(dup, 4096, MAX_JSON_DEPTH).unwrap_err();
    assert!(matches!(err, ProtoError::DuplicateJsonKey));

    let escaped_dup = r#"{"model":"gpt-5","\u006dodel":"gpt-4"}"#;
    let err2 = parse_strict_json_str(escaped_dup, 4096, MAX_JSON_DEPTH).unwrap_err();
    assert!(matches!(err2, ProtoError::DuplicateJsonKey));

    let mut deep = "[".repeat(MAX_JSON_DEPTH + 1);
    deep.push('1');
    deep.push_str(&"]".repeat(MAX_JSON_DEPTH + 1));
    let err3 = parse_strict_json_str(&deep, 4096, MAX_JSON_DEPTH).unwrap_err();
    assert!(matches!(err3, ProtoError::DepthLimitExceeded));

    let nested_ok = r#"{"a":{"a":1},"b":[{"a":2}]}"#;
    assert!(parse_strict_json_str(nested_ok, 4096, MAX_JSON_DEPTH).is_ok());
}

#[test]
fn decompression_allows_normal_gzip_and_rejects_over_100_to_1_bomb() {
    let json =
        br#"{"model":"claude-sonnet-4","messages":[{"role":"user","content":"hello world"}]}"#;
    let gz = encode_gzip_stored_block(json);
    let encs = parse_content_encoding_header("gzip").unwrap();
    let decoded = decompress_bounded(&gz, &encs, 1024 * 1024, 100).unwrap();
    assert_eq!(decoded, json);

    // 65_536 zero bytes compressed with repeated 258-byte deflate backreferences compresses cleanly -> >100:1
    let bomb = encode_gzip_fixed_huffman_zeros(65_536);
    assert!(
        65_536 / bomb.len() > 100,
        "bomb len {} too large",
        bomb.len()
    );
    let err =
        decompress_bounded(&bomb, &[ContentEncodingKind::Gzip], 1024 * 1024, 100).unwrap_err();
    assert!(matches!(err, ProtoError::DecompressionRejected(_)));
}

#[test]
fn inspects_all_major_llm_providers_and_sigv4_headers_without_mutation() {
    let reg = ProviderSchemaRegistry::default_embedded().unwrap();

    let openai_resp = inspect_llm_http_request(
        &reg,
        "api.openai.com",
        "/v1/responses",
        &[],
        br#"{"model":"gpt-5","instructions":"Be safe","input":"hi","stream":true,"tools":[{"type":"function","name":"run_sql"}]}"#,
    )
    .unwrap();
    assert_eq!(openai_resp.family, ProviderFamily::OpenAiResponses);
    assert_eq!(openai_resp.delivery, StreamDeliveryKind::Streaming);
    assert_eq!(openai_resp.meta.tool_names, vec!["run_sql"]);
    assert!(openai_resp.meta.has_system_prompt);

    let gemini = inspect_llm_http_request(
        &reg,
        "generativelanguage.googleapis.com",
        "/v1beta/models/gemini-2.5-pro:streamGenerateContent",
        &[],
        br#"{"contents":[{"role":"user","parts":[{"text":"hi"}]}],"tools":[{"functionDeclarations":[{"name":"fetch_url"}]}]}"#,
    )
    .unwrap();
    assert_eq!(gemini.family, ProviderFamily::GoogleGemini);
    assert_eq!(gemini.meta.model.as_deref(), Some("gemini-2.5-pro"));
    assert_eq!(gemini.meta.tool_names, vec!["fetch_url"]);
    assert_eq!(gemini.delivery, StreamDeliveryKind::Streaming);

    let sigv4_headers = vec![
        (
            "host".to_string(),
            "bedrock-runtime.us-east-1.amazonaws.com".to_string(),
        ),
        ("x-amz-date".to_string(), "20261126T100000Z".to_string()),
        (
            "x-amz-content-sha256".to_string(),
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855".to_string(),
        ),
        (
            "authorization".to_string(),
            format!(
                "AWS4-HMAC-SHA256 Credential=AKIAIOSFODNN7EXAMPLE/20261126/us-east-1/bedrock/aws4_request, SignedHeaders=host;x-amz-content-sha256;x-amz-date, Signature={}",
                "a".repeat(64)
            ),
        ),
    ];
    let bedrock = inspect_llm_http_request(
        &reg,
        "bedrock-runtime.us-east-1.amazonaws.com",
        "/model/anthropic.claude-3-7-sonnet/converse-stream",
        &sigv4_headers,
        br#"{"messages":[{"role":"user","content":[{"text":"hi"}]}],"toolConfig":{"tools":[{"toolSpec":{"name":"query_db"}}]}}"#,
    )
    .unwrap();
    assert_eq!(bedrock.family, ProviderFamily::AwsBedrock);
    assert_eq!(bedrock.delivery, StreamDeliveryKind::Streaming);
    assert_eq!(
        bedrock.meta.model.as_deref(),
        Some("anthropic.claude-3-7-sonnet")
    );
    assert_eq!(bedrock.meta.tool_names, vec!["query_db"]);
    let sig = bedrock.sigv4.unwrap();
    assert_eq!(sig.region, "us-east-1");
    assert_eq!(sig.service, "bedrock");
    assert_eq!(sig.payload_hash_kind, SigV4PayloadHashKind::Sha256Hex);
}

#[test]
fn parses_streaming_sse_deltas_bedrock_eventstream_and_realtime_ws() {
    let mut anthropic_sse = LlmStreamInspector::new(ProviderFamily::AnthropicMessages);
    let chunk1 = b"event: content_block_start\ndata: {\"type\":\"content_block_start\",\"index\":0,\"content_block\":{\"type\":\"tool_use\",\"id\":\"tu_1\",\"name\":\"read_file\"}}\n\n";
    let chunk2 = b"event: content_block_delta\ndata: {\"type\":\"content_block_delta\",\"index\":0,\"delta\":{\"type\":\"input_json_delta\",\"partial_json\":\"{\\\"path\\\":\\\"/etc\"}}\n\nevent: message_stop\ndata: {\"type\":\"message_stop\"}\n\n";
    let d1 = anthropic_sse.push_sse_chunk(&chunk1[..25]).unwrap();
    assert!(d1.is_empty());
    let d2 = anthropic_sse.push_sse_chunk(&chunk1[25..]).unwrap();
    assert_eq!(d2.len(), 1);
    assert_eq!(d2[0].tool_calls[0].name.as_deref(), Some("read_file"));
    let d3 = anthropic_sse.push_sse_chunk(chunk2).unwrap();
    assert_eq!(d3.len(), 2);
    assert_eq!(d3[0].tool_calls[0].arguments_delta, r#"{"path":"/etc"#);
    assert!(d3[1].finished);

    // Build AWS EventStream frame with real IEEE CRC32 prelude + message CRCs
    let crc32 = |data: &[u8]| -> u32 {
        let mut crc: u32 = 0xFFFF_FFFF;
        for &b in data {
            crc ^= u32::from(b);
            for _ in 0..8 {
                let mask = (crc & 1).wrapping_neg();
                crc = (crc >> 1) ^ (0xEDB8_8320 & mask);
            }
        }
        !crc
    };
    let mut hdrs = Vec::new();
    hdrs.push(11u8);
    hdrs.extend_from_slice(b":event-type");
    hdrs.push(7u8);
    hdrs.extend_from_slice(&(17u16.to_be_bytes()));
    hdrs.extend_from_slice(b"contentBlockDelta");
    let payload = br#"{"delta":{"text":"ok"}}"#;
    let total_len = (12 + hdrs.len() + payload.len() + 4) as u32;
    let mut ev_frame = Vec::new();
    ev_frame.extend_from_slice(&total_len.to_be_bytes());
    ev_frame.extend_from_slice(&(hdrs.len() as u32).to_be_bytes());
    let prelude_crc = crc32(&ev_frame[0..8]);
    ev_frame.extend_from_slice(&prelude_crc.to_be_bytes());
    ev_frame.extend_from_slice(&hdrs);
    ev_frame.extend_from_slice(payload);
    let msg_crc = crc32(&ev_frame);
    ev_frame.extend_from_slice(&msg_crc.to_be_bytes());
    let (ev_frames, consumed) = decode_aws_eventstream_frames(&ev_frame, 65_536).unwrap();
    assert_eq!(consumed, ev_frame.len());
    assert_eq!(ev_frames[0].event_type, "contentBlockDelta");

    // Corrupt message CRC must be rejected.
    let mut bad_crc_frame = ev_frame.clone();
    let last_idx = bad_crc_frame.len() - 1;
    bad_crc_frame[last_idx] ^= 0x01;
    assert!(decode_aws_eventstream_frames(&bad_crc_frame, 65_536).is_err());

    // Masked client->server RFC 6455 Realtime frame
    let rt_json = br#"{"type":"session.update","session":{"model":"gpt-4o-realtime","modalities":["text"],"instructions":"stay brief","tools":[{"name":"search"}]}}"#;
    let mask = [0xAAu8, 0xBB, 0xCC, 0xDD];
    let mut ws = vec![0x81u8, 0x80 | 126u8];
    ws.extend_from_slice(&(rt_json.len() as u16).to_be_bytes());
    ws.extend_from_slice(&mask);
    for (idx, b) in rt_json.iter().enumerate() {
        ws.push(b ^ mask[idx % 4]);
    }
    let (ws_frames, ws_used) = parse_ws_frames(&ws, 65_536).unwrap();
    assert_eq!(ws_used, ws.len());
    assert_eq!(ws_frames[0].opcode, WsOpcode::Text);
    let rt_meta = parse_realtime_frame_json(&ws_frames[0].payload).unwrap();
    assert_eq!(rt_meta.event_type, "session.update");
    assert_eq!(rt_meta.model.as_deref(), Some("gpt-4o-realtime"));
    assert_eq!(rt_meta.tools, vec!["search"]);
}

#[test]
fn parses_a2a_1_0_1_requests_and_rejects_weak_jws_agent_cards() {
    let req = parse_a2a_request(
        "/",
        br#"{"jsonrpc":"2.0","id":1,"method":"message/stream","params":{"contextId":"ctx-9","configuration":{"pushNotificationConfig":{"url":"https://agent.example/hook"}},"message":{"parts":[{"kind":"text","text":"ping"}]}}}"#,
    )
    .unwrap();
    assert_eq!(req.method_kind, A2aMethodKind::MessageStream);
    assert_eq!(req.context_id.as_deref(), Some("ctx-9"));
    assert_eq!(
        req.push_webhook_url.as_deref(),
        Some("https://agent.example/hook")
    );

    // Valid compact EdDSA JWS (64-byte signature)
    let hdr_b64 = "eyJhbGciOiJFZERTQSIsImtpZCI6ImtleS0xIn0";
    let payload_b64 = "eyJuYW1lIjoiYWdlbnQifQ";
    let sig_b64 =
        "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    let jws = parse_jws_compact(&format!("{hdr_b64}.{payload_b64}.{sig_b64}")).unwrap();
    assert_eq!(jws.alg, "EdDSA");
    assert_eq!(jws.kid.as_deref(), Some("key-1"));
    assert_eq!(jws.signature.len(), 64);

    // Reject alg=none, crit, b64:false, padded segments
    let none_hdr = "eyJhbGciOiJub25lIn0";
    assert!(parse_jws_compact(&format!("{none_hdr}.{payload_b64}.{sig_b64}")).is_err());
    let crit_hdr = "eyJhbGciOiJFZERTQSIsImNyaXQiOlsiYjY0Il19";
    assert!(parse_jws_compact(&format!("{crit_hdr}.{payload_b64}.{sig_b64}")).is_err());

    let card_json = format!(
        r#"{{"name":"Planner","url":"https://planner.example","version":"1.0.1","protocolVersion":"1.0.1","iat":1000,"exp":2000,"capabilities":{{"streaming":true,"pushNotifications":false}},"skills":[{{"id":"plan"}}],"signatures":[{{"protected":"{hdr_b64}","signature":"{sig_b64}"}}]}}"#
    );
    let unverified = parse_a2a_agent_card(card_json.as_bytes()).unwrap();
    assert_eq!(unverified.unverified_metadata().name, "Planner");
    assert!(unverified.unverified_metadata().streaming_supported);
    assert_ne!(
        unverified.unverified_metadata().signatures[0].payload_b64,
        ""
    );
    // Type-state enforces verification and freshness
    let verified = unverified
        .clone()
        .verify_ed25519_with(1500, 60, |_input, _sig, kid| {
            if kid == Some("key-1") {
                Ok(())
            } else {
                Err("unknown kid".into())
            }
        })
        .unwrap();
    assert_eq!(verified.metadata().name, "Planner");
    assert_eq!(verified.verified_key_id(), Some("key-1"));
    assert!(
        unverified
            .verify_ed25519_with(5000, 60, |_, _, _| Ok(()))
            .is_err()
    );
    assert!(grdr_llm_proto::strict_json::decode_base64_std("=").is_none());
    assert!(grdr_llm_proto::strict_json::decode_base64_std("AB==").is_none());
    assert!(grdr_llm_proto::strict_json::decode_base64_url("AA=").is_none());
}

#[test]
fn sse_decoder_aligns_cr_only_crlf_and_lf_across_split_chunks() {
    use grdr_llm_proto::stream::SseLineDecoder;

    let payload = br#"{"type":"content_block_start","index":0,"content_block":{"type":"tool_use","id":"tu_cr","name":"exec_shell"}}"#;
    let cr_event = format!(
        "event: content_block_start\rdata: {}\r\r",
        std::str::from_utf8(payload).unwrap()
    );
    let lf_event = format!(
        "event: content_block_start\ndata: {}\n\n",
        std::str::from_utf8(payload).unwrap()
    );

    let mut dec_cr = SseLineDecoder::new(65_536);
    let mut cr_frames = dec_cr.push_chunk(cr_event.as_bytes()).unwrap();
    if let Some(tail) = dec_cr.finish().unwrap() {
        cr_frames.push(tail);
    }
    assert!(!dec_cr.has_unflushed_state());
    assert_eq!(cr_frames.len(), 1);

    let mut dec_lf = SseLineDecoder::new(65_536);
    let lf_frames = dec_lf.push_chunk(lf_event.as_bytes()).unwrap();
    assert!(!dec_lf.has_unflushed_state());
    assert_eq!(lf_frames.len(), 1);
    assert_eq!(cr_frames[0], lf_frames[0]);

    let mut dec_split_crlf = SseLineDecoder::new(65_536);
    assert!(
        dec_split_crlf
            .push_chunk(b"data: one\r")
            .unwrap()
            .is_empty()
    );
    let f1 = dec_split_crlf.push_chunk(b"\n\ndata: two\r\n").unwrap();
    assert_eq!(f1.len(), 1);
    assert_eq!(f1[0].data, "one");
    let f2 = dec_split_crlf.finish().unwrap().unwrap();
    assert_eq!(f2.data, "two");

    let mut dec_split_cr = SseLineDecoder::new(65_536);
    assert!(
        dec_split_cr
            .push_chunk(b"data: alpha\r")
            .unwrap()
            .is_empty()
    );
    let mut f_cr = dec_split_cr.push_chunk(b"\rdata: beta\r\r").unwrap();
    if let Some(tail) = dec_split_cr.finish().unwrap() {
        f_cr.push(tail);
    }
    assert_eq!(f_cr.len(), 2);
    assert_eq!(f_cr[0].data, "alpha");
    assert_eq!(f_cr[1].data, "beta");

    let mut insp = LlmStreamInspector::new(ProviderFamily::AnthropicMessages);
    let mut deltas = insp.push_sse_chunk(cr_event.as_bytes()).unwrap();
    if let Some(tail) = insp.finish_sse().unwrap() {
        deltas.push(tail);
    }
    assert_eq!(deltas.len(), 1);
    assert_eq!(deltas[0].tool_calls[0].name.as_deref(), Some("exec_shell"));
}
