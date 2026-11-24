// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::io::{BufReader, Read, Write};
use std::net::TcpStream;
use std::time::Duration;

use grdr_model::CodedError;

use crate::config::{CODE_NATS_WIRE, JetStreamStreamSpec, NatsDiscardPolicy};

const MAX_NATS_LINE_BYTES: usize = 64 * 1024;
const MAX_REPLY_FRAMES: usize = 1_024;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatsWireState {
    Disconnected,
    Connected,
    Failed { reason: String },
}

pub fn encode_connect_cmd(client_name: &str, tls_required: bool) -> Result<String, CodedError> {
    if client_name.trim().is_empty() || has_control_chars(client_name) {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            "Invalid NATS client_name containing empty or control characters.",
            "Configure a clean client_name.",
        ));
    }
    let payload = serde_json::json!({
        "verbose": false,
        "pedantic": true,
        "tls_required": tls_required,
        "name": client_name,
        "lang": "rust",
        "version": "0.1.0",
        "protocol": 1,
        "headers": true,
        "no_responders": true,
    });
    let encoded = serde_json::to_string(&payload).map_err(|e| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Failed encoding NATS CONNECT frame: {e}"),
            "Check client_name characters.",
        )
    })?;
    Ok(format!("CONNECT {encoded}\r\n"))
}

pub fn encode_hpub_cmd(
    subject: &str,
    msg_id: &str,
    headers: &BTreeMap<String, String>,
    payload: &[u8],
) -> Result<Vec<u8>, CodedError> {
    validate_nats_subject(subject)?;
    validate_nats_header_value("Nats-Msg-Id", msg_id)?;
    if msg_id.is_empty() {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            "NATS Nats-Msg-Id header cannot be empty.",
            "Supply a non-empty deduplication message identifier.",
        ));
    }

    let mut hdr_block = String::from("NATS/1.0\r\n");
    hdr_block.push_str(&format!("Nats-Msg-Id: {msg_id}\r\n"));
    for (k, v) in headers {
        if k.eq_ignore_ascii_case("Nats-Msg-Id") {
            if v != msg_id {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    "Conflicting Nats-Msg-Id header values in NATS HPUB batch.",
                    "Provide a single consistent Nats-Msg-Id header.",
                ));
            }
            continue;
        }
        validate_nats_header_name(k)?;
        validate_nats_header_value(k, v)?;
        hdr_block.push_str(&format!("{k}: {v}\r\n"));
    }
    hdr_block.push_str("\r\n");

    let hdr_bytes = hdr_block.as_bytes();
    let hdr_len = hdr_bytes.len();
    let total_len = hdr_len.saturating_add(payload.len());

    let cmd = format!("HPUB {subject} {hdr_len} {total_len}\r\n");
    let mut frame = Vec::with_capacity(cmd.len().saturating_add(total_len).saturating_add(2));
    frame.extend_from_slice(cmd.as_bytes());
    frame.extend_from_slice(hdr_bytes);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(b"\r\n");
    Ok(frame)
}

pub fn jetstream_stream_create_subject(stream_name: &str) -> String {
    format!("$JS.API.STREAM.CREATE.{stream_name}")
}

pub fn jetstream_stream_purge_subject(stream_name: &str) -> String {
    format!("$JS.API.STREAM.PURGE.{stream_name}")
}

pub fn encode_stream_create_payload(spec: &JetStreamStreamSpec) -> Result<Vec<u8>, CodedError> {
    let discard = match spec.discard_policy {
        NatsDiscardPolicy::New => "new",
        NatsDiscardPolicy::Old => "old",
    };
    let max_age_ns = u128::from(spec.retention_max_age_secs).saturating_mul(1_000_000_000);
    let body = serde_json::json!({
        "name": spec.stream_name,
        "subjects": spec.subjects,
        "retention": "limits",
        "storage": "file",
        "discard": discard,
        "max_age": max_age_ns,
        "max_bytes": spec.max_bytes,
        "num_replicas": spec.replicas,
        "allow_rollup_hdrs": false,
        "deny_delete": false,
        "deny_purge": false,
    });
    serde_json::to_vec(&body).map_err(|e| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Failed serializing JetStream stream spec: {e}"),
            "Check JetStreamStreamSpec fields.",
        )
    })
}

pub fn publish_batch_wire(
    server_url: &str,
    client_name: &str,
    timeout_ms: u32,
    frames: &[Vec<u8>],
) -> Result<(), CodedError> {
    let trimmed = server_url.trim();
    if trimmed.starts_with("tls://") {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            "NATS tls:// transport requires TLS stream wrapping, which is not enabled in this build.",
            "Terminate TLS via a local verified proxy or enable TLS transport before using tls://.",
        ));
    }
    let addr = trimmed.strip_prefix("nats://").ok_or_else(|| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Unsupported NATS wire scheme in `{server_url}`."),
            "Use nats://host:port or tls://host:port.",
        )
    })?;

    let mut stream = TcpStream::connect(addr).map_err(|e| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Failed connecting to NATS server `{server_url}`: {e}"),
            "Verify NATS JetStream endpoint and network reachability.",
        )
    })?;
    let dur = Duration::from_millis(u64::from(timeout_ms.max(100)));
    let _ = stream.set_read_timeout(Some(dur));
    let _ = stream.set_write_timeout(Some(dur));

    let mut reader = BufReader::new(stream.try_clone().map_err(nats_io_err)?);
    let info_line = read_bounded_line(&mut reader)?;
    if !info_line.starts_with("INFO ") {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("Expected NATS INFO handshake, got `{}`.", info_line.trim()),
            "Verify NATS server protocol compatibility.",
        ));
    }

    let connect = encode_connect_cmd(client_name, false)?;
    stream.write_all(connect.as_bytes()).map_err(nats_io_err)?;
    for frame in frames {
        stream.write_all(frame).map_err(nats_io_err)?;
    }
    stream.write_all(b"PING\r\n").map_err(nats_io_err)?;
    stream.flush().map_err(nats_io_err)?;

    for _ in 0..MAX_REPLY_FRAMES {
        let reply = read_bounded_line(&mut reader)?;
        let line = reply.trim_end_matches(['\r', '\n']);
        if line == "PONG" {
            return Ok(());
        }
        if line == "+OK" {
            continue;
        }
        if line.starts_with("-ERR") {
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                format!("NATS server rejected publish: {line}"),
                "Inspect JetStream stream limits and subject permissions.",
            ));
        }
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("Unexpected NATS wire reply `{line}` while awaiting PONG."),
            "Verify NATS JetStream protocol framing.",
        ));
    }

    Err(CodedError::new(
        CODE_NATS_WIRE,
        "NATS server exceeded maximum reply frames without PONG.",
        "Inspect NATS server health.",
    ))
}

pub(crate) fn validate_nats_subject(subject: &str) -> Result<(), CodedError> {
    if subject.is_empty()
        || subject.starts_with('.')
        || subject.ends_with('.')
        || subject.contains("..")
        || subject
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '*' | '>' | '\0'))
    {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("Invalid or injected NATS subject `{subject}`."),
            "Subjects must contain valid non-wildcard ASCII tokens separated by single dots.",
        ));
    }
    Ok(())
}

fn validate_nats_header_name(name: &str) -> Result<(), CodedError> {
    if name.is_empty()
        || name
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, ':' | '\0'))
    {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("Invalid NATS header name `{name}`."),
            "Header names cannot contain whitespace, colons, or control characters.",
        ));
    }
    Ok(())
}

fn validate_nats_header_value(name: &str, value: &str) -> Result<(), CodedError> {
    if has_control_chars(value) {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("NATS header `{name}` contains forbidden control or newline characters."),
            "Strip CR/LF/NUL characters from NATS message headers.",
        ));
    }
    Ok(())
}

fn has_control_chars(raw: &str) -> bool {
    raw.chars()
        .any(|c| matches!(c, '\r' | '\n' | '\0') || c.is_control())
}

fn read_bounded_line<R: Read>(reader: &mut R) -> Result<String, CodedError> {
    let mut buf = Vec::new();
    let mut byte = [0u8; 1];
    loop {
        let n = reader.read(&mut byte).map_err(nats_io_err)?;
        if n == 0 {
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                "Unexpected EOF reading NATS wire frame.",
                "Verify NATS server stayed connected through handshake.",
            ));
        }
        buf.push(byte[0]);
        if byte[0] == b'\n' {
            break;
        }
        if buf.len() >= MAX_NATS_LINE_BYTES {
            return Err(CodedError::new(
                CODE_NATS_WIRE,
                "NATS server wire line exceeded maximum frame length.",
                "Verify NATS server protocol health.",
            ));
        }
    }
    String::from_utf8(buf).map_err(|e| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Non-UTF-8 NATS wire line: {e}"),
            "Inspect NATS server encoding.",
        )
    })
}

fn nats_io_err(err: std::io::Error) -> CodedError {
    CodedError::new(
        CODE_NATS_WIRE,
        format!("NATS wire I/O failed: {err}"),
        "Check NATS socket connection.",
    )
}
