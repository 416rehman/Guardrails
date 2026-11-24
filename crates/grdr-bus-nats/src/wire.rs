// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::time::Duration;

use grdr_model::CodedError;

use crate::config::{CODE_NATS_WIRE, JetStreamStreamSpec, NatsDiscardPolicy};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatsWireState {
    Disconnected,
    Connected,
    Failed { reason: String },
}

pub fn encode_connect_cmd(client_name: &str) -> Result<String, CodedError> {
    let payload = serde_json::json!({
        "verbose": false,
        "pedantic": true,
        "tls_required": false,
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
) -> Vec<u8> {
    let mut hdr_block = String::from("NATS/1.0\r\n");
    hdr_block.push_str(&format!("Nats-Msg-Id: {msg_id}\r\n"));
    for (k, v) in headers {
        let clean_k = k.replace(['\r', '\n', ':'], "_");
        let clean_v = v.replace(['\r', '\n'], " ");
        hdr_block.push_str(&format!("{clean_k}: {clean_v}\r\n"));
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
    frame
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
    let addr = server_url
        .trim()
        .strip_prefix("nats://")
        .or_else(|| server_url.trim().strip_prefix("tls://"))
        .unwrap_or(server_url.trim());
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
    let mut info_line = String::new();
    reader.read_line(&mut info_line).map_err(nats_io_err)?;
    if !info_line.starts_with("INFO ") {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("Expected NATS INFO handshake, got `{}`.", info_line.trim()),
            "Verify NATS server protocol compatibility.",
        ));
    }

    let connect = encode_connect_cmd(client_name)?;
    stream.write_all(connect.as_bytes()).map_err(nats_io_err)?;
    for frame in frames {
        stream.write_all(frame).map_err(nats_io_err)?;
    }
    stream.write_all(b"PING\r\n").map_err(nats_io_err)?;
    stream.flush().map_err(nats_io_err)?;

    let mut reply = String::new();
    reader.read_line(&mut reply).map_err(nats_io_err)?;
    if reply.starts_with("-ERR") {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            format!("NATS server rejected publish: {}", reply.trim()),
            "Inspect JetStream stream limits and subject permissions.",
        ));
    }
    Ok(())
}

fn nats_io_err(err: std::io::Error) -> CodedError {
    CodedError::new(
        CODE_NATS_WIRE,
        format!("NATS wire I/O failed: {err}"),
        "Check NATS socket connection.",
    )
}
