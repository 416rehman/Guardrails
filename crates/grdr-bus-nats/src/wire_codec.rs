// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::Deserialize;

use grdr_model::CodedError;

use crate::config::{CODE_NATS_WIRE, JetStreamStreamSpec, NatsAuthConfig, NatsDiscardPolicy};
use crate::nkey::sign_nonce_with_seed;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NatsWireState {
    Disconnected,
    Connected,
    Failed { reason: String },
}

#[derive(Debug, Clone, Default, Deserialize)]
pub(crate) struct NatsServerInfo {
    #[serde(default)]
    pub(crate) jetstream: Option<bool>,
    #[serde(default)]
    pub(crate) tls_required: Option<bool>,
    #[serde(default)]
    pub(crate) auth_required: Option<bool>,
    #[serde(default)]
    pub(crate) nonce: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct NatsInboundMessage {
    pub(crate) subject: String,
    pub(crate) sid: String,
    pub(crate) reply_to: Option<String>,
    pub(crate) status_code: Option<u16>,
    pub(crate) headers: BTreeMap<String, String>,
    pub(crate) payload: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum NatsInboundFrame {
    Pong,
    Ping,
    Ok,
    Err(String),
    Msg(NatsInboundMessage),
}

pub fn encode_connect_cmd(client_name: &str, tls_required: bool) -> Result<String, CodedError> {
    encode_connect_with_auth(client_name, tls_required, &NatsServerInfo::default(), None)
}

pub(crate) fn encode_connect_with_auth(
    client_name: &str,
    tls_required: bool,
    info: &NatsServerInfo,
    auth: Option<&NatsAuthConfig>,
) -> Result<String, CodedError> {
    if client_name.trim().is_empty() || has_control_chars(client_name) {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            "Invalid NATS client_name containing empty or control characters.",
            "Configure a clean client_name.",
        ));
    }
    let mut map = serde_json::Map::new();
    map.insert("verbose".into(), serde_json::Value::Bool(false));
    map.insert("pedantic".into(), serde_json::Value::Bool(true));
    map.insert("tls_required".into(), serde_json::Value::Bool(tls_required));
    map.insert("name".into(), serde_json::Value::String(client_name.into()));
    map.insert("lang".into(), serde_json::Value::String("rust".into()));
    map.insert("version".into(), serde_json::Value::String("0.1.0".into()));
    map.insert("protocol".into(), serde_json::Value::Number(1.into()));
    map.insert("headers".into(), serde_json::Value::Bool(true));
    map.insert("no_responders".into(), serde_json::Value::Bool(true));

    if info.auth_required == Some(true)
        && auth.and_then(|a| a.nkey_seed.as_ref()).is_none()
        && auth.and_then(|a| a.jwt.as_ref()).is_none()
    {
        return Err(CodedError::new(
            CODE_NATS_WIRE,
            "NATS server requires authentication, but no NKey seed or JWT was configured.",
            "Configure NKey seed or .creds JWT credentials.",
        ));
    }

    if let Some(auth_cfg) = auth {
        if let Some(ref jwt) = auth_cfg.jwt {
            map.insert("jwt".into(), serde_json::Value::String(jwt.clone()));
        }
        if let Some(ref seed) = auth_cfg.nkey_seed {
            let Some(nonce) = info.nonce.as_deref().filter(|value| !value.is_empty()) else {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    "NATS server requires NKey authentication but INFO omitted nonce challenge.",
                    "Verify NATS server NKey configuration.",
                ));
            };
            let signed = sign_nonce_with_seed(seed, nonce.as_bytes())?;
            map.insert("nkey".into(), serde_json::Value::String(signed.public_nkey));
            map.insert(
                "sig".into(),
                serde_json::Value::String(signed.signature_b64),
            );
        }
    }

    let encoded = serde_json::to_string(&serde_json::Value::Object(map)).map_err(|e| {
        CodedError::new(
            CODE_NATS_WIRE,
            format!("Failed encoding NATS CONNECT frame: {e}"),
            "Check client_name and auth credentials.",
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
    encode_hpub_with_reply(subject, None, msg_id, headers, payload)
}

pub(crate) fn encode_hpub_with_reply(
    subject: &str,
    reply_to: Option<&str>,
    msg_id: &str,
    headers: &BTreeMap<String, String>,
    payload: &[u8],
) -> Result<Vec<u8>, CodedError> {
    validate_nats_subject(subject)?;
    if let Some(reply) = reply_to {
        validate_nats_subject(reply)?;
    }
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

    let cmd = match reply_to {
        Some(reply) => format!("HPUB {subject} {reply} {hdr_len} {total_len}\r\n"),
        None => format!("HPUB {subject} {hdr_len} {total_len}\r\n"),
    };
    let mut frame = Vec::with_capacity(cmd.len().saturating_add(total_len).saturating_add(2));
    frame.extend_from_slice(cmd.as_bytes());
    frame.extend_from_slice(hdr_bytes);
    frame.extend_from_slice(payload);
    frame.extend_from_slice(b"\r\n");
    Ok(frame)
}

pub(crate) fn encode_pub_cmd(
    subject: &str,
    reply_to: Option<&str>,
    payload: &[u8],
) -> Result<Vec<u8>, CodedError> {
    validate_nats_subject(subject)?;
    if let Some(reply) = reply_to {
        validate_nats_subject(reply)?;
    }
    let cmd = match reply_to {
        Some(reply) => format!("PUB {subject} {reply} {}\r\n", payload.len()),
        None => format!("PUB {subject} {}\r\n", payload.len()),
    };
    let mut frame = Vec::with_capacity(cmd.len().saturating_add(payload.len()).saturating_add(2));
    frame.extend_from_slice(cmd.as_bytes());
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

pub(crate) fn parse_nats_headers(
    bytes: &[u8],
) -> Result<(Option<u16>, BTreeMap<String, String>), CodedError> {
    let raw = std::str::from_utf8(bytes).map_err(|_| nats_frame_err("non-UTF-8 HMSG headers"))?;
    let mut lines = raw.split("\r\n");
    let first = lines.next().unwrap_or("");
    let status_code = first
        .strip_prefix("NATS/1.0")
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .and_then(|s| s.split_whitespace().next())
        .and_then(|code_s| code_s.parse::<u16>().ok());
    let mut headers = BTreeMap::new();
    for line in lines {
        if line.is_empty() {
            continue;
        }
        if let Some((k, v)) = line.split_once(':') {
            let trimmed_k = k.trim();
            let trimmed_v = v.trim();
            let key = if trimmed_k
                .get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case("x-grdr-"))
            {
                trimmed_k.to_ascii_lowercase()
            } else {
                trimmed_k.to_string()
            };
            if let Some(prev) = headers.get(&key)
                && prev != trimmed_v
                && key.starts_with("x-grdr-")
            {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    format!("Conflicting duplicate `{key}` headers in inbound NATS frame."),
                    "Reject ambiguous tenant or metadata headers.",
                ));
            }
            headers.insert(key, trimmed_v.to_string());
        }
    }
    Ok((status_code, headers))
}

pub(crate) fn header_ci<'a>(
    headers: &'a BTreeMap<String, String>,
    target: &str,
) -> Result<Option<&'a str>, CodedError> {
    let mut found: Option<&'a str> = None;
    for (k, v) in headers {
        if k.eq_ignore_ascii_case(target) {
            if let Some(prev) = found
                && prev != v
            {
                return Err(CodedError::new(
                    CODE_NATS_WIRE,
                    format!("Conflicting case-variant headers for `{target}`."),
                    "Reject ambiguous NATS headers.",
                ));
            }
            found = Some(v.as_str());
        }
    }
    Ok(found)
}

pub(crate) fn strip_reserved_grdr_headers(
    headers: &BTreeMap<String, String>,
) -> BTreeMap<String, String> {
    headers
        .iter()
        .filter(|(k, _)| {
            !k.trim()
                .get(..7)
                .is_some_and(|p| p.eq_ignore_ascii_case("x-grdr-"))
        })
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
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

pub(crate) fn nats_frame_err(detail: &str) -> CodedError {
    CodedError::new(
        CODE_NATS_WIRE,
        format!("Invalid NATS wire frame: {detail}."),
        "Verify NATS JetStream protocol framing.",
    )
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
