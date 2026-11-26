// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Loopback OTLP telemetry receiver (`R-68`) sanitizing and redacting untrusted
//! signals strictly under `ProvenanceSource::Claimed`.

use axum::http::HeaderMap;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use url::Url;
use uuid::Uuid;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource};
use grdr_os_clock::{Clock, SystemClock};
use grdr_strings::sanitize_untrusted_text;

use crate::ProxyError;
use crate::egress::{EgressGuardConfig, LoopbackUpstreamPolicy};
use crate::router_otlp::send_sanitized_otlp_event;

pub const MAX_OTLP_BODY_BYTES: usize = 512 * 1024;
pub const MAX_OTLP_SUMMARY_BYTES: usize = 4_096;
const SECRET_PREFIXES_LOWER: &[&str] = &[
    "sk-",
    "sk_live_",
    "sk_test_",
    "github_pat_",
    "ghp_",
    "gho_",
    "ghs_",
    "ghr_",
    "xoxb-",
    "akia",
    "grdr_wk_",
    "grdr_ph_",
];

const SECRET_KEY_NAMES_LOWER: &[&str] = &[
    "authorization",
    "bearer",
    "basic",
    "token",
    "access_token",
    "refresh_token",
    "api_key",
    "apikey",
    "x-api-key",
    "secret",
    "password",
];

const AUTH_SCHEME_TOKENS_LOWER: &[&str] = &["bearer", "basic", "token"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtlpSignalKind {
    Traces,
    Logs,
    Metrics,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OtlpWireFormat {
    Json,
    Protobuf,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SanitizedOtlpEvent {
    pub signal: OtlpSignalKind,
    pub format: OtlpWireFormat,
    pub attempt: ActionAttempt,
    pub sanitized_bytes: usize,
}

#[derive(Debug, Deserialize)]
struct RawOtlpPayload {
    session_id: Option<String>,
    agent_name: Option<String>,
    summary: Option<String>,
}

#[derive(Debug, Clone)]
pub struct OtlpCollectorConfig {
    pub endpoint_base_url: Url,
    pub egress_config: EgressGuardConfig,
    pub queue_capacity: usize,
}

#[derive(Clone, Debug)]
pub struct OtlpUpstreamShipper {
    sender: mpsc::Sender<SanitizedOtlpEvent>,
    collector_url: String,
}

impl OtlpSignalKind {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Traces => "traces",
            Self::Logs => "logs",
            Self::Metrics => "metrics",
        }
    }
}

impl OtlpWireFormat {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Protobuf => "protobuf",
        }
    }
}

impl OtlpUpstreamShipper {
    pub fn spawn(config: OtlpCollectorConfig) -> Result<Self, ProxyError> {
        if !config.endpoint_base_url.username().is_empty()
            || config.endpoint_base_url.password().is_some()
            || config.endpoint_base_url.query().is_some()
            || config.endpoint_base_url.fragment().is_some()
        {
            return Err(ProxyError::Sr39Rejected(
                "OTLP collector URL must not contain credentials, query, or fragment".into(),
            ));
        }
        let scheme = config.endpoint_base_url.scheme();
        let raw_host = config
            .endpoint_base_url
            .host_str()
            .ok_or_else(|| ProxyError::Sr39Rejected("OTLP collector missing host".into()))?;
        let host = raw_host
            .strip_prefix('[')
            .and_then(|s| s.strip_suffix(']'))
            .unwrap_or(raw_host)
            .to_owned();
        let allow_loopback_http = config.egress_config.loopback_policy
            == LoopbackUpstreamPolicy::AllowExplicitLoopbackUpstreams
            && (host == "127.0.0.1" || host == "::1" || host.eq_ignore_ascii_case("localhost"));
        if scheme != "https" && !(scheme == "http" && allow_loopback_http) {
            return Err(ProxyError::Sr39Rejected(format!(
                "OTLP collector requires HTTPS (got scheme `{scheme}`)"
            )));
        }
        let port = config
            .endpoint_base_url
            .port_or_known_default()
            .ok_or_else(|| ProxyError::Sr39Rejected("OTLP collector missing port".into()))?;
        let base_str = config
            .endpoint_base_url
            .as_str()
            .trim_end_matches('/')
            .to_owned();
        let (tx, mut rx) = mpsc::channel::<SanitizedOtlpEvent>(config.queue_capacity.max(16));
        let egress_cfg = config.egress_config;
        let collector_label = base_str.clone();

        tokio::spawn(async move {
            while let Some(event) = rx.recv().await {
                if let Err(err) =
                    send_sanitized_otlp_event(&base_str, &host, port, &egress_cfg, &event).await
                {
                    tracing::warn!(error = %err, "OTLP upstream collector export failed");
                }
            }
        });

        Ok(Self {
            sender: tx,
            collector_url: collector_label,
        })
    }

    #[must_use]
    pub fn collector_url(&self) -> &str {
        &self.collector_url
    }

    pub fn try_enqueue(&self, event: SanitizedOtlpEvent) -> bool {
        self.sender.try_send(event).is_ok()
    }
}

pub fn ingest_otlp_payload(
    headers: &HeaderMap,
    signal: OtlpSignalKind,
    body: &[u8],
) -> Result<SanitizedOtlpEvent, ProxyError> {
    if headers.contains_key("origin") {
        return Err(ProxyError::Sr39Rejected(
            "Origin header rejected on loopback OTLP listener".into(),
        ));
    }
    if body.is_empty() || body.len() > MAX_OTLP_BODY_BYTES {
        return Err(ProxyError::Sr39Rejected(format!(
            "OTLP body length {} out of allowed bounds",
            body.len()
        )));
    }

    let ctype = headers
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| ProxyError::Sr39Rejected("OTLP requires Content-Type header".into()))?
        .split(';')
        .next()
        .unwrap_or("")
        .trim()
        .to_ascii_lowercase();

    let (format, session_id, agent_name, raw_summary) = match ctype.as_str() {
        "application/json" => parse_otlp_json_summary(body)?,
        "application/x-protobuf" | "application/protobuf" => {
            validate_protobuf_wire(body)?;
            (
                OtlpWireFormat::Protobuf,
                "sess-otlp".to_owned(),
                "otlp-agent".to_owned(),
                format!("protobuf-signal bytes={}", body.len()),
            )
        }
        other => {
            return Err(ProxyError::Sr39Rejected(format!(
                "unsupported OTLP Content-Type `{other}`"
            )));
        }
    };

    let now = SystemClock::new()
        .now_wall()
        .map_err(|e| ProxyError::Transport(format!("wall clock unavailable: {e}")))?;
    let clean_session = redact_secret_tokens(&sanitize_untrusted_text(&session_id));
    let clean_agent = redact_secret_tokens(&sanitize_untrusted_text(&agent_name));
    let clean_summary = redact_secret_tokens(&sanitize_untrusted_text(&raw_summary));
    let attempt = ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: clean_session,
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: clean_agent,
        action_class: ActionClass::DataFlow,
        control_point: ControlPoint::Proxy,
        target: format!("otlp://{}/{}", signal.as_str(), format.as_str()),
        summary: clean_summary,
        timestamp: now,
        provenance: ProvenanceSource::Claimed,
        ..Default::default()
    };

    Ok(SanitizedOtlpEvent {
        signal,
        format,
        attempt,
        sanitized_bytes: body.len(),
    })
}

fn validate_protobuf_wire(mut bytes: &[u8]) -> Result<(), ProxyError> {
    if bytes.is_empty() {
        return Err(ProxyError::Sr39Rejected("empty OTLP protobuf frame".into()));
    }
    let mut fields = 0usize;
    while !bytes.is_empty() {
        fields = fields.saturating_add(1);
        if fields > 65_536 {
            return Err(ProxyError::Sr39Rejected(
                "protobuf field limit exceeded".into(),
            ));
        }
        let key = decode_proto_varint(&mut bytes)?;
        let field_num = key >> 3;
        let wire_type = key & 0x07;
        if field_num == 0 {
            return Err(ProxyError::Sr39Rejected("invalid protobuf field 0".into()));
        }
        match wire_type {
            0 => {
                let _ = decode_proto_varint(&mut bytes)?;
            }
            1 => {
                let Some((_chunk, rest)) = bytes.split_at_checked(8) else {
                    return Err(ProxyError::Sr39Rejected(
                        "truncated protobuf 64-bit field".into(),
                    ));
                };
                bytes = rest;
            }
            2 => {
                let len_u64 = decode_proto_varint(&mut bytes)?;
                let len = usize::try_from(len_u64)
                    .map_err(|_| ProxyError::Sr39Rejected("protobuf length overflow".into()))?;
                let Some((_chunk, rest)) = bytes.split_at_checked(len) else {
                    return Err(ProxyError::Sr39Rejected(
                        "truncated protobuf length-delimited field".into(),
                    ));
                };
                bytes = rest;
            }
            5 => {
                let Some((_chunk, rest)) = bytes.split_at_checked(4) else {
                    return Err(ProxyError::Sr39Rejected(
                        "truncated protobuf 32-bit field".into(),
                    ));
                };
                bytes = rest;
            }
            _ => {
                return Err(ProxyError::Sr39Rejected(
                    "unsupported or deprecated protobuf wire type".into(),
                ));
            }
        }
    }
    Ok(())
}

fn decode_proto_varint(bytes: &mut &[u8]) -> Result<u64, ProxyError> {
    let mut val = 0_u64;
    for shift in 0..10_u32 {
        let Some((&b, rest)) = bytes.split_first() else {
            return Err(ProxyError::Sr39Rejected("truncated protobuf varint".into()));
        };
        *bytes = rest;
        let bits = u64::from(b & 0x7f);
        val |= bits
            .checked_shl(shift.saturating_mul(7))
            .ok_or_else(|| ProxyError::Sr39Rejected("protobuf varint overflow".into()))?;
        if (b & 0x80) == 0 {
            return Ok(val);
        }
    }
    Err(ProxyError::Sr39Rejected("overlong protobuf varint".into()))
}

fn parse_otlp_json_summary(
    body: &[u8],
) -> Result<(OtlpWireFormat, String, String, String), ProxyError> {
    let payload: RawOtlpPayload = serde_json::from_slice(body)
        .map_err(|e| ProxyError::Sr39Rejected(format!("invalid OTLP JSON: {e}")))?;
    let session = payload
        .session_id
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("sess-otlp")
        .to_owned();
    let agent = payload
        .agent_name
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .unwrap_or("otlp-agent")
        .to_owned();
    let mut summary_text = match payload.summary {
        Some(s) => s,
        None => std::str::from_utf8(body)
            .map_err(|_| ProxyError::Sr39Rejected("OTLP JSON must be valid UTF-8".into()))?
            .to_owned(),
    };
    if summary_text.len() > MAX_OTLP_SUMMARY_BYTES {
        summary_text = summary_text.chars().take(MAX_OTLP_SUMMARY_BYTES).collect();
    }
    Ok((OtlpWireFormat::Json, session, agent, summary_text))
}

#[must_use]
pub fn redact_secret_tokens(input: &str) -> String {
    if input.to_ascii_lowercase().contains("private key-----") {
        return "[REDACTED_PEM_PRIVATE_KEY]".into();
    }
    let url_scrubbed = redact_url_userinfo(input);
    let mut tokens: Vec<String> = Vec::new();
    let mut redact_next = false;
    for raw_seg in
        url_scrubbed.split(|c: char| c.is_whitespace() || matches!(c, '"' | '\'' | ',' | '{' | '}'))
    {
        if raw_seg.is_empty() {
            continue;
        }
        let trimmed = raw_seg.trim_matches(|c| matches!(c, '[' | ']' | ';'));
        if trimmed.is_empty() {
            continue;
        }
        if redact_next && (trimmed == ":" || trimmed == "=") {
            tokens.push(trimmed.to_owned());
            continue;
        }
        let lower = trimmed.to_ascii_lowercase();
        let key_stem = lower.trim_end_matches([':', '=']);
        if redact_next && AUTH_SCHEME_TOKENS_LOWER.contains(&key_stem) {
            tokens.push(trimmed.to_owned());
            continue;
        }
        if redact_next {
            tokens.push("[REDACTED_TOKEN]".into());
            redact_next = false;
            continue;
        }
        if SECRET_KEY_NAMES_LOWER.contains(&key_stem)
            && !lower.contains('=')
            && !lower.contains(':')
        {
            tokens.push(trimmed.to_owned());
            redact_next = true;
            continue;
        }
        let first_sep = match (trimmed.find('='), trimmed.find(':')) {
            (Some(eq_i), Some(col_i)) => {
                if eq_i < col_i {
                    Some(('=', eq_i))
                } else {
                    Some((':', col_i))
                }
            }
            (Some(eq_i), None) => Some(('=', eq_i)),
            (None, Some(col_i)) => Some((':', col_i)),
            (None, None) => None,
        };
        if let Some((sep, sep_idx)) = first_sep
            && let (Some(k), Some(v)) = (
                trimmed.get(..sep_idx),
                trimmed.get(sep_idx.saturating_add(1)..),
            )
        {
            let k_lower = k.trim().to_ascii_lowercase();
            if SECRET_KEY_NAMES_LOWER.contains(&k_lower.as_str()) {
                let v_trim = v.trim();
                if v_trim.is_empty() {
                    tokens.push(trimmed.to_owned());
                    redact_next = true;
                } else if AUTH_SCHEME_TOKENS_LOWER.contains(&v_trim.to_ascii_lowercase().as_str()) {
                    tokens.push(format!("{k}{sep}{v_trim}"));
                    redact_next = true;
                } else {
                    tokens.push(format!("{k}{sep}[REDACTED_TOKEN]"));
                }
                continue;
            }
            if (k_lower == "bearer" || k_lower == "basic") && !v.trim().is_empty() {
                tokens.push(format!("{k}{sep}[REDACTED_TOKEN]"));
                continue;
            }
        }
        let has_secret_prefix = SECRET_PREFIXES_LOWER.iter().any(|pfx| lower.contains(pfx));
        let looks_like_jwt = lower.starts_with("eyj") && trimmed.matches('.').count() >= 2;
        if has_secret_prefix
            || looks_like_jwt
            || ((lower.starts_with("bearer:")
                || lower.starts_with("basic:")
                || lower.starts_with("bearer=")
                || lower.starts_with("basic="))
                && trimmed.len() > 7)
        {
            tokens.push("[REDACTED_TOKEN]".into());
        } else {
            tokens.push(trimmed.to_owned());
        }
    }
    tokens.join(" ")
}

fn redact_url_userinfo(input: &str) -> String {
    let mut out = String::with_capacity(input.len());
    let mut rest = input;
    while let Some(scheme_idx) = rest.find("://") {
        let authority_start = scheme_idx.saturating_add(3);
        let Some((prefix, after_scheme)) = rest.split_at_checked(authority_start) else {
            break;
        };
        out.push_str(prefix);
        let auth_end = after_scheme
            .find(|c: char| c.is_whitespace() || matches!(c, '/' | '"' | '\'' | ',' | '}'))
            .unwrap_or(after_scheme.len());
        let (authority, tail) = after_scheme.split_at(auth_end);
        if let Some((_creds, host)) = authority.rsplit_once('@') {
            out.push_str("[REDACTED_CRED]@");
            out.push_str(host);
        } else {
            out.push_str(authority);
        }
        rest = tail;
    }
    out.push_str(rest);
    out
}
