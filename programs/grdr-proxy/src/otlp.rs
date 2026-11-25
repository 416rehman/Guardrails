// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Loopback OTLP telemetry receiver (`R-68`) sanitizing and redacting untrusted
//! signals strictly under `ProvenanceSource::Claimed`.

use axum::http::HeaderMap;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use grdr_model::{ActionAttempt, ActionClass, ControlPoint, ProvenanceSource};
use grdr_strings::sanitize_untrusted_text;

use crate::ProxyError;

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
        "application/x-protobuf" | "application/protobuf" => (
            OtlpWireFormat::Protobuf,
            "sess-otlp".to_owned(),
            "otlp-agent".to_owned(),
            format!("protobuf-signal bytes={}", body.len()),
        ),
        other => {
            return Err(ProxyError::Sr39Rejected(format!(
                "unsupported OTLP Content-Type `{other}`"
            )));
        }
    };

    let clean_summary = redact_secret_tokens(&sanitize_untrusted_text(&raw_summary));
    let attempt = ActionAttempt {
        id: format!("att_{}", Uuid::now_v7().simple()),
        session_id: sanitize_untrusted_text(&session_id),
        device_id: "dev-local".into(),
        device_name: "local-host".into(),
        agent_name: sanitize_untrusted_text(&agent_name),
        action_class: ActionClass::DataFlow,
        control_point: ControlPoint::Proxy,
        target: format!("otlp://{}/{}", signal.as_str(), format.as_str()),
        summary: clean_summary,
        timestamp: Timestamp::now(),
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

fn parse_otlp_json_summary(
    body: &[u8],
) -> Result<(OtlpWireFormat, String, String, String), ProxyError> {
    let val: serde_json::Value = serde_json::from_slice(body)
        .map_err(|e| ProxyError::Sr39Rejected(format!("invalid OTLP JSON: {e}")))?;
    let session = val
        .get("session_id")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("sess-otlp")
        .to_owned();
    let agent = val
        .get("agent_name")
        .and_then(serde_json::Value::as_str)
        .filter(|s| !s.trim().is_empty())
        .unwrap_or("otlp-agent")
        .to_owned();
    let mut summary_text = val
        .get("summary")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned)
        .unwrap_or_else(|| val.to_string());
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
        if SECRET_KEY_NAMES_LOWER.contains(&key_stem) && !lower.contains('=') {
            tokens.push(trimmed.to_owned());
            redact_next = true;
            continue;
        }
        if let Some((k, _v)) = trimmed.split_once('=') {
            let k_lower = k.trim().to_ascii_lowercase();
            if SECRET_KEY_NAMES_LOWER.contains(&k_lower.as_str()) {
                tokens.push(format!("{k}=[REDACTED_TOKEN]"));
                continue;
            }
        }
        let has_secret_prefix = SECRET_PREFIXES_LOWER.iter().any(|pfx| lower.contains(pfx));
        let looks_like_jwt = lower.starts_with("eyj") && trimmed.matches('.').count() >= 2;
        if has_secret_prefix
            || looks_like_jwt
            || ((lower.starts_with("bearer:") || lower.starts_with("basic:")) && trimmed.len() > 14)
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
