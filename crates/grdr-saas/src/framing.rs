// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::CodedError;

use crate::{CODE_SAAS_INVALID_INPUT, saas_error};

#[derive(Debug, Clone, Default)]
pub(crate) struct CanonicalFrame {
    buf: Vec<u8>,
}

impl CanonicalFrame {
    pub(crate) fn new(tag: &str) -> Self {
        let mut frame = Self::default();
        frame.push_str(tag);
        frame
    }

    pub(crate) fn push_str(&mut self, value: &str) {
        let bytes = value.as_bytes();
        let len = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
        self.buf.extend_from_slice(&len.to_le_bytes());
        self.buf.extend_from_slice(bytes);
    }

    pub(crate) fn push_u32(&mut self, value: u32) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn push_u64(&mut self, value: u64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn push_i64(&mut self, value: i64) {
        self.buf.extend_from_slice(&value.to_le_bytes());
    }

    pub(crate) fn as_bytes(&self) -> &[u8] {
        &self.buf
    }
}

pub(crate) fn ensure_clean_token(field: &str, value: &str) -> Result<(), CodedError> {
    if value.trim().is_empty() || value.trim() != value {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            format!("Field `{field}` must be non-empty without leading/trailing whitespace."),
            "Trim and populate the required identifier.",
        ));
    }
    if value.chars().any(char::is_control) {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            format!("Field `{field}` must not contain control characters."),
            "Remove ASCII control, newline, or NUL bytes.",
        ));
    }
    Ok(())
}

pub(crate) fn validate_https_endpoint(endpoint: &str) -> Result<(), CodedError> {
    if endpoint.trim() != endpoint
        || endpoint
            .chars()
            .any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Endpoint URL must not contain whitespace or control characters.",
            "Pass a canonical trimmed https:// URL.",
        ));
    }
    let Some(rest) = endpoint.strip_prefix("https://") else {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Endpoint URL must start with https://.",
            "Configure an https:// base URL.",
        ));
    };
    let authority = rest.split('/').next().unwrap_or("");
    if authority.is_empty() || authority.contains('@') || rest.contains('?') || rest.contains('#') {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Endpoint URL must carry a clean host authority without credentials, query, or fragment.",
            "Provide https://host.example[:port] without userinfo or query parameters.",
        ));
    }
    let (host, opt_port) = match authority.split_once(':') {
        Some((h, port_str)) => (h, Some(port_str)),
        None => (authority, None),
    };
    if let Some(port_str) = opt_port {
        if port_str.is_empty() || !port_str.bytes().all(|b| b.is_ascii_digit()) {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Endpoint URL contains an invalid port specification.",
                "Specify an optional numeric TCP port in 1..=65535.",
            ));
        }
        let port = port_str.parse::<u16>().map_err(|_| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Endpoint URL port is out of range.",
                "Specify a valid TCP port in 1..=65535.",
            )
        })?;
        if port == 0 {
            return Err(saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Endpoint URL port cannot be 0.",
                "Specify a valid TCP port in 1..=65535.",
            ));
        }
    }
    if host.is_empty()
        || host.starts_with('.')
        || host.ends_with('.')
        || host.split('.').any(|label| {
            label.is_empty()
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-')
        })
    {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Endpoint URL contains an invalid host authority.",
            "Use a valid DNS hostname over HTTPS.",
        ));
    }
    Ok(())
}
