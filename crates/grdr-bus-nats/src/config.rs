// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::CodedError;
use grdr_ports::OrgId;

pub const CODE_NATS_IO: &str = "GRDR-NATS-0001";
pub const CODE_NATS_CONFIG: &str = "GRDR-NATS-0002";
pub const CODE_NATS_WIRE: &str = "GRDR-NATS-0003";
pub const CODE_NATS_STREAM_FULL: &str = "GRDR-NATS-0004";

const EVENTS_STREAM_SHARDS: u32 = 8;
const DEFAULT_NATS_MAX_MSGS: usize = 1_000_000;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ListenerPolicy {
    Disabled,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatsListenerGuard {
    pub leafnode: ListenerPolicy,
    pub mqtt: ListenerPolicy,
    pub websocket: ListenerPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "mode", rename_all = "snake_case")]
pub enum NatsTransportMode {
    EmbeddedMemory,
    JetStreamTcp { server_url: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NatsDiscardPolicy {
    New,
    Old,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JetStreamStreamSpec {
    pub stream_name: String,
    pub subjects: Vec<String>,
    pub retention_max_age_secs: u64,
    pub max_bytes: u64,
    pub discard_policy: NatsDiscardPolicy,
    pub replicas: u8,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NatsConfig {
    pub transport: NatsTransportMode,
    pub listener_guard: NatsListenerGuard,
    pub client_name: String,
    pub max_bytes_per_stream: u64,
    pub max_msgs_per_stream: usize,
    pub max_age_secs: u64,
    pub replicas: u8,
    pub connect_timeout_ms: u32,
}

impl Default for NatsListenerGuard {
    fn default() -> Self {
        Self {
            leafnode: ListenerPolicy::Disabled,
            mqtt: ListenerPolicy::Disabled,
            websocket: ListenerPolicy::Disabled,
        }
    }
}

impl NatsListenerGuard {
    pub fn validate(&self) -> Result<(), CodedError> {
        if self.leafnode == ListenerPolicy::Enabled
            || self.mqtt == ListenerPolicy::Enabled
            || self.websocket == ListenerPolicy::Enabled
        {
            return Err(CodedError::new(
                CODE_NATS_CONFIG,
                "NATS JetStream unused listeners (leafnode, mqtt, websocket) must be disabled.",
                "Disable unused NATS protocol listeners in cluster configuration.",
            ));
        }
        Ok(())
    }
}

impl NatsConfig {
    pub fn embedded_default() -> Self {
        Self {
            transport: NatsTransportMode::EmbeddedMemory,
            listener_guard: NatsListenerGuard::default(),
            client_name: "grdr-server".into(),
            max_bytes_per_stream: 1024 * 1024 * 1024,
            max_msgs_per_stream: DEFAULT_NATS_MAX_MSGS,
            max_age_secs: 72 * 3600,
            replicas: 3,
            connect_timeout_ms: 5_000,
        }
    }

    pub fn parse_url(server_url: &str) -> Result<Self, CodedError> {
        let trimmed = server_url.trim();
        let (scheme, hostport) = if let Some(rest) = trimmed.strip_prefix("nats://") {
            ("nats://", rest)
        } else if let Some(rest) = trimmed.strip_prefix("tls://") {
            ("tls://", rest)
        } else {
            return Err(CodedError::new(
                CODE_NATS_CONFIG,
                "NATS server URL must begin with nats:// or tls://.",
                "Provide a valid NATS JetStream endpoint URL.",
            ));
        };
        let normalized_hostport = validate_nats_hostport(hostport)?;
        let mut cfg = Self::embedded_default();
        cfg.transport = NatsTransportMode::JetStreamTcp {
            server_url: format!("{scheme}{normalized_hostport}"),
        };
        Ok(cfg)
    }

    pub fn validate(&self) -> Result<(), CodedError> {
        self.listener_guard.validate()?;
        if self.client_name.trim().is_empty()
            || self
                .client_name
                .chars()
                .any(|c| c == '\r' || c == '\n' || c == '\0' || c.is_control())
        {
            return Err(CodedError::new(
                CODE_NATS_CONFIG,
                "NATS client_name must be non-empty without control characters.",
                "Set a valid NATS client_name.",
            ));
        }
        if self.max_bytes_per_stream == 0 || self.max_msgs_per_stream == 0 || self.replicas == 0 {
            return Err(CodedError::new(
                CODE_NATS_CONFIG,
                "NATS stream max_bytes_per_stream, max_msgs_per_stream, and replicas must be positive.",
                "Set valid JetStream stream capacity and replication factor.",
            ));
        }
        if let NatsTransportMode::JetStreamTcp { server_url } = &self.transport
            && server_url.trim().is_empty()
        {
            return Err(CodedError::new(
                CODE_NATS_CONFIG,
                "NATS JetStreamTcp server_url cannot be empty.",
                "Provide a nats:// or tls:// endpoint.",
            ));
        }
        Ok(())
    }

    pub fn stream_spec(&self, stream: &str, partition: u32) -> JetStreamStreamSpec {
        let js_name = jetstream_stream_name(stream, partition);
        let subject_pattern = format!("grdr.*.{}.*", sanitize_token(stream));
        JetStreamStreamSpec {
            stream_name: js_name,
            subjects: vec![subject_pattern],
            retention_max_age_secs: self.max_age_secs,
            max_bytes: self.max_bytes_per_stream,
            discard_policy: NatsDiscardPolicy::New,
            replicas: self.replicas,
        }
    }
}

pub fn subject_for(org: &OrgId, stream: &str, partition: u32) -> String {
    format!(
        "grdr.{}.{}.p{partition}",
        sanitize_token(org.as_str()),
        sanitize_token(stream)
    )
}

pub fn jetstream_stream_name(stream: &str, partition: u32) -> String {
    match stream.trim().to_ascii_lowercase().as_str() {
        "events" => format!("GRDR_EVENTS_{}", partition % EVENTS_STREAM_SHARDS),
        "decision" => "GRDR_DECISION".into(),
        "detect-keyed" | "detect_keyed" => "GRDR_DETECT_KEYED".into(),
        "findings" => "GRDR_FINDINGS".into(),
        "control" => "GRDR_CONTROL".into(),
        "usage" => "GRDR_USAGE".into(),
        other => format!(
            "GRDR_{}",
            other
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() {
                    c.to_ascii_uppercase()
                } else {
                    '_'
                })
                .collect::<String>()
        ),
    }
}

fn validate_nats_hostport(raw: &str) -> Result<String, CodedError> {
    if raw.is_empty()
        || raw
            .chars()
            .any(|c| c.is_whitespace() || c.is_control() || matches!(c, '@' | '/' | '?' | '#'))
    {
        return Err(CodedError::new(
            CODE_NATS_CONFIG,
            "NATS server URL hostport contains invalid characters.",
            "Provide a clean nats://host:port or tls://host:port endpoint.",
        ));
    }
    if let Some(after_open) = raw.strip_prefix('[') {
        let (host, rest) = after_open.split_once(']').ok_or_else(|| {
            CodedError::new(
                CODE_NATS_CONFIG,
                "Invalid IPv6 host literal in NATS URL.",
                "Use [addr]:port format for IPv6 hosts.",
            )
        })?;
        if host.is_empty() {
            return Err(CodedError::new(
                CODE_NATS_CONFIG,
                "NATS server IPv6 host cannot be empty.",
                "Provide a valid IPv6 host address.",
            ));
        }
        if rest.is_empty() {
            return Ok(format!("[{host}]:4222"));
        }
        let port_str = rest.strip_prefix(':').ok_or_else(|| {
            CodedError::new(
                CODE_NATS_CONFIG,
                "Unexpected suffix after IPv6 host in NATS URL.",
                "Use [addr]:port format.",
            )
        })?;
        validate_port(port_str)?;
        return Ok(format!("[{host}]:{port_str}"));
    }
    if let Some((host, port_str)) = raw.split_once(':') {
        if host.is_empty() || port_str.contains(':') {
            return Err(CodedError::new(
                CODE_NATS_CONFIG,
                "Invalid host:port in NATS URL.",
                "Format NATS endpoint as host:port.",
            ));
        }
        validate_port(port_str)?;
        Ok(format!("{host}:{port_str}"))
    } else {
        Ok(format!("{raw}:4222"))
    }
}

fn validate_port(raw: &str) -> Result<u16, CodedError> {
    let port: u16 = raw.parse().map_err(|_| {
        CodedError::new(
            CODE_NATS_CONFIG,
            format!("Invalid NATS port `{raw}`."),
            "Specify a numeric TCP port between 1 and 65535.",
        )
    })?;
    if port == 0 {
        return Err(CodedError::new(
            CODE_NATS_CONFIG,
            "NATS TCP port cannot be zero.",
            "Specify a numeric TCP port between 1 and 65535.",
        ));
    }
    Ok(port)
}

fn sanitize_token(raw: &str) -> String {
    let cleaned: String = raw
        .trim()
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .collect();
    if cleaned.is_empty() {
        "default".into()
    } else {
        cleaned
    }
}
