// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::{
    ActionAttempt, ActionClass, AssuranceRecord, ControlPoint, ControlStrength, OnFailure,
    ProvenanceSource, SpanKind, TamperGrade, Visibility,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::IntegrationError;

const MAX_INERT_TEXT_CHARS: usize = 512;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SaasParseLimits {
    pub max_payload_bytes: usize,
    pub max_events_per_page: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicActor {
    #[serde(rename = "type")]
    pub actor_type: String,
    pub id: String,
    #[serde(default)]
    pub email_address: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicActivityEvent {
    pub id: String,
    #[serde(rename = "type")]
    pub event_type: String,
    pub created_at: Timestamp,
    pub actor: AnthropicActor,
    #[serde(default)]
    pub organization_id: Option<String>,
    #[serde(default)]
    pub session_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnthropicActivityPage {
    pub data: Vec<AnthropicActivityEvent>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub first_id: Option<String>,
    #[serde(default)]
    pub last_id: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiComplianceEvent {
    pub id: String,
    pub event_type: String,
    pub timestamp: i64,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub workspace_id: Option<String>,
    #[serde(default)]
    pub conversation_id: Option<String>,
    #[serde(default)]
    pub model: Option<String>,
    #[serde(default)]
    pub tool_name: Option<String>,
    #[serde(default)]
    pub target: Option<String>,
    #[serde(default)]
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OpenAiCompliancePage {
    pub data: Vec<OpenAiComplianceEvent>,
    #[serde(default)]
    pub has_more: bool,
    #[serde(default)]
    pub last_id: Option<String>,
}

#[derive(Debug, Clone)]
pub struct RateBudgetTracker {
    limit_per_window: u32,
    window_secs: i64,
    window_started_at: Timestamp,
    consumed: u32,
}

impl Default for SaasParseLimits {
    fn default() -> Self {
        Self {
            max_payload_bytes: 4 * 1024 * 1024,
            max_events_per_page: 1_000,
        }
    }
}

impl RateBudgetTracker {
    #[must_use]
    pub fn new(limit_per_window: u32, window_secs: i64, now: Timestamp) -> Self {
        Self {
            limit_per_window,
            window_secs,
            window_started_at: now,
            consumed: 0,
        }
    }

    pub fn try_acquire(&mut self, units: u32, now: Timestamp) -> Result<u32, IntegrationError> {
        if self.window_secs <= 0 {
            return Err(IntegrationError::MalformedPayload(
                "rate budget window_secs must be positive".into(),
            ));
        }
        let elapsed = now
            .as_second()
            .saturating_sub(self.window_started_at.as_second());
        if elapsed >= self.window_secs {
            self.window_started_at = now;
            self.consumed = 0;
        }
        let next = self
            .consumed
            .checked_add(units)
            .ok_or(IntegrationError::RateBudgetExceeded)?;
        if next > self.limit_per_window {
            return Err(IntegrationError::RateBudgetExceeded);
        }
        self.consumed = next;
        Ok(self.limit_per_window.saturating_sub(self.consumed))
    }
}

#[must_use]
pub const fn connector_assurance() -> AssuranceRecord {
    AssuranceRecord {
        visibility: Visibility::Observed,
        control: ControlStrength::None,
        on_failure: OnFailure::Open,
        tamper: TamperGrade::User,
    }
}

#[must_use]
pub fn sanitize_inert_text(raw: &str, max_chars: usize) -> String {
    raw.chars()
        .filter(|c| !is_bidi_or_control(*c))
        .take(max_chars)
        .collect::<String>()
        .trim()
        .to_owned()
}

pub fn parse_anthropic_compliance_page(
    json_bytes: &[u8],
    default_device_id: &str,
    default_device_name: &str,
) -> Result<Vec<ActionAttempt>, IntegrationError> {
    parse_anthropic_compliance_page_with_limits(
        json_bytes,
        default_device_id,
        default_device_name,
        SaasParseLimits::default(),
    )
}

pub fn parse_anthropic_compliance_page_with_limits(
    json_bytes: &[u8],
    default_device_id: &str,
    default_device_name: &str,
    limits: SaasParseLimits,
) -> Result<Vec<ActionAttempt>, IntegrationError> {
    if json_bytes.len() > limits.max_payload_bytes {
        return Err(IntegrationError::MalformedPayload(format!(
            "Anthropic payload length {} exceeds limit {}",
            json_bytes.len(),
            limits.max_payload_bytes
        )));
    }
    let page: AnthropicActivityPage = serde_json::from_slice(json_bytes).map_err(|e| {
        IntegrationError::MalformedPayload(format!("Anthropic compliance JSON error: {e}"))
    })?;
    if page.data.len() > limits.max_events_per_page {
        return Err(IntegrationError::MalformedPayload(format!(
            "Anthropic page event count {} exceeds limit {}",
            page.data.len(),
            limits.max_events_per_page
        )));
    }

    let mut attempts = Vec::with_capacity(page.data.len());
    for event in page.data {
        let fallback_session = format!("anth_{}", sanitize_inert_text(&event.id, 64));
        let raw_target = event
            .target
            .as_deref()
            .or(event.tool_name.as_deref())
            .or(event.model.as_deref())
            .unwrap_or(&event.event_type);
        let raw_summary = event.summary.as_deref().unwrap_or(&event.event_type);
        let (action_class, span_kind) =
            map_event_kind(&event.event_type, event.tool_name.as_deref());
        attempts.push(build_connector_attempt(
            &event.id,
            event.session_id.as_deref().unwrap_or(&fallback_session),
            Some(event.actor.id.as_str()),
            action_class,
            span_kind,
            (raw_target, raw_summary, event.tool_name.as_deref()),
            (
                event.created_at,
                "anthropic-compliance",
                default_device_id,
                default_device_name,
            ),
        ));
    }
    Ok(attempts)
}

pub fn parse_openai_compliance_page(
    json_bytes: &[u8],
    default_device_id: &str,
    default_device_name: &str,
) -> Result<Vec<ActionAttempt>, IntegrationError> {
    parse_openai_compliance_page_with_limits(
        json_bytes,
        default_device_id,
        default_device_name,
        SaasParseLimits::default(),
    )
}

pub fn parse_openai_compliance_page_with_limits(
    json_bytes: &[u8],
    default_device_id: &str,
    default_device_name: &str,
    limits: SaasParseLimits,
) -> Result<Vec<ActionAttempt>, IntegrationError> {
    if json_bytes.len() > limits.max_payload_bytes {
        return Err(IntegrationError::MalformedPayload(format!(
            "OpenAI payload length {} exceeds limit {}",
            json_bytes.len(),
            limits.max_payload_bytes
        )));
    }
    let page: OpenAiCompliancePage = serde_json::from_slice(json_bytes).map_err(|e| {
        IntegrationError::MalformedPayload(format!("OpenAI compliance JSON error: {e}"))
    })?;
    if page.data.len() > limits.max_events_per_page {
        return Err(IntegrationError::MalformedPayload(format!(
            "OpenAI page event count {} exceeds limit {}",
            page.data.len(),
            limits.max_events_per_page
        )));
    }

    let mut attempts = Vec::with_capacity(page.data.len());
    for event in page.data {
        let ts = Timestamp::from_second(event.timestamp).map_err(|e| {
            IntegrationError::MalformedPayload(format!("invalid OpenAI event timestamp: {e}"))
        })?;
        let fallback_session = format!("oai_{}", sanitize_inert_text(&event.id, 64));
        let raw_target = event
            .target
            .as_deref()
            .or(event.tool_name.as_deref())
            .or(event.model.as_deref())
            .unwrap_or(&event.event_type);
        let raw_summary = event.summary.as_deref().unwrap_or(&event.event_type);
        let (action_class, span_kind) =
            map_event_kind(&event.event_type, event.tool_name.as_deref());
        attempts.push(build_connector_attempt(
            &event.id,
            event
                .conversation_id
                .as_deref()
                .unwrap_or(&fallback_session),
            event.user_id.as_deref(),
            action_class,
            span_kind,
            (raw_target, raw_summary, event.tool_name.as_deref()),
            (
                ts,
                "openai-compliance",
                default_device_id,
                default_device_name,
            ),
        ));
    }
    Ok(attempts)
}

fn build_connector_attempt(
    id: &str,
    session_id: &str,
    user_id: Option<&str>,
    action_class: ActionClass,
    span_kind: SpanKind,
    text: (&str, &str, Option<&str>),
    origin: (Timestamp, &str, &str, &str),
) -> ActionAttempt {
    let (raw_target, raw_summary, tool_name) = text;
    let (timestamp, agent_name, default_device_id, default_device_name) = origin;

    ActionAttempt {
        id: sanitize_inert_text(id, MAX_INERT_TEXT_CHARS),
        session_id: sanitize_inert_text(session_id, MAX_INERT_TEXT_CHARS),
        device_id: default_device_id.to_owned(),
        device_name: default_device_name.to_owned(),
        agent_name: agent_name.to_owned(),
        action_class,
        control_point: ControlPoint::Connector,
        target: sanitize_inert_text(raw_target, MAX_INERT_TEXT_CHARS),
        summary: sanitize_inert_text(raw_summary, MAX_INERT_TEXT_CHARS),
        timestamp,
        user_id: user_id.map(|u| sanitize_inert_text(u, MAX_INERT_TEXT_CHARS)),
        user_display: None,
        turn_index: 1,
        span_id: None,
        parent_span_id: None,
        span_kind,
        duration_ms: 0,
        provenance: ProvenanceSource::Observed,
        secondary_actions: Vec::new(),
        skill_used: tool_name.map(|t| sanitize_inert_text(t, MAX_INERT_TEXT_CHARS)),
        compaction: false,
    }
}

fn map_event_kind(event_type: &str, tool_name: Option<&str>) -> (ActionClass, SpanKind) {
    let lower = event_type.to_ascii_lowercase();
    if lower.contains("mcp") {
        return (ActionClass::McpCall, SpanKind::McpCall);
    }
    if lower.contains("tool") || tool_name.is_some() {
        return (ActionClass::Exec, SpanKind::ExecuteTool);
    }
    if lower.contains("file") || lower.contains("upload") {
        return (ActionClass::FileWrite, SpanKind::OsEffect);
    }
    if lower.contains("api_key") || lower.contains("config") || lower.contains("setting") {
        return (ActionClass::ConfigChange, SpanKind::OsEffect);
    }
    (ActionClass::LlmRequest, SpanKind::Chat)
}

fn is_bidi_or_control(c: char) -> bool {
    c.is_control()
        || matches!(
            c,
            '\u{00AD}'
                | '\u{034F}'
                | '\u{061C}'
                | '\u{115F}'..='\u{1160}'
                | '\u{17B4}'..='\u{17B5}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{2028}'..='\u{202F}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
                | '\u{E0000}'..='\u{E007F}'
        )
}
