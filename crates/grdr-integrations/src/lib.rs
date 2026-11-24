// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod grc;
pub mod manifest;
pub mod outbox;
pub mod saas;

#[cfg(test)]
mod tests;

pub use grc::{
    CisoAssistantEvidencePayload, GrcControlStatus, GrcEvidenceInput, GrcPushEnvelope,
    GrcPushPayload, GrcTarget, ProboEvidencePayload, build_grc_evidence_push,
};
pub use manifest::{
    AuthScheme, CaptureCeiling, CodecKind, ConfigFieldSpec, ConfigFieldType, ConnectorDirection,
    ConnectorHealth, ConnectorKind, ConnectorManifest, IntegrationHost, IntegrationInstance,
    SecretRef, StabilityClass, SupportTier, VendorApiCompat, validate_egress_url,
    validate_manifest,
};
pub use outbox::{
    CircuitBreakerConfig, CircuitState, DeliveryOutcome, ExportCursor, ExportEnvelope,
    ExportStream, OutboxItem, OutboxItemState, OutboxQueue, RetryPolicy,
};
pub use saas::{
    AnthropicActivityEvent, AnthropicActivityPage, AnthropicActor, OpenAiComplianceEvent,
    OpenAiCompliancePage, RateBudgetTracker, connector_assurance, parse_anthropic_compliance_page,
    parse_openai_compliance_page, sanitize_inert_text,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IntegrationError {
    #[error("GRDR-INT-0001: manifest validation failed: {0}")]
    InvalidManifest(String),
    #[error("GRDR-INT-0002: forbidden action scope `{0}` rejected by SR-33")]
    ForbiddenScope(String),
    #[error("GRDR-INT-0003: egress target `{0}` rejected by SSRF guard")]
    EgressDenied(String),
    #[error("GRDR-INT-0004: unknown connector manifest `{0}`")]
    UnknownConnector(String),
    #[error("GRDR-INT-0005: malformed SaaS compliance payload: {0}")]
    MalformedPayload(String),
    #[error("GRDR-INT-0006: shared compliance API rate budget exceeded")]
    RateBudgetExceeded,
    #[error("GRDR-INT-0007: GRC evidence input invalid: {0}")]
    InvalidGrcInput(String),
    #[error("GRDR-INT-0008: outbox circuit is open until {retry_after_at}")]
    CircuitOpen { retry_after_at: String },
    #[error("GRDR-INT-0009: outbox item `{0}` not found or invalid state")]
    OutboxState(String),
}
