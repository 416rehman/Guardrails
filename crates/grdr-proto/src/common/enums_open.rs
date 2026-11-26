// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Canonical open and inventory wire enumerations synced with `enums.proto` and `export.proto`.

use crate::proto_enum_codec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Disposition {
    Unspecified = 0,
    ConfirmedAgent = 1,
    KnownVariant = 2,
    LlmClient = 3,
    NotAi = 4,
    Snoozed = 5,
}
proto_enum_codec!(Disposition, disposition_serde, [
    Disposition::Unspecified => "DISPOSITION_UNSPECIFIED",
    Disposition::ConfirmedAgent => "DISPOSITION_CONFIRMED_AGENT" | "confirmed_agent",
    Disposition::KnownVariant => "DISPOSITION_KNOWN_VARIANT" | "known_variant",
    Disposition::LlmClient => "DISPOSITION_LLM_CLIENT" | "llm_client",
    Disposition::NotAi => "DISPOSITION_NOT_AI" | "not_ai",
    Disposition::Snoozed => "DISPOSITION_SNOOZED" | "snoozed",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum EvidenceKind {
    Unspecified = 0,
    SpanText = 1,
    ArtifactDigest = 2,
    ReceiptRef = 3,
    ProcessLineage = 4,
    Other = 99,
}
proto_enum_codec!(EvidenceKind, evidence_kind_serde, [
    EvidenceKind::Unspecified => "EVIDENCE_KIND_UNSPECIFIED",
    EvidenceKind::SpanText => "EVIDENCE_KIND_SPAN_TEXT" | "span_text",
    EvidenceKind::ArtifactDigest => "EVIDENCE_KIND_ARTIFACT_DIGEST" | "artifact_digest",
    EvidenceKind::ReceiptRef => "EVIDENCE_KIND_RECEIPT_REF" | "receipt_ref",
    EvidenceKind::ProcessLineage => "EVIDENCE_KIND_PROCESS_LINEAGE" | "process_lineage",
    EvidenceKind::Other => "EVIDENCE_KIND_OTHER" | "other",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ChannelKind {
    Unspecified = 0,
    HookCallback = 1,
    SensorExec = 2,
    ProxyHttp = 3,
    McpBroker = 4,
    Otlp = 5,
    TranscriptTail = 6,
    Other = 99,
}
proto_enum_codec!(ChannelKind, channel_kind_serde, [
    ChannelKind::Unspecified => "CHANNEL_KIND_UNSPECIFIED",
    ChannelKind::HookCallback => "CHANNEL_KIND_HOOK_CALLBACK" | "hook_callback",
    ChannelKind::SensorExec => "CHANNEL_KIND_SENSOR_EXEC" | "sensor_exec",
    ChannelKind::ProxyHttp => "CHANNEL_KIND_PROXY_HTTP" | "proxy_http",
    ChannelKind::McpBroker => "CHANNEL_KIND_MCP_BROKER" | "mcp_broker",
    ChannelKind::Otlp => "CHANNEL_KIND_OTLP" | "otlp",
    ChannelKind::TranscriptTail => "CHANNEL_KIND_TRANSCRIPT_TAIL" | "transcript_tail",
    ChannelKind::Other => "CHANNEL_KIND_OTHER" | "other",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum AttributionEvidenceKind {
    Unspecified = 0,
    SessionContainer = 1,
    HookCorrelation = 2,
    DeclaredOnly = 3,
    Lineage = 4,
    HumanEntry = 5,
    SystemPrincipal = 6,
    Influenced = 7,
    ExecTag = 8,
    Other = 99,
}
proto_enum_codec!(AttributionEvidenceKind, attribution_evidence_kind_serde, [
    AttributionEvidenceKind::Unspecified => "ATTRIBUTION_EVIDENCE_KIND_UNSPECIFIED",
    AttributionEvidenceKind::SessionContainer => "ATTRIBUTION_EVIDENCE_KIND_SESSION_CONTAINER" | "session_container",
    AttributionEvidenceKind::HookCorrelation => "ATTRIBUTION_EVIDENCE_KIND_HOOK_CORRELATION" | "hook_correlation",
    AttributionEvidenceKind::DeclaredOnly => "ATTRIBUTION_EVIDENCE_KIND_DECLARED_ONLY" | "declared_only",
    AttributionEvidenceKind::Lineage => "ATTRIBUTION_EVIDENCE_KIND_LINEAGE" | "lineage",
    AttributionEvidenceKind::HumanEntry => "ATTRIBUTION_EVIDENCE_KIND_HUMAN_ENTRY" | "human_entry",
    AttributionEvidenceKind::SystemPrincipal => "ATTRIBUTION_EVIDENCE_KIND_SYSTEM_PRINCIPAL" | "system_principal",
    AttributionEvidenceKind::Influenced => "ATTRIBUTION_EVIDENCE_KIND_INFLUENCED" | "influenced",
    AttributionEvidenceKind::ExecTag => "ATTRIBUTION_EVIDENCE_KIND_EXEC_TAG" | "exec_tag",
    AttributionEvidenceKind::Other => "ATTRIBUTION_EVIDENCE_KIND_OTHER" | "other",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum HashAlgorithm {
    Unspecified = 0,
    Sha256 = 1,
    HmacSha256 = 2,
    Other = 99,
}
proto_enum_codec!(HashAlgorithm, hash_algorithm_serde, [
    HashAlgorithm::Unspecified => "HASH_ALGORITHM_UNSPECIFIED",
    HashAlgorithm::Sha256 => "HASH_ALGORITHM_SHA256" | "sha256",
    HashAlgorithm::HmacSha256 => "HASH_ALGORITHM_HMAC_SHA256" | "hmac_sha256",
    HashAlgorithm::Other => "HASH_ALGORITHM_OTHER" | "other",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ExportDialect {
    Unspecified = 0,
    NativeJson = 1,
    Ocsf19 = 2,
    Otlp = 3,
    Syslog = 4,
    Hec = 5,
    Other = 99,
}
proto_enum_codec!(ExportDialect, export_dialect_serde, [
    ExportDialect::Unspecified => "EXPORT_DIALECT_UNSPECIFIED",
    ExportDialect::NativeJson => "EXPORT_DIALECT_NATIVE_JSON" | "native_json",
    ExportDialect::Ocsf19 => "EXPORT_DIALECT_OCSF_1_9" | "ocsf_1_9",
    ExportDialect::Otlp => "EXPORT_DIALECT_OTLP" | "otlp",
    ExportDialect::Syslog => "EXPORT_DIALECT_SYSLOG" | "syslog",
    ExportDialect::Hec => "EXPORT_DIALECT_HEC" | "hec",
    ExportDialect::Other => "EXPORT_DIALECT_OTHER" | "other",
]);
