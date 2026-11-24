// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::proto_enum_codec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum FindingClass {
    Unspecified = 0,
    Threat = 1,
    PolicyViolation = 2,
    Overeager = 3,
    Tamper = 4,
    CoverageGap = 5,
}
proto_enum_codec!(FindingClass, finding_class_serde, [
    FindingClass::Unspecified => "FINDING_CLASS_UNSPECIFIED",
    FindingClass::Threat => "FINDING_CLASS_THREAT" | "threat",
    FindingClass::PolicyViolation => "FINDING_CLASS_POLICY_VIOLATION" | "policy_violation",
    FindingClass::Overeager => "FINDING_CLASS_OVEREAGER" | "overeager",
    FindingClass::Tamper => "FINDING_CLASS_TAMPER" | "tamper",
    FindingClass::CoverageGap => "FINDING_CLASS_COVERAGE_GAP" | "coverage_gap",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum FindingSeverity {
    Unspecified = 0,
    Low = 1,
    Medium = 2,
    High = 3,
    Critical = 4,
}
proto_enum_codec!(FindingSeverity, finding_severity_serde, [
    FindingSeverity::Unspecified => "FINDING_SEVERITY_UNSPECIFIED",
    FindingSeverity::Low => "FINDING_SEVERITY_LOW" | "low",
    FindingSeverity::Medium => "FINDING_SEVERITY_MEDIUM" | "medium",
    FindingSeverity::High => "FINDING_SEVERITY_HIGH" | "high",
    FindingSeverity::Critical => "FINDING_SEVERITY_CRITICAL" | "critical",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum FindingLifecycle {
    Unspecified = 0,
    Open = 1,
    Acknowledged = 2,
    Contained = 3,
    Resolved = 4,
}
proto_enum_codec!(FindingLifecycle, finding_lifecycle_serde, [
    FindingLifecycle::Unspecified => "FINDING_LIFECYCLE_UNSPECIFIED",
    FindingLifecycle::Open => "FINDING_LIFECYCLE_OPEN" | "open",
    FindingLifecycle::Acknowledged => "FINDING_LIFECYCLE_ACKNOWLEDGED" | "acknowledged",
    FindingLifecycle::Contained => "FINDING_LIFECYCLE_CONTAINED" | "contained",
    FindingLifecycle::Resolved => "FINDING_LIFECYCLE_RESOLVED" | "resolved",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum SpanKind {
    Unspecified = 0,
    InvokeAgent = 1,
    Chat = 2,
    ExecuteTool = 3,
    McpCall = 4,
    OsEffect = 5,
    SubagentSpawn = 6,
    Compaction = 7,
}
proto_enum_codec!(SpanKind, span_kind_serde, [
    SpanKind::Unspecified => "SPAN_KIND_UNSPECIFIED",
    SpanKind::InvokeAgent => "SPAN_KIND_INVOKE_AGENT" | "invoke_agent",
    SpanKind::Chat => "SPAN_KIND_CHAT" | "chat",
    SpanKind::ExecuteTool => "SPAN_KIND_EXECUTE_TOOL" | "execute_tool",
    SpanKind::McpCall => "SPAN_KIND_MCP_CALL" | "mcp_call",
    SpanKind::OsEffect => "SPAN_KIND_OS_EFFECT" | "os_effect",
    SpanKind::SubagentSpawn => "SPAN_KIND_SUBAGENT_SPAWN" | "subagent_spawn",
    SpanKind::Compaction => "SPAN_KIND_COMPACTION" | "compaction",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ProvenanceSource {
    Unspecified = 0,
    Claimed = 1,
    Observed = 2,
    Mediated = 3,
    Reconciled = 4,
}
proto_enum_codec!(ProvenanceSource, provenance_source_serde, [
    ProvenanceSource::Unspecified => "PROVENANCE_SOURCE_UNSPECIFIED",
    ProvenanceSource::Claimed => "PROVENANCE_SOURCE_CLAIMED" | "claimed",
    ProvenanceSource::Observed => "PROVENANCE_SOURCE_OBSERVED" | "observed",
    ProvenanceSource::Mediated => "PROVENANCE_SOURCE_MEDIATED" | "mediated",
    ProvenanceSource::Reconciled => "PROVENANCE_SOURCE_RECONCILED" | "reconciled",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum SessionLabel {
    Unspecified = 0,
    CredentialAccessed = 1,
    UntrustedWebFetched = 2,
    RepeatedDenials = 3,
    TaintedExfilRisk = 4,
}
proto_enum_codec!(SessionLabel, session_label_serde, [
    SessionLabel::Unspecified => "SESSION_LABEL_UNSPECIFIED",
    SessionLabel::CredentialAccessed => "SESSION_LABEL_CREDENTIAL_ACCESSED" | "credential_accessed",
    SessionLabel::UntrustedWebFetched => "SESSION_LABEL_UNTRUSTED_WEB_FETCHED" | "untrusted_web_fetched",
    SessionLabel::RepeatedDenials => "SESSION_LABEL_REPEATED_DENIALS" | "repeated_denials",
    SessionLabel::TaintedExfilRisk => "SESSION_LABEL_TAINTED_EXFIL_RISK" | "tainted_exfil_risk",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ArtifactKind {
    Unspecified = 0,
    Skill = 1,
    Rule = 2,
    Plugin = 3,
    Command = 4,
    Subagent = 5,
}
proto_enum_codec!(ArtifactKind, artifact_kind_serde, [
    ArtifactKind::Unspecified => "ARTIFACT_KIND_UNSPECIFIED",
    ArtifactKind::Skill => "ARTIFACT_KIND_SKILL" | "skill",
    ArtifactKind::Rule => "ARTIFACT_KIND_RULE" | "rule",
    ArtifactKind::Plugin => "ARTIFACT_KIND_PLUGIN" | "plugin",
    ArtifactKind::Command => "ARTIFACT_KIND_COMMAND" | "command",
    ArtifactKind::Subagent => "ARTIFACT_KIND_SUBAGENT" | "subagent",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ArtifactScope {
    Unspecified = 0,
    User = 1,
    Workspace = 2,
    Managed = 3,
}
proto_enum_codec!(ArtifactScope, artifact_scope_serde, [
    ArtifactScope::Unspecified => "ARTIFACT_SCOPE_UNSPECIFIED",
    ArtifactScope::User => "ARTIFACT_SCOPE_USER" | "user",
    ArtifactScope::Workspace => "ARTIFACT_SCOPE_WORKSPACE" | "workspace",
    ArtifactScope::Managed => "ARTIFACT_SCOPE_MANAGED" | "managed",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ArtifactRiskFlag {
    Unspecified = 0,
    HasScripts = 1,
    RequestsBroadTools = 2,
    BidiObfuscation = 3,
    UnpinnedDigest = 4,
}
proto_enum_codec!(ArtifactRiskFlag, artifact_risk_flag_serde, [
    ArtifactRiskFlag::Unspecified => "ARTIFACT_RISK_FLAG_UNSPECIFIED",
    ArtifactRiskFlag::HasScripts => "ARTIFACT_RISK_FLAG_HAS_SCRIPTS" | "has-scripts" | "has_scripts",
    ArtifactRiskFlag::RequestsBroadTools => "ARTIFACT_RISK_FLAG_REQUESTS_BROAD_TOOLS" | "requests-broad-tools" | "requests_broad_tools",
    ArtifactRiskFlag::BidiObfuscation => "ARTIFACT_RISK_FLAG_BIDI_OBFUSCATION" | "bidi-obfuscation" | "bidi_obfuscation",
    ArtifactRiskFlag::UnpinnedDigest => "ARTIFACT_RISK_FLAG_UNPINNED_DIGEST" | "unpinned-digest" | "unpinned_digest",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum IdentityMode {
    Unspecified = 0,
    Named = 1,
    Pseudonymous = 2,
}
proto_enum_codec!(IdentityMode, identity_mode_serde, [
    IdentityMode::Unspecified => "IDENTITY_MODE_UNSPECIFIED",
    IdentityMode::Named => "IDENTITY_MODE_NAMED" | "named",
    IdentityMode::Pseudonymous => "IDENTITY_MODE_PSEUDONYMOUS" | "pseudonymous",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum RiskTier {
    Unspecified = 0,
    Low = 1,
    Elevated = 2,
    High = 3,
    Critical = 4,
}
proto_enum_codec!(RiskTier, risk_tier_serde, [
    RiskTier::Unspecified => "RISK_TIER_UNSPECIFIED",
    RiskTier::Low => "RISK_TIER_LOW" | "low",
    RiskTier::Elevated => "RISK_TIER_ELEVATED" | "elevated",
    RiskTier::High => "RISK_TIER_HIGH" | "high",
    RiskTier::Critical => "RISK_TIER_CRITICAL" | "critical",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum DeploymentKeyStatus {
    Unspecified = 0,
    Active = 1,
    Exhausted = 2,
    Expired = 3,
    Revoked = 4,
}
proto_enum_codec!(DeploymentKeyStatus, deployment_key_status_serde, [
    DeploymentKeyStatus::Unspecified => "DEPLOYMENT_KEY_STATUS_UNSPECIFIED",
    DeploymentKeyStatus::Active => "DEPLOYMENT_KEY_STATUS_ACTIVE" | "active",
    DeploymentKeyStatus::Exhausted => "DEPLOYMENT_KEY_STATUS_EXHAUSTED" | "exhausted",
    DeploymentKeyStatus::Expired => "DEPLOYMENT_KEY_STATUS_EXPIRED" | "expired",
    DeploymentKeyStatus::Revoked => "DEPLOYMENT_KEY_STATUS_REVOKED" | "revoked",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum MdmFormat {
    Unspecified = 0,
    IntuneWin32 = 1,
    JamfMobileconfig = 2,
    Hexnode = 3,
    Tanium = 4,
    ChromeEnterprise = 5,
    FirefoxGpo = 6,
    LinuxRepo = 7,
}
proto_enum_codec!(MdmFormat, mdm_format_serde, [
    MdmFormat::Unspecified => "MDM_FORMAT_UNSPECIFIED",
    MdmFormat::IntuneWin32 => "MDM_FORMAT_INTUNE_WIN32" | "intune_win32",
    MdmFormat::JamfMobileconfig => "MDM_FORMAT_JAMF_MOBILECONFIG" | "jamf_mobileconfig",
    MdmFormat::Hexnode => "MDM_FORMAT_HEXNODE" | "hexnode",
    MdmFormat::Tanium => "MDM_FORMAT_TANIUM" | "tanium",
    MdmFormat::ChromeEnterprise => "MDM_FORMAT_CHROME_ENTERPRISE" | "chrome_enterprise",
    MdmFormat::FirefoxGpo => "MDM_FORMAT_FIREFOX_GPO" | "firefox_gpo",
    MdmFormat::LinuxRepo => "MDM_FORMAT_LINUX_REPO" | "linux_repo",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum IntegrationCategory {
    Unspecified = 0,
    DirectorySync = 1,
    SaasConnector = 2,
    ExportSink = 3,
}
proto_enum_codec!(IntegrationCategory, integration_category_serde, [
    IntegrationCategory::Unspecified => "INTEGRATION_CATEGORY_UNSPECIFIED",
    IntegrationCategory::DirectorySync => "INTEGRATION_CATEGORY_DIRECTORY_SYNC" | "directory_sync",
    IntegrationCategory::SaasConnector => "INTEGRATION_CATEGORY_SAAS_CONNECTOR" | "saas_connector",
    IntegrationCategory::ExportSink => "INTEGRATION_CATEGORY_EXPORT_SINK" | "export_sink",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum IntegrationHealthState {
    Unspecified = 0,
    Connected = 1,
    AtRisk = 2,
    Degraded = 3,
    NotConfigured = 4,
}
proto_enum_codec!(IntegrationHealthState, integration_health_state_serde, [
    IntegrationHealthState::Unspecified => "INTEGRATION_HEALTH_STATE_UNSPECIFIED",
    IntegrationHealthState::Connected => "INTEGRATION_HEALTH_STATE_CONNECTED" | "connected",
    IntegrationHealthState::AtRisk => "INTEGRATION_HEALTH_STATE_AT_RISK" | "at_risk",
    IntegrationHealthState::Degraded => "INTEGRATION_HEALTH_STATE_DEGRADED" | "degraded",
    IntegrationHealthState::NotConfigured => "INTEGRATION_HEALTH_STATE_NOT_CONFIGURED" | "not_configured",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum BrowserDlpClass {
    Unspecified = 0,
    FileUpload = 1,
    PasteSecret = 2,
    SourceCode = 3,
    CustomerPii = 4,
}
proto_enum_codec!(BrowserDlpClass, browser_dlp_class_serde, [
    BrowserDlpClass::Unspecified => "BROWSER_DLP_CLASS_UNSPECIFIED",
    BrowserDlpClass::FileUpload => "BROWSER_DLP_CLASS_FILE_UPLOAD" | "file_upload",
    BrowserDlpClass::PasteSecret => "BROWSER_DLP_CLASS_PASTE_SECRET" | "paste_secret",
    BrowserDlpClass::SourceCode => "BROWSER_DLP_CLASS_SOURCE_CODE" | "source_code",
    BrowserDlpClass::CustomerPii => "BROWSER_DLP_CLASS_CUSTOMER_PII" | "customer_pii",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum SchemaDataClass {
    Unspecified = 0,
    Metadata = 1,
    NamedIdentity = 2,
    Content = 3,
    Secret = 4,
}
proto_enum_codec!(SchemaDataClass, schema_data_class_serde, [
    SchemaDataClass::Unspecified => "SCHEMA_DATA_CLASS_UNSPECIFIED",
    SchemaDataClass::Metadata => "SCHEMA_DATA_CLASS_METADATA" | "metadata",
    SchemaDataClass::NamedIdentity => "SCHEMA_DATA_CLASS_NAMED_IDENTITY" | "named_identity",
    SchemaDataClass::Content => "SCHEMA_DATA_CLASS_CONTENT" | "content",
    SchemaDataClass::Secret => "SCHEMA_DATA_CLASS_SECRET" | "secret",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ServerHealth {
    Unspecified = 0,
    Ok = 1,
    Healthy = 2,
    Degraded = 3,
    Unavailable = 4,
}
proto_enum_codec!(ServerHealth, server_health_serde, [
    ServerHealth::Unspecified => "SERVER_HEALTH_UNSPECIFIED",
    ServerHealth::Ok => "SERVER_HEALTH_OK" | "ok",
    ServerHealth::Healthy => "SERVER_HEALTH_HEALTHY" | "healthy",
    ServerHealth::Degraded => "SERVER_HEALTH_DEGRADED" | "degraded",
    ServerHealth::Unavailable => "SERVER_HEALTH_UNAVAILABLE" | "unavailable",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum StorageKind {
    Unspecified = 0,
    Memory = 1,
    Sqlite = 2,
}
proto_enum_codec!(StorageKind, storage_kind_serde, [
    StorageKind::Unspecified => "STORAGE_KIND_UNSPECIFIED",
    StorageKind::Memory => "STORAGE_KIND_MEMORY" | "memory",
    StorageKind::Sqlite => "STORAGE_KIND_SQLITE" | "sqlite",
]);
