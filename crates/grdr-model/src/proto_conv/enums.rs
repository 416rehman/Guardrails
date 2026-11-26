// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_proto::common as pb;

use crate::{
    ActionClass, ApprovalGrade, AssuranceLevel, BrowserDlpClass, ControlPoint, ControlStrength,
    DeploymentKeyStatus, GrantScope, IdentityMode, InstallProfile, IntegrationCategory,
    IntegrationHealthState, KillAction, KillScope, MdmFormat, Mode, OnFailure, ProvenanceSource,
    RiskTier, SchemaDataClass, ServerHealth, SessionLabel, SpanKind, TamperGrade, Verdict,
    Visibility,
};

pub use super::enums_ops::*;

pub fn proto_to_mode(val: i32) -> Option<Mode> {
    match pb::Mode::try_from(val).ok()? {
        pb::Mode::Off => Some(Mode::Off),
        pb::Mode::Watch => Some(Mode::Watch),
        pb::Mode::Ask => Some(Mode::Ask),
        pb::Mode::Block => Some(Mode::Block),
        pb::Mode::Unspecified => None,
    }
}

pub fn mode_to_proto(val: Mode) -> i32 {
    match val {
        Mode::Off => pb::Mode::Off as i32,
        Mode::Watch => pb::Mode::Watch as i32,
        Mode::Ask => pb::Mode::Ask as i32,
        Mode::Block => pb::Mode::Block as i32,
    }
}

pub fn verdict_to_proto(val: Verdict) -> i32 {
    match val {
        Verdict::Allow => pb::Verdict::Allow as i32,
        Verdict::Modify => pb::Verdict::Modify as i32,
        Verdict::StepUp => pb::Verdict::StepUp as i32,
        Verdict::Defer => pb::Verdict::Defer as i32,
        Verdict::Deny => pb::Verdict::Deny as i32,
    }
}

pub fn proto_to_verdict(val: i32) -> Option<Verdict> {
    match pb::Verdict::try_from(val).ok()? {
        pb::Verdict::Allow => Some(Verdict::Allow),
        pb::Verdict::Modify => Some(Verdict::Modify),
        pb::Verdict::StepUp => Some(Verdict::StepUp),
        pb::Verdict::Defer => Some(Verdict::Defer),
        pb::Verdict::Deny => Some(Verdict::Deny),
        pb::Verdict::Unspecified => None,
    }
}

pub fn action_class_to_proto(val: ActionClass) -> i32 {
    match val {
        ActionClass::Exec => pb::ActionClass::Exec as i32,
        ActionClass::FileRead => pb::ActionClass::FileRead as i32,
        ActionClass::FileWrite => pb::ActionClass::FileWrite as i32,
        ActionClass::FileDelete => pb::ActionClass::FileDelete as i32,
        ActionClass::NetConnect => pb::ActionClass::NetConnect as i32,
        ActionClass::NetRequest => pb::ActionClass::NetRequest as i32,
        ActionClass::LlmRequest => pb::ActionClass::LlmRequest as i32,
        ActionClass::McpConnect => pb::ActionClass::McpConnect as i32,
        ActionClass::McpCall => pb::ActionClass::McpCall as i32,
        ActionClass::CredUse => pb::ActionClass::CredUse as i32,
        ActionClass::AgentSpawn => pb::ActionClass::AgentSpawn as i32,
        ActionClass::ConfigChange => pb::ActionClass::ConfigChange as i32,
        ActionClass::Elevate => pb::ActionClass::Elevate as i32,
        ActionClass::UiAct => pb::ActionClass::UiAct as i32,
        ActionClass::DataFlow => pb::ActionClass::DataFlow as i32,
    }
}

pub fn proto_to_action_class(val: i32) -> Option<ActionClass> {
    match pb::ActionClass::try_from(val).ok()? {
        pb::ActionClass::Exec => Some(ActionClass::Exec),
        pb::ActionClass::FileRead => Some(ActionClass::FileRead),
        pb::ActionClass::FileWrite => Some(ActionClass::FileWrite),
        pb::ActionClass::FileDelete => Some(ActionClass::FileDelete),
        pb::ActionClass::NetConnect => Some(ActionClass::NetConnect),
        pb::ActionClass::NetRequest => Some(ActionClass::NetRequest),
        pb::ActionClass::LlmRequest => Some(ActionClass::LlmRequest),
        pb::ActionClass::McpConnect => Some(ActionClass::McpConnect),
        pb::ActionClass::McpCall => Some(ActionClass::McpCall),
        pb::ActionClass::CredUse => Some(ActionClass::CredUse),
        pb::ActionClass::AgentSpawn => Some(ActionClass::AgentSpawn),
        pb::ActionClass::ConfigChange => Some(ActionClass::ConfigChange),
        pb::ActionClass::Elevate => Some(ActionClass::Elevate),
        pb::ActionClass::UiAct => Some(ActionClass::UiAct),
        pb::ActionClass::DataFlow => Some(ActionClass::DataFlow),
        pb::ActionClass::Unspecified => None,
    }
}

pub fn control_point_to_proto(val: ControlPoint) -> i32 {
    match val {
        ControlPoint::Hook => pb::ControlPoint::Hook as i32,
        ControlPoint::McpBroker => pb::ControlPoint::McpBroker as i32,
        ControlPoint::Proxy => pb::ControlPoint::Proxy as i32,
        ControlPoint::Sandbox => pb::ControlPoint::Sandbox as i32,
        ControlPoint::Sensor => pb::ControlPoint::Sensor as i32,
        ControlPoint::Browser => pb::ControlPoint::Browser as i32,
        ControlPoint::Gateway => pb::ControlPoint::Gateway as i32,
        ControlPoint::Connector => pb::ControlPoint::Connector as i32,
    }
}

pub fn proto_to_control_point(val: i32) -> Option<ControlPoint> {
    match pb::ControlPoint::try_from(val).ok()? {
        pb::ControlPoint::Hook => Some(ControlPoint::Hook),
        pb::ControlPoint::McpBroker => Some(ControlPoint::McpBroker),
        pb::ControlPoint::Proxy => Some(ControlPoint::Proxy),
        pb::ControlPoint::Sandbox => Some(ControlPoint::Sandbox),
        pb::ControlPoint::Sensor => Some(ControlPoint::Sensor),
        pb::ControlPoint::Browser => Some(ControlPoint::Browser),
        pb::ControlPoint::Gateway => Some(ControlPoint::Gateway),
        pb::ControlPoint::Connector => Some(ControlPoint::Connector),
        pb::ControlPoint::Unspecified => None,
    }
}

pub fn visibility_to_proto(val: Visibility) -> i32 {
    match val {
        Visibility::None => pb::Visibility::None as i32,
        Visibility::Claimed => pb::Visibility::Claimed as i32,
        Visibility::Observed => pb::Visibility::Observed as i32,
        Visibility::CrossChecked => pb::Visibility::CrossChecked as i32,
    }
}

pub fn proto_to_visibility(val: i32) -> Visibility {
    match pb::Visibility::try_from(val).ok() {
        Some(pb::Visibility::Claimed) => Visibility::Claimed,
        Some(pb::Visibility::Observed) => Visibility::Observed,
        Some(pb::Visibility::CrossChecked) => Visibility::CrossChecked,
        _ => Visibility::None,
    }
}

pub fn control_strength_to_proto(val: ControlStrength) -> i32 {
    match val {
        ControlStrength::None => pb::ControlStrength::None as i32,
        ControlStrength::Request => pb::ControlStrength::Request as i32,
        ControlStrength::ScopedBoundary => pb::ControlStrength::ScopedBoundary as i32,
        ControlStrength::MandatoryBoundary => pb::ControlStrength::MandatoryBoundary as i32,
    }
}

pub fn proto_to_control_strength(val: i32) -> ControlStrength {
    match pb::ControlStrength::try_from(val).ok() {
        Some(pb::ControlStrength::Request) => ControlStrength::Request,
        Some(pb::ControlStrength::ScopedBoundary) => ControlStrength::ScopedBoundary,
        Some(pb::ControlStrength::MandatoryBoundary) => ControlStrength::MandatoryBoundary,
        _ => ControlStrength::None,
    }
}

pub fn on_failure_to_proto(val: OnFailure) -> i32 {
    match val {
        OnFailure::Open => pb::OnFailure::Open as i32,
        OnFailure::Closed => pb::OnFailure::Closed as i32,
    }
}

pub fn proto_to_on_failure(val: i32) -> OnFailure {
    match pb::OnFailure::try_from(val).ok() {
        Some(pb::OnFailure::Closed) => OnFailure::Closed,
        _ => OnFailure::Open,
    }
}

pub fn tamper_grade_to_proto(val: TamperGrade) -> i32 {
    match val {
        TamperGrade::User => pb::TamperGrade::User as i32,
        TamperGrade::Admin => pb::TamperGrade::Admin as i32,
        TamperGrade::Platform => pb::TamperGrade::Platform as i32,
    }
}

pub fn proto_to_tamper_grade(val: i32) -> TamperGrade {
    match pb::TamperGrade::try_from(val).ok() {
        Some(pb::TamperGrade::Admin) => TamperGrade::Admin,
        Some(pb::TamperGrade::Platform) => TamperGrade::Platform,
        _ => TamperGrade::User,
    }
}

pub fn assurance_to_proto(val: AssuranceLevel) -> i32 {
    match val {
        AssuranceLevel::Al0Inventoried => pb::AssuranceLevel::Al0 as i32,
        AssuranceLevel::Al1Observed => pb::AssuranceLevel::Al1 as i32,
        AssuranceLevel::Al2Guided => pb::AssuranceLevel::Al2 as i32,
        AssuranceLevel::Al3Contained => pb::AssuranceLevel::Al3 as i32,
        AssuranceLevel::Al4Enforced => pb::AssuranceLevel::Al4 as i32,
    }
}

pub fn proto_to_assurance(val: i32) -> AssuranceLevel {
    match pb::AssuranceLevel::try_from(val).ok() {
        Some(pb::AssuranceLevel::Al1) => AssuranceLevel::Al1Observed,
        Some(pb::AssuranceLevel::Al2) => AssuranceLevel::Al2Guided,
        Some(pb::AssuranceLevel::Al3) => AssuranceLevel::Al3Contained,
        Some(pb::AssuranceLevel::Al4) => AssuranceLevel::Al4Enforced,
        _ => AssuranceLevel::Al0Inventoried,
    }
}

pub fn install_profile_to_proto(val: InstallProfile) -> i32 {
    match val {
        InstallProfile::User => pb::InstallProfile::User as i32,
        InstallProfile::Protected => pb::InstallProfile::Protected as i32,
    }
}

pub fn proto_to_install_profile(val: i32) -> InstallProfile {
    match pb::InstallProfile::try_from(val).ok() {
        Some(pb::InstallProfile::Protected) => InstallProfile::Protected,
        _ => InstallProfile::User,
    }
}

pub fn approval_grade_to_proto(val: ApprovalGrade) -> i32 {
    match val {
        ApprovalGrade::G0 => pb::ApprovalGrade::G0 as i32,
        ApprovalGrade::G1 => pb::ApprovalGrade::G1 as i32,
        ApprovalGrade::G2 => pb::ApprovalGrade::G2 as i32,
        ApprovalGrade::G3 => pb::ApprovalGrade::G3 as i32,
    }
}

pub fn proto_to_approval_grade(val: i32) -> Option<ApprovalGrade> {
    match pb::ApprovalGrade::try_from(val).ok()? {
        pb::ApprovalGrade::G0 => Some(ApprovalGrade::G0),
        pb::ApprovalGrade::G1 => Some(ApprovalGrade::G1),
        pb::ApprovalGrade::G2 => Some(ApprovalGrade::G2),
        pb::ApprovalGrade::G3 => Some(ApprovalGrade::G3),
        pb::ApprovalGrade::Unspecified => None,
    }
}

pub fn grant_scope_to_proto(val: GrantScope) -> i32 {
    match val {
        GrantScope::Once => pb::GrantScope::Once as i32,
        GrantScope::Session => pb::GrantScope::Session as i32,
        GrantScope::OneHour => pb::GrantScope::OneHour as i32,
    }
}

pub fn proto_to_grant_scope(val: i32) -> Option<GrantScope> {
    match pb::GrantScope::try_from(val).ok()? {
        pb::GrantScope::Once => Some(GrantScope::Once),
        pb::GrantScope::Session => Some(GrantScope::Session),
        pb::GrantScope::OneHour => Some(GrantScope::OneHour),
        pb::GrantScope::Unspecified => None,
    }
}

pub fn kill_scope_to_proto(val: KillScope) -> i32 {
    match val {
        KillScope::Session => pb::KillScope::Session as i32,
        KillScope::Device => pb::KillScope::Device as i32,
        KillScope::Organisation => pb::KillScope::Organisation as i32,
    }
}

pub fn proto_to_kill_scope(val: i32) -> Option<KillScope> {
    match pb::KillScope::try_from(val).ok()? {
        pb::KillScope::Session => Some(KillScope::Session),
        pb::KillScope::Device => Some(KillScope::Device),
        pb::KillScope::Organisation => Some(KillScope::Organisation),
        pb::KillScope::Unspecified => None,
    }
}

pub fn proto_to_kill_action(val: i32) -> Option<KillAction> {
    match pb::KillAction::try_from(val).ok()? {
        pb::KillAction::Freeze => Some(KillAction::Freeze),
        pb::KillAction::Kill => Some(KillAction::Kill),
        pb::KillAction::Release => Some(KillAction::Release),
        pb::KillAction::Unspecified => None,
    }
}

pub fn span_kind_to_proto(val: SpanKind) -> i32 {
    match val {
        SpanKind::InvokeAgent => pb::SpanKind::InvokeAgent as i32,
        SpanKind::Chat => pb::SpanKind::Chat as i32,
        SpanKind::ExecuteTool => pb::SpanKind::ExecuteTool as i32,
        SpanKind::McpCall => pb::SpanKind::McpCall as i32,
        SpanKind::OsEffect => pb::SpanKind::OsEffect as i32,
        SpanKind::SubagentSpawn => pb::SpanKind::SubagentSpawn as i32,
        SpanKind::Compaction => pb::SpanKind::Compaction as i32,
    }
}

pub fn proto_to_span_kind(val: i32) -> SpanKind {
    match pb::SpanKind::try_from(val).ok() {
        Some(pb::SpanKind::InvokeAgent) => SpanKind::InvokeAgent,
        Some(pb::SpanKind::Chat) => SpanKind::Chat,
        Some(pb::SpanKind::McpCall) => SpanKind::McpCall,
        Some(pb::SpanKind::OsEffect) => SpanKind::OsEffect,
        Some(pb::SpanKind::SubagentSpawn) => SpanKind::SubagentSpawn,
        Some(pb::SpanKind::Compaction) => SpanKind::Compaction,
        _ => SpanKind::ExecuteTool,
    }
}

pub fn provenance_to_proto(val: ProvenanceSource) -> i32 {
    match val {
        ProvenanceSource::Claimed => pb::ProvenanceSource::Claimed as i32,
        ProvenanceSource::Observed => pb::ProvenanceSource::Observed as i32,
        ProvenanceSource::Mediated => pb::ProvenanceSource::Mediated as i32,
        ProvenanceSource::Reconciled => pb::ProvenanceSource::Reconciled as i32,
    }
}

pub fn proto_to_provenance(val: i32) -> ProvenanceSource {
    match pb::ProvenanceSource::try_from(val).ok() {
        Some(pb::ProvenanceSource::Claimed) => ProvenanceSource::Claimed,
        Some(pb::ProvenanceSource::Mediated) => ProvenanceSource::Mediated,
        Some(pb::ProvenanceSource::Reconciled) => ProvenanceSource::Reconciled,
        _ => ProvenanceSource::Observed,
    }
}

pub fn session_label_to_proto(val: SessionLabel) -> i32 {
    match val {
        SessionLabel::CredentialAccessed => pb::SessionLabel::CredentialAccessed as i32,
        SessionLabel::UntrustedWebFetched => pb::SessionLabel::UntrustedWebFetched as i32,
        SessionLabel::RepeatedDenials => pb::SessionLabel::RepeatedDenials as i32,
        SessionLabel::TaintedExfilRisk => pb::SessionLabel::TaintedExfilRisk as i32,
    }
}

pub fn identity_mode_to_proto(val: IdentityMode) -> i32 {
    match val {
        IdentityMode::Named => pb::IdentityMode::Named as i32,
        IdentityMode::Pseudonymous => pb::IdentityMode::Pseudonymous as i32,
    }
}

pub fn proto_to_identity_mode(val: i32) -> Option<IdentityMode> {
    match pb::IdentityMode::try_from(val).ok()? {
        pb::IdentityMode::Named => Some(IdentityMode::Named),
        pb::IdentityMode::Pseudonymous => Some(IdentityMode::Pseudonymous),
        pb::IdentityMode::Unspecified => None,
    }
}

pub fn risk_tier_to_proto(val: RiskTier) -> i32 {
    match val {
        RiskTier::Low => pb::RiskTier::Low as i32,
        RiskTier::Elevated => pb::RiskTier::Elevated as i32,
        RiskTier::High => pb::RiskTier::High as i32,
        RiskTier::Critical => pb::RiskTier::Critical as i32,
    }
}

pub fn deployment_key_status_to_proto(val: DeploymentKeyStatus) -> i32 {
    match val {
        DeploymentKeyStatus::Active => pb::DeploymentKeyStatus::Active as i32,
        DeploymentKeyStatus::Exhausted => pb::DeploymentKeyStatus::Exhausted as i32,
        DeploymentKeyStatus::Expired => pb::DeploymentKeyStatus::Expired as i32,
        DeploymentKeyStatus::Revoked => pb::DeploymentKeyStatus::Revoked as i32,
    }
}

pub fn mdm_format_to_proto(val: MdmFormat) -> i32 {
    match val {
        MdmFormat::IntuneWin32 => pb::MdmFormat::IntuneWin32 as i32,
        MdmFormat::JamfMobileconfig => pb::MdmFormat::JamfMobileconfig as i32,
        MdmFormat::Hexnode => pb::MdmFormat::Hexnode as i32,
        MdmFormat::Tanium => pb::MdmFormat::Tanium as i32,
        MdmFormat::ChromeEnterprise => pb::MdmFormat::ChromeEnterprise as i32,
        MdmFormat::FirefoxGpo => pb::MdmFormat::FirefoxGpo as i32,
        MdmFormat::LinuxRepo => pb::MdmFormat::LinuxRepo as i32,
    }
}

pub fn proto_to_mdm_format(val: i32) -> Option<MdmFormat> {
    match pb::MdmFormat::try_from(val).ok()? {
        pb::MdmFormat::IntuneWin32 => Some(MdmFormat::IntuneWin32),
        pb::MdmFormat::JamfMobileconfig => Some(MdmFormat::JamfMobileconfig),
        pb::MdmFormat::Hexnode => Some(MdmFormat::Hexnode),
        pb::MdmFormat::Tanium => Some(MdmFormat::Tanium),
        pb::MdmFormat::ChromeEnterprise => Some(MdmFormat::ChromeEnterprise),
        pb::MdmFormat::FirefoxGpo => Some(MdmFormat::FirefoxGpo),
        pb::MdmFormat::LinuxRepo => Some(MdmFormat::LinuxRepo),
        pb::MdmFormat::Unspecified => None,
    }
}

pub fn integration_category_to_proto(val: IntegrationCategory) -> i32 {
    match val {
        IntegrationCategory::DirectorySync => pb::IntegrationCategory::DirectorySync as i32,
        IntegrationCategory::SaasConnector => pb::IntegrationCategory::SaasConnector as i32,
        IntegrationCategory::ExportSink => pb::IntegrationCategory::ExportSink as i32,
    }
}

pub fn integration_health_to_proto(val: IntegrationHealthState) -> i32 {
    match val {
        IntegrationHealthState::Connected => pb::IntegrationHealthState::Connected as i32,
        IntegrationHealthState::AtRisk => pb::IntegrationHealthState::AtRisk as i32,
        IntegrationHealthState::Degraded => pb::IntegrationHealthState::Degraded as i32,
        IntegrationHealthState::NotConfigured => pb::IntegrationHealthState::NotConfigured as i32,
    }
}

pub fn browser_dlp_to_proto(val: BrowserDlpClass) -> i32 {
    match val {
        BrowserDlpClass::FileUpload => pb::BrowserDlpClass::FileUpload as i32,
        BrowserDlpClass::PasteSecret => pb::BrowserDlpClass::PasteSecret as i32,
        BrowserDlpClass::SourceCode => pb::BrowserDlpClass::SourceCode as i32,
        BrowserDlpClass::CustomerPii => pb::BrowserDlpClass::CustomerPii as i32,
    }
}

pub fn proto_to_browser_dlp(val: i32) -> Option<BrowserDlpClass> {
    match pb::BrowserDlpClass::try_from(val).ok()? {
        pb::BrowserDlpClass::FileUpload => Some(BrowserDlpClass::FileUpload),
        pb::BrowserDlpClass::PasteSecret => Some(BrowserDlpClass::PasteSecret),
        pb::BrowserDlpClass::SourceCode => Some(BrowserDlpClass::SourceCode),
        pb::BrowserDlpClass::CustomerPii => Some(BrowserDlpClass::CustomerPii),
        pb::BrowserDlpClass::Unspecified => None,
    }
}

pub fn schema_data_class_to_proto(val: SchemaDataClass) -> i32 {
    match val {
        SchemaDataClass::Metadata => pb::SchemaDataClass::Metadata as i32,
        SchemaDataClass::NamedIdentity => pb::SchemaDataClass::NamedIdentity as i32,
        SchemaDataClass::Content => pb::SchemaDataClass::Content as i32,
        SchemaDataClass::Secret => pb::SchemaDataClass::Secret as i32,
    }
}

pub fn server_health_to_proto(val: ServerHealth) -> i32 {
    match val {
        ServerHealth::Ok => pb::ServerHealth::Ok as i32,
        ServerHealth::Healthy => pb::ServerHealth::Healthy as i32,
        ServerHealth::Degraded => pb::ServerHealth::Degraded as i32,
        ServerHealth::Unavailable => pb::ServerHealth::Unavailable as i32,
    }
}
