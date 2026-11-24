// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::proto_enum_codec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Mode {
    Unspecified = 0,
    Off = 1,
    Watch = 2,
    Ask = 3,
    Block = 4,
}
proto_enum_codec!(Mode, mode_serde, [
    Mode::Unspecified => "MODE_UNSPECIFIED",
    Mode::Off => "MODE_OFF" | "off",
    Mode::Watch => "MODE_WATCH" | "watch",
    Mode::Ask => "MODE_ASK" | "ask",
    Mode::Block => "MODE_BLOCK" | "block",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Verdict {
    Unspecified = 0,
    Allow = 1,
    Modify = 2,
    StepUp = 3,
    Defer = 4,
    Deny = 5,
}
proto_enum_codec!(Verdict, verdict_serde, [
    Verdict::Unspecified => "VERDICT_UNSPECIFIED",
    Verdict::Allow => "VERDICT_ALLOW" | "allow",
    Verdict::Modify => "VERDICT_MODIFY" | "modify",
    Verdict::StepUp => "VERDICT_STEP_UP" | "step_up",
    Verdict::Defer => "VERDICT_DEFER" | "defer",
    Verdict::Deny => "VERDICT_DENY" | "deny",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ActionClass {
    Unspecified = 0,
    Exec = 1,
    FileRead = 2,
    FileWrite = 3,
    FileDelete = 4,
    NetConnect = 5,
    NetRequest = 6,
    LlmRequest = 7,
    McpConnect = 8,
    McpCall = 9,
    CredUse = 10,
    AgentSpawn = 11,
    ConfigChange = 12,
    Elevate = 13,
    UiAct = 14,
    DataFlow = 15,
}
proto_enum_codec!(ActionClass, action_class_serde, [
    ActionClass::Unspecified => "ACTION_CLASS_UNSPECIFIED",
    ActionClass::Exec => "ACTION_CLASS_EXEC" | "exec",
    ActionClass::FileRead => "ACTION_CLASS_FILE_READ" | "file.read" | "file_read",
    ActionClass::FileWrite => "ACTION_CLASS_FILE_WRITE" | "file.write" | "file_write",
    ActionClass::FileDelete => "ACTION_CLASS_FILE_DELETE" | "file.delete" | "file_delete",
    ActionClass::NetConnect => "ACTION_CLASS_NET_CONNECT" | "net.connect" | "net_connect",
    ActionClass::NetRequest => "ACTION_CLASS_NET_REQUEST" | "net.request" | "net_request",
    ActionClass::LlmRequest => "ACTION_CLASS_LLM_REQUEST" | "llm.request" | "llm_request",
    ActionClass::McpConnect => "ACTION_CLASS_MCP_CONNECT" | "mcp.connect" | "mcp_connect",
    ActionClass::McpCall => "ACTION_CLASS_MCP_CALL" | "mcp.call" | "mcp_call",
    ActionClass::CredUse => "ACTION_CLASS_CRED_USE" | "cred.use" | "cred_use",
    ActionClass::AgentSpawn => "ACTION_CLASS_AGENT_SPAWN" | "agent.spawn" | "agent_spawn",
    ActionClass::ConfigChange => "ACTION_CLASS_CONFIG_CHANGE" | "config.change" | "config_change",
    ActionClass::Elevate => "ACTION_CLASS_ELEVATE" | "elevate",
    ActionClass::UiAct => "ACTION_CLASS_UI_ACT" | "ui.act" | "ui_act",
    ActionClass::DataFlow => "ACTION_CLASS_DATA_FLOW" | "data.flow" | "data_flow",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ControlPoint {
    Unspecified = 0,
    Hook = 1,
    McpBroker = 2,
    Proxy = 3,
    Sandbox = 4,
    Sensor = 5,
    Browser = 6,
    Gateway = 7,
    Connector = 8,
}
proto_enum_codec!(ControlPoint, control_point_serde, [
    ControlPoint::Unspecified => "CONTROL_POINT_UNSPECIFIED",
    ControlPoint::Hook => "CONTROL_POINT_HOOK" | "hook",
    ControlPoint::McpBroker => "CONTROL_POINT_MCP_BROKER" | "mcp-broker" | "mcp_broker",
    ControlPoint::Proxy => "CONTROL_POINT_PROXY" | "proxy",
    ControlPoint::Sandbox => "CONTROL_POINT_SANDBOX" | "sandbox",
    ControlPoint::Sensor => "CONTROL_POINT_SENSOR" | "sensor",
    ControlPoint::Browser => "CONTROL_POINT_BROWSER" | "browser",
    ControlPoint::Gateway => "CONTROL_POINT_GATEWAY" | "gateway",
    ControlPoint::Connector => "CONTROL_POINT_CONNECTOR" | "connector",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum Visibility {
    Unspecified = 0,
    None = 1,
    Claimed = 2,
    Observed = 3,
    CrossChecked = 4,
}
proto_enum_codec!(Visibility, visibility_serde, [
    Visibility::Unspecified => "VISIBILITY_UNSPECIFIED",
    Visibility::None => "VISIBILITY_NONE" | "none",
    Visibility::Claimed => "VISIBILITY_CLAIMED" | "claimed",
    Visibility::Observed => "VISIBILITY_OBSERVED" | "observed",
    Visibility::CrossChecked => "VISIBILITY_CROSS_CHECKED" | "cross_checked",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ControlStrength {
    Unspecified = 0,
    None = 1,
    Request = 2,
    ScopedBoundary = 3,
    MandatoryBoundary = 4,
}
proto_enum_codec!(ControlStrength, control_strength_serde, [
    ControlStrength::Unspecified => "CONTROL_STRENGTH_UNSPECIFIED",
    ControlStrength::None => "CONTROL_STRENGTH_NONE" | "none",
    ControlStrength::Request => "CONTROL_STRENGTH_REQUEST" | "request",
    ControlStrength::ScopedBoundary => "CONTROL_STRENGTH_SCOPED_BOUNDARY" | "scoped-boundary" | "scoped_boundary",
    ControlStrength::MandatoryBoundary => "CONTROL_STRENGTH_MANDATORY_BOUNDARY" | "mandatory-boundary" | "mandatory_boundary",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum OnFailure {
    Unspecified = 0,
    Open = 1,
    Closed = 2,
}
proto_enum_codec!(OnFailure, on_failure_serde, [
    OnFailure::Unspecified => "ON_FAILURE_UNSPECIFIED",
    OnFailure::Open => "ON_FAILURE_OPEN" | "open",
    OnFailure::Closed => "ON_FAILURE_CLOSED" | "closed",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum TamperGrade {
    Unspecified = 0,
    User = 1,
    Admin = 2,
    Platform = 3,
}
proto_enum_codec!(TamperGrade, tamper_grade_serde, [
    TamperGrade::Unspecified => "TAMPER_GRADE_UNSPECIFIED",
    TamperGrade::User => "TAMPER_GRADE_USER" | "user",
    TamperGrade::Admin => "TAMPER_GRADE_ADMIN" | "admin",
    TamperGrade::Platform => "TAMPER_GRADE_PLATFORM" | "platform",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum AssuranceLevel {
    Unspecified = 0,
    Al0 = 1,
    Al1 = 2,
    Al2 = 3,
    Al3 = 4,
    Al4 = 5,
}
proto_enum_codec!(AssuranceLevel, assurance_level_serde, [
    AssuranceLevel::Unspecified => "ASSURANCE_LEVEL_UNSPECIFIED",
    AssuranceLevel::Al0 => "ASSURANCE_LEVEL_AL0" | "al0",
    AssuranceLevel::Al1 => "ASSURANCE_LEVEL_AL1" | "al1",
    AssuranceLevel::Al2 => "ASSURANCE_LEVEL_AL2" | "al2",
    AssuranceLevel::Al3 => "ASSURANCE_LEVEL_AL3" | "al3",
    AssuranceLevel::Al4 => "ASSURANCE_LEVEL_AL4" | "al4",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum InstallProfile {
    Unspecified = 0,
    User = 1,
    Protected = 2,
}
proto_enum_codec!(InstallProfile, install_profile_serde, [
    InstallProfile::Unspecified => "INSTALL_PROFILE_UNSPECIFIED",
    InstallProfile::User => "INSTALL_PROFILE_USER" | "user",
    InstallProfile::Protected => "INSTALL_PROFILE_PROTECTED" | "protected",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ApprovalGrade {
    Unspecified = 0,
    G0 = 1,
    G1 = 2,
    G2 = 3,
    G3 = 4,
}
proto_enum_codec!(ApprovalGrade, approval_grade_serde, [
    ApprovalGrade::Unspecified => "APPROVAL_GRADE_UNSPECIFIED",
    ApprovalGrade::G0 => "APPROVAL_GRADE_G0" | "g0",
    ApprovalGrade::G1 => "APPROVAL_GRADE_G1" | "g1",
    ApprovalGrade::G2 => "APPROVAL_GRADE_G2" | "g2",
    ApprovalGrade::G3 => "APPROVAL_GRADE_G3" | "g3",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum GrantScope {
    Unspecified = 0,
    Once = 1,
    Session = 2,
    OneHour = 3,
}
proto_enum_codec!(GrantScope, grant_scope_serde, [
    GrantScope::Unspecified => "GRANT_SCOPE_UNSPECIFIED",
    GrantScope::Once => "GRANT_SCOPE_ONCE" | "once",
    GrantScope::Session => "GRANT_SCOPE_SESSION" | "session",
    GrantScope::OneHour => "GRANT_SCOPE_ONE_HOUR" | "one_hour",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ApprovalStatus {
    Unspecified = 0,
    Pending = 1,
    Approved = 2,
    Denied = 3,
    Expired = 4,
}
proto_enum_codec!(ApprovalStatus, approval_status_serde, [
    ApprovalStatus::Unspecified => "APPROVAL_STATUS_UNSPECIFIED",
    ApprovalStatus::Pending => "APPROVAL_STATUS_PENDING" | "pending",
    ApprovalStatus::Approved => "APPROVAL_STATUS_APPROVED" | "approved",
    ApprovalStatus::Denied => "APPROVAL_STATUS_DENIED" | "denied",
    ApprovalStatus::Expired => "APPROVAL_STATUS_EXPIRED" | "expired",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum KillScope {
    Unspecified = 0,
    Session = 1,
    Device = 2,
    Organisation = 3,
}
proto_enum_codec!(KillScope, kill_scope_serde, [
    KillScope::Unspecified => "KILL_SCOPE_UNSPECIFIED",
    KillScope::Session => "KILL_SCOPE_SESSION" | "session",
    KillScope::Device => "KILL_SCOPE_DEVICE" | "device",
    KillScope::Organisation => "KILL_SCOPE_ORGANISATION" | "organisation",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum KillAction {
    Unspecified = 0,
    Freeze = 1,
    Kill = 2,
    Release = 3,
}
proto_enum_codec!(KillAction, kill_action_serde, [
    KillAction::Unspecified => "KILL_ACTION_UNSPECIFIED",
    KillAction::Freeze => "KILL_ACTION_FREEZE" | "freeze",
    KillAction::Kill => "KILL_ACTION_KILL" | "kill",
    KillAction::Release => "KILL_ACTION_RELEASE" | "release",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum KillState {
    Unspecified = 0,
    Inactive = 1,
    Frozen = 2,
    Killed = 3,
}
proto_enum_codec!(KillState, kill_state_serde, [
    KillState::Unspecified => "KILL_STATE_UNSPECIFIED",
    KillState::Inactive => "KILL_STATE_INACTIVE" | "inactive",
    KillState::Frozen => "KILL_STATE_FROZEN" | "frozen",
    KillState::Killed => "KILL_STATE_KILLED" | "killed",
]);
