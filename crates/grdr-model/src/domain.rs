// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    Off,
    Watch,
    Ask,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    Allow,
    Modify,
    StepUp,
    Defer,
    Deny,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ActionClass {
    Exec,
    #[serde(rename = "file.read")]
    FileRead,
    #[serde(rename = "file.write")]
    FileWrite,
    #[serde(rename = "file.delete")]
    FileDelete,
    #[serde(rename = "net.connect")]
    NetConnect,
    #[serde(rename = "net.request")]
    NetRequest,
    #[serde(rename = "llm.request")]
    LlmRequest,
    #[serde(rename = "mcp.connect")]
    McpConnect,
    #[serde(rename = "mcp.call")]
    McpCall,
    #[serde(rename = "cred.use")]
    CredUse,
    #[serde(rename = "agent.spawn")]
    AgentSpawn,
    #[serde(rename = "config.change")]
    ConfigChange,
    Elevate,
    #[serde(rename = "ui.act")]
    UiAct,
    #[serde(rename = "data.flow")]
    DataFlow,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlPoint {
    Hook,
    McpBroker,
    Proxy,
    Sandbox,
    Sensor,
    Browser,
    Gateway,
    Connector,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Visibility {
    None,
    Claimed,
    Observed,
    CrossChecked,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ControlStrength {
    None,
    Request,
    ScopedBoundary,
    MandatoryBoundary,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OnFailure {
    Open,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TamperGrade {
    User,
    Admin,
    Platform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum AssuranceLevel {
    #[serde(rename = "AL0")]
    Al0Inventoried,
    #[serde(rename = "AL1")]
    Al1Observed,
    #[serde(rename = "AL2")]
    Al2Guided,
    #[serde(rename = "AL3")]
    Al3Contained,
    #[serde(rename = "AL4")]
    Al4Enforced,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AssuranceRecord {
    pub visibility: Visibility,
    pub control: ControlStrength,
    pub on_failure: OnFailure,
    pub tamper: TamperGrade,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum InstallProfile {
    User,
    Protected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum ApprovalGrade {
    G0,
    G1,
    G2,
    G3,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantScope {
    Once,
    Session,
    OneHour,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum ApprovalState {
    Pending {
        expires_at: Timestamp,
    },
    Approved {
        grant_id: String,
        scope: GrantScope,
        decided_at: Timestamp,
        note: String,
    },
    Denied {
        decided_at: Timestamp,
        note: String,
    },
    Expired {
        expired_at: Timestamp,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillScope {
    Session,
    Device,
    Organisation,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum KillSwitchState {
    Inactive,
    Frozen {
        scope: KillScope,
        target_id: String,
        reason: String,
        issued_at: Timestamp,
        expires_at: Timestamp,
    },
    Killed {
        scope: KillScope,
        target_id: String,
        reason: String,
        issued_at: Timestamp,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingClass {
    Threat,
    PolicyViolation,
    Overeager,
    Tamper,
    CoverageGap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingSeverity {
    Low,
    Medium,
    High,
    Critical,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FindingLifecycle {
    Open,
    Acknowledged,
    Contained,
    Resolved,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLabel {
    CredentialAccessed,
    UntrustedWebFetched,
    RepeatedDenials,
    TaintedExfilRisk,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommandParseStatus {
    Resolved,
    Unresolved,
    Malformed,
}

impl Mode {
    pub fn label(self) -> &'static str {
        match self {
            Self::Off => "Off",
            Self::Watch => "Watch",
            Self::Ask => "Ask",
            Self::Block => "Block",
        }
    }
}

impl ActionClass {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Exec => "exec",
            Self::FileRead => "file.read",
            Self::FileWrite => "file.write",
            Self::FileDelete => "file.delete",
            Self::NetConnect => "net.connect",
            Self::NetRequest => "net.request",
            Self::LlmRequest => "llm.request",
            Self::McpConnect => "mcp.connect",
            Self::McpCall => "mcp.call",
            Self::CredUse => "cred.use",
            Self::AgentSpawn => "agent.spawn",
            Self::ConfigChange => "config.change",
            Self::Elevate => "elevate",
            Self::UiAct => "ui.act",
            Self::DataFlow => "data.flow",
        }
    }

    pub fn from_name(raw: &str) -> Self {
        match raw.trim().to_ascii_lowercase().as_str() {
            "exec" | "shell" | "bash" | "powershell" => Self::Exec,
            "file.read" | "read" => Self::FileRead,
            "file.write" | "write" | "edit" => Self::FileWrite,
            "file.delete" | "delete" => Self::FileDelete,
            "net.connect" | "connect" => Self::NetConnect,
            "net.request" | "http" => Self::NetRequest,
            "llm.request" | "llm" => Self::LlmRequest,
            "mcp.connect" => Self::McpConnect,
            "mcp.call" | "mcp" => Self::McpCall,
            "cred.use" | "credential" => Self::CredUse,
            "agent.spawn" | "spawn" => Self::AgentSpawn,
            "config.change" | "config" => Self::ConfigChange,
            "elevate" | "sudo" => Self::Elevate,
            "ui.act" => Self::UiAct,
            "data.flow" | "exfil" => Self::DataFlow,
            _ => Self::Exec,
        }
    }
}

impl AssuranceRecord {
    pub fn level(&self) -> AssuranceLevel {
        if self.visibility == Visibility::CrossChecked
            && self.control == ControlStrength::MandatoryBoundary
        {
            return AssuranceLevel::Al4Enforced;
        }
        if matches!(
            self.control,
            ControlStrength::ScopedBoundary | ControlStrength::MandatoryBoundary
        ) {
            return AssuranceLevel::Al3Contained;
        }
        if self.control == ControlStrength::Request {
            return AssuranceLevel::Al2Guided;
        }
        if self.visibility != Visibility::None {
            return AssuranceLevel::Al1Observed;
        }
        AssuranceLevel::Al0Inventoried
    }
}

impl AssuranceLevel {
    pub fn label(self) -> &'static str {
        match self {
            Self::Al0Inventoried => "AL0 Inventoried",
            Self::Al1Observed => "AL1 Observed",
            Self::Al2Guided => "AL2 Guided",
            Self::Al3Contained => "AL3 Contained",
            Self::Al4Enforced => "AL4 Enforced",
        }
    }
}

impl ApprovalGrade {
    pub fn label(self) -> &'static str {
        match self {
            Self::G0 => "You",
            Self::G1 => "OS authenticator",
            Self::G2 => "An administrator",
            Self::G3 => "Two approvers",
        }
    }
}

impl SessionLabel {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::CredentialAccessed => "credential_accessed",
            Self::UntrustedWebFetched => "untrusted_web_fetched",
            Self::RepeatedDenials => "repeated_denials",
            Self::TaintedExfilRisk => "tainted_exfil_risk",
        }
    }

    pub fn label(self) -> &'static str {
        match self {
            Self::CredentialAccessed => "Credential accessed",
            Self::UntrustedWebFetched => "Untrusted web fetched",
            Self::RepeatedDenials => "Repeated denials",
            Self::TaintedExfilRisk => "Tainted exfil risk",
        }
    }
}

impl KillSwitchState {
    pub fn is_active_for(&self, session_id: &str, device_id: &str, now: Timestamp) -> bool {
        match self {
            Self::Inactive => false,
            Self::Frozen {
                scope,
                target_id,
                expires_at,
                ..
            } => {
                if *expires_at <= now {
                    return false;
                }
                scope_matches(*scope, target_id, session_id, device_id)
            }
            Self::Killed {
                scope, target_id, ..
            } => scope_matches(*scope, target_id, session_id, device_id),
        }
    }
}

fn scope_matches(scope: KillScope, target_id: &str, session_id: &str, device_id: &str) -> bool {
    match scope {
        KillScope::Organisation => true,
        KillScope::Device => target_id == "*" || target_id == device_id,
        KillScope::Session => target_id == "*" || target_id == session_id,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn assurance_level_ladder_holds() {
        let al0 = AssuranceRecord {
            visibility: Visibility::None,
            control: ControlStrength::None,
            on_failure: OnFailure::Open,
            tamper: TamperGrade::User,
        };
        assert_eq!(al0.level(), AssuranceLevel::Al0Inventoried);

        let al1 = AssuranceRecord {
            visibility: Visibility::Observed,
            ..al0
        };
        assert_eq!(al1.level(), AssuranceLevel::Al1Observed);

        let al2 = AssuranceRecord {
            visibility: Visibility::Claimed,
            control: ControlStrength::Request,
            ..al0
        };
        assert_eq!(al2.level(), AssuranceLevel::Al2Guided);

        let al3 = AssuranceRecord {
            visibility: Visibility::Observed,
            control: ControlStrength::ScopedBoundary,
            ..al0
        };
        assert_eq!(al3.level(), AssuranceLevel::Al3Contained);

        let al4 = AssuranceRecord {
            visibility: Visibility::CrossChecked,
            control: ControlStrength::MandatoryBoundary,
            on_failure: OnFailure::Closed,
            tamper: TamperGrade::Platform,
        };
        assert_eq!(al4.level(), AssuranceLevel::Al4Enforced);
    }

    #[test]
    fn kill_switch_respects_scope_and_expiry() {
        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let active = KillSwitchState::Frozen {
            scope: KillScope::Session,
            target_id: "sess-1".into(),
            reason: "freeze".into(),
            issued_at: now,
            expires_at: Timestamp::from_second(1_700_003_600).unwrap(),
        };
        assert!(active.is_active_for("sess-1", "dev-1", now));
        assert!(!active.is_active_for("sess-2", "dev-1", now));
        assert!(!active.is_active_for(
            "sess-1",
            "dev-1",
            Timestamp::from_second(1_700_004_000).unwrap()
        ));
    }
}
