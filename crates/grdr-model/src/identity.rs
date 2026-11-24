// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::api::{Device, SessionDetailResponse, SessionSummary};
use crate::artifacts::ArtifactEntry;
use crate::policy::{ActionAttempt, DecisionReceipt, Finding};

const DEFAULT_RISK_MAX: u32 = 100;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IdentityMode {
    #[default]
    Named,
    Pseudonymous,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OrgPrivacyConfig {
    pub identity_mode: IdentityMode,
    pub user_risk_scoring: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RiskTier {
    Low,
    Elevated,
    High,
    Critical,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserRiskFactor {
    pub code: String,
    pub label: String,
    pub points: u32,
    pub count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserProfile {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub department: String,
    pub idp_source: String,
    pub pseudonym_id: String,
    pub device_ids: Vec<String>,
    pub agent_names: Vec<String>,
    pub artifact_count: usize,
    pub session_count: usize,
    pub blocked_count: usize,
    pub asked_count: usize,
    pub watch_count: usize,
    pub finding_count: usize,
    pub risk_score: u32,
    pub risk_tier: RiskTier,
    pub risk_factors: Vec<UserRiskFactor>,
    pub last_active: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UserDetailResponse {
    pub user: UserProfile,
    pub devices: Vec<Device>,
    pub sessions: Vec<SessionSummary>,
    pub recent_attempts: Vec<ActionAttempt>,
    pub receipts: Vec<DecisionReceipt>,
    pub findings: Vec<Finding>,
    pub artifacts: Vec<ArtifactEntry>,
    pub identity_mode: IdentityMode,
    #[serde(default)]
    pub recent_session_details: Vec<SessionDetailResponse>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdatePrivacyConfigInput {
    pub identity_mode: Option<IdentityMode>,
    pub user_risk_scoring: Option<bool>,
    pub actor: Option<String>,
}

impl Default for OrgPrivacyConfig {
    fn default() -> Self {
        Self {
            identity_mode: IdentityMode::Named,
            user_risk_scoring: true,
        }
    }
}

pub fn compute_user_risk(
    blocked: u32,
    asked: u32,
    watch_hits: u32,
    critical_findings: u32,
    high_findings: u32,
    risky_artifacts: u32,
    unpinned_mcps: u32,
) -> (u32, RiskTier, Vec<UserRiskFactor>) {
    let candidates = [
        (
            "risk.blocked_actions",
            "Blocked actions",
            blocked,
            blocked.saturating_mul(18).min(36),
        ),
        (
            "risk.critical_findings",
            "Critical findings",
            critical_findings,
            critical_findings.saturating_mul(25).min(50),
        ),
        (
            "risk.high_findings",
            "High severity findings",
            high_findings,
            high_findings.saturating_mul(15).min(30),
        ),
        (
            "risk.asked_actions",
            "Approval escalations",
            asked,
            asked.saturating_mul(6).min(18),
        ),
        (
            "risk.watch_hits",
            "Watch mode hits",
            watch_hits,
            watch_hits.saturating_mul(4).min(12),
        ),
        (
            "risk.artifact_flags",
            "Flagged skills or rules",
            risky_artifacts,
            risky_artifacts.saturating_mul(10).min(20),
        ),
        (
            "risk.unpinned_mcp",
            "Unpinned MCP servers",
            unpinned_mcps,
            unpinned_mcps.saturating_mul(8).min(16),
        ),
    ];

    let mut total: u32 = 0;
    let mut factors = Vec::new();
    for (code, label, count, points) in candidates {
        if count > 0 && points > 0 {
            total = total.saturating_add(points);
            factors.push(UserRiskFactor {
                code: code.into(),
                label: label.into(),
                points,
                count,
            });
        }
    }

    let score = total.min(DEFAULT_RISK_MAX);
    let tier = match score {
        75..=100 => RiskTier::Critical,
        45..=74 => RiskTier::High,
        20..=44 => RiskTier::Elevated,
        _ => RiskTier::Low,
    };

    (score, tier, factors)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn user_risk_is_bounded_and_explainable() {
        let (score, tier, factors) = compute_user_risk(2, 1, 2, 1, 1, 2, 1);
        assert!(score <= 100);
        assert_eq!(tier, RiskTier::Critical);
        assert!(
            factors
                .iter()
                .any(|f| f.code == "risk.blocked_actions" && f.points == 36)
        );
        assert!(
            factors
                .iter()
                .any(|f| f.code == "risk.artifact_flags" && f.points == 20)
        );
    }

    #[test]
    fn clean_user_has_low_risk_and_zero_factors() {
        let (score, tier, factors) = compute_user_risk(0, 0, 0, 0, 0, 0, 0);
        assert_eq!(score, 0);
        assert_eq!(tier, RiskTier::Low);
        assert!(factors.is_empty());
    }
}
