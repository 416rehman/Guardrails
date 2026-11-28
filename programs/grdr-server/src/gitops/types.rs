// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::eval::FourBucketSummary;
use grdr_model::{ApprovalGrade, Mode, PolicyPack, RuleMatch};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum PolicyChangeState {
    Draft,
    Checked,
    Failed,
    AwaitingApproval,
    RollingOut,
    Halted,
    Applied,
    Denied,
    Superseded,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum GitopsSourceKind {
    #[default]
    None,
    Git,
    Terraform,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum DriftStatus {
    #[default]
    InSync,
    Drifted,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ProposerKind {
    #[default]
    Human,
    Gitops,
    Terraform,
    AgentSession,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DiffEffect {
    Narrowing,
    Neutral,
    Widening,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum PolicyChangeOp {
    UpsertRule {
        pack_id: String,
        id: Option<String>,
        title: String,
        description: String,
        mode: Mode,
        min_grade: Option<ApprovalGrade>,
        matcher: RuleMatch,
        reason_template: String,
        cedar: Option<String>,
        enabled: Option<bool>,
    },
    UpdateRuleMode {
        rule_id: String,
        mode: Mode,
    },
    DeleteRule {
        rule_id: String,
    },
    ReplacePackRules {
        pack_id: String,
        packs: Vec<PolicyPack>,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDiffEntry {
    pub pack_id: String,
    pub rule_id: String,
    pub change_kind: String,
    pub previous_mode: Option<Mode>,
    pub candidate_mode: Option<Mode>,
    pub effect: DiffEffect,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyDiffSummary {
    pub is_widening: bool,
    pub promotes_enforcement: bool,
    pub effect: DiffEffect,
    pub entries: Vec<PolicyDiffEntry>,
    pub effective_hash_before: String,
    pub effective_hash_after: String,
    pub risk_reasons: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PolicyChangeRecord {
    pub id: String,
    pub tenant_id: String,
    pub title: String,
    pub description: String,
    pub state: PolicyChangeState,
    pub proposer_id: String,
    pub proposer_kind: ProposerKind,
    pub source_ref: String,
    pub operations: Vec<PolicyChangeOp>,
    pub diff: Option<PolicyDiffSummary>,
    pub check_errors: Vec<String>,
    pub replay_summary: Option<FourBucketSummary>,
    pub simulation_job_id: Option<String>,
    pub rollout_ring: Option<u8>,
    pub requires_human_approval: bool,
    pub approved_by: Option<String>,
    pub denied_by: Option<String>,
    pub denied_reason: Option<String>,
    pub created_at: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct GitopsBinding {
    pub source: GitopsSourceKind,
    pub repo_url: String,
    pub branch: String,
    pub path: String,
    pub drift_status: DriftStatus,
    pub expected_effective_hash: String,
    pub actual_effective_hash: String,
    pub locked_by: String,
    pub last_reconciled_at: Option<String>,
    pub updated_at: String,
    pub edit_anyway_approvers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GitopsBundle {
    pub schema: String,
    pub effective_hash: String,
    pub source_ref: String,
    pub packs: Vec<PolicyPack>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreatePolicyChangeRequest {
    pub title: String,
    #[serde(default)]
    pub description: String,
    #[serde(default)]
    pub proposer_kind: Option<ProposerKind>,
    #[serde(default)]
    pub source_ref: String,
    pub operations: Vec<PolicyChangeOp>,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct ApproveChangeRequest {
    #[serde(default)]
    pub note: String,
}

#[derive(Debug, Clone, Deserialize, Default)]
#[serde(rename_all = "camelCase")]
pub struct DenyChangeRequest {
    #[serde(default)]
    pub reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpsertGitopsBindingRequest {
    pub source: GitopsSourceKind,
    #[serde(default)]
    pub repo_url: String,
    #[serde(default)]
    pub branch: String,
    #[serde(default)]
    pub path: String,
    #[serde(default)]
    pub expected_effective_hash: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EditAnywayRequest {
    pub reason: String,
    #[serde(default)]
    pub second_approver_id: String,
    #[serde(default)]
    pub second_approver_token: Option<String>,
    #[serde(default)]
    pub second_approver_step_up: Option<String>,
    pub operations: Vec<PolicyChangeOp>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ReconcileBundleRequest {
    pub bundle: GitopsBundle,
}
