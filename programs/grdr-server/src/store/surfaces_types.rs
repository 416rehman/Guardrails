// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_comply::{Hold, PrivacyCeilingProfile, RetentionPreset};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReviewDecisionState {
    Open,
    Promoted,
    Suppressed,
    Dismissed,
    Escalated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReviewDecisionOverride {
    pub status: ReviewDecisionState,
    pub note: String,
    pub updated_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SubjectRequestLifecycle {
    Executed,
    PendingHeld,
}

fn default_org_id() -> String {
    "org-default".to_owned()
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SubjectReqRecord {
    pub request_id: String,
    #[serde(default = "default_org_id")]
    pub organisation: String,
    pub kind: String,
    pub subject_ref: String,
    pub status: SubjectRequestLifecycle,
    pub hold_ids: Vec<String>,
    pub requested_at: String,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ReidLifecycle {
    PendingQuorum,
    Approved,
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReidentificationRecord {
    pub request_id: String,
    #[serde(default = "default_org_id")]
    pub organisation: String,
    pub pseudonym_id: String,
    pub requester: String,
    pub reason: String,
    pub legal_basis: String,
    pub status: ReidLifecycle,
    pub approvers: Vec<String>,
    pub resolved_identity: Option<String>,
    pub created_at: String,
    pub resolved_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DisclosureRecord {
    pub id: String,
    #[serde(default = "default_org_id")]
    pub organisation: String,
    pub kind: String,
    pub actor: String,
    pub target_ref: String,
    pub legal_basis: String,
    pub timestamp: String,
    pub quarter: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ConnectorRuntimeRecord {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub stability: String,
    pub circuit_state: String,
    pub queued_items: u32,
    pub delivered_items: u32,
    pub capture_ceiling: String,
    pub assurance_label: String,
    pub last_delivery_at: Option<String>,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FirstRunPersistedState {
    pub selected_profile: String,
    pub confirmed: bool,
    pub step_up_enabled: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PendingLegalHoldRecord {
    pub hold_id: String,
    pub organisation: String,
    pub matter_ref: String,
    pub reason: String,
    pub target_ref: String,
    pub created_by: String,
    pub approvers: Vec<String>,
    pub created_at: String,
    pub review_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ComplianceGovernanceState {
    pub privacy_profile: PrivacyCeilingProfile,
    pub presets: Vec<RetentionPreset>,
    pub override_legal_basis: Option<String>,
    pub capture_level: String,
    pub legal_holds: Vec<Hold>,
    #[serde(default)]
    pub pending_holds: Vec<PendingLegalHoldRecord>,
    pub subject_requests: Vec<SubjectReqRecord>,
    pub connectors: Vec<ConnectorRuntimeRecord>,
    pub reid_requests: Vec<ReidentificationRecord>,
    pub disclosures: Vec<DisclosureRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderActingSession {
    pub org_id: String,
    pub reason: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderOrgHealthState {
    Healthy,
    Attention,
    Offline,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderOrgRecord {
    pub org_id: String,
    pub name: String,
    pub org_set: String,
    pub ring: String,
    pub devices_count: u32,
    pub open_findings: u32,
    pub pending_approvals: u32,
    pub coverage_pct: u32,
    pub floor_version: String,
    pub delegated_overrides: u32,
    pub status: ProviderOrgHealthState,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderRingRecord {
    pub ring: String,
    pub org_count: u32,
    pub target_version: String,
    pub health_state: String,
    pub soak_hours: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProviderGovernanceState {
    #[serde(default)]
    pub acting_sessions: BTreeMap<String, ProviderActingSession>,
    pub orgs: Vec<ProviderOrgRecord>,
    pub rings: Vec<ProviderRingRecord>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ConfigRevLifecycle {
    Draft,
    Validated,
    Applying,
    Applied,
    RolledBack,
    Superseded,
    Discarded,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorConfigSnapshot {
    pub revision_id: String,
    pub version: u64,
    pub capture_level: String,
    pub privacy_profile: String,
    pub retention_preset: String,
    pub hot_days: u32,
    pub activity_days: u32,
    pub decision_days: u32,
    pub audit_days: u32,
    pub otlp_enabled: bool,
    pub release_channel: String,
    pub summary: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorDiffRecord {
    pub field: String,
    pub previous: String,
    pub next: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorRevisionRecord {
    pub revision_id: String,
    pub version: u64,
    pub state: ConfigRevLifecycle,
    pub author: String,
    pub summary: String,
    pub created_at: String,
    pub applied_at: Option<String>,
    pub diff_lines: Vec<OperatorDiffRecord>,
    pub config: OperatorConfigSnapshot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TargetHealthLifecycle {
    Healthy,
    Degraded,
    OpenCircuit,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TargetHealthRecord {
    pub id: String,
    pub name: String,
    pub tier: u32,
    pub kind: String,
    pub status: TargetHealthLifecycle,
    pub circuit_state: String,
    pub failure_count: u32,
    pub latency_ms: u32,
    pub detail: String,
    pub last_checked_at: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DrillLifecycle {
    Passed,
    Running,
    Failed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BackupDrillStateRecord {
    pub drill_id: String,
    pub kind: String,
    pub status: DrillLifecycle,
    pub snapshot_digest: String,
    pub record_count: u32,
    pub verified_tables: u32,
    pub duration_ms: u32,
    pub executed_at: String,
    pub actor: String,
    pub note: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OperatorGovernanceState {
    pub current: OperatorConfigSnapshot,
    pub revisions: Vec<OperatorRevisionRecord>,
    pub target_upgrade_version: String,
    pub targets: Vec<TargetHealthRecord>,
    pub drills: Vec<BackupDrillStateRecord>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct SurfacesGovernanceState {
    pub review_overrides: BTreeMap<String, ReviewDecisionOverride>,
    pub first_run: FirstRunPersistedState,
    pub compliance: Option<ComplianceGovernanceState>,
    pub provider: Option<ProviderGovernanceState>,
    pub operator: Option<OperatorGovernanceState>,
}

impl Default for FirstRunPersistedState {
    fn default() -> Self {
        Self {
            selected_profile: "protected".into(),
            confirmed: false,
            step_up_enabled: false,
        }
    }
}
