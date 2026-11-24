// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::artifacts::ArtifactEntry;
use crate::domain::{
    ActionClass, ApprovalGrade, AssuranceLevel, AssuranceRecord, ControlPoint, FindingLifecycle,
    GrantScope, InstallProfile, KillScope, KillSwitchState, Mode, SessionLabel, Verdict,
};
use crate::identity::UserProfile;
use crate::policy::{ActionAttempt, CompiledFloorTable, DecisionReceipt, PolicyPack, RuleMatch};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct McpServerEntry {
    pub name: String,
    pub transport: String,
    pub command: String,
    pub source_agent: String,
    pub config_path: String,
    pub pinned: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveredAgent {
    pub id: String,
    pub name: String,
    pub kind: String,
    pub config_path: String,
    pub hook_installed: bool,
    pub mcp_count: usize,
    pub assurance: AssuranceRecord,
    pub assurance_level: AssuranceLevel,
    pub sponsor: Option<String>,
    pub detected_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DiscoveryReport {
    pub device_name: String,
    pub os: String,
    pub arch: String,
    pub install_profile: InstallProfile,
    pub agents: Vec<DiscoveredAgent>,
    pub mcp_servers: Vec<McpServerEntry>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEntry>,
    pub scanned_paths: Vec<String>,
    pub warnings: Vec<String>,
    pub scanned_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Device {
    pub id: String,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub install_profile: InstallProfile,
    pub daemon_version: String,
    pub online: bool,
    pub hook_effective: bool,
    pub agents: Vec<DiscoveredAgent>,
    pub mcp_servers: Vec<McpServerEntry>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEntry>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub user_display: Option<String>,
    pub last_seen: Timestamp,
    #[serde(default)]
    pub public_key: Option<TrustedKeyInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnSummary {
    pub turn_index: u32,
    pub trace_id: String,
    pub span_count: usize,
    pub duration_ms: u64,
    pub blocked_count: usize,
    pub asked_count: usize,
    pub has_compaction: bool,
    pub has_subagent_handoff: bool,
    pub started_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSummary {
    pub id: String,
    pub device_id: String,
    pub device_name: String,
    pub agent_name: String,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub user_display: Option<String>,
    #[serde(default)]
    pub turn_count: usize,
    #[serde(default)]
    pub parent_session_id: Option<String>,
    pub started_at: Timestamp,
    pub last_activity: Timestamp,
    pub total_actions: u64,
    pub blocked_count: u64,
    pub step_up_count: u64,
    pub watch_hits: u64,
    pub assurance_level: AssuranceLevel,
    #[serde(default)]
    pub labels: Vec<SessionLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionDetailResponse {
    pub session: SessionSummary,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<DecisionReceipt>,
    #[serde(default)]
    pub turns: Vec<TurnSummary>,
    #[serde(default)]
    pub user: Option<UserProfile>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct InsightTile {
    pub id: String,
    pub headline: String,
    pub metric: String,
    pub comparison: String,
    pub action_label: String,
    pub route: String,
    pub tone: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SetupStep {
    pub id: String,
    pub label: String,
    pub done: bool,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerHealth {
    Ok,
    Healthy,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum StorageMode {
    Memory,
    Sqlite { path: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OverviewResponse {
    pub server_status: ServerHealth,
    pub total_devices: usize,
    pub online_devices: usize,
    pub total_agents: usize,
    pub total_mcp_servers: usize,
    pub active_sessions: usize,
    pub pending_approvals: usize,
    pub open_findings: usize,
    #[serde(default)]
    pub open_incidents: usize,
    pub kill_switch: KillSwitchState,
    pub tiles: Vec<InsightTile>,
    pub setup_steps: Vec<SetupStep>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthResponse {
    pub status: ServerHealth,
    pub version: String,
    pub storage_mode: StorageMode,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCheckinRequest {
    pub device_id: Option<String>,
    pub hostname: String,
    pub os: String,
    pub arch: String,
    pub install_profile: InstallProfile,
    pub daemon_version: String,
    pub hook_effective: bool,
    pub agents: Vec<DiscoveredAgent>,
    pub mcp_servers: Vec<McpServerEntry>,
    #[serde(default)]
    pub artifacts: Vec<ArtifactEntry>,
    #[serde(default)]
    pub user_id: Option<String>,
    #[serde(default)]
    pub user_display: Option<String>,
    #[serde(default)]
    pub device_public_key: Option<TrustedKeyInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrustedKeyInfo {
    pub key_id: String,
    pub public_key_b64: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedFloorBundle {
    pub table: CompiledFloorTable,
    pub signer: TrustedKeyInfo,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCheckinResponse {
    pub device: Device,
    pub packs: Vec<PolicyPack>,
    pub grants: Vec<crate::policy::Grant>,
    pub kill_switch: KillSwitchState,
    pub server_time: Timestamp,
    #[serde(default)]
    pub trusted_keys: Vec<TrustedKeyInfo>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideInput {
    pub session_id: Option<String>,
    pub device_id: Option<String>,
    pub device_name: Option<String>,
    pub agent_name: String,
    pub action_class: ActionClass,
    pub control_point: Option<ControlPoint>,
    pub target: String,
    pub summary: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEventsInput {
    pub device_id: String,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<DecisionReceipt>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BatchEventsResponse {
    pub accepted: usize,
    pub findings_created: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CreateRuleInput {
    pub pack_id: Option<String>,
    pub title: String,
    pub description: String,
    pub mode: Mode,
    pub min_grade: Option<ApprovalGrade>,
    pub matcher: RuleMatch,
    pub reason_template: String,
    #[serde(default)]
    pub cedar: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRuleModeInput {
    pub mode: Mode,
    pub actor: Option<String>,
    pub replay_confirmed: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateRuleInput {
    pub title: Option<String>,
    pub description: Option<String>,
    pub mode: Option<Mode>,
    pub min_grade: Option<ApprovalGrade>,
    pub matcher: Option<RuleMatch>,
    pub reason_template: Option<String>,
    #[serde(default)]
    pub cedar: Option<String>,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReplayRuleInput {
    pub candidate_mode: Mode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DecideApprovalInput {
    pub approve: bool,
    pub scope: Option<GrantScope>,
    pub note: Option<String>,
    pub actor: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpdateFindingInput {
    pub lifecycle: FindingLifecycle,
    pub note: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KillSwitchInput {
    pub action: KillAction,
    pub scope: KillScope,
    pub target_id: String,
    pub reason: String,
    pub duration_minutes: Option<i64>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum KillAction {
    Freeze,
    Kill,
    Release,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LiveEvent {
    pub id: String,
    pub topic: String,
    pub summary: String,
    pub verdict: Option<Verdict>,
    pub timestamp: Timestamp,
}

impl StorageMode {
    pub fn label(&self) -> String {
        match self {
            Self::Memory => "embedded:memory".into(),
            Self::Sqlite { path } => format!("embedded:sqlite:{path}"),
        }
    }
}

impl DecideInput {
    pub fn into_attempt(
        self,
        default_session: &str,
        default_device_id: &str,
        default_device_name: &str,
        default_summary: &str,
        now: Timestamp,
    ) -> ActionAttempt {
        ActionAttempt {
            id: format!("att_{}", Uuid::now_v7().simple()),
            session_id: self
                .session_id
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| default_session.into()),
            device_id: self
                .device_id
                .filter(|d| !d.trim().is_empty())
                .unwrap_or_else(|| default_device_id.into()),
            device_name: self
                .device_name
                .filter(|n| !n.trim().is_empty())
                .unwrap_or_else(|| default_device_name.into()),
            agent_name: if self.agent_name.trim().is_empty() {
                "claude-code".into()
            } else {
                self.agent_name
            },
            action_class: self.action_class,
            control_point: self.control_point.unwrap_or(ControlPoint::Hook),
            target: self.target,
            summary: self
                .summary
                .filter(|s| !s.trim().is_empty())
                .unwrap_or_else(|| default_summary.into()),
            timestamp: now,
            ..Default::default()
        }
    }
}

pub fn summarize_sessions(
    attempts: &[ActionAttempt],
    receipts: &[DecisionReceipt],
) -> Vec<SessionSummary> {
    let mut map: BTreeMap<String, SessionSummary> = BTreeMap::new();
    let mut turns_by_session: BTreeMap<String, std::collections::BTreeSet<u32>> = BTreeMap::new();

    for attempt in attempts {
        let entry = map
            .entry(attempt.session_id.clone())
            .or_insert_with(|| SessionSummary {
                id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                device_name: attempt.device_name.clone(),
                agent_name: attempt.agent_name.clone(),
                user_id: attempt.user_id.clone(),
                user_display: attempt.user_display.clone(),
                turn_count: 1,
                parent_session_id: None,
                started_at: attempt.timestamp,
                last_activity: attempt.timestamp,
                total_actions: 0,
                blocked_count: 0,
                step_up_count: 0,
                watch_hits: 0,
                assurance_level: AssuranceLevel::Al2Guided,
                labels: Vec::new(),
            });
        if entry.user_id.is_none() && attempt.user_id.is_some() {
            entry.user_id = attempt.user_id.clone();
            entry.user_display = attempt.user_display.clone();
        }
        turns_by_session
            .entry(attempt.session_id.clone())
            .or_default()
            .insert(attempt.turn_index.max(1));
        if attempt.timestamp < entry.started_at {
            entry.started_at = attempt.timestamp;
        }
        if attempt.timestamp > entry.last_activity {
            entry.last_activity = attempt.timestamp;
        }
        entry.total_actions = entry.total_actions.saturating_add(1);
    }

    for (session_id, turns) in turns_by_session {
        if let Some(entry) = map.get_mut(&session_id) {
            entry.turn_count = turns.len().max(1);
        }
    }

    for receipt in receipts {
        if let Some(entry) = map.get_mut(&receipt.session_id) {
            match receipt.verdict {
                Verdict::Deny => entry.blocked_count = entry.blocked_count.saturating_add(1),
                Verdict::StepUp => entry.step_up_count = entry.step_up_count.saturating_add(1),
                Verdict::Allow if receipt.mode_applied == Some(Mode::Watch) => {
                    entry.watch_hits = entry.watch_hits.saturating_add(1);
                }
                _ => {}
            }
        }
    }

    let mut sessions: Vec<SessionSummary> = map.into_values().collect();
    sessions.sort_by_key(|session| std::cmp::Reverse(session.last_activity));
    sessions
}

pub fn summarize_session_turns(
    attempts: &[ActionAttempt],
    receipts: &[DecisionReceipt],
) -> Vec<TurnSummary> {
    let verdict_by_attempt: BTreeMap<&str, Verdict> = receipts
        .iter()
        .map(|r| (r.attempt_id.as_str(), r.verdict))
        .collect();
    let mut turns: BTreeMap<u32, TurnSummary> = BTreeMap::new();

    for attempt in attempts {
        let turn_num = attempt.turn_index.max(1);
        let verdict = verdict_by_attempt.get(attempt.id.as_str()).copied();
        let is_blocked = verdict == Some(Verdict::Deny);
        let is_asked = verdict == Some(Verdict::StepUp);
        let is_handoff = attempt.span_kind == crate::policy::SpanKind::SubagentSpawn;

        let summary = turns.entry(turn_num).or_insert_with(|| TurnSummary {
            turn_index: turn_num,
            trace_id: format!("trc_{}_{}", attempt.session_id, turn_num),
            span_count: 0,
            duration_ms: 0,
            blocked_count: 0,
            asked_count: 0,
            has_compaction: false,
            has_subagent_handoff: false,
            started_at: attempt.timestamp,
        });
        summary.span_count = summary.span_count.saturating_add(1);
        summary.duration_ms = summary.duration_ms.saturating_add(attempt.duration_ms);
        if is_blocked {
            summary.blocked_count = summary.blocked_count.saturating_add(1);
        }
        if is_asked {
            summary.asked_count = summary.asked_count.saturating_add(1);
        }
        if attempt.compaction || attempt.span_kind == crate::policy::SpanKind::Compaction {
            summary.has_compaction = true;
        }
        if is_handoff {
            summary.has_subagent_handoff = true;
        }
        if attempt.timestamp < summary.started_at {
            summary.started_at = attempt.timestamp;
        }
    }

    turns.into_values().collect()
}

pub fn slugify_id(raw: &str, max_len: usize, fallback: &str) -> String {
    let mut out = String::new();
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
        } else if !out.ends_with('-') {
            out.push('-');
        }
    }
    let trimmed = out.trim_matches('-');
    if trimmed.is_empty() {
        fallback.into()
    } else {
        trimmed.chars().take(max_len).collect()
    }
}
