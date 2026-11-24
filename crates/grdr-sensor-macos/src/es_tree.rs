// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::ActionClass;

pub const ENGINE_BUDGET_SHARE_PCT: u64 = 50;
pub const DESCENDANTS_HOLD_CAP_PCT: u64 = 80;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ProcessTreeKey {
    pub pid: u32,
    pub pidversion: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct EsAuditToken {
    pub key: ProcessTreeKey,
    pub uid: u32,
    pub team_id: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsClientConcern {
    Recorder,
    ExecAuthorizer,
    ProtectedPathGuard,
    SelfProtection,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EsClientStatus {
    Active,
    MissingEntitlement,
    TooManyClients,
    NotPermittedFda,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeadlineMissPolicy {
    FullClientFailOpen,
    DescendantsFailClosed,
    DescendantsFailOpen,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthDeadlineBudget {
    pub kernel_deadline_ms: u64,
    pub engine_cutoff_ms: u64,
    pub policy: DeadlineMissPolicy,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "event", rename_all = "snake_case")]
pub enum EsEventPayload {
    RegisterAgentRoot {
        root: EsAuditToken,
        session_id: String,
    },
    NotifyFork {
        parent: ProcessTreeKey,
        child: EsAuditToken,
    },
    AuthExec {
        old_key: ProcessTreeKey,
        target: EsAuditToken,
        executable_path: String,
    },
    NotifyExec {
        old_key: ProcessTreeKey,
        new_token: EsAuditToken,
        executable_path: String,
    },
    NotifyExit {
        key: ProcessTreeKey,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TrackedTreeMember {
    pub token: EsAuditToken,
    pub session_id: String,
    pub agent_root_pid: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HealthGapEvent {
    pub expected_seq: u64,
    pub observed_seq: u64,
    pub lost_events: u64,
    pub occurred_at: Timestamp,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditRecordPhase {
    Effect,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeniedExecOutcome {
    Denied,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeniedExecAuditRecord {
    pub session_id: String,
    pub target_key: ProcessTreeKey,
    pub executable_path: String,
    pub reason: String,
    pub record_phase: AuditRecordPhase,
    pub outcome: DeniedExecOutcome,
    pub occurred_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupervisorWatchdogOutcome {
    pub session_id: String,
    pub verified_members_to_kill: Vec<ProcessTreeKey>,
    pub skipped_recycled_pids: Vec<u32>,
    pub response_reason: &'static str,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EsApplyOutcome {
    pub session_id: Option<String>,
    pub action_class: ActionClass,
    pub summary: String,
    pub unmuted_targets: Vec<ProcessTreeKey>,
}

#[derive(Debug, Clone, Default)]
pub struct EsTreeFollower {
    members: BTreeMap<ProcessTreeKey, TrackedTreeMember>,
    muted_incumbent_teams: BTreeSet<String>,
    pending_denied_execs: BTreeMap<ProcessTreeKey, (String, String, String)>,
    next_expected_seq: Option<u64>,
    total_sequence_gaps: u64,
}

impl AuthDeadlineBudget {
    pub fn for_full_client(kernel_deadline_ms: u64) -> Self {
        let cutoff = kernel_deadline_ms.saturating_mul(ENGINE_BUDGET_SHARE_PCT) / 100;
        Self {
            kernel_deadline_ms,
            engine_cutoff_ms: cutoff.max(1),
            policy: DeadlineMissPolicy::FullClientFailOpen,
        }
    }

    pub fn for_descendants_supervisor(deadline_floor_ms: u64, fail_closed: bool) -> Self {
        let hold_cap = deadline_floor_ms.saturating_mul(DESCENDANTS_HOLD_CAP_PCT) / 100;
        Self {
            kernel_deadline_ms: deadline_floor_ms,
            engine_cutoff_ms: hold_cap.max(1),
            policy: if fail_closed {
                DeadlineMissPolicy::DescendantsFailClosed
            } else {
                DeadlineMissPolicy::DescendantsFailOpen
            },
        }
    }
}

impl EsTreeFollower {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn mute_incumbent_team(&mut self, team_id: impl Into<String>) {
        self.muted_incumbent_teams.insert(team_id.into());
    }

    pub fn is_muted_incumbent(&self, token: &EsAuditToken) -> bool {
        token
            .team_id
            .as_ref()
            .is_some_and(|tid| self.muted_incumbent_teams.contains(tid))
    }

    pub fn member_count(&self) -> usize {
        self.members.len()
    }

    pub fn total_sequence_gaps(&self) -> u64 {
        self.total_sequence_gaps
    }

    pub fn record_sequence(&mut self, seq_num: u64, now: Timestamp) -> Option<HealthGapEvent> {
        let gap = match self.next_expected_seq {
            Some(expected) if seq_num > expected => {
                let lost = seq_num.saturating_sub(expected);
                self.total_sequence_gaps = self.total_sequence_gaps.saturating_add(lost);
                Some(HealthGapEvent {
                    expected_seq: expected,
                    observed_seq: seq_num,
                    lost_events: lost,
                    occurred_at: now,
                })
            }
            _ => None,
        };
        self.next_expected_seq = Some(seq_num.saturating_add(1));
        gap
    }

    pub fn record_denied_auth_exec(
        &mut self,
        target_key: ProcessTreeKey,
        session_id: impl Into<String>,
        executable_path: impl Into<String>,
        reason: impl Into<String>,
    ) {
        self.pending_denied_execs.insert(
            target_key,
            (session_id.into(), executable_path.into(), reason.into()),
        );
    }

    pub fn consume_exit_for_denied_exec(
        &mut self,
        key: ProcessTreeKey,
        occurred_at: Timestamp,
    ) -> Option<DeniedExecAuditRecord> {
        let (session_id, executable_path, reason) = self.pending_denied_execs.remove(&key)?;
        Some(synthesize_denied_exec_audit(
            session_id,
            key,
            executable_path,
            reason,
            occurred_at,
        ))
    }

    pub fn apply_event(&mut self, event: &EsEventPayload) -> EsApplyOutcome {
        match event {
            EsEventPayload::RegisterAgentRoot { root, session_id } => {
                self.members.insert(
                    root.key,
                    TrackedTreeMember {
                        token: root.clone(),
                        session_id: session_id.clone(),
                        agent_root_pid: root.key.pid,
                    },
                );
                EsApplyOutcome {
                    session_id: Some(session_id.clone()),
                    action_class: ActionClass::AgentSpawn,
                    summary: format!("ES registered agent root pid={}", root.key.pid),
                    unmuted_targets: vec![root.key],
                }
            }
            EsEventPayload::NotifyFork { parent, child } => {
                if self.is_muted_incumbent(child) {
                    return EsApplyOutcome {
                        session_id: None,
                        action_class: ActionClass::Exec,
                        summary: "ES ignored muted incumbent fork".into(),
                        unmuted_targets: Vec::new(),
                    };
                }
                if let Some(parent_member) = self.members.get(parent).cloned() {
                    self.members.insert(
                        child.key,
                        TrackedTreeMember {
                            token: child.clone(),
                            session_id: parent_member.session_id.clone(),
                            agent_root_pid: parent_member.agent_root_pid,
                        },
                    );
                    EsApplyOutcome {
                        session_id: Some(parent_member.session_id),
                        action_class: ActionClass::Exec,
                        summary: format!(
                            "ES fork pid={} -> child pid={}",
                            parent.pid, child.key.pid
                        ),
                        unmuted_targets: vec![child.key],
                    }
                } else {
                    EsApplyOutcome {
                        session_id: None,
                        action_class: ActionClass::Exec,
                        summary: format!("ES fork outside tracked tree pid={}", child.key.pid),
                        unmuted_targets: Vec::new(),
                    }
                }
            }
            EsEventPayload::AuthExec {
                old_key,
                target,
                executable_path,
            } => {
                // Pre-select the new exec target before answering AUTH_EXEC so no early event of the new image is missed.
                if let Some(prev) = self.members.get(old_key).cloned() {
                    self.members.insert(
                        target.key,
                        TrackedTreeMember {
                            token: target.clone(),
                            session_id: prev.session_id.clone(),
                            agent_root_pid: prev.agent_root_pid,
                        },
                    );
                    EsApplyOutcome {
                        session_id: Some(prev.session_id),
                        action_class: ActionClass::Exec,
                        summary: format!("ES AUTH_EXEC pre-selected {executable_path}"),
                        unmuted_targets: vec![target.key],
                    }
                } else {
                    EsApplyOutcome {
                        session_id: None,
                        action_class: ActionClass::Exec,
                        summary: format!("ES AUTH_EXEC untracked {executable_path}"),
                        unmuted_targets: Vec::new(),
                    }
                }
            }
            EsEventPayload::NotifyExec {
                old_key,
                new_token,
                executable_path,
            } => {
                let session_id = self.members.remove(old_key).map(|m| m.session_id);
                EsApplyOutcome {
                    session_id,
                    action_class: ActionClass::Exec,
                    summary: format!(
                        "ES NOTIFY_EXEC pid={} -> pidversion={} ({executable_path})",
                        new_token.key.pid, new_token.key.pidversion
                    ),
                    unmuted_targets: Vec::new(),
                }
            }
            EsEventPayload::NotifyExit { key } => {
                let session_id = self.members.remove(key).map(|m| m.session_id);
                EsApplyOutcome {
                    session_id,
                    action_class: ActionClass::Exec,
                    summary: format!("ES NOTIFY_EXIT pid={}", key.pid),
                    unmuted_targets: Vec::new(),
                }
            }
        }
    }

    pub fn plan_supervisor_loss_kill(
        &self,
        session_id: &str,
        live_pidversions: &BTreeMap<u32, u32>,
    ) -> SupervisorWatchdogOutcome {
        let mut verified = Vec::new();
        let mut skipped = Vec::new();
        for member in self.members.values() {
            if member.session_id != session_id {
                continue;
            }
            match live_pidversions.get(&member.token.key.pid) {
                Some(live_ver) if *live_ver == member.token.key.pidversion => {
                    verified.push(member.token.key);
                }
                Some(_) => {
                    skipped.push(member.token.key.pid);
                }
                None => {}
            }
        }
        SupervisorWatchdogOutcome {
            session_id: session_id.to_string(),
            verified_members_to_kill: verified,
            skipped_recycled_pids: skipped,
            response_reason: "supervisor-lost",
        }
    }
}

pub fn synthesize_denied_exec_audit(
    session_id: String,
    target_key: ProcessTreeKey,
    executable_path: String,
    reason: String,
    occurred_at: Timestamp,
) -> DeniedExecAuditRecord {
    DeniedExecAuditRecord {
        session_id,
        target_key,
        executable_path,
        reason,
        record_phase: AuditRecordPhase::Effect,
        outcome: DeniedExecOutcome::Denied,
        occurred_at,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn es_tree_follows_fork_exec_exit_and_detects_seq_gaps() {
        let mut follower = EsTreeFollower::new();
        let ts = Timestamp::from_second(1_700_000_000).unwrap();

        assert!(follower.record_sequence(10, ts).is_none());
        let gap = follower.record_sequence(14, ts).unwrap();
        assert_eq!(gap.lost_events, 3);
        assert_eq!(follower.total_sequence_gaps(), 3);

        let root_key = ProcessTreeKey {
            pid: 500,
            pidversion: 1,
        };
        let root_tok = EsAuditToken {
            key: root_key,
            uid: 501,
            team_id: None,
        };
        follower.apply_event(&EsEventPayload::RegisterAgentRoot {
            root: root_tok,
            session_id: "sess-es-1".into(),
        });

        let child_v1 = ProcessTreeKey {
            pid: 501,
            pidversion: 1,
        };
        let child_tok = EsAuditToken {
            key: child_v1,
            uid: 501,
            team_id: None,
        };
        let fork_out = follower.apply_event(&EsEventPayload::NotifyFork {
            parent: root_key,
            child: child_tok,
        });
        assert_eq!(fork_out.unmuted_targets, vec![child_v1]);

        let child_v2 = ProcessTreeKey {
            pid: 501,
            pidversion: 2,
        };
        let exec_tok = EsAuditToken {
            key: child_v2,
            uid: 501,
            team_id: None,
        };
        let auth_out = follower.apply_event(&EsEventPayload::AuthExec {
            old_key: child_v1,
            target: exec_tok.clone(),
            executable_path: "/usr/bin/curl".into(),
        });
        assert_eq!(auth_out.unmuted_targets, vec![child_v2]);

        follower.apply_event(&EsEventPayload::NotifyExec {
            old_key: child_v1,
            new_token: exec_tok,
            executable_path: "/usr/bin/curl".into(),
        });
        assert_eq!(follower.member_count(), 2);

        let mut live = BTreeMap::new();
        live.insert(500, 1);
        live.insert(501, 99);
        let wd = follower.plan_supervisor_loss_kill("sess-es-1", &live);
        assert_eq!(wd.verified_members_to_kill, vec![root_key]);
        assert_eq!(wd.skipped_recycled_pids, vec![501]);
    }

    #[test]
    fn synthesizes_denied_exec_audit_from_exit_event() {
        let mut follower = EsTreeFollower::new();
        let target = ProcessTreeKey {
            pid: 888,
            pidversion: 4,
        };
        follower.record_denied_auth_exec(
            target,
            "sess-es-2",
            "/usr/bin/sudo",
            "elevate-denied-in-sandbox",
        );
        let audit = follower
            .consume_exit_for_denied_exec(target, Timestamp::from_second(1_700_000_000).unwrap())
            .unwrap();
        assert_eq!(audit.record_phase, AuditRecordPhase::Effect);
        assert_eq!(audit.outcome, DeniedExecOutcome::Denied);
        assert_eq!(audit.executable_path, "/usr/bin/sudo");
    }
}
