// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Session lifecycle state machine, boot isolation, and resume taint propagation (`docs/design/06`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::{ActionClass, CodedError, Mode, SessionFreezeState};
use serde::{Deserialize, Serialize};

const MAX_TRACKED_SESSIONS: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionLifecyclePhase {
    Opening,
    Active,
    Frozen,
    Draining,
    Lingering,
    Ended,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum StartBasis {
    Launched,
    ObservedExec,
    Adopted,
    Claimed,
    Spawned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionCloseTrigger {
    HookSessionEnd,
    ProcessExit,
    SocketSilenceTimeout,
    BootChanged,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClaimClosureState {
    Open,
    EndClaimedPendingExit,
    Closed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantInheritancePolicy {
    NeverInherited,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionConstraints {
    pub max_depth: u8,
    pub current_depth: u8,
    pub ceiling_mode: Mode,
    pub disallowed_classes: Vec<ActionClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRecord {
    pub session_id: String,
    pub boot_id: String,
    pub agent_id: String,
    pub phase: SessionLifecyclePhase,
    pub start_basis: StartBasis,
    pub claim_state: ClaimClosureState,
    pub grant_inheritance: GrantInheritancePolicy,
    pub taint_labels: BTreeSet<String>,
    pub prior_denials: u32,
    pub resumed_from_session_id: Option<String>,
    pub constraints: SessionConstraints,
    pub opened_at_ms: u64,
    pub ended_at_ms: Option<u64>,
}

#[derive(Debug, Default)]
pub struct SessionRegistry {
    active_boot_id: String,
    sessions: BTreeMap<String, SessionRecord>,
}

impl Default for SessionConstraints {
    fn default() -> Self {
        Self {
            max_depth: 4,
            current_depth: 0,
            ceiling_mode: Mode::Watch,
            disallowed_classes: Vec::new(),
        }
    }
}

impl SessionConstraints {
    #[must_use]
    pub fn narrow_for_child(
        &self,
        requested_max_depth: u8,
        requested_ceiling: Mode,
        extra_disallowed: &[ActionClass],
    ) -> Self {
        let mut disallowed = self.disallowed_classes.clone();
        for cls in extra_disallowed {
            if !disallowed.contains(cls) {
                disallowed.push(*cls);
            }
        }
        let remaining_parent_depth = self.max_depth.saturating_sub(1);
        let child_depth = self.current_depth.saturating_add(1);
        Self {
            max_depth: remaining_parent_depth.min(requested_max_depth),
            current_depth: child_depth,
            ceiling_mode: stricter_mode(self.ceiling_mode, requested_ceiling),
            disallowed_classes: disallowed,
        }
    }
}

impl SessionRecord {
    #[must_use]
    pub fn to_freeze_state(&self) -> SessionFreezeState {
        match self.phase {
            SessionLifecyclePhase::Frozen => SessionFreezeState::Frozen,
            SessionLifecyclePhase::Opening
            | SessionLifecyclePhase::Active
            | SessionLifecyclePhase::Draining
            | SessionLifecyclePhase::Lingering
            | SessionLifecyclePhase::Ended => SessionFreezeState::Active,
        }
    }

    #[must_use]
    pub fn accepts_events(&self, event_boot_id: &str) -> bool {
        self.boot_id == event_boot_id && !matches!(self.phase, SessionLifecyclePhase::Ended)
    }
}

impl SessionRegistry {
    #[must_use]
    pub fn new(boot_id: impl Into<String>) -> Self {
        Self {
            active_boot_id: boot_id.into(),
            sessions: BTreeMap::new(),
        }
    }

    #[must_use]
    pub fn active_boot_id(&self) -> &str {
        &self.active_boot_id
    }

    #[must_use]
    pub fn get(&self, session_id: &str) -> Option<&SessionRecord> {
        self.sessions.get(session_id)
    }

    pub fn open_session(
        &mut self,
        session_id: impl Into<String>,
        agent_id: impl Into<String>,
        start_basis: StartBasis,
        constraints: SessionConstraints,
        now_ms: u64,
    ) -> Result<&SessionRecord, CodedError> {
        let sid = session_id.into();
        if sid.trim().is_empty() {
            return Err(CodedError::new(
                "GRDR-SESS-0001",
                "session_id must not be empty",
                "Provide a non-empty session identifier.",
            ));
        }
        if self.sessions.contains_key(&sid) {
            return Err(CodedError::new(
                "GRDR-SESS-0001",
                "session_id already exists",
                "Choose a unique session identifier.",
            ));
        }
        if self.sessions.len() >= MAX_TRACKED_SESSIONS {
            return Err(CodedError::new(
                "GRDR-SESS-0002",
                "session registry capacity limit reached",
                "Close or evict expired sessions before opening new ones.",
            ));
        }
        let phase = match start_basis {
            StartBasis::Claimed => SessionLifecyclePhase::Opening,
            StartBasis::Launched
            | StartBasis::ObservedExec
            | StartBasis::Adopted
            | StartBasis::Spawned => SessionLifecyclePhase::Active,
        };
        let record = SessionRecord {
            session_id: sid.clone(),
            boot_id: self.active_boot_id.clone(),
            agent_id: agent_id.into(),
            phase,
            start_basis,
            claim_state: ClaimClosureState::Open,
            grant_inheritance: GrantInheritancePolicy::NeverInherited,
            taint_labels: BTreeSet::new(),
            prior_denials: 0,
            resumed_from_session_id: None,
            constraints,
            opened_at_ms: now_ms,
            ended_at_ms: None,
        };
        self.sessions.insert(sid.clone(), record);
        self.sessions.get(&sid).ok_or_else(|| {
            CodedError::new(
                "GRDR-SESS-0001",
                "missing inserted session",
                "Retry opening the session.",
            )
        })
    }

    pub fn apply_close_trigger(
        &mut self,
        session_id: &str,
        trigger: SessionCloseTrigger,
        now_ms: u64,
    ) -> Result<SessionLifecyclePhase, CodedError> {
        let rec = self.sessions.get_mut(session_id).ok_or_else(|| {
            CodedError::new(
                "GRDR-SESS-0001",
                "cannot close unknown session",
                "Verify session_id exists in the active registry.",
            )
        })?;
        match trigger {
            SessionCloseTrigger::HookSessionEnd => {
                // Doc 06: SessionEnd claim never closes a session by itself.
                rec.claim_state = ClaimClosureState::EndClaimedPendingExit;
                if matches!(
                    rec.phase,
                    SessionLifecyclePhase::Opening | SessionLifecyclePhase::Active
                ) {
                    rec.phase = SessionLifecyclePhase::Draining;
                }
            }
            SessionCloseTrigger::ProcessExit => {
                rec.phase = match rec.phase {
                    SessionLifecyclePhase::Frozen => SessionLifecyclePhase::Frozen,
                    SessionLifecyclePhase::Draining => SessionLifecyclePhase::Ended,
                    SessionLifecyclePhase::Ended => SessionLifecyclePhase::Ended,
                    _ => SessionLifecyclePhase::Lingering,
                };
                if rec.phase == SessionLifecyclePhase::Ended {
                    rec.claim_state = ClaimClosureState::Closed;
                    rec.ended_at_ms = Some(now_ms);
                }
            }
            SessionCloseTrigger::SocketSilenceTimeout => {
                if rec.phase != SessionLifecyclePhase::Frozen {
                    rec.phase = SessionLifecyclePhase::Ended;
                    rec.claim_state = ClaimClosureState::Closed;
                    rec.ended_at_ms = Some(now_ms);
                }
            }
            SessionCloseTrigger::BootChanged => {
                if rec.phase != SessionLifecyclePhase::Frozen {
                    rec.phase = SessionLifecyclePhase::Ended;
                    rec.claim_state = ClaimClosureState::Closed;
                    rec.ended_at_ms = Some(now_ms);
                }
            }
        }
        Ok(rec.phase)
    }

    pub fn freeze_session(&mut self, session_id: &str) -> Result<(), CodedError> {
        let rec = self.sessions.get_mut(session_id).ok_or_else(|| {
            CodedError::new(
                "GRDR-SESS-0001",
                "cannot freeze unknown session",
                "Verify session_id exists in the active registry.",
            )
        })?;
        if rec.phase != SessionLifecyclePhase::Ended {
            rec.phase = SessionLifecyclePhase::Frozen;
        }
        Ok(())
    }

    pub fn record_boot_transition(&mut self, new_boot_id: impl Into<String>, now_ms: u64) -> usize {
        let next_boot = new_boot_id.into();
        if next_boot == self.active_boot_id {
            return 0;
        }
        let mut closed = 0usize;
        for rec in self.sessions.values_mut() {
            if !matches!(
                rec.phase,
                SessionLifecyclePhase::Ended | SessionLifecyclePhase::Frozen
            ) {
                rec.phase = SessionLifecyclePhase::Ended;
                rec.claim_state = ClaimClosureState::Closed;
                rec.ended_at_ms = Some(now_ms);
                closed = closed.saturating_add(1);
            }
        }
        self.active_boot_id = next_boot;
        closed
    }

    pub fn resume_session(
        &mut self,
        prior_session_id: &str,
        new_session_id: impl Into<String>,
        now_ms: u64,
    ) -> Result<&SessionRecord, CodedError> {
        let prior = self
            .sessions
            .get(prior_session_id)
            .cloned()
            .ok_or_else(|| {
                CodedError::new(
                    "GRDR-SESS-0001",
                    "cannot resume from unknown prior session",
                    "Ensure prior session exists before resuming.",
                )
            })?;
        if prior.phase == SessionLifecyclePhase::Frozen {
            return Err(CodedError::new(
                "GRDR-SESS-0001",
                "cannot resume a frozen session",
                "Investigate why the prior session was frozen before starting a fresh session.",
            ));
        }
        let new_id = new_session_id.into();
        if new_id.trim().is_empty() || new_id == prior_session_id {
            return Err(CodedError::new(
                "GRDR-SESS-0001",
                "resumed session_id must be non-empty and distinct from prior session",
                "Provide a fresh non-empty session identifier.",
            ));
        }
        if self.sessions.contains_key(&new_id) {
            return Err(CodedError::new(
                "GRDR-SESS-0001",
                "resumed session_id already exists",
                "Choose a unique session identifier.",
            ));
        }
        if self.sessions.len() >= MAX_TRACKED_SESSIONS {
            return Err(CodedError::new(
                "GRDR-SESS-0002",
                "session registry capacity limit reached",
                "Close or evict expired sessions before opening new ones.",
            ));
        }
        let resumed = SessionRecord {
            session_id: new_id.clone(),
            boot_id: self.active_boot_id.clone(),
            agent_id: prior.agent_id,
            phase: SessionLifecyclePhase::Active,
            start_basis: StartBasis::Adopted,
            claim_state: ClaimClosureState::Open,
            grant_inheritance: GrantInheritancePolicy::NeverInherited,
            taint_labels: prior.taint_labels,
            prior_denials: prior.prior_denials,
            resumed_from_session_id: Some(prior.session_id),
            constraints: prior.constraints,
            opened_at_ms: now_ms,
            ended_at_ms: None,
        };
        self.sessions.insert(new_id.clone(), resumed);
        self.sessions.get(&new_id).ok_or_else(|| {
            CodedError::new(
                "GRDR-SESS-0001",
                "missing resumed session",
                "Retry resuming the session.",
            )
        })
    }

    pub fn add_taint(
        &mut self,
        session_id: &str,
        label: impl Into<String>,
    ) -> Result<(), CodedError> {
        let rec = self.sessions.get_mut(session_id).ok_or_else(|| {
            CodedError::new(
                "GRDR-SESS-0001",
                "cannot taint unknown session",
                "Verify session_id exists before adding taint.",
            )
        })?;
        rec.taint_labels.insert(label.into());
        Ok(())
    }

    pub fn record_denial(&mut self, session_id: &str) -> Result<u32, CodedError> {
        let rec = self.sessions.get_mut(session_id).ok_or_else(|| {
            CodedError::new(
                "GRDR-SESS-0001",
                "cannot record denial for unknown session",
                "Verify session_id exists before recording denial.",
            )
        })?;
        rec.prior_denials = rec.prior_denials.saturating_add(1);
        Ok(rec.prior_denials)
    }

    #[must_use]
    pub fn sessions(&self) -> &BTreeMap<String, SessionRecord> {
        &self.sessions
    }
}

#[must_use]
pub fn stricter_mode(a: Mode, b: Mode) -> Mode {
    if mode_rank(a) >= mode_rank(b) { a } else { b }
}

const fn mode_rank(mode: Mode) -> u8 {
    match mode {
        Mode::Off => 0,
        Mode::Watch => 1,
        Mode::Ask => 2,
        Mode::Block => 3,
    }
}
