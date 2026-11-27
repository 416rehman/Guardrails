// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Hook-vs-sensor reconciliation and divergence detections (`docs/design/06`).

use std::collections::BTreeSet;

use grdr_model::ApprovalGrade;
use serde::{Deserialize, Serialize};

use super::lifecycle::{SessionLifecyclePhase, SessionRecord};

pub const RULE_HOOK_DARK: &str = "grdr.det.core.r33.hook-dark";
pub const RULE_EFFECT_MISMATCH: &str = "grdr.det.core.r34.effect-mismatch";
pub const RULE_UNDECLARED_EXEC: &str = "grdr.det.core.r12.undeclared-agent-execution";
pub const RULE_SESSION_CONFLICT: &str = "grdr.det.core.r45.label-late";

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DivergenceKind {
    HookDark,
    HookSilent,
    UndeclaredActivity,
    ClaimWithoutEffect,
    EffectMismatch,
    SessionClaimMismatch,
    TagConflict,
    UndeclaredHop,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookObservation {
    pub session_id: String,
    pub claimed_session_id: Option<String>,
    pub target_digest: Option<String>,
    pub last_hook_ms: Option<u64>,
    pub hook_calls_count: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SensorObservation {
    pub attributed_session_id: Option<String>,
    pub observed_at_ms: u64,
    pub effect_digest: Option<String>,
    pub socket_tag_owner_sessions: Vec<String>,
    pub via_unregistered_hop: bool,
    pub looks_like_agent_process: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ReconciliationInput {
    pub now_ms: u64,
    pub hook_dark_threshold_ms: u64,
    pub sessions: Vec<SessionRecord>,
    pub hooks: Vec<HookObservation>,
    pub sensors: Vec<SensorObservation>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReconciliationFinding {
    pub kind: DivergenceKind,
    pub detection_rule_id: &'static str,
    pub session_id: String,
    pub detail: String,
    pub recommended_grade: ApprovalGrade,
}

#[must_use]
pub fn reconcile_session_evidence(input: &ReconciliationInput) -> Vec<ReconciliationFinding> {
    let mut findings = Vec::new();
    let mut hooks_by_sid: std::collections::BTreeMap<&str, Vec<&HookObservation>> =
        std::collections::BTreeMap::new();
    for hook in &input.hooks {
        hooks_by_sid
            .entry(hook.session_id.as_str())
            .or_default()
            .push(hook);
    }
    let session_by_sid: std::collections::BTreeMap<&str, &SessionRecord> = input
        .sessions
        .iter()
        .map(|s| (s.session_id.as_str(), s))
        .collect();
    let mut silent_reported: BTreeSet<&str> = BTreeSet::new();
    let mut dark_reported: BTreeSet<&str> = BTreeSet::new();

    for hook in &input.hooks {
        if let Some(claimed) = &hook.claimed_session_id
            && claimed != &hook.session_id
        {
            findings.push(ReconciliationFinding {
                kind: DivergenceKind::SessionClaimMismatch,
                detection_rule_id: RULE_SESSION_CONFLICT,
                session_id: hook.session_id.clone(),
                detail: format!(
                    "GRDR-SESS-0004: K4 lineage `{}` disagrees with hook claim `{claimed}`",
                    hook.session_id
                ),
                recommended_grade: ApprovalGrade::G1,
            });
        }
    }

    for sensor in &input.sensors {
        let distinct_tags: BTreeSet<&str> = sensor
            .socket_tag_owner_sessions
            .iter()
            .map(String::as_str)
            .collect();
        if distinct_tags.len() > 1 {
            findings.push(ReconciliationFinding {
                kind: DivergenceKind::TagConflict,
                detection_rule_id: RULE_SESSION_CONFLICT,
                session_id: sensor
                    .attributed_session_id
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                detail: format!(
                    "multiple sessions claim same socket tag ({})",
                    distinct_tags.len()
                ),
                recommended_grade: ApprovalGrade::G0,
            });
        }
        if sensor.via_unregistered_hop {
            findings.push(ReconciliationFinding {
                kind: DivergenceKind::UndeclaredHop,
                detection_rule_id: RULE_UNDECLARED_EXEC,
                session_id: sensor
                    .attributed_session_id
                    .clone()
                    .unwrap_or_else(|| "unknown".into()),
                detail: "cross-process execution observed without declared broker or child edge"
                    .into(),
                recommended_grade: ApprovalGrade::G1,
            });
        }
        match &sensor.attributed_session_id {
            None if sensor.looks_like_agent_process => {
                findings.push(ReconciliationFinding {
                    kind: DivergenceKind::UndeclaredActivity,
                    detection_rule_id: RULE_UNDECLARED_EXEC,
                    session_id: "unattributed".into(),
                    detail: "agent activity observed without registered hook or active session"
                        .into(),
                    recommended_grade: ApprovalGrade::G1,
                });
            }
            Some(sid) => {
                let Some(sess) = session_by_sid.get(sid.as_str()) else {
                    continue;
                };
                if !matches!(
                    sess.phase,
                    SessionLifecyclePhase::Active | SessionLifecyclePhase::Draining
                ) {
                    continue;
                }
                if let Some(hooks) = hooks_by_sid.get(sid.as_str()) {
                    let total_calls = hooks
                        .iter()
                        .map(|h| u64::from(h.hook_calls_count))
                        .fold(0u64, u64::saturating_add);
                    let latest_hook_ms = hooks.iter().filter_map(|h| h.last_hook_ms).max();
                    let silent_ms = latest_hook_ms
                        .map(|t| sensor.observed_at_ms.saturating_sub(t))
                        .unwrap_or_else(|| sensor.observed_at_ms.saturating_sub(sess.opened_at_ms));
                    if silent_ms > input.hook_dark_threshold_ms
                        && total_calls > 0
                        && dark_reported.insert(sid.as_str())
                    {
                        findings.push(ReconciliationFinding {
                            kind: DivergenceKind::HookDark,
                            detection_rule_id: RULE_HOOK_DARK,
                            session_id: sid.clone(),
                            detail: format!(
                                "sensor activity observed {silent_ms}ms after last hook event"
                            ),
                            recommended_grade: ApprovalGrade::G3,
                        });
                    } else if total_calls == 0
                        && silent_ms > input.hook_dark_threshold_ms
                        && silent_reported.insert(sid.as_str())
                    {
                        findings.push(ReconciliationFinding {
                            kind: DivergenceKind::HookSilent,
                            detection_rule_id: RULE_HOOK_DARK,
                            session_id: sid.clone(),
                            detail: "active session had zero hook events despite sensor effects"
                                .into(),
                            recommended_grade: ApprovalGrade::G2,
                        });
                    }
                    for hook in hooks {
                        if let (Some(h_dig), Some(s_dig)) =
                            (&hook.target_digest, &sensor.effect_digest)
                            && h_dig != s_dig
                        {
                            findings.push(ReconciliationFinding {
                                kind: DivergenceKind::EffectMismatch,
                                detection_rule_id: RULE_EFFECT_MISMATCH,
                                session_id: sid.clone(),
                                detail:
                                    "hook claimed target digest disagrees with sensor observed effect"
                                        .into(),
                                recommended_grade: ApprovalGrade::G3,
                            });
                        }
                    }
                } else if sensor.observed_at_ms.saturating_sub(sess.opened_at_ms)
                    > input.hook_dark_threshold_ms
                    && silent_reported.insert(sid.as_str())
                {
                    findings.push(ReconciliationFinding {
                        kind: DivergenceKind::HookSilent,
                        detection_rule_id: RULE_HOOK_DARK,
                        session_id: sid.clone(),
                        detail: "active session had zero hook observations despite sensor effects"
                            .into(),
                        recommended_grade: ApprovalGrade::G2,
                    });
                }
            }
            None => {}
        }
    }

    for hook in &input.hooks {
        if hook.target_digest.is_some()
            && !input
                .sensors
                .iter()
                .any(|s| s.attributed_session_id.as_deref() == Some(hook.session_id.as_str()))
        {
            findings.push(ReconciliationFinding {
                kind: DivergenceKind::ClaimWithoutEffect,
                detection_rule_id: RULE_EFFECT_MISMATCH,
                session_id: hook.session_id.clone(),
                detail: "hook reported effect claim without matching OS sensor observation".into(),
                recommended_grade: ApprovalGrade::G1,
            });
        }
    }

    findings
}
