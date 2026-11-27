// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! K1-K6 correlation join, tie-breaking, provenance evidence grades 0..4,
//! actor classification, and late attribution supersession (`docs/design/06`).

use grdr_model::{ActorKind, ApprovalGrade};
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvidenceGrade {
    Grade0 = 0,
    Grade1 = 1,
    Grade2 = 2,
    Grade3 = 3,
    Grade4 = 4,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionActorKind {
    Agent,
    Human,
    System,
    Undetermined,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CorrelationKeyKind {
    K1WrapperEnv,
    K2SocketToken,
    K3HookMetadata,
    K4ProcessLineage,
    K5CgroupKey,
    K6HeuristicFallback,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum K4MatchStrength {
    PatternOnly,
    ExactPidStartTime,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinConsumptionState {
    Unconsumed,
    ConsumedByOtherRoot,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProvenanceKind {
    ObservedKernel,
    Mediated,
    ObservedUser,
    Claimed,
    Reported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostSharingMode {
    IsolatedAgentTree,
    SharedHostProcess,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessRoleHint {
    AgentOrSubprocess,
    HostDaemon,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JoinCandidate {
    pub session_id: String,
    pub boot_id: String,
    pub key_kind: CorrelationKeyKind,
    pub k4_strength: K4MatchStrength,
    pub consumption: JoinConsumptionState,
    pub start_delta_ms: u64,
    pub user_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct JoinContext {
    pub process_boot_id: String,
    pub actor_user_id: String,
    pub provenance: ProvenanceKind,
    pub host_sharing: HostSharingMode,
    pub process_role: ProcessRoleHint,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JoinResult {
    Matched {
        session_id: String,
        key_kind: CorrelationKeyKind,
        grade: EvidenceGrade,
        actor_kind: SessionActorKind,
        tie_break_reason: String,
    },
    Ambiguous {
        candidate_ids: Vec<String>,
        grade: EvidenceGrade,
        actor_kind: SessionActorKind,
    },
    Unmatched {
        grade: EvidenceGrade,
        actor_kind: SessionActorKind,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AttributionRecord {
    pub session_id: Option<String>,
    pub key_kind: Option<CorrelationKeyKind>,
    pub provenance: ProvenanceKind,
    pub grade: EvidenceGrade,
    pub actor_kind: SessionActorKind,
    pub superseded_previous: Option<String>,
    pub attribution_late: bool,
}

impl EvidenceGrade {
    #[must_use]
    pub const fn as_u8(self) -> u8 {
        self as u8
    }

    #[must_use]
    pub const fn to_approval_grade(self) -> ApprovalGrade {
        match self {
            Self::Grade0 => ApprovalGrade::G0,
            Self::Grade1 => ApprovalGrade::G1,
            Self::Grade2 => ApprovalGrade::G2,
            Self::Grade3 | Self::Grade4 => ApprovalGrade::G3,
        }
    }
}

impl From<SessionActorKind> for ActorKind {
    fn from(value: SessionActorKind) -> Self {
        match value {
            SessionActorKind::Agent => Self::Agent,
            SessionActorKind::Human => Self::Human,
            SessionActorKind::System => Self::System,
            SessionActorKind::Undetermined => Self::Undetermined,
        }
    }
}

impl CorrelationKeyKind {
    const fn priority_tier(self, k4_strength: K4MatchStrength) -> u8 {
        match (self, k4_strength) {
            (Self::K4ProcessLineage, K4MatchStrength::ExactPidStartTime) => 6,
            (Self::K1WrapperEnv, _) | (Self::K2SocketToken, _) => 5,
            (Self::K4ProcessLineage, K4MatchStrength::PatternOnly) => 4,
            (Self::K5CgroupKey, _) => 3,
            (Self::K3HookMetadata, _) => 2,
            (Self::K6HeuristicFallback, _) => 1,
        }
    }
}

#[must_use]
pub fn grade_for_evidence(
    provenance: ProvenanceKind,
    key_kind: CorrelationKeyKind,
    k4_strength: K4MatchStrength,
    unambiguous: bool,
) -> EvidenceGrade {
    if !unambiguous
        || matches!(provenance, ProvenanceKind::Reported)
        || key_kind == CorrelationKeyKind::K6HeuristicFallback
    {
        return EvidenceGrade::Grade0;
    }
    let ceiling = match provenance {
        ProvenanceKind::ObservedKernel | ProvenanceKind::Mediated => EvidenceGrade::Grade4,
        ProvenanceKind::ObservedUser => EvidenceGrade::Grade2,
        ProvenanceKind::Claimed => EvidenceGrade::Grade1,
        ProvenanceKind::Reported => EvidenceGrade::Grade0,
    };
    let key_grade = match (key_kind, k4_strength) {
        (CorrelationKeyKind::K1WrapperEnv, _)
        | (CorrelationKeyKind::K2SocketToken, _)
        | (CorrelationKeyKind::K4ProcessLineage, K4MatchStrength::ExactPidStartTime) => {
            EvidenceGrade::Grade4
        }
        (CorrelationKeyKind::K4ProcessLineage, K4MatchStrength::PatternOnly)
        | (CorrelationKeyKind::K5CgroupKey, _) => EvidenceGrade::Grade3,
        (CorrelationKeyKind::K3HookMetadata, _) => EvidenceGrade::Grade2,
        (CorrelationKeyKind::K6HeuristicFallback, _) => EvidenceGrade::Grade0,
    };
    if ceiling <= key_grade {
        ceiling
    } else {
        key_grade
    }
}

#[must_use]
pub fn satisfies_unless_floor(
    grade: EvidenceGrade,
    provenance: ProvenanceKind,
    min_grade: EvidenceGrade,
) -> bool {
    if grade < min_grade {
        return false;
    }
    if min_grade >= EvidenceGrade::Grade2
        && !matches!(
            provenance,
            ProvenanceKind::ObservedKernel | ProvenanceKind::Mediated
        )
    {
        return false;
    }
    true
}

#[must_use]
pub fn resolve_correlation_join(candidates: &[JoinCandidate], ctx: &JoinContext) -> JoinResult {
    if ctx.process_role == ProcessRoleHint::HostDaemon {
        return JoinResult::Unmatched {
            grade: EvidenceGrade::Grade3,
            actor_kind: SessionActorKind::System,
        };
    }

    if ctx.process_boot_id.trim().is_empty() {
        return JoinResult::Unmatched {
            grade: EvidenceGrade::Grade0,
            actor_kind: SessionActorKind::Undetermined,
        };
    }

    let mut eligible: Vec<&JoinCandidate> = candidates
        .iter()
        .filter(|c| !c.session_id.trim().is_empty() && !c.boot_id.trim().is_empty())
        .filter(|c| c.boot_id == ctx.process_boot_id)
        .filter(|c| {
            c.key_kind != CorrelationKeyKind::K3HookMetadata || c.user_id == ctx.actor_user_id
        })
        .collect();

    if eligible.is_empty() {
        let actor_kind = match ctx.host_sharing {
            HostSharingMode::SharedHostProcess => SessionActorKind::Human,
            HostSharingMode::IsolatedAgentTree => SessionActorKind::Undetermined,
        };
        return JoinResult::Unmatched {
            grade: EvidenceGrade::Grade0,
            actor_kind,
        };
    }

    eligible.sort_by(|a, b| compare_candidates(a, b));
    let Some(best) = eligible.first().copied() else {
        return JoinResult::Unmatched {
            grade: EvidenceGrade::Grade0,
            actor_kind: SessionActorKind::Undetermined,
        };
    };

    let tied: Vec<String> = eligible
        .iter()
        .filter(|c| same_rank(best, c) && c.session_id != best.session_id)
        .map(|c| c.session_id.clone())
        .collect();

    if !tied.is_empty() {
        let mut all_ids = vec![best.session_id.clone()];
        all_ids.extend(tied);
        all_ids.sort();
        all_ids.dedup();
        return JoinResult::Ambiguous {
            candidate_ids: all_ids,
            grade: EvidenceGrade::Grade0,
            actor_kind: SessionActorKind::Undetermined,
        };
    }

    if ctx.host_sharing == HostSharingMode::SharedHostProcess
        && matches!(
            best.key_kind,
            CorrelationKeyKind::K3HookMetadata | CorrelationKeyKind::K6HeuristicFallback
        )
    {
        return JoinResult::Unmatched {
            grade: EvidenceGrade::Grade0,
            actor_kind: SessionActorKind::Human,
        };
    }

    let grade = grade_for_evidence(ctx.provenance, best.key_kind, best.k4_strength, true);
    let actor_kind = match best.key_kind {
        CorrelationKeyKind::K6HeuristicFallback => SessionActorKind::Undetermined,
        _ => SessionActorKind::Agent,
    };
    JoinResult::Matched {
        session_id: best.session_id.clone(),
        key_kind: best.key_kind,
        grade,
        actor_kind,
        tie_break_reason: format!(
            "tier={} consumption={:?} delta_ms={}",
            best.key_kind.priority_tier(best.k4_strength),
            best.consumption,
            best.start_delta_ms
        ),
    }
}

#[must_use]
pub fn supersede_attribution(
    prior: &AttributionRecord,
    late_outcome: &JoinResult,
    late_provenance: ProvenanceKind,
) -> AttributionRecord {
    match late_outcome {
        JoinResult::Matched {
            session_id,
            key_kind,
            grade,
            actor_kind,
            ..
        } if *grade > prior.grade || (*grade == prior.grade && prior.session_id.is_none()) => {
            AttributionRecord {
                session_id: Some(session_id.clone()),
                key_kind: Some(*key_kind),
                provenance: late_provenance,
                grade: *grade,
                actor_kind: *actor_kind,
                superseded_previous: prior.session_id.clone(),
                attribution_late: true,
            }
        }
        _ => prior.clone(),
    }
}

fn compare_candidates(a: &JoinCandidate, b: &JoinCandidate) -> std::cmp::Ordering {
    let tier_cmp = b
        .key_kind
        .priority_tier(b.k4_strength)
        .cmp(&a.key_kind.priority_tier(a.k4_strength));
    if tier_cmp != std::cmp::Ordering::Equal {
        return tier_cmp;
    }
    let cons_cmp = consumption_rank(a.consumption).cmp(&consumption_rank(b.consumption));
    if cons_cmp != std::cmp::Ordering::Equal {
        return cons_cmp;
    }
    a.start_delta_ms.cmp(&b.start_delta_ms)
}

fn same_rank(a: &JoinCandidate, b: &JoinCandidate) -> bool {
    compare_candidates(a, b) == std::cmp::Ordering::Equal
}

const fn consumption_rank(c: JoinConsumptionState) -> u8 {
    match c {
        JoinConsumptionState::Unconsumed => 0,
        JoinConsumptionState::ConsumedByOtherRoot => 1,
    }
}
