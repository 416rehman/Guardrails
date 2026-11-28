// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Doc 06 section 5 deterministic 6-step K1-K6+W join, tie-breaking,
//! grant ambiguity guard, and unbound effect classification (`docs/design/06`).

use std::collections::BTreeSet;
use std::sync::OnceLock;

use grdr_model::ActionClass;
use grdr_schema::limits::load_embedded_limits;
use serde::{Deserialize, Serialize};

use super::hops::BasisValue;
use super::join::EvidenceGrade;

const FALLBACK_NO_POST_WINDOW_MS: u64 = 600_000;
const FALLBACK_PRE_DECISION_TOLERANCE_MS: u64 = 50;
const FALLBACK_POST_EVENT_TAIL_MS: u64 = 2_000;

static JOIN_BOUNDS: OnceLock<JoinTimeBounds> = OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct JoinTimeBounds {
    pub default_no_post_window_ms: u64,
    pub pre_decision_tolerance_ms: u64,
    pub post_event_tail_ms: u64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
struct TieBreakRank(u8, u8, u8, u8, u64);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct ProcessKey {
    pub boot_id: String,
    pub pid: u32,
    pub start_time_ns: u64,
    pub exec_generation: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum K4MatchKind {
    #[default]
    Exact,
    Pattern,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectationMultiplicity {
    #[default]
    SingleUse,
    MultiChildWrapper,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ExpectationConsumption {
    #[default]
    Open,
    Consumed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EffectOriginRole {
    AgentDirectChild,
    AgentInProcess,
    #[default]
    HostDescendant,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostExclusivity {
    #[default]
    SessionExclusive,
    SharedHost,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum UnboundEffectClass {
    Housekeeping,
    DeclaredService,
    HumanDirect,
    Undeclared,
    #[default]
    Undetermined,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolExpectation {
    pub session_id: String,
    pub tool_use_id: String,
    pub agent_process_key: ProcessKey,
    pub action_class: ActionClass,
    pub k4_cmd_hmac: Option<String>,
    pub k4_match_kind: K4MatchKind,
    pub k5_cwd_hmac: Option<String>,
    pub k6_targets: Vec<String>,
    pub grant_id: Option<String>,
    pub decision_time_ms: u64,
    pub post_event_ms: Option<u64>,
    pub multiplicity: ExpectationMultiplicity,
    pub state: ExpectationConsumption,
}

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct ObservedEffect {
    pub effect_id: String,
    pub process_key: Option<ProcessKey>,
    pub agent_process_key: Option<ProcessKey>,
    pub action_class: Option<ActionClass>,
    pub observed_at_ms: u64,
    pub k2_session_id: Option<String>,
    pub k3_tag_kernel: Option<(String, String)>,
    pub k3_tag_user: Option<(String, String)>,
    pub registered_stamp_session: Option<String>,
    pub k4_cmd_hmac: Option<String>,
    pub k5_cwd_hmac: Option<String>,
    pub k6_target: Option<String>,
    pub parent_bound_tool_call: Option<(String, String, EvidenceGrade)>,
    pub descendant_of_host_sessions: Vec<String>,
    pub role: EffectOriginRole,
    pub host_exclusivity: HostExclusivity,
    pub unbound_hint: Option<UnboundEffectClass>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "outcome", rename_all = "snake_case")]
pub enum EffectJoinOutcome {
    Bound {
        session_id: String,
        tool_use_id: Option<String>,
        basis: BasisValue,
        grade: EvidenceGrade,
        binding_ambiguous: bool,
        honored_grant_id: Option<String>,
        tag_conflict: bool,
    },
    Unbound {
        session_id: Option<String>,
        classification: UnboundEffectClass,
        candidate_sessions: Vec<String>,
    },
}

impl JoinTimeBounds {
    #[must_use]
    pub fn embedded() -> Self {
        *JOIN_BOUNDS.get_or_init(|| match load_embedded_limits() {
            Ok(limits) => Self {
                default_no_post_window_ms: limits
                    .broker
                    .circuit_breaker
                    .window_ms
                    .saturating_mul(2)
                    .max(FALLBACK_NO_POST_WINDOW_MS),
                pre_decision_tolerance_ms: u64::from(limits.endpoint.latency_ms.hook_linux_p99)
                    .max(1),
                post_event_tail_ms: u64::from(limits.endpoint.latency_ms.shim_hang_max).max(100),
            },
            Err(_) => Self {
                default_no_post_window_ms: FALLBACK_NO_POST_WINDOW_MS,
                pre_decision_tolerance_ms: FALLBACK_PRE_DECISION_TOLERANCE_MS,
                post_event_tail_ms: FALLBACK_POST_EVENT_TAIL_MS,
            },
        })
    }
}

impl ToolExpectation {
    #[must_use]
    pub fn contains_time(&self, observed_at_ms: u64) -> bool {
        let bounds = JoinTimeBounds::embedded();
        let start = self
            .decision_time_ms
            .saturating_sub(bounds.pre_decision_tolerance_ms);
        let end = match self.post_event_ms {
            Some(post) => post.saturating_add(bounds.post_event_tail_ms),
            None => self
                .decision_time_ms
                .saturating_add(bounds.default_no_post_window_ms),
        };
        observed_at_ms >= start && observed_at_ms <= end
    }
}

pub fn resolve_effect_join(
    effect: &ObservedEffect,
    expectations: &mut [ToolExpectation],
) -> EffectJoinOutcome {
    let resolved_session = effect
        .k2_session_id
        .clone()
        .or_else(|| effect.registered_stamp_session.clone())
        .or_else(|| effect.k3_tag_kernel.as_ref().map(|(sid, _)| sid.clone()));

    let tag_conflict = check_tag_conflict(
        resolved_session.as_deref(),
        effect
            .parent_bound_tool_call
            .as_ref()
            .map(|(s, _, _)| s.as_str()),
        effect
            .k3_tag_kernel
            .as_ref()
            .or(effect.k3_tag_user.as_ref()),
    );

    if let Some((parent_sid, parent_tc, parent_grade)) = &effect.parent_bound_tool_call
        && resolved_session
            .as_deref()
            .is_none_or(|s| s == parent_sid.as_str())
    {
        return EffectJoinOutcome::Bound {
            session_id: resolved_session.unwrap_or_else(|| parent_sid.clone()),
            tool_use_id: Some(parent_tc.clone()),
            basis: BasisValue::Lineage,
            grade: *parent_grade,
            binding_ambiguous: false,
            honored_grant_id: None,
            tag_conflict,
        };
    }

    if let Some((tag_sid, tag_tc)) = &effect.k3_tag_kernel
        && resolved_session
            .as_deref()
            .is_none_or(|s| s == tag_sid.as_str())
        && let Some(idx) = expectations.iter().position(|exp| {
            exp.state == ExpectationConsumption::Open
                && exp.session_id == *tag_sid
                && exp.tool_use_id == *tag_tc
                && exp.contains_time(effect.observed_at_ms)
                && effect.action_class.is_none_or(|ac| exp.action_class == ac)
                && effect
                    .agent_process_key
                    .as_ref()
                    .is_none_or(|apk| *apk == exp.agent_process_key)
        })
        && let Some(winner) = expectations.get_mut(idx)
    {
        if winner.multiplicity == ExpectationMultiplicity::SingleUse {
            winner.state = ExpectationConsumption::Consumed;
        }
        return EffectJoinOutcome::Bound {
            session_id: winner.session_id.clone(),
            tool_use_id: Some(winner.tool_use_id.clone()),
            basis: BasisValue::ExecTag,
            grade: EvidenceGrade::Grade3,
            binding_ambiguous: false,
            honored_grant_id: winner.grant_id.clone(),
            tag_conflict,
        };
    }

    if effect.role == EffectOriginRole::AgentDirectChild
        && let Some(ref eff_k4) = effect.k4_cmd_hmac
    {
        let matches = collect_matching_exec_indices(
            effect,
            expectations,
            eff_k4,
            resolved_session.as_deref(),
        );
        if is_cross_session_ambiguous(&matches, expectations, resolved_session.as_deref()) {
            return unbound_outcome(resolved_session, effect);
        }
        if let Some((winner_idx, ambiguous, shared_grant)) =
            pick_tie_broken_winner(&matches, effect, expectations)
        {
            let Some(winner) = expectations.get_mut(winner_idx) else {
                return unbound_outcome(resolved_session, effect);
            };
            if winner.multiplicity == ExpectationMultiplicity::SingleUse {
                winner.state = ExpectationConsumption::Consumed;
            }
            return EffectJoinOutcome::Bound {
                session_id: winner.session_id.clone(),
                tool_use_id: Some(winner.tool_use_id.clone()),
                basis: BasisValue::DeclaredMatched,
                grade: EvidenceGrade::Grade2,
                binding_ambiguous: ambiguous,
                honored_grant_id: shared_grant,
                tag_conflict,
            };
        }
    }

    if effect.role == EffectOriginRole::AgentInProcess
        && let Some(ref target) = effect.k6_target
    {
        let matches =
            collect_in_process_indices(effect, expectations, target, resolved_session.as_deref());
        if is_cross_session_ambiguous(&matches, expectations, resolved_session.as_deref()) {
            return unbound_outcome(resolved_session, effect);
        }
        if let Some((winner_idx, ambiguous, shared_grant)) =
            pick_tie_broken_winner(&matches, effect, expectations)
        {
            let Some(winner) = expectations.get_mut(winner_idx) else {
                return unbound_outcome(resolved_session, effect);
            };
            if winner.multiplicity == ExpectationMultiplicity::SingleUse {
                winner.state = ExpectationConsumption::Consumed;
            }
            return EffectJoinOutcome::Bound {
                session_id: winner.session_id.clone(),
                tool_use_id: Some(winner.tool_use_id.clone()),
                basis: BasisValue::DeclaredMatched,
                grade: EvidenceGrade::Grade2,
                binding_ambiguous: ambiguous,
                honored_grant_id: shared_grant,
                tag_conflict,
            };
        }
    }

    unbound_outcome(resolved_session, effect)
}

fn check_tag_conflict(
    resolved_sid: Option<&str>,
    inherited_sid: Option<&str>,
    tag: Option<&(String, String)>,
) -> bool {
    if let (Some(rsid), Some(isid)) = (resolved_sid, inherited_sid)
        && rsid != isid
    {
        return true;
    }
    let Some((tag_sid, _)) = tag else {
        return false;
    };
    if let Some(sid) = resolved_sid
        && sid != tag_sid
    {
        return true;
    }
    if let Some(inh) = inherited_sid
        && inh != tag_sid
    {
        return true;
    }
    false
}

fn collect_matching_exec_indices(
    effect: &ObservedEffect,
    expectations: &[ToolExpectation],
    eff_k4: &str,
    resolved_sid: Option<&str>,
) -> Vec<usize> {
    if resolved_sid.is_none() && effect.agent_process_key.is_none() {
        return Vec::new();
    }
    let want_action = effect.action_class.unwrap_or(ActionClass::Exec);
    let mut out = Vec::new();
    for (idx, exp) in expectations.iter().enumerate() {
        if exp.state != ExpectationConsumption::Open
            || exp.action_class != want_action
            || !exp.contains_time(effect.observed_at_ms)
        {
            continue;
        }
        if let Some(sid) = resolved_sid
            && exp.session_id != sid
        {
            continue;
        }
        if let Some(ref apk) = effect.agent_process_key
            && apk != &exp.agent_process_key
        {
            continue;
        }
        if let Some(ref pkey) = effect.process_key
            && (pkey.boot_id != exp.agent_process_key.boot_id
                || pkey.start_time_ns < exp.agent_process_key.start_time_ns)
        {
            continue;
        }
        if exp.k4_cmd_hmac.as_deref() == Some(eff_k4) {
            out.push(idx);
        }
    }
    out
}

fn collect_in_process_indices(
    effect: &ObservedEffect,
    expectations: &[ToolExpectation],
    target: &str,
    resolved_sid: Option<&str>,
) -> Vec<usize> {
    if resolved_sid.is_none() && effect.agent_process_key.is_none() && effect.process_key.is_none()
    {
        return Vec::new();
    }
    let mut out = Vec::new();
    for (idx, exp) in expectations.iter().enumerate() {
        if exp.state != ExpectationConsumption::Open || !exp.contains_time(effect.observed_at_ms) {
            continue;
        }
        if effect.action_class.is_some_and(|ac| exp.action_class != ac) {
            continue;
        }
        if let Some(sid) = resolved_sid
            && exp.session_id != sid
        {
            continue;
        }
        if let Some(ref apk) = effect.agent_process_key
            && apk != &exp.agent_process_key
        {
            continue;
        }
        if let Some(ref pkey) = effect.process_key
            && pkey != &exp.agent_process_key
        {
            continue;
        }
        if exp.k6_targets.iter().any(|t| t == target) {
            out.push(idx);
        }
    }
    out
}

fn is_cross_session_ambiguous(
    indices: &[usize],
    expectations: &[ToolExpectation],
    resolved_sid: Option<&str>,
) -> bool {
    if resolved_sid.is_some() || indices.len() <= 1 {
        return false;
    }
    let sessions: BTreeSet<&str> = indices
        .iter()
        .filter_map(|&i| expectations.get(i).map(|e| e.session_id.as_str()))
        .collect();
    sessions.len() > 1
}

fn pick_tie_broken_winner(
    indices: &[usize],
    effect: &ObservedEffect,
    expectations: &[ToolExpectation],
) -> Option<(usize, bool, Option<String>)> {
    if indices.is_empty() {
        return None;
    }
    let rank_tuple = |exp: &ToolExpectation| -> TieBreakRank {
        let exact_k4 = u8::from(exp.k4_match_kind == K4MatchKind::Exact);
        let k5_eq = u8::from(effect.k5_cwd_hmac.is_some() && effect.k5_cwd_hmac == exp.k5_cwd_hmac);
        let user_k3 = u8::from(
            effect
                .k3_tag_user
                .as_ref()
                .is_some_and(|(s, tc)| s == &exp.session_id && tc == &exp.tool_use_id),
        );
        let unconsumed = u8::from(exp.state == ExpectationConsumption::Open);
        TieBreakRank(
            exact_k4,
            k5_eq,
            user_k3,
            unconsumed,
            u64::MAX.saturating_sub(exp.decision_time_ms),
        )
    };

    let mut ranked: Vec<(usize, TieBreakRank)> = indices
        .iter()
        .filter_map(|&idx| expectations.get(idx).map(|e| (idx, rank_tuple(e))))
        .collect();
    ranked.sort_by_key(|a| std::cmp::Reverse(a.1));
    let (best_idx, best_rank) = *ranked.first()?;
    let tied: Vec<usize> = ranked
        .iter()
        .filter(|(_, r)| *r == best_rank)
        .map(|(idx, _)| *idx)
        .collect();
    let ambiguous = tied.len() > 1;
    let first_grant = expectations
        .get(best_idx)
        .and_then(|e| e.grant_id.as_ref())
        .cloned();
    let shared_grant = if !ambiguous {
        first_grant
    } else {
        first_grant.filter(|g| {
            tied.iter()
                .all(|&i| expectations.get(i).and_then(|e| e.grant_id.as_ref()) == Some(g))
        })
    };
    Some((best_idx, ambiguous, shared_grant))
}

fn unbound_outcome(resolved_session: Option<String>, effect: &ObservedEffect) -> EffectJoinOutcome {
    let classification = match effect.unbound_hint {
        Some(
            h @ (UnboundEffectClass::Housekeeping
            | UnboundEffectClass::DeclaredService
            | UnboundEffectClass::HumanDirect),
        ) => h,
        _ => match effect.host_exclusivity {
            HostExclusivity::SharedHost => UnboundEffectClass::Undetermined,
            HostExclusivity::SessionExclusive => UnboundEffectClass::Undeclared,
        },
    };
    let candidates = effect
        .descendant_of_host_sessions
        .iter()
        .take(3)
        .cloned()
        .collect();
    EffectJoinOutcome::Unbound {
        session_id: resolved_session,
        classification,
        candidate_sessions: candidates,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pkey(pid: u32, gen_num: u32) -> ProcessKey {
        ProcessKey {
            boot_id: "b1".into(),
            pid,
            start_time_ns: 100,
            exec_generation: gen_num,
        }
    }

    #[test]
    fn k1_k6_tie_break_grant_ambiguity_and_tag_conflict_work() {
        let agent_pk = pkey(42, 1);
        let mut exps = vec![
            ToolExpectation {
                session_id: "s1".into(),
                tool_use_id: "tc-1".into(),
                agent_process_key: agent_pk.clone(),
                action_class: ActionClass::Exec,
                k4_cmd_hmac: Some("h1".into()),
                k4_match_kind: K4MatchKind::Exact,
                k5_cwd_hmac: Some("cwd-a".into()),
                k6_targets: vec![],
                grant_id: Some("g-shared".into()),
                decision_time_ms: 1_000,
                post_event_ms: None,
                multiplicity: ExpectationMultiplicity::SingleUse,
                state: ExpectationConsumption::Open,
            },
            ToolExpectation {
                session_id: "s1".into(),
                tool_use_id: "tc-2".into(),
                agent_process_key: agent_pk.clone(),
                action_class: ActionClass::Exec,
                k4_cmd_hmac: Some("h1".into()),
                k4_match_kind: K4MatchKind::Exact,
                k5_cwd_hmac: Some("cwd-a".into()),
                k6_targets: vec![],
                grant_id: Some("g-other".into()),
                decision_time_ms: 1_000,
                post_event_ms: None,
                multiplicity: ExpectationMultiplicity::SingleUse,
                state: ExpectationConsumption::Open,
            },
        ];
        let eff = ObservedEffect {
            effect_id: "ef-1".into(),
            process_key: Some(pkey(99, 1)),
            agent_process_key: Some(agent_pk),
            action_class: Some(ActionClass::Exec),
            observed_at_ms: 1_100,
            k2_session_id: Some("s1".into()),
            k3_tag_kernel: Some(("s-evil".into(), "tc-evil".into())),
            k4_cmd_hmac: Some("h1".into()),
            k5_cwd_hmac: Some("cwd-a".into()),
            role: EffectOriginRole::AgentDirectChild,
            ..ObservedEffect::default()
        };
        match resolve_effect_join(&eff, &mut exps) {
            EffectJoinOutcome::Bound {
                binding_ambiguous,
                honored_grant_id,
                tag_conflict,
                ..
            } => {
                assert!(binding_ambiguous);
                assert!(honored_grant_id.is_none());
                assert!(tag_conflict);
            }
            other => panic!("expected Bound, got {other:?}"),
        }
    }

    #[test]
    fn single_use_replay_in_process_and_cross_session_unbound_enforced() {
        let pk = pkey(77, 2);
        let mut exps = vec![ToolExpectation {
            session_id: "s1".into(),
            tool_use_id: "tc-inproc".into(),
            agent_process_key: pk.clone(),
            action_class: ActionClass::NetRequest,
            k4_cmd_hmac: None,
            k4_match_kind: K4MatchKind::Exact,
            k5_cwd_hmac: None,
            k6_targets: vec!["api.example.com".into()],
            grant_id: Some("g-inproc".into()),
            decision_time_ms: 2_000,
            post_event_ms: None,
            multiplicity: ExpectationMultiplicity::SingleUse,
            state: ExpectationConsumption::Open,
        }];
        let eff = ObservedEffect {
            effect_id: "ef-ip-1".into(),
            process_key: Some(pk.clone()),
            action_class: Some(ActionClass::NetRequest),
            observed_at_ms: 2_050,
            k2_session_id: Some("s1".into()),
            k6_target: Some("api.example.com".into()),
            role: EffectOriginRole::AgentInProcess,
            ..ObservedEffect::default()
        };
        assert!(matches!(
            resolve_effect_join(&eff, &mut exps),
            EffectJoinOutcome::Bound { .. }
        ));
        // Second call must NOT replay Consumed SingleUse expectation.
        assert!(matches!(
            resolve_effect_join(&eff, &mut exps),
            EffectJoinOutcome::Unbound { .. }
        ));

        // Reset to Open, mismatch exec_generation -> refused.
        exps[0].state = ExpectationConsumption::Open;
        let wrong_gen = ObservedEffect {
            process_key: Some(pkey(77, 3)),
            ..eff.clone()
        };
        assert!(matches!(
            resolve_effect_join(&wrong_gen, &mut exps),
            EffectJoinOutcome::Unbound { .. }
        ));

        // Unbound when resolved_session is None and no process key binds the session.
        let no_sid = ObservedEffect {
            process_key: None,
            agent_process_key: None,
            k2_session_id: None,
            ..eff
        };
        assert!(matches!(
            resolve_effect_join(&no_sid, &mut exps),
            EffectJoinOutcome::Unbound { .. }
        ));

        // Parent session mismatch triggers tag_conflict without blind parent binding.
        let parent_mismatch = ObservedEffect {
            effect_id: "ef-pm".into(),
            observed_at_ms: 2_050,
            k2_session_id: Some("s1".into()),
            parent_bound_tool_call: Some((
                "s-other".into(),
                "tc-other".into(),
                EvidenceGrade::Grade3,
            )),
            ..ObservedEffect::default()
        };
        assert!(matches!(
            resolve_effect_join(&parent_mismatch, &mut exps),
            EffectJoinOutcome::Unbound { .. }
        ));
    }
}
