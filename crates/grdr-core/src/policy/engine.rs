// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Sans-IO Policy `Engine::{load, step, interest, snapshot, restore}` (`docs/design/03`, `D-05`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::eval::CacheScope;
use grdr_model::{ExecutedVerb, Grant, GrantScope, KillSwitchState, Mode, PolicyPack, Verdict};
use jiff::Timestamp;

use super::PolicyError;
use super::caps::Entropy;
use super::compiler::{CompileOptions, CompiledPolicyBundle, compile_packs_with_options};
use super::engine_bundle::{
    compile_verified_bundle, profile_layer, verify_grant_signature_for_bundle,
};
use super::engine_snapshot::{compute_snapshot_mac, parse_note_epoch, validate_snapshot_envelope};
use super::engine_types::{
    EngineInput, EngineOutput, EngineSnapshot, InterestSet, SessionSnapshotEntry, VerifiedBundle,
};
use super::layers::EffectiveLayerRule;
use crate::session::SessionRuleState;

pub(crate) const APPROVAL_STREAK_LIMIT: u32 = 3;
pub(crate) const MAX_ACTIVE_GRANTS: usize = 1024;
pub(crate) const MAX_TRACKED_SESSIONS: usize = 4096;
pub(crate) const MAX_SPENT_TOMBSTONES: usize = 4096;

#[derive(Debug, Clone)]
pub(crate) struct CachedVerdictEntry {
    pub(crate) scope: CacheScope,
    pub(crate) expires_at: Timestamp,
    pub(crate) last_used_seq: u64,
    pub(crate) verdict: Verdict,
    pub(crate) would_be: Option<Verdict>,
    pub(crate) rule_id: Option<String>,
    pub(crate) pack_id: Option<String>,
    pub(crate) mode_applied: Option<Mode>,
    pub(crate) reason: String,
    pub(crate) next_step: String,
    pub(crate) executed_verb: ExecutedVerb,
}

#[derive(Debug)]
pub struct Engine {
    pub(crate) bundle: VerifiedBundle,
    pub(crate) effective_packs: Vec<PolicyPack>,
    pub(crate) compiled: CompiledPolicyBundle,
    pub(crate) layer_overrides: BTreeMap<String, EffectiveLayerRule>,
    pub(crate) interest: InterestSet,
    pub(crate) snapshot_key: [u8; 32],
    pub(crate) kill_switch: KillSwitchState,
    pub(crate) grants: Vec<Grant>,
    pub(crate) grant_label_epochs: BTreeMap<String, u64>,
    pub(crate) session_label_epochs: BTreeMap<String, u64>,
    pub(crate) session_last_taint_at: BTreeMap<String, Timestamp>,
    pub(crate) spent_once_grants: BTreeMap<String, Timestamp>,
    pub(crate) sessions: BTreeMap<String, SessionRuleState>,
    pub(crate) session_lru_seq: BTreeMap<String, u64>,
    pub(crate) lru_counter: u64,
    pub(crate) cache_lru_counter: u64,
    pub(crate) approval_streaks: BTreeMap<String, u32>,
    pub(crate) frozen_sessions: BTreeSet<String>,
    pub(crate) session_state_seq: u64,
    pub(crate) verdict_cache: BTreeMap<String, CachedVerdictEntry>,
}

impl Engine {
    pub fn load(
        bundle: VerifiedBundle,
        snapshot_key: [u8; 32],
        now: Timestamp,
    ) -> Result<Self, PolicyError> {
        if snapshot_key == [0u8; 32] {
            return Err(PolicyError::ValidationFailed {
                rule_id: bundle.bundle_id.clone(),
                detail: "snapshot_key must not be all zeros".into(),
            });
        }
        let (effective_packs, compiled, interest, layer_overrides) =
            compile_verified_bundle(&bundle, now)?;
        Ok(Self {
            bundle,
            effective_packs,
            compiled,
            layer_overrides,
            interest,
            snapshot_key,
            kill_switch: KillSwitchState::Inactive,
            grants: Vec::new(),
            grant_label_epochs: BTreeMap::new(),
            session_label_epochs: BTreeMap::new(),
            session_last_taint_at: BTreeMap::new(),
            spent_once_grants: BTreeMap::new(),
            sessions: BTreeMap::new(),
            session_lru_seq: BTreeMap::new(),
            lru_counter: 0,
            cache_lru_counter: 0,
            approval_streaks: BTreeMap::new(),
            frozen_sessions: BTreeSet::new(),
            session_state_seq: 0,
            verdict_cache: BTreeMap::new(),
        })
    }

    pub fn interest(&self) -> &InterestSet {
        &self.interest
    }

    pub fn kill_switch(&self) -> &KillSwitchState {
        &self.kill_switch
    }

    pub fn effective_hash(&self) -> &str {
        &self.compiled.effective_hash
    }

    pub fn session_state_seq(&self) -> u64 {
        self.session_state_seq
    }

    pub fn step(
        &mut self,
        input: EngineInput,
        _entropy: &mut dyn Entropy,
        now: Timestamp,
    ) -> Result<EngineOutput, PolicyError> {
        match input {
            EngineInput::ReloadBundle { bundle } => {
                let (effective_packs, compiled, interest, layer_overrides) =
                    compile_verified_bundle(&bundle, now)?;
                self.bundle = bundle;
                self.effective_packs = effective_packs;
                self.compiled = compiled;
                self.layer_overrides = layer_overrides;
                self.interest = interest;
                let keys = &self.bundle.trusted_keys;
                let active = &self.compiled.active_rules;
                self.grants.retain(|g| {
                    verify_grant_signature_for_bundle(g, keys).is_ok()
                        && active
                            .iter()
                            .any(|m| m.rule_id == g.rule_id && !m.is_final && m.mode >= Mode::Ask)
                });
                let live_ids: BTreeSet<&str> =
                    self.grants.iter().map(|g| g.grant_id.as_str()).collect();
                self.grant_label_epochs
                    .retain(|gid, _| live_ids.contains(gid.as_str()));
                self.verdict_cache.clear();
                self.session_state_seq = self.session_state_seq.saturating_add(1);
                Ok(EngineOutput::BundleLoaded {
                    bundle_hash: self.bundle.bundle_hash.clone(),
                    effective_hash: self.compiled.effective_hash.clone(),
                    rule_count: self.compiled.active_rules.len(),
                    session_state_seq: self.session_state_seq,
                })
            }
            EngineInput::UpdateKillSwitch { kill_switch } => {
                self.kill_switch = kill_switch;
                self.verdict_cache.clear();
                self.session_state_seq = self.session_state_seq.saturating_add(1);
                Ok(EngineOutput::StateAdvanced {
                    session_state_seq: self.session_state_seq,
                })
            }
            EngineInput::Tick { now: tick_now } => {
                self.grants.retain(|g| g.is_active(tick_now));
                let live_ids: BTreeSet<&str> =
                    self.grants.iter().map(|g| g.grant_id.as_str()).collect();
                self.grant_label_epochs
                    .retain(|gid, _| live_ids.contains(gid.as_str()));
                self.spent_once_grants.retain(|_, exp| *exp > tick_now);
                self.verdict_cache.retain(|_, v| v.expires_at > tick_now);
                Ok(EngineOutput::StateAdvanced {
                    session_state_seq: self.session_state_seq,
                })
            }
            EngineInput::IssueGrant { grant } => self.step_issue_grant(grant, now),
            EngineInput::ApprovalOutcome {
                session_id,
                approved,
                at,
            } => self.step_approval_outcome(session_id, approved, at),
            EngineInput::Evaluate {
                attempt,
                options,
                host_deadline_ms,
            } => Ok(self.step_evaluate(attempt, *options, host_deadline_ms, _entropy, now)),
        }
    }

    pub fn snapshot(&self) -> EngineSnapshot {
        let sessions = self
            .sessions
            .values()
            .map(|s| SessionSnapshotEntry {
                session_id: s.session_id.clone(),
                labels: s.labels.clone(),
                denial_count: s.denial_count,
                step_up_count: s.step_up_count,
                event_seq: s.event_seq,
                approval_streak: self
                    .approval_streaks
                    .get(&s.session_id)
                    .copied()
                    .unwrap_or(0),
            })
            .collect();
        let mut snap = EngineSnapshot {
            bundle_hash: self.bundle.bundle_hash.clone(),
            effective_hash: self.compiled.effective_hash.clone(),
            session_state_seq: self.session_state_seq,
            kill_switch: self.kill_switch.clone(),
            grants: self.grants.clone(),
            grant_label_epochs: self.grant_label_epochs.clone(),
            session_label_epochs: self.session_label_epochs.clone(),
            session_last_taint_at: self.session_last_taint_at.clone(),
            spent_once_grants: self.spent_once_grants.clone(),
            approval_streaks: self.approval_streaks.clone(),
            frozen_sessions: self.frozen_sessions.clone(),
            sessions,
            snapshot_mac: String::new(),
        };
        snap.snapshot_mac = compute_snapshot_mac(&snap, &self.snapshot_key);
        snap
    }

    pub fn restore(
        bundle: VerifiedBundle,
        snapshot: EngineSnapshot,
        snapshot_key: &[u8; 32],
        now: Timestamp,
    ) -> Result<Self, PolicyError> {
        validate_snapshot_envelope(
            &bundle,
            &snapshot,
            snapshot_key,
            MAX_ACTIVE_GRANTS,
            MAX_TRACKED_SESSIONS,
            MAX_SPENT_TOMBSTONES,
        )?;
        let mut engine = Self::load(bundle, *snapshot_key, now)?;
        if engine.compiled.effective_hash != snapshot.effective_hash {
            return Err(PolicyError::SnapshotCorrupt {
                detail: format!(
                    "effective policy hash mismatch: expected {}, got {}",
                    engine.compiled.effective_hash, snapshot.effective_hash
                ),
            });
        }
        engine.kill_switch = snapshot.kill_switch;
        engine.grants = snapshot
            .grants
            .into_iter()
            .filter(|g| !snapshot.spent_once_grants.contains_key(&g.grant_id) && g.is_active(now))
            .collect();
        let live_gids: BTreeSet<&str> = engine.grants.iter().map(|g| g.grant_id.as_str()).collect();
        engine.grant_label_epochs = snapshot
            .grant_label_epochs
            .into_iter()
            .filter(|(gid, _)| live_gids.contains(gid.as_str()))
            .collect();
        engine.session_label_epochs = snapshot.session_label_epochs;
        engine.session_last_taint_at = snapshot.session_last_taint_at;
        engine.spent_once_grants = snapshot
            .spent_once_grants
            .into_iter()
            .filter(|(_, exp)| *exp > now)
            .collect();
        engine.approval_streaks = snapshot.approval_streaks;
        engine.frozen_sessions = snapshot.frozen_sessions;
        engine.session_state_seq = snapshot.session_state_seq;
        for (idx, entry) in snapshot.sessions.into_iter().enumerate() {
            engine.session_lru_seq.insert(
                entry.session_id.clone(),
                u64::try_from(idx).unwrap_or(u64::MAX),
            );
            engine.lru_counter = engine
                .lru_counter
                .max(u64::try_from(idx.saturating_add(1)).unwrap_or(u64::MAX));
            engine.sessions.insert(
                entry.session_id.clone(),
                SessionRuleState {
                    session_id: entry.session_id,
                    labels: entry.labels,
                    denial_count: entry.denial_count,
                    step_up_count: entry.step_up_count,
                    event_seq: entry.event_seq,
                },
            );
        }
        Ok(engine)
    }

    pub(crate) fn compile_for_state(
        &self,
        session_id: &str,
        device_id: &str,
        now: Timestamp,
    ) -> Result<CompiledPolicyBundle, PolicyError> {
        compile_packs_with_options(
            &self.effective_packs,
            &self.kill_switch,
            session_id,
            device_id,
            &CompileOptions {
                identity_mode: self.bundle.identity_mode,
                pack_layer: profile_layer(self.bundle.host_profile),
                layer_overrides: self.layer_overrides.clone(),
            },
            now,
        )
    }

    pub(crate) fn step_issue_grant(
        &mut self,
        grant: Grant,
        now: Timestamp,
    ) -> Result<EngineOutput, PolicyError> {
        if self.spent_once_grants.contains_key(&grant.grant_id) {
            return Err(PolicyError::ValidationFailed {
                rule_id: grant.rule_id,
                detail: format!("spent Once grant `{}` cannot be replayed", grant.grant_id),
            });
        }
        if self.grants.iter().any(|g| g.grant_id == grant.grant_id) {
            return Err(PolicyError::ValidationFailed {
                rule_id: grant.rule_id,
                detail: format!("duplicate grant id `{}`", grant.grant_id),
            });
        }
        verify_grant_signature_for_bundle(&grant, &self.bundle.trusted_keys).map_err(|_| {
            PolicyError::ValidationFailed {
                rule_id: grant.rule_id.clone(),
                detail: "grant cryptographic signature invalid or key untrusted".into(),
            }
        })?;
        if grant.scope == GrantScope::Once {
            self.spent_once_grants.retain(|_, exp| *exp > now);
            if self.spent_once_grants.len() >= MAX_SPENT_TOMBSTONES {
                return Err(PolicyError::ValidationFailed {
                    rule_id: grant.rule_id,
                    detail: "spent Once grant tombstone table is saturated".into(),
                });
            }
        }
        if grant.scope == GrantScope::OneHour && grant.expires_at.is_none() {
            return Err(PolicyError::ValidationFailed {
                rule_id: grant.rule_id,
                detail: "OneHour grant must specify expires_at".into(),
            });
        }
        if !grant.is_active(now) || grant.granted_at > now {
            return Err(PolicyError::ValidationFailed {
                rule_id: grant.rule_id,
                detail: "expired, exhausted, or future-dated grant rejected".into(),
            });
        }
        let epoch = self
            .session_label_epochs
            .get(&grant.session_id)
            .copied()
            .unwrap_or(0);
        let note_epoch = parse_note_epoch(&grant.note)?;
        if let Some(ne) = note_epoch
            && ne != epoch
        {
            return Err(PolicyError::ValidationFailed {
                rule_id: grant.rule_id,
                detail: format!("grant note epoch {ne} != current epoch {epoch}"),
            });
        }
        if let Some(&last_taint) = self.session_last_taint_at.get(&grant.session_id)
            && (grant.granted_at < last_taint
                || (grant.granted_at == last_taint && !(note_epoch == Some(epoch) && epoch > 0)))
        {
            return Err(PolicyError::ValidationFailed {
                rule_id: grant.rule_id,
                detail: "grant issued before or without post-taint epoch is stale".into(),
            });
        }
        let grant_id = grant.grant_id.clone();
        if self.grants.len() >= MAX_ACTIVE_GRANTS {
            self.grants.retain(|g| g.is_active(now));
            if self.grants.len() >= MAX_ACTIVE_GRANTS {
                self.grants.remove(0);
            }
            let live_gids: BTreeSet<&str> =
                self.grants.iter().map(|g| g.grant_id.as_str()).collect();
            self.grant_label_epochs
                .retain(|gid, _| live_gids.contains(gid.as_str()));
        }
        self.grant_label_epochs.insert(grant_id.clone(), epoch);
        self.grants.push(grant);
        self.verdict_cache.clear();
        self.session_state_seq = self.session_state_seq.saturating_add(1);
        Ok(EngineOutput::GrantRecorded {
            grant_id,
            session_state_seq: self.session_state_seq,
        })
    }
}
