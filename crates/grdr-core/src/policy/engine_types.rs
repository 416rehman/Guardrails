// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Sans-IO Policy `Engine` data types, bundle configuration, inputs, outputs, and cache keys.

use std::collections::{BTreeMap, BTreeSet};

use grdr_crypto::domain_sha256_hex;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, BoundaryObserver, DecisionReceipt, ExecutedVerb,
    Grant, IdentityMode, Incident, InstallProfile, KillSwitchState, PolicyPack, SessionLabel,
    TrustedKeyInfo,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use super::PolicyError;
use super::caps::Obligation;
use super::engine_bundle::{compute_bundle_hash_parts, verify_bundle_contents};
use super::layers::PolicyLayerSpec;
use super::request::{ActorKind, CredUseMode, RequestBuildOptions, SessionFreezeState};

#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct InterestSet {
    pub process_scoped: bool,
    pub action_classes: Vec<ActionClass>,
    pub agents: BTreeSet<String>,
    pub path_prefixes: BTreeSet<String>,
    pub path_contains: BTreeSet<String>,
    pub hosts: BTreeSet<String>,
    pub ports: BTreeSet<u16>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedBundle {
    pub(crate) bundle_id: String,
    pub(crate) bundle_hash: String,
    pub(crate) version: String,
    pub(crate) packs: Vec<PolicyPack>,
    pub(crate) layers: Vec<PolicyLayerSpec>,
    pub(crate) identity_mode: IdentityMode,
    pub(crate) host_profile: InstallProfile,
    pub(crate) user_timelock_enabled: bool,
    pub(crate) device_max_grade: ApprovalGrade,
    pub(crate) trusted_keys: Vec<TrustedKeyInfo>,
}

#[derive(Debug, Clone)]
pub enum EngineInput {
    Evaluate {
        attempt: ActionAttempt,
        options: Box<RequestBuildOptions>,
        host_deadline_ms: Option<u64>,
    },
    IssueGrant {
        grant: Grant,
    },
    ApprovalOutcome {
        session_id: String,
        approved: bool,
        at: Timestamp,
    },
    UpdateKillSwitch {
        kill_switch: KillSwitchState,
    },
    ReloadBundle {
        bundle: VerifiedBundle,
    },
    Tick {
        now: Timestamp,
    },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EngineOutput {
    Evaluated {
        receipt: Box<DecisionReceipt>,
        executed_verb: ExecutedVerb,
        obligations: Vec<Obligation>,
        retry_token: Option<String>,
        modified_attempt: Option<ActionAttempt>,
        cache_hit: bool,
        session_state_seq: u64,
    },
    GrantRecorded {
        grant_id: String,
        session_state_seq: u64,
    },
    ApprovalStreakFrozen {
        session_id: String,
        incident: Incident,
        session_state_seq: u64,
    },
    BundleLoaded {
        bundle_hash: String,
        effective_hash: String,
        rule_count: usize,
        session_state_seq: u64,
    },
    StateAdvanced {
        session_state_seq: u64,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionSnapshotEntry {
    pub session_id: String,
    pub labels: BTreeSet<SessionLabel>,
    pub denial_count: u32,
    pub step_up_count: u32,
    pub event_seq: u64,
    pub approval_streak: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EngineSnapshot {
    pub bundle_hash: String,
    pub effective_hash: String,
    pub session_state_seq: u64,
    pub kill_switch: KillSwitchState,
    pub grants: Vec<Grant>,
    pub grant_label_epochs: BTreeMap<String, u64>,
    pub session_label_epochs: BTreeMap<String, u64>,
    pub session_last_taint_at: BTreeMap<String, Timestamp>,
    pub spent_once_grants: BTreeMap<String, Timestamp>,
    pub approval_streaks: BTreeMap<String, u32>,
    pub frozen_sessions: BTreeSet<String>,
    pub sessions: Vec<SessionSnapshotEntry>,
    pub snapshot_mac: String,
}

impl VerifiedBundle {
    #[allow(
        clippy::too_many_arguments,
        reason = "verified bundle constructor binds signed packs, hierarchy layers, and host profile configuration"
    )]
    pub fn new_verified(
        bundle_id: String,
        bundle_hash: String,
        version: String,
        packs: Vec<PolicyPack>,
        layers: Vec<PolicyLayerSpec>,
        identity_mode: IdentityMode,
        host_profile: InstallProfile,
        user_timelock_enabled: bool,
        device_max_grade: ApprovalGrade,
        trusted_keys: Vec<TrustedKeyInfo>,
    ) -> Result<Self, PolicyError> {
        let bundle = Self {
            bundle_id,
            bundle_hash,
            version,
            packs,
            layers,
            identity_mode,
            host_profile,
            user_timelock_enabled,
            device_max_grade,
            trusted_keys,
        };
        verify_bundle_contents(&bundle)?;
        Ok(bundle)
    }

    pub fn compute_bundle_hash(
        packs: &[PolicyPack],
        layers: &[PolicyLayerSpec],
        identity_mode: IdentityMode,
        host_profile: InstallProfile,
        user_timelock_enabled: bool,
        device_max_grade: ApprovalGrade,
    ) -> String {
        compute_bundle_hash_parts(
            packs,
            layers,
            identity_mode,
            host_profile,
            user_timelock_enabled,
            device_max_grade,
        )
    }

    pub fn bundle_id(&self) -> &str {
        &self.bundle_id
    }

    pub fn bundle_hash(&self) -> &str {
        &self.bundle_hash
    }

    pub fn version(&self) -> &str {
        &self.version
    }

    pub fn packs(&self) -> &[PolicyPack] {
        &self.packs
    }

    pub fn layers(&self) -> &[PolicyLayerSpec] {
        &self.layers
    }

    pub fn identity_mode(&self) -> IdentityMode {
        self.identity_mode
    }

    pub fn host_profile(&self) -> InstallProfile {
        self.host_profile
    }

    pub fn user_timelock_enabled(&self) -> bool {
        self.user_timelock_enabled
    }

    pub fn device_max_grade(&self) -> ApprovalGrade {
        self.device_max_grade
    }

    pub fn trusted_keys(&self) -> &[TrustedKeyInfo] {
        &self.trusted_keys
    }
}

pub(crate) fn push_len(buf: &mut String, val: &str) {
    buf.push_str(&val.len().to_string());
    buf.push(':');
    buf.push_str(val);
    buf.push(';');
}

pub(crate) fn push_opt(buf: &mut String, val: Option<&str>) {
    match val {
        Some(s) => {
            buf.push('1');
            push_len(buf, s);
        }
        None => buf.push('0'),
    }
}

pub(crate) fn verdict_cache_key(
    effective_hash: &str,
    session_epoch: u64,
    session_event_seq: u64,
    attempt: &ActionAttempt,
    options: &RequestBuildOptions,
) -> String {
    let mut buf = String::new();
    push_len(&mut buf, effective_hash);
    push_len(&mut buf, &session_epoch.to_string());
    push_len(&mut buf, &session_event_seq.to_string());
    push_len(&mut buf, &attempt.id);
    push_len(&mut buf, &attempt.device_id);
    push_len(&mut buf, &attempt.session_id);
    push_len(&mut buf, &attempt.agent_name);
    push_opt(&mut buf, attempt.user_id.as_deref());
    push_opt(&mut buf, attempt.skill_used.as_deref());
    push_len(&mut buf, attempt.action_class.as_str());
    push_len(&mut buf, &format!("{:?}", attempt.control_point));
    push_len(&mut buf, &attempt.target);
    append_options_key(&mut buf, options);
    domain_sha256_hex("grdr.engine.verdict-cache.v2", buf.as_bytes())
}

fn append_options_key(buf: &mut String, o: &RequestBuildOptions) {
    let id_mode = match o.identity_mode {
        IdentityMode::Named => "named",
        IdentityMode::Pseudonymous => "pseudo",
    };
    let profile = match o.host_profile {
        InstallProfile::User => "user",
        InstallProfile::Protected => "protected",
    };
    let actor = match o.actor_kind {
        ActorKind::Agent => "agent",
        ActorKind::Human => "human",
        ActorKind::System => "system",
        ActorKind::Undetermined => "undetermined",
    };
    let cred = match o.cred_mode {
        CredUseMode::Inject => "inject",
        CredUseMode::Release => "release",
    };
    let freeze = match o.session_freeze {
        SessionFreezeState::Active => "active",
        SessionFreezeState::Frozen => "frozen",
    };
    let obs = match o.observer {
        BoundaryObserver::None => "none",
        BoundaryObserver::ScopedBoundary => "scoped",
    };
    push_len(buf, id_mode);
    push_len(buf, profile);
    push_len(buf, actor);
    push_len(buf, cred);
    push_len(buf, freeze);
    push_len(buf, obs);
    buf.push_str(&format!(
        "{}:{:?}:{:?}:{}:{}:{}:{}:{}:{:?}:{}:{:?}:{:?}:{:?}:{}:{}:{}:{}:{:?};",
        o.agent_capable_host,
        o.attribution_grade,
        o.min_attribution_grade,
        o.session_depth,
        o.session_contained,
        o.label_epoch,
        o.child_depth,
        o.child_contained,
        o.parsed_port,
        o.mcp_hints.args_extracted,
        o.mcp_hints.server_pinned,
        o.mcp_hints.tool_pinned,
        o.mcp_hints.read_only_hint,
        o.verification.cloud_verified,
        o.verification.llm_tenant_verified,
        o.extra_absent.len(),
        o.extra_pending.len(),
        o.assurance,
    ));
    for s in [
        &o.os_name,
        &o.org_id,
        &o.group_id,
        &o.department,
        &o.user_risk_tier,
        &o.agent_tier,
        &o.child_tier,
        &o.session_containment,
        &o.mcp_transport,
        &o.mcp_server_id,
    ] {
        push_len(buf, s);
    }
    buf.push_str(&format!("CC{};", o.child_classes.len()));
    for cc in &o.child_classes {
        push_len(buf, cc);
    }
    match &o.skill_meta {
        Some(sk) => {
            buf.push_str("SK1:");
            push_len(buf, &sk.id);
            push_len(buf, &sk.kind);
            buf.push_str(&format!(
                "{}:{}:{}:{}:{};",
                sk.digest_pinned,
                sk.has_scripts,
                sk.requests_broad_tools,
                sk.bidi_obfuscation,
                sk.classes.len(),
            ));
            for c in &sk.classes {
                push_len(buf, c);
            }
        }
        None => buf.push_str("SK0;"),
    }
    for f in &o.extra_absent {
        buf.push_str(&format!("{f:?},"));
    }
    for f in &o.extra_pending {
        buf.push_str(&format!("{f:?},"));
    }
}
