// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Privileged daemon state, signing keypair, segmented hash-chained spool, zstd SQLite
//! flight recorder (`recorder.db`), signed `audit.checkpoint`, and floor fallback evaluation.

use std::collections::{BTreeSet, VecDeque};
use std::path::PathBuf;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use grdr_crypto::{SigningKeypair, load_or_create_keypair};
use grdr_model::{
    DecisionReceipt, DiscoveryReport, Grant, InstallProfile, KillSwitchState, PolicyPack,
    TrustedKeyInfo,
};
use grdr_os_clock::{Clock, SystemClock};
use grdr_os_service::ladder::LadderRung;
use grdr_store_local::LocalStore;
use grdr_store_local::checkpoint::load_and_verify_checkpoint_checked;
use grdr_store_local::recorder::FlightRecorderDb;
use grdr_store_local::spool::{SegmentedSpool, SpoolPolicy};
use grdr_wire::floor_bin::FloorRuleRecord;
use grdr_wire::messages::{
    BundleLoadFrame, DaemonHealthSummary, DecideRequestFrame, DecideVerdictFrame,
    EngineForwardFrame, EngineResultFrame, WireEnforcementMode,
};
use grdr_wire::peer_auth::VerifiedPeer;
use jiff::Timestamp;

use crate::dir_guard::{default_principal, derive_device_id, ensure_dir_secure};
use crate::floor_compiler::CompiledFloorCache;
use crate::grant_ops::{
    apply_local_kill_switch, consume_grant, revoke_grant_entry, validate_and_insert_grant,
};
use crate::ladder_codec::{load_ladder_state, load_prior_floor_rules};
use crate::receipt_audit::{
    build_bundle_frame, kill_switch_block_reason, now_wall_checked, persist_snapshot,
    record_decision_audit, resolve_outcome,
};
use crate::supervisor::{RestartSpec, SupervisedChild};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DaemonLifecycle {
    Healthy,
    Degraded,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum UplinkState {
    LocalOnly,
    Connected { server_url: String },
    Degraded { reason: String },
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CallerPrincipal {
    pub uid: Option<u32>,
    pub windows_sid: Option<String>,
}

pub struct ChildSlot {
    pub spec: Option<RestartSpec>,
    pub child: Option<SupervisedChild>,
    pub retry_not_before_s: i64,
    pub last_ladder_rung: LadderRung,
}

pub struct DaemonData {
    pub device_id: String,
    pub hostname: String,
    pub install_profile: InstallProfile,
    pub uplink: UplinkState,
    pub lifecycle: DaemonLifecycle,
    pub degraded_reason: String,
    pub sandbox_partial_reason: Option<String>,
    pub discovery: DiscoveryReport,
    pub packs: Vec<PolicyPack>,
    pub grants: Vec<Grant>,
    pub revoked_grant_ids: VecDeque<String>,
    pub forced_deny_rule_ids: BTreeSet<String>,
    pub prior_floor_rules: Vec<FloorRuleRecord>,
    pub signing_key: SigningKeypair,
    pub trusted_keys: Vec<TrustedKeyInfo>,
    pub kill_switch: KillSwitchState,
    pub last_checkin_server_s: Option<i64>,
    pub state_dir: PathBuf,
    pub local_store: LocalStore,
    pub spool: SegmentedSpool,
    pub recorder: FlightRecorderDb,
    pub floor: CompiledFloorCache,
    pub epoch: u64,
    pub receipts_total: u64,
    pub recent_receipts: Vec<DecisionReceipt>,
    pub receipt_owners: Vec<(String, CallerPrincipal)>,
    pub last_recorder_head_seq: u64,
    pub persistence_errors: u64,
}

#[derive(Clone)]
pub struct DaemonState {
    pub inner: Arc<Mutex<DaemonData>>,
    pub engine: Arc<Mutex<ChildSlot>>,
    pub uplink_child: Arc<Mutex<ChildSlot>>,
    pub updater_child: Arc<Mutex<ChildSlot>>,
    pub ipc_drops: Arc<AtomicU64>,
}

impl CallerPrincipal {
    #[must_use]
    pub fn from_peer(peer: &VerifiedPeer) -> Self {
        crate::dir_guard::caller_principal_from_peer(peer)
    }
}

impl ChildSlot {
    #[must_use]
    pub const fn empty() -> Self {
        Self {
            spec: None,
            child: None,
            retry_not_before_s: 0,
            last_ladder_rung: LadderRung::Normal,
        }
    }
}

impl DaemonState {
    pub fn initialize(
        data_dir: PathBuf,
        state_dir: PathBuf,
        profile: InstallProfile,
    ) -> Result<Self, String> {
        ensure_dir_secure(&data_dir, false)?;
        ensure_dir_secure(&state_dir, true)?;

        let signing_key = load_or_create_keypair(&data_dir.join("daemon-signing.key"))
            .map_err(|e| format!("load daemon keypair: {e}"))?;
        let local_store =
            LocalStore::open(data_dir.join("snapshot-store")).map_err(|e| e.to_string())?;
        let spool =
            SegmentedSpool::open(state_dir.join("spool"), SpoolPolicy::from_embedded_limits())
                .map_err(|e| format!("open spool: {e}"))?;
        let recorder =
            FlightRecorderDb::open(data_dir.join("recorder.db")).map_err(|e| e.to_string())?;
        let last_recorder_head_seq = recorder
            .head_seq()
            .map_err(|e| format!("query flight recorder head seq: {e}"))?;

        let derived_id = derive_device_id(&signing_key);
        let snap = local_store.load_snapshot().map_err(|err| {
            format!("GRDR-DAEM-0001: corrupt snapshot store refused fail-closed: {err}")
        })?;
        let (
            device_id,
            packs,
            grants,
            revoked_grant_ids,
            trusted_keys,
            kill_switch,
            recent_receipts,
        ) = crate::receipt_audit::restore_daemon_snapshot(snap, derived_id);

        let now_ts = now_wall_checked()?;
        let ckpt_opt = load_and_verify_checkpoint_checked(
            state_dir.join("audit.checkpoint"),
            &signing_key.public_key_b64(),
            &device_id,
            0,
        )
        .map_err(|e| format!("GRDR-DAEM-0001: verify audit checkpoint: {e}"))?;
        let epoch = local_store
            .advance_epoch()
            .map_err(|e| format!("GRDR-DAEM-0001: advance daemon epoch: {e}"))?;
        if let Some(ckpt) = ckpt_opt
            && ckpt.payload.epoch >= epoch
        {
            return Err(format!(
                "GRDR-DAEM-0001: store epoch {epoch} <= checkpoint epoch {}",
                ckpt.payload.epoch
            ));
        }

        let prior_rules = load_prior_floor_rules(
            &state_dir.join("floor.bin"),
            &signing_key,
            now_ts.as_second(),
        )?;
        let (ladder, _) = load_ladder_state(&data_dir.join("engine-ladder.bin"), now_ts);
        let forced_deny_rule_ids = ladder.effective_floor().fail_closed_rule_ids.clone();
        let floor = CompiledFloorCache::compile_and_write(
            &packs,
            &prior_rules,
            &forced_deny_rule_ids,
            epoch,
            now_ts.as_second(),
            &state_dir,
            &signing_key,
        )
        .map_err(|e| e.to_string())?;
        let receipt_owners = recent_receipts
            .iter()
            .map(|r| (r.receipt_id.clone(), default_principal()))
            .collect();

        let data = DaemonData {
            device_id,
            hostname: "localhost".to_string(),
            install_profile: profile,
            uplink: UplinkState::LocalOnly,
            lifecycle: DaemonLifecycle::Healthy,
            degraded_reason: String::new(),
            sandbox_partial_reason: None,
            discovery: DiscoveryReport {
                device_name: "localhost".to_string(),
                os: std::env::consts::OS.to_string(),
                arch: std::env::consts::ARCH.to_string(),
                install_profile: profile,
                agents: Vec::new(),
                mcp_servers: Vec::new(),
                artifacts: Vec::new(),
                scanned_paths: Vec::new(),
                warnings: Vec::new(),
                scanned_at: now_ts,
            },
            packs,
            grants,
            revoked_grant_ids,
            forced_deny_rule_ids,
            prior_floor_rules: floor.doc.rules.clone(),
            signing_key,
            trusted_keys,
            kill_switch,
            last_checkin_server_s: None,
            state_dir,
            local_store,
            spool,
            recorder,
            floor,
            epoch,
            receipts_total: u64::try_from(recent_receipts.len()).unwrap_or(0),
            recent_receipts,
            receipt_owners,
            last_recorder_head_seq,
            persistence_errors: 0,
        };
        Ok(Self {
            inner: Arc::new(Mutex::new(data)),
            engine: Arc::new(Mutex::new(ChildSlot::empty())),
            uplink_child: Arc::new(Mutex::new(ChildSlot::empty())),
            updater_child: Arc::new(Mutex::new(ChildSlot::empty())),
            ipc_drops: Arc::new(AtomicU64::new(0)),
        })
    }

    pub fn record_ipc_drop(&self) {
        let _ = self.ipc_drops.fetch_add(1, Ordering::Relaxed);
    }

    #[must_use]
    pub fn device_id(&self) -> String {
        self.inner
            .lock()
            .map_or_else(|_| String::new(), |g| g.device_id.clone())
    }

    pub fn current_bundle(&self) -> Result<BundleLoadFrame, String> {
        let guard = self
            .inner
            .lock()
            .map_err(|_| "daemon state lock poisoned".to_string())?;
        build_bundle_frame(&guard)
    }

    pub fn push_bundle_to_engine_slot(&self, bundle: BundleLoadFrame) -> Result<(), String> {
        let mut slot = self
            .engine
            .lock()
            .map_err(|_| "engine slot lock poisoned".to_string())?;
        match slot.child.as_mut() {
            Some(child) => child.send_bundle(bundle).map_err(|e| e.to_string()),
            None => Ok(()),
        }
    }

    #[must_use]
    pub fn health_summary(&self) -> DaemonHealthSummary {
        let (engine_alive, rss_bytes, engine_partial) = self
            .engine
            .lock()
            .ok()
            .and_then(|g| {
                g.child.as_ref().map(|c| {
                    (
                        c.is_healthy(),
                        c.last_rss_bytes,
                        c.sandbox_partial_reason.clone(),
                    )
                })
            })
            .unwrap_or((false, 0, None));
        let uplink_child_alive = self
            .uplink_child
            .lock()
            .ok()
            .is_some_and(|g| g.child.as_ref().is_some_and(SupervisedChild::is_healthy));
        let updater_alive = self
            .updater_child
            .lock()
            .ok()
            .is_some_and(|g| g.child.as_ref().is_some_and(SupervisedChild::is_healthy));
        let Ok(guard) = self.inner.lock() else {
            return DaemonHealthSummary::default();
        };
        let uplink_alive =
            uplink_child_alive || matches!(guard.uplink, UplinkState::Connected { .. });
        let floor_digest = format!("{}:{}", guard.floor.digest_hex, guard.floor.epoch);
        let drops = self.ipc_drops.load(Ordering::Relaxed);
        let degraded_reason = if !guard.degraded_reason.is_empty() {
            guard.degraded_reason.clone()
        } else if drops > 0 {
            format!("overload:ipc-drops={drops}")
        } else if guard.persistence_errors > 0 {
            format!("audit-persistence-fault:{}", guard.persistence_errors)
        } else {
            engine_partial
                .or_else(|| guard.sandbox_partial_reason.clone())
                .unwrap_or_default()
        };
        DaemonHealthSummary {
            pid: std::process::id(),
            enforcement_mode: WireEnforcementMode::Block as i32,
            degraded_reason,
            floor_digest,
            engine_alive,
            uplink_alive,
            updater_alive,
            spool_bytes: guard.spool.total_bytes(),
            gap_count: u64::try_from(guard.spool.gap_records().len()).unwrap_or(0),
            rss_bytes,
            receipts_total: guard.receipts_total,
        }
    }

    pub fn decide_request(
        &self,
        req: &DecideRequestFrame,
        caller: Option<&CallerPrincipal>,
    ) -> Result<DecideVerdictFrame, String> {
        let now = now_wall_checked()?;
        let attempt_id = if req.request_id.is_empty() {
            uuid::Uuid::now_v7().to_string()
        } else {
            req.request_id.clone()
        };
        let (epoch, device_id, pre_kill_reason) = {
            let guard = self
                .inner
                .lock()
                .map_err(|_| "daemon state lock poisoned".to_string())?;
            let ks = kill_switch_block_reason(
                &guard.kill_switch,
                &req.session_id,
                &guard.device_id,
                now,
            );
            (guard.epoch, guard.device_id.clone(), ks)
        };

        let engine_outcome = if pre_kill_reason.is_some() {
            Err("kill-switch".to_string())
        } else {
            let fwd = EngineForwardFrame {
                request_id: req.request_id.clone(),
                attempt_id: attempt_id.clone(),
                agent: req.agent.clone(),
                control_point: req.control_point,
                action_class: req.action_class,
                session_id: req.session_id.clone(),
                target: req.target.clone(),
                summary: req.summary.clone(),
                command_line: req.command_line.clone(),
                received_mono_ms: req.emitted_mono_ms,
                epoch,
                tool_name: req.tool_name.clone(),
                device_id,
            };
            forward_to_engine_slot(&self.engine, fwd)
        };

        let mut updated_bundle = None;
        let frame = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "daemon state lock poisoned".to_string())?;
            let live_ks = kill_switch_block_reason(
                &guard.kill_switch,
                &req.session_id,
                &guard.device_id,
                now,
            )
            .or(pre_kill_reason);
            let out = resolve_outcome(&mut guard, req, live_ks, engine_outcome, now);
            if let Some(gid) = out.consumed_grant_id.clone() {
                let g = &mut *guard;
                if consume_grant(&mut g.grants, &mut g.revoked_grant_ids, &gid) {
                    persist_snapshot(&mut guard)?;
                    updated_bundle = Some(build_bundle_frame(&guard)?);
                }
            }
            let principal = caller.cloned().unwrap_or_else(default_principal);
            record_decision_audit(&mut guard, &attempt_id, req, out, now, principal)?
        };
        if let Some(bundle) = updated_bundle {
            self.push_bundle_to_engine_slot(bundle)?;
        }
        Ok(frame)
    }

    pub fn prepare_engine_bundle_from_data(
        &self,
        guard: &mut DaemonData,
    ) -> Result<BundleLoadFrame, String> {
        let now_ts = now_wall_checked()?;
        guard.epoch = guard
            .local_store
            .advance_epoch()
            .map_err(|e| format!("advance daemon epoch: {e}"))?;
        let next_floor = CompiledFloorCache::compile_and_write(
            &guard.packs,
            &guard.prior_floor_rules,
            &guard.forced_deny_rule_ids,
            guard.epoch,
            now_ts.as_second(),
            &guard.state_dir,
            &guard.signing_key,
        )
        .map_err(|e| e.to_string())?;
        guard.prior_floor_rules = next_floor.doc.rules.clone();
        guard.floor = next_floor;
        persist_snapshot(guard)?;
        build_bundle_frame(guard)
    }

    pub fn recompile_floor(&self, packs: Option<Vec<PolicyPack>>) -> Result<(), String> {
        let bundle = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "daemon state lock poisoned".to_string())?;
            if let Some(next_packs) = packs {
                guard.packs = next_packs;
            }
            self.prepare_engine_bundle_from_data(&mut guard)?
        };
        self.push_bundle_to_engine_slot(bundle)
    }

    pub fn set_kill_switch(&self, active: bool, reason: &str) -> Result<(), String> {
        let now = now_wall_checked()?;
        let bundle = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "daemon state lock poisoned".to_string())?;
            apply_local_kill_switch(&mut guard, active, reason, now)?;
            self.prepare_engine_bundle_from_data(&mut guard)?
        };
        self.push_bundle_to_engine_slot(bundle)
    }

    pub fn issue_grant(&self, grant: Grant) -> Result<(), String> {
        let now = now_wall_checked()?;
        let bundle = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "daemon state lock poisoned".to_string())?;
            validate_and_insert_grant(&mut guard, grant, now)?;
            self.prepare_engine_bundle_from_data(&mut guard)?
        };
        self.push_bundle_to_engine_slot(bundle)
    }

    pub fn revoke_grant(&self, grant_id: &str) -> Result<(), String> {
        let bundle = {
            let mut guard = self
                .inner
                .lock()
                .map_err(|_| "daemon state lock poisoned".to_string())?;
            revoke_grant_entry(&mut guard, grant_id)?;
            self.prepare_engine_bundle_from_data(&mut guard)?
        };
        self.push_bundle_to_engine_slot(bundle)
    }
}

fn forward_to_engine_slot(
    slot_mutex: &Arc<Mutex<ChildSlot>>,
    fwd: EngineForwardFrame,
) -> Result<EngineResultFrame, String> {
    let mut slot = slot_mutex
        .lock()
        .map_err(|_| "engine slot lock poisoned".to_string())?;
    let res = match slot.child.as_mut() {
        Some(child) => child.forward_to_engine(fwd).map_err(|e| e.to_string()),
        None => Err("overload".to_string()),
    };
    if res.is_err() && slot.child.as_ref().is_some_and(|c| !c.is_healthy()) {
        slot.child = None;
    }
    res
}

#[must_use]
pub fn now_wall() -> Timestamp {
    SystemClock::new()
        .now_wall()
        .unwrap_or(Timestamp::UNIX_EPOCH)
}
