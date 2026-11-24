// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs;
use std::path::PathBuf;
use std::sync::Arc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use grdr_agents::discover_local_agents;
use grdr_core::compile::compile_floor_table;
use grdr_core::policy::evaluate_with_session;
use grdr_core::session::{SessionRuleState, replay_session_states};
use grdr_crypto::SigningKeypair;
use grdr_model::eval::essentials_pack;
use grdr_model::{
    ActionAttempt, DecideInput, DecisionReceipt, DiscoveryReport, Grant, InstallProfile,
    KillSwitchState, PolicyPack, SessionSummary, SignedFloorBundle, TrustedKeyInfo, slugify_id,
    summarize_sessions,
};
use grdr_store_local::{LocalStore, PersistedDaemonSnapshot, SNAPSHOT_SCHEMA_VERSION};

const MAX_LOCAL_HISTORY: usize = 300;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DaemonStatus {
    pub status: String,
    pub device_id: String,
    pub hostname: String,
    pub install_profile: InstallProfile,
    pub server_url: Option<String>,
    pub server_connected: bool,
    pub last_sync: Option<Timestamp>,
    pub last_sync_error: Option<String>,
    pub agent_count: usize,
    pub mcp_count: usize,
    pub cached_rules: usize,
    pub pending_events: usize,
    pub kill_switch: KillSwitchState,
}

#[derive(Clone)]
pub struct DaemonData {
    pub device_id: String,
    pub hostname: String,
    pub install_profile: InstallProfile,
    pub server_url: Option<String>,
    pub server_connected: bool,
    pub last_sync: Option<Timestamp>,
    pub last_sync_error: Option<String>,
    pub discovery: DiscoveryReport,
    pub packs: Vec<PolicyPack>,
    pub grants: Vec<Grant>,
    pub trusted_keys: Vec<TrustedKeyInfo>,
    pub signing_key: SigningKeypair,
    pub floor_table_path: Option<PathBuf>,
    pub local_store: Option<LocalStore>,
    pub kill_switch: KillSwitchState,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<DecisionReceipt>,
    pub pending_attempts: Vec<ActionAttempt>,
    pub pending_receipts: Vec<DecisionReceipt>,
}

#[derive(Clone)]
pub struct DaemonState {
    pub inner: Arc<RwLock<DaemonData>>,
}

impl DaemonState {
    pub fn init_with_store(
        profile: InstallProfile,
        device_name: Option<String>,
        server_url: Option<String>,
        floor_table_path: Option<PathBuf>,
        data_dir: Option<PathBuf>,
    ) -> Result<Self, String> {
        let mut discovery = discover_local_agents(profile);
        if let Some(custom) = device_name
            && !custom.trim().is_empty()
        {
            discovery.device_name = custom;
        }
        let device_id = format!("dev-{}", slugify_id(&discovery.device_name, 40, "local"));
        let hostname = discovery.device_name.clone();

        let local_store = match data_dir {
            Some(dir) => Some(LocalStore::open(dir).map_err(|e| e.to_string())?),
            None => None,
        };

        let signing_key = match &local_store {
            Some(store) => store
                .load_or_create_signing_key()
                .map_err(|e| e.to_string())?,
            None => SigningKeypair::generate()
                .map_err(|e| format!("failed generating daemon signing key: {e}"))?,
        };

        let restored = match &local_store {
            Some(store) => store.load_snapshot().map_err(|e| e.to_string())?,
            None => None,
        };

        let mut data = DaemonData {
            device_id,
            hostname,
            install_profile: profile,
            server_url,
            server_connected: false,
            last_sync: None,
            last_sync_error: None,
            discovery,
            packs: vec![essentials_pack()],
            grants: Vec::new(),
            trusted_keys: Vec::new(),
            signing_key,
            floor_table_path,
            local_store,
            kill_switch: KillSwitchState::Inactive,
            attempts: Vec::new(),
            receipts: Vec::new(),
            pending_attempts: Vec::new(),
            pending_receipts: Vec::new(),
        };

        if let Some(snapshot) = restored {
            data.device_id = snapshot.device_id;
            data.hostname = snapshot.hostname;
            if !snapshot.packs.is_empty() {
                data.packs = snapshot.packs;
            }
            data.grants = snapshot.grants;
            data.trusted_keys = snapshot.trusted_keys;
            data.kill_switch = snapshot.kill_switch;
            data.attempts = snapshot.attempts;
            data.receipts = snapshot.receipts;
            data.pending_attempts = snapshot.pending_attempts;
            data.pending_receipts = snapshot.pending_receipts;
        } else {
            let _ = persist_daemon_snapshot(&data);
        }

        let _ = write_signed_floor_bundle(&data, Timestamp::now());

        Ok(Self {
            inner: Arc::new(RwLock::new(data)),
        })
    }

    pub async fn status(&self) -> DaemonStatus {
        let guard = self.inner.read().await;
        let cached_rules = guard
            .packs
            .iter()
            .map(|p| p.rules.len())
            .fold(0usize, usize::saturating_add);
        DaemonStatus {
            status: "running".into(),
            device_id: guard.device_id.clone(),
            hostname: guard.hostname.clone(),
            install_profile: guard.install_profile,
            server_url: guard.server_url.clone(),
            server_connected: guard.server_connected,
            last_sync: guard.last_sync,
            last_sync_error: guard.last_sync_error.clone(),
            agent_count: guard.discovery.agents.len(),
            mcp_count: guard.discovery.mcp_servers.len(),
            cached_rules,
            pending_events: guard.pending_receipts.len(),
            kill_switch: guard.kill_switch.clone(),
        }
    }

    pub async fn rescan(&self) -> DiscoveryReport {
        let profile = {
            let guard = self.inner.read().await;
            guard.install_profile
        };
        let mut report = discover_local_agents(profile);
        let mut guard = self.inner.write().await;
        report.device_name = guard.hostname.clone();
        guard.discovery = report.clone();
        report
    }

    pub async fn decide_local(&self, input: DecideInput) -> DecisionReceipt {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;

        let attempt = input.into_attempt(
            "sess-local",
            &guard.device_id,
            &guard.hostname,
            "Local endpoint hook check",
            now,
        );

        let mut receipt = {
            let mut sess_state = replay_session_states(&guard.attempts, &guard.receipts)
                .remove(&attempt.session_id)
                .unwrap_or_else(|| SessionRuleState::new(attempt.session_id.clone()));
            let data = &mut *guard;
            evaluate_with_session(
                &attempt,
                &data.packs,
                &mut data.grants,
                &data.kill_switch,
                &mut sess_state,
                now,
            )
        };
        let _ = guard.signing_key.sign_receipt(&mut receipt);

        guard.attempts.push(attempt.clone());
        guard.receipts.push(receipt.clone());
        guard.pending_attempts.push(attempt);
        guard.pending_receipts.push(receipt.clone());

        if guard.attempts.len() > MAX_LOCAL_HISTORY {
            let excess = guard.attempts.len().saturating_sub(MAX_LOCAL_HISTORY);
            guard.attempts.drain(..excess);
        }
        if guard.receipts.len() > MAX_LOCAL_HISTORY {
            let excess = guard.receipts.len().saturating_sub(MAX_LOCAL_HISTORY);
            guard.receipts.drain(..excess);
        }

        if let Some(store) = &guard.local_store {
            let _ = store.append_receipt_wal(&receipt);
        }
        let _ = persist_daemon_snapshot(&guard);

        receipt
    }

    pub async fn sessions(&self) -> Vec<SessionSummary> {
        let guard = self.inner.read().await;
        summarize_sessions(&guard.attempts, &guard.receipts)
    }
}

pub fn default_floor_table_path() -> PathBuf {
    std::env::temp_dir().join("grdr-failsafe-floor.json")
}

pub(crate) fn persist_daemon_snapshot(data: &DaemonData) -> Result<(), String> {
    let Some(store) = &data.local_store else {
        return Ok(());
    };
    let snapshot = PersistedDaemonSnapshot {
        schema_version: SNAPSHOT_SCHEMA_VERSION,
        device_id: data.device_id.clone(),
        hostname: data.hostname.clone(),
        packs: data.packs.clone(),
        grants: data.grants.clone(),
        trusted_keys: data.trusted_keys.clone(),
        kill_switch: data.kill_switch.clone(),
        attempts: data.attempts.clone(),
        receipts: data.receipts.clone(),
        pending_attempts: data.pending_attempts.clone(),
        pending_receipts: data.pending_receipts.clone(),
    };
    store.save_snapshot(&snapshot).map_err(|e| e.to_string())
}

pub(crate) fn write_signed_floor_bundle(data: &DaemonData, now: Timestamp) -> Result<(), String> {
    let Some(path) = &data.floor_table_path else {
        return Ok(());
    };
    if let Some(parent) = path.parent() {
        fs::create_dir_all(parent).map_err(|e| format!("create floor dir: {e}"))?;
    }
    let mut table = compile_floor_table(&data.packs, now);
    data.signing_key
        .sign_floor_table(&mut table)
        .map_err(|e| format!("sign floor table: {e}"))?;
    let signer = data.signing_key.public_info();
    let key_json =
        serde_json::to_string_pretty(&signer).map_err(|e| format!("serialize floor key: {e}"))?;
    let key_path = path.with_extension("pub");
    let key_tmp = path.with_extension("pub.tmp");
    fs::write(&key_tmp, key_json).map_err(|e| format!("write temp floor key: {e}"))?;
    fs::rename(&key_tmp, &key_path).map_err(|e| format!("commit floor key: {e}"))?;

    let bundle = SignedFloorBundle { table, signer };
    let json = serde_json::to_string_pretty(&bundle).map_err(|e| format!("serialize: {e}"))?;
    let tmp = path.with_extension("json.tmp");
    fs::write(&tmp, json).map_err(|e| format!("write temp floor table: {e}"))?;
    fs::rename(&tmp, path).map_err(|e| format!("commit floor table: {e}"))?;
    Ok(())
}
