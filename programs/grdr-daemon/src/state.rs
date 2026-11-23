// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::sync::Arc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use grdr_agents::discover_local_agents;
use grdr_model::eval::{essentials_pack, evaluate_attempt};
use grdr_model::{
    ActionAttempt, DecideInput, DecisionReceipt, DiscoveryReport, Grant, InstallProfile,
    KillSwitchState, PolicyPack, SessionSummary, slugify_id, summarize_sessions,
};

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

#[derive(Debug, Clone)]
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
    pub fn init(
        profile: InstallProfile,
        device_name: Option<String>,
        server_url: Option<String>,
    ) -> Self {
        let mut discovery = discover_local_agents(profile);
        if let Some(custom) = device_name
            && !custom.trim().is_empty()
        {
            discovery.device_name = custom;
        }
        let device_id = format!("dev-{}", slugify_id(&discovery.device_name, 40, "local"));
        let hostname = discovery.device_name.clone();

        Self {
            inner: Arc::new(RwLock::new(DaemonData {
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
                kill_switch: KillSwitchState::Inactive,
                attempts: Vec::new(),
                receipts: Vec::new(),
                pending_attempts: Vec::new(),
                pending_receipts: Vec::new(),
            })),
        }
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

        let receipt = evaluate_attempt(
            &attempt,
            &guard.packs,
            &guard.grants,
            &guard.kill_switch,
            now,
        );

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

        receipt
    }

    pub async fn sessions(&self) -> Vec<SessionSummary> {
        let guard = self.inner.read().await;
        summarize_sessions(&guard.attempts, &guard.receipts)
    }
}
