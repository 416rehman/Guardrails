// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod browser;
mod connect;
mod connect_mdm;
mod overview;
mod persistence;
mod policy_ops;
mod query_ir;
mod response_ops;
pub(crate) mod users;

use std::path::PathBuf;
use std::sync::Arc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use uuid::Uuid;

use grdr_core::{detect, policy, session};
use grdr_crypto::{SigningKeypair, load_or_create_keypair, verify_receipt};
use grdr_model::error::{CODE_INVALID_INPUT, CODE_NOT_FOUND, CODE_STORE_IO};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ApprovalRequest, ApprovalState, AuditEntry, BatchEventsInput,
    BatchEventsResponse, BrowserAppPolicy, CodedError, DecideInput, DecisionReceipt, DeploymentKey,
    Device, DeviceCheckinRequest, DeviceCheckinResponse, Finding, Grant, Incident,
    IntegrationEntry, KillSwitchState, LiveEvent, OrgPrivacyConfig, OtlpFanoutConfig, PolicyPack,
    SessionDetailResponse, SessionSummary, SignatureStatus, TrustedKeyInfo, Verdict, slugify_id,
    summarize_session_turns, summarize_sessions,
};

use crate::demo;
use persistence::{
    bump_rule_counters, expire_pending_approvals, find_rule_metadata, load_from_dir,
    persist_snapshot, record_attempt_and_receipt, trim_retained,
};

pub(crate) const MAX_RETAINED_EVENTS: usize = 500;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoreData {
    pub packs: Vec<PolicyPack>,
    #[serde(default)]
    pub user_directory: Vec<users::DirectoryUserRecord>,
    #[serde(default)]
    pub privacy: OrgPrivacyConfig,
    #[serde(default)]
    pub deployment_keys: Vec<DeploymentKey>,
    #[serde(default)]
    pub integrations: Vec<IntegrationEntry>,
    #[serde(default)]
    pub otlp_config: OtlpFanoutConfig,
    #[serde(default)]
    pub browser_policies: Vec<BrowserAppPolicy>,
    pub devices: Vec<Device>,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<DecisionReceipt>,
    pub approvals: Vec<ApprovalRequest>,
    pub grants: Vec<Grant>,
    pub findings: Vec<Finding>,
    pub kill_switch: KillSwitchState,
    pub audit: Vec<AuditEntry>,
}

#[derive(Clone)]
pub struct AppState {
    pub inner: Arc<RwLock<StoreData>>,
    pub live_tx: broadcast::Sender<LiveEvent>,
    pub data_dir: Option<PathBuf>,
    pub storage_mode: String,
    pub signing_key: SigningKeypair,
}

impl Default for StoreData {
    fn default() -> Self {
        Self {
            packs: vec![policy::essentials_pack()],
            user_directory: Vec::new(),
            privacy: OrgPrivacyConfig::default(),
            deployment_keys: Vec::new(),
            integrations: Vec::new(),
            otlp_config: OtlpFanoutConfig::default(),
            browser_policies: Vec::new(),
            devices: Vec::new(),
            attempts: Vec::new(),
            receipts: Vec::new(),
            approvals: Vec::new(),
            grants: Vec::new(),
            findings: Vec::new(),
            kill_switch: KillSwitchState::Inactive,
            audit: Vec::new(),
        }
    }
}

impl AppState {
    pub fn init(data_dir: Option<PathBuf>, demo_seed: bool) -> Result<Self, CodedError> {
        let now = Timestamp::now();
        let storage_mode = match &data_dir {
            Some(dir) => format!("disk:{}", dir.display()),
            None => "memory".into(),
        };

        let signing_key = match &data_dir {
            Some(dir) => load_or_create_keypair(&dir.join("signing.key")).map_err(|e| {
                CodedError::new(
                    CODE_STORE_IO,
                    format!("Failed initializing server signing key: {e}"),
                    "Verify write permissions in --data-dir.",
                )
            })?,
            None => SigningKeypair::generate().map_err(|e| {
                CodedError::new(
                    CODE_STORE_IO,
                    format!("Failed generating ephemeral signing key: {e}"),
                    "Check OS entropy availability.",
                )
            })?,
        };

        let mut data = match &data_dir {
            Some(dir) => load_from_dir(dir)?,
            None => StoreData::default(),
        };

        if demo_seed && data.devices.is_empty() && data.attempts.is_empty() {
            let seed = demo::build_demo_seed(now);
            data.packs = seed.packs;
            data.user_directory = seed.user_directory;
            data.devices = seed.devices;
            data.attempts = seed.attempts;
            data.receipts = seed.receipts;
            data.approvals = seed.approvals;
            data.grants = seed.grants;
            data.findings = seed.findings;
            data.audit = seed.audit;
        }
        if demo_seed && data.deployment_keys.is_empty() && data.integrations.is_empty() {
            let demo_connect = connect_mdm::demo_connect_state(now);
            data.deployment_keys = demo_connect.deployment_keys;
            data.integrations = demo_connect.integrations;
            data.otlp_config = demo_connect.otlp_config;
        }
        if demo_seed && data.browser_policies.is_empty() {
            data.browser_policies = browser::demo_browser_policies();
        }

        for pack in &mut data.packs {
            if pack.signature.is_none() {
                let _ = signing_key.sign_pack(pack);
            }
        }
        for receipt in &mut data.receipts {
            if receipt.signature.is_none() {
                let _ = signing_key.sign_receipt(receipt);
            }
        }
        if let Some(dir) = &data_dir {
            persist_snapshot(dir, &data)?;
        }

        let (live_tx, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(RwLock::new(data)),
            live_tx,
            data_dir,
            storage_mode,
            signing_key,
        })
    }

    pub async fn checkin_device(
        &self,
        req: DeviceCheckinRequest,
    ) -> Result<DeviceCheckinResponse, CodedError> {
        if req.hostname.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Device hostname cannot be empty.",
                "Provide a non-empty hostname in DeviceCheckinRequest.",
            ));
        }

        let now = Timestamp::now();
        let device_id = req
            .device_id
            .filter(|id| !id.trim().is_empty())
            .unwrap_or_else(|| format!("dev-{}", slugify_id(&req.hostname, 48, "node")));

        let device = Device {
            id: device_id.clone(),
            hostname: req.hostname,
            os: req.os,
            arch: req.arch,
            install_profile: req.install_profile,
            daemon_version: req.daemon_version,
            online: true,
            hook_effective: req.hook_effective,
            agents: req.agents,
            mcp_servers: req.mcp_servers,
            artifacts: req.artifacts,
            user_id: req.user_id,
            user_display: req.user_display,
            last_seen: now,
            public_key: req.device_public_key,
        };

        let (packs, grants, kill_switch) = {
            let mut guard = self.inner.write().await;
            if let Some(existing) = guard.devices.iter_mut().find(|d| d.id == device_id) {
                *existing = device.clone();
            } else {
                guard.devices.push(device.clone());
                guard.audit.insert(
                    0,
                    AuditEntry {
                        id: format!("aud_{}", Uuid::now_v7().simple()),
                        timestamp: now,
                        kind: "device.enrolled".into(),
                        actor: device.hostname.clone(),
                        summary: format!(
                            "Enrolled endpoint {} ({} agents)",
                            device.hostname,
                            device.agents.len()
                        ),
                        target: device.id.clone(),
                    },
                );
            }
            if let Some(dir) = &self.data_dir {
                persist_snapshot(dir, &guard)?;
            }
            (
                guard.packs.clone(),
                guard
                    .grants
                    .iter()
                    .filter(|g| g.is_active(now))
                    .cloned()
                    .collect(),
                guard.kill_switch.clone(),
            )
        };

        self.emit_live(
            "inventory.device",
            format!(
                "Endpoint {} checked in ({} agents)",
                device.hostname,
                device.agents.len()
            ),
            None,
        );

        Ok(DeviceCheckinResponse {
            device,
            packs,
            grants,
            kill_switch,
            server_time: now,
            trusted_keys: self.trusted_keys(),
        })
    }

    pub async fn evaluate_and_record(
        &self,
        input: DecideInput,
    ) -> Result<DecisionReceipt, CodedError> {
        if input.target.trim().is_empty() {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "Action target cannot be empty.",
                "Specify a command, file path, host, or tool name to evaluate.",
            ));
        }

        let now = Timestamp::now();
        let attempt = input.into_attempt(
            "sess-live-eval",
            "dev-demo-01",
            "console-tester",
            "Evaluated action attempt",
            now,
        );

        let receipt = {
            let mut guard = self.inner.write().await;
            let mut sess_state = session::replay_session_states(&guard.attempts, &guard.receipts)
                .remove(&attempt.session_id)
                .unwrap_or_else(|| session::SessionRuleState::new(attempt.session_id.clone()));
            let mut receipt = {
                let data = &mut *guard;
                policy::evaluate_with_session(
                    &attempt,
                    &data.packs,
                    &mut data.grants,
                    &data.kill_switch,
                    &mut sess_state,
                    now,
                )
            };
            let _ = self.signing_key.sign_receipt(&mut receipt);
            record_attempt_and_receipt(&mut guard, attempt.clone(), receipt.clone(), now);
            if let Some(dir) = &self.data_dir {
                persist_snapshot(dir, &guard)?;
            }
            receipt
        };

        self.emit_live(
            "session.verdict",
            format!(
                "{:?} {} -> {}",
                receipt.verdict,
                attempt.action_class.as_str(),
                attempt.target
            ),
            Some(receipt.verdict),
        );

        Ok(receipt)
    }

    pub async fn ingest_batch(
        &self,
        batch: BatchEventsInput,
    ) -> Result<BatchEventsResponse, CodedError> {
        let now = Timestamp::now();
        let accepted = batch.receipts.len();
        let mut findings_created: usize = 0;

        {
            let mut guard = self.inner.write().await;
            let device_name = guard
                .devices
                .iter()
                .find(|d| d.id == batch.device_id)
                .map(|d| d.hostname.clone())
                .unwrap_or_else(|| batch.device_id.clone());

            for attempt in batch.attempts {
                if !guard
                    .attempts
                    .iter()
                    .any(|existing| existing.id == attempt.id)
                {
                    guard.attempts.push(attempt);
                }
            }
            for receipt in batch.receipts {
                if guard
                    .receipts
                    .iter()
                    .any(|existing| existing.receipt_id == receipt.receipt_id)
                {
                    continue;
                }
                bump_rule_counters(&mut guard.packs, &receipt);
                if let Some(grant_id) = receipt.grant_id.as_deref()
                    && let Some(grant) = guard.grants.iter_mut().find(|g| g.grant_id == grant_id)
                {
                    grant.consume_use();
                }
                if receipt.verdict == Verdict::StepUp {
                    let (rule_title, required_grade) =
                        find_rule_metadata(&guard.packs, receipt.rule_id.as_deref());
                    guard.approvals.insert(
                        0,
                        ApprovalRequest {
                            id: format!("apr_{}", Uuid::now_v7().simple()),
                            receipt_id: receipt.receipt_id.clone(),
                            session_id: receipt.session_id.clone(),
                            device_id: receipt.device_id.clone(),
                            device_name: device_name.clone(),
                            agent_name: receipt.agent_name.clone(),
                            action_class: receipt.action_class,
                            target: receipt.target.clone(),
                            rule_id: receipt
                                .rule_id
                                .clone()
                                .unwrap_or_else(|| "policy.step_up".into()),
                            rule_title,
                            required_grade,
                            reason: receipt.reason.clone(),
                            requested_at: receipt.decided_at,
                            state: ApprovalState::Pending {
                                expires_at: add_seconds(now, 1800),
                            },
                        },
                    );
                }
                if let Some(finding) = detect::finding_from_receipt(&receipt, &device_name) {
                    guard.findings.insert(0, finding);
                    findings_created = findings_created.saturating_add(1);
                }
                guard.receipts.push(receipt);
            }
            trim_retained(&mut guard);
            if let Some(dir) = &self.data_dir {
                persist_snapshot(dir, &guard)?;
            }
        }

        if accepted > 0 {
            self.emit_live(
                "uplink.batch",
                format!("Ingested {accepted} endpoint decision receipt(s)"),
                None,
            );
        }

        Ok(BatchEventsResponse {
            accepted,
            findings_created,
        })
    }

    pub async fn sessions(&self) -> Vec<SessionSummary> {
        let guard = self.inner.read().await;
        let states = session::replay_session_states(&guard.attempts, &guard.receipts);
        let mut summaries = summarize_sessions(&guard.attempts, &guard.receipts);
        session::attach_session_labels(&mut summaries, &states);
        users::mask_sessions(&mut summaries, &guard);
        summaries
    }

    pub async fn incidents(&self) -> Vec<Incident> {
        let guard = self.inner.read().await;
        let states = session::replay_session_states(&guard.attempts, &guard.receipts);
        detect::correlate_incidents(&guard.findings, &states)
    }

    pub async fn list_approvals(&self) -> Vec<ApprovalRequest> {
        let now = Timestamp::now();
        let mut guard = self.inner.write().await;
        if expire_pending_approvals(&mut guard.approvals, now)
            && let Some(dir) = &self.data_dir
        {
            let _ = persist_snapshot(dir, &guard);
        }
        guard.approvals.clone()
    }

    pub async fn session_detail(
        &self,
        session_id: &str,
    ) -> Result<SessionDetailResponse, CodedError> {
        let guard = self.inner.read().await;
        let states = session::replay_session_states(&guard.attempts, &guard.receipts);
        let mut summaries = summarize_sessions(&guard.attempts, &guard.receipts);
        session::attach_session_labels(&mut summaries, &states);
        let summary = summaries
            .into_iter()
            .find(|s| s.id == session_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_NOT_FOUND,
                    format!("Session `{session_id}` was not found."),
                    "Return to Sessions to pick an active session.",
                )
            })?;

        let mut summary_vec = [summary];
        users::mask_sessions(&mut summary_vec, &guard);
        let [summary] = summary_vec;

        let mut attempts: Vec<ActionAttempt> = guard
            .attempts
            .iter()
            .filter(|a| a.session_id == session_id)
            .cloned()
            .collect();
        users::mask_attempts(&mut attempts, &guard);

        let mut keys = self.trusted_keys();
        for device in &guard.devices {
            if let Some(pk) = &device.public_key
                && !keys.iter().any(|existing| existing.key_id == pk.key_id)
            {
                keys.push(pk.clone());
            }
        }
        let receipts: Vec<DecisionReceipt> = guard
            .receipts
            .iter()
            .filter(|r| r.session_id == session_id)
            .cloned()
            .map(|mut r| {
                r.signature_verified = match verify_receipt(&r, &keys) {
                    SignatureStatus::Verified => Some(true),
                    SignatureStatus::Invalid => Some(false),
                    SignatureStatus::Unsigned => None,
                };
                r
            })
            .collect();

        let turns = summarize_session_turns(&attempts, &receipts);
        let user = summary.user_id.as_deref().and_then(|uid| {
            users::build_user_profiles(&guard)
                .into_iter()
                .find(|u| u.id == uid)
        });

        Ok(SessionDetailResponse {
            session: summary,
            attempts,
            receipts,
            turns,
            user,
        })
    }

    pub fn trusted_keys(&self) -> Vec<TrustedKeyInfo> {
        vec![self.signing_key.public_info()]
    }

    pub(crate) fn emit_live(&self, topic: &str, summary: String, verdict: Option<Verdict>) {
        let _ = self.live_tx.send(LiveEvent {
            id: format!("evt_{}", Uuid::now_v7().simple()),
            topic: topic.into(),
            summary,
            verdict,
            timestamp: Timestamp::now(),
        });
    }
}
