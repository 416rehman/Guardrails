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
mod session_ops;
pub(crate) mod users;

use std::path::PathBuf;
use std::sync::Arc;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::sync::{RwLock, broadcast};
use uuid::Uuid;

use grdr_core::policy;
use grdr_crypto::{AeadKey, SigningKeypair, load_or_create_keypair};
use grdr_model::error::CODE_STORE_IO;
use grdr_model::{
    ActionAttempt, ApprovalRequest, AuditEntry, BrowserAppPolicy, CodedError, DecisionReceipt,
    DeploymentKey, Device, Finding, Grant, IntegrationEntry, KillSwitchState, LiveEvent,
    OrgPrivacyConfig, OtlpFanoutConfig, PolicyPack, StorageMode, Verdict,
};
use grdr_ports::ProfileKind;
use grdr_proto::common::CollectionKind;

use crate::aip::revision::RevisionTable;
use crate::demo;
use persistence::EmbeddedStorage;

pub(crate) const MAX_RETAINED_EVENTS: usize = 500;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum StorageBackend {
    Memory,
    Disk(PathBuf),
}

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
    pub(crate) storage: Option<Arc<EmbeddedStorage>>,
    pub backend: StorageBackend,
    pub signing_key: SigningKeypair,
    pub page_key: AeadKey,
    pub revisions: Arc<RevisionTable>,
}

impl StorageBackend {
    pub fn from_flags(memory: bool, data_dir: Option<PathBuf>) -> Self {
        if memory {
            Self::Memory
        } else {
            match data_dir {
                Some(dir) => Self::Disk(dir),
                None => Self::Memory,
            }
        }
    }

    pub fn storage_mode(&self) -> StorageMode {
        match self {
            Self::Memory => StorageMode::Memory,
            Self::Disk(dir) => StorageMode::Sqlite {
                path: dir.display().to_string(),
            },
        }
    }
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
    #[cfg(test)]
    pub fn init(backend: StorageBackend, demo_seed: bool) -> Result<Self, CodedError> {
        Self::init_with_profile(ProfileKind::Embedded, backend, demo_seed)
    }

    pub fn init_with_profile(
        profile: ProfileKind,
        backend: StorageBackend,
        demo_seed: bool,
    ) -> Result<Self, CodedError> {
        if profile != ProfileKind::Embedded {
            return Err(CodedError::new(
                CODE_STORE_IO,
                format!(
                    "Storage profile `{}` adapters are not available in this server binary.",
                    profile.as_str()
                ),
                "Start grdr-server with --profile embedded.",
            ));
        }

        let now = Timestamp::now();
        let signing_key = match &backend {
            StorageBackend::Disk(dir) => {
                load_or_create_keypair(&dir.join("signing.key")).map_err(|e| {
                    CodedError::new(
                        CODE_STORE_IO,
                        format!("Failed initializing server signing key: {e}"),
                        "Verify write permissions in --data-dir.",
                    )
                })?
            }
            StorageBackend::Memory => SigningKeypair::generate().map_err(|e| {
                CodedError::new(
                    CODE_STORE_IO,
                    format!("Failed generating ephemeral signing key: {e}"),
                    "Check OS entropy availability.",
                )
            })?,
        };

        let storage = match &backend {
            StorageBackend::Disk(dir) => Some(Arc::new(EmbeddedStorage::open(dir)?)),
            StorageBackend::Memory => None,
        };

        let mut data = match &storage {
            Some(store) => store.load_store_data()?,
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
        if let Some(store) = &storage {
            store.persist_store_data(&data)?;
        }

        let page_key = signing_key.derive_aead_key("aip158.page_token");
        let (live_tx, _) = broadcast::channel(256);
        Ok(Self {
            inner: Arc::new(RwLock::new(data)),
            live_tx,
            storage,
            backend,
            signing_key,
            page_key,
            revisions: Arc::new(RevisionTable::new()),
        })
    }

    pub(crate) fn bump_revision(&self, collection: CollectionKind) -> u64 {
        self.revisions.bump(collection)
    }

    pub(crate) fn persist_store(&self, data: &StoreData) -> Result<(), CodedError> {
        if let Some(store) = &self.storage {
            store.persist_store_data(data)?;
        }
        Ok(())
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
