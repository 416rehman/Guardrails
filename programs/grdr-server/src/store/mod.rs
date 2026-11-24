// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod browser;
mod connect;
mod connect_mdm;
mod lake_ops;
mod overview;
mod persistence;
mod policy_ops;
pub mod profile;
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
#[cfg(test)]
use grdr_ports::{
    ErasureReceipt, LakeCompactionResult, LakeFlushResult, LakeManifest, LakeQueryIr,
    LakeQueryResult,
};
use grdr_proto::common::CollectionKind;

use crate::aip::revision::RevisionTable;
use crate::demo;
use persistence::EmbeddedStorage;
#[cfg(test)]
pub use profile::{
    BlobAdapterKind, BusAdapterKind, LakeAdapterKind, ProfileAdapterSet, RelationalAdapterKind,
    validate_profile_adapters,
};
pub use profile::{CODE_STORE_PROFILE_MISMATCH, StorageBackend, validate_backend_endpoints};

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

    pub fn from_profile_flags(
        profile: ProfileKind,
        memory: bool,
        data_dir: Option<PathBuf>,
        postgres_dsn: Option<String>,
        nats_url: Option<String>,
        object_store_dir: Option<PathBuf>,
    ) -> Result<Self, CodedError> {
        match profile {
            ProfileKind::Embedded => Ok(Self::from_flags(memory, data_dir)),
            ProfileKind::Ha => {
                let dsn = postgres_dsn.ok_or_else(|| {
                    CodedError::new(
                        CODE_STORE_PROFILE_MISMATCH,
                        "HA profile requires --postgres-dsn (GRDR_POSTGRES_DSN).",
                        "Pass --postgres-dsn postgres://... or use --profile embedded.",
                    )
                })?;
                let blob_dir = object_store_dir.or(data_dir).ok_or_else(|| {
                    CodedError::new(
                        CODE_STORE_PROFILE_MISMATCH,
                        "HA profile requires --object-store-dir or --data-dir.",
                        "Provide an object-store directory or bucket path.",
                    )
                })?;
                Ok(Self::Ha {
                    postgres_dsn: dsn,
                    object_store_dir: blob_dir,
                })
            }
            ProfileKind::Distributed => {
                let dsn = postgres_dsn.ok_or_else(|| {
                    CodedError::new(
                        CODE_STORE_PROFILE_MISMATCH,
                        "Distributed profile requires --postgres-dsn (GRDR_POSTGRES_DSN).",
                        "Pass --postgres-dsn postgres://... or use --profile embedded.",
                    )
                })?;
                let nats = nats_url.ok_or_else(|| {
                    CodedError::new(
                        CODE_STORE_PROFILE_MISMATCH,
                        "Distributed profile requires --nats-url (GRDR_NATS_URL).",
                        "Pass --nats-url nats://... or use --profile ha.",
                    )
                })?;
                let blob_dir = object_store_dir.or(data_dir).ok_or_else(|| {
                    CodedError::new(
                        CODE_STORE_PROFILE_MISMATCH,
                        "Distributed profile requires --object-store-dir or --data-dir.",
                        "Provide an object-store directory or bucket path.",
                    )
                })?;
                Ok(Self::Distributed {
                    postgres_dsn: dsn,
                    nats_url: nats,
                    object_store_dir: blob_dir,
                })
            }
        }
    }

    pub fn storage_mode(&self) -> StorageMode {
        match self {
            Self::Memory => StorageMode::Memory,
            Self::Disk(dir) => StorageMode::Sqlite {
                path: dir.display().to_string(),
            },
            Self::Ha {
                object_store_dir, ..
            }
            | Self::Distributed {
                object_store_dir, ..
            } => StorageMode::Sqlite {
                path: object_store_dir.display().to_string(),
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
        validate_backend_endpoints(profile, &backend)?;

        let now = Timestamp::now();
        let signing_key = match &backend {
            StorageBackend::Disk(dir)
            | StorageBackend::Ha {
                object_store_dir: dir,
                ..
            }
            | StorageBackend::Distributed {
                object_store_dir: dir,
                ..
            } => load_or_create_keypair(&dir.join("signing.key")).map_err(|e| {
                CodedError::new(
                    CODE_STORE_IO,
                    format!("Failed initializing server signing key: {e}"),
                    "Verify write permissions in --data-dir.",
                )
            })?,
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
            StorageBackend::Ha { postgres_dsn, .. } => {
                let pg_cfg = grdr_rel_postgres::PostgresConfig::parse_dsn(postgres_dsn)?;
                let _pg = grdr_rel_postgres::PostgresRelationalStore::connect(pg_cfg)?;
                None
            }
            StorageBackend::Distributed {
                postgres_dsn,
                nats_url,
                ..
            } => {
                let pg_cfg = grdr_rel_postgres::PostgresConfig::parse_dsn(postgres_dsn)?;
                let _pg = grdr_rel_postgres::PostgresRelationalStore::connect(pg_cfg)?;
                let nats_cfg = grdr_bus_nats::NatsConfig::parse_url(nats_url)?;
                let _nats = grdr_bus_nats::NatsJetStreamBus::connect(nats_cfg)?;
                None
            }
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

    #[cfg(test)]
    pub(crate) fn flush_lake(&self, now_ms: i64) -> Result<LakeFlushResult, CodedError> {
        let Some(store) = &self.storage else {
            return Err(CodedError::new(
                CODE_STORE_IO,
                "Lake flush requires disk-backed EmbeddedStorage.",
                "Initialize server with StorageBackend::Disk.",
            ));
        };
        store.flush_lake(now_ms)
    }

    #[cfg(test)]
    pub(crate) fn compact_lake(&self, now_ms: i64) -> Result<LakeCompactionResult, CodedError> {
        let Some(store) = &self.storage else {
            return Err(CodedError::new(
                CODE_STORE_IO,
                "Lake compaction requires disk-backed EmbeddedStorage.",
                "Initialize server with StorageBackend::Disk.",
            ));
        };
        store.compact_lake(now_ms)
    }

    #[cfg(test)]
    pub(crate) fn query_lake(&self, query: &LakeQueryIr) -> Result<LakeQueryResult, CodedError> {
        let Some(store) = &self.storage else {
            return Err(CodedError::new(
                CODE_STORE_IO,
                "Lake query requires disk-backed EmbeddedStorage.",
                "Initialize server with StorageBackend::Disk.",
            ));
        };
        store.query_lake(query)
    }

    #[cfg(test)]
    pub(crate) fn erase_lake_session(
        &self,
        root_session_id: &str,
        reason: &str,
        now_ms: i64,
    ) -> Result<ErasureReceipt, CodedError> {
        let Some(store) = &self.storage else {
            return Err(CodedError::new(
                CODE_STORE_IO,
                "Lake session erasure requires disk-backed EmbeddedStorage.",
                "Initialize server with StorageBackend::Disk.",
            ));
        };
        store.erase_lake_session(root_session_id, reason, now_ms)
    }

    #[cfg(test)]
    pub(crate) fn lake_manifest(&self) -> Result<Option<LakeManifest>, CodedError> {
        let Some(store) = &self.storage else {
            return Err(CodedError::new(
                CODE_STORE_IO,
                "Lake manifest requires disk-backed EmbeddedStorage.",
                "Initialize server with StorageBackend::Disk.",
            ));
        };
        store.lake_manifest()
    }
}
