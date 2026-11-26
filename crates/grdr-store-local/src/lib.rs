// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod checkpoint;
pub mod crc32c;
pub mod daemon_codecs;
pub mod fs_hardening;
pub mod recorder;
mod recorder_retention;
pub mod spool;
pub mod spool_io;
mod spool_recover;
pub mod zstd_frame;

use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use grdr_crypto::{SigningKeypair, load_or_create_keypair};
use grdr_model::error::{CODE_STORE_CORRUPT, CODE_STORE_IO};
use grdr_model::{
    ActionAttempt, CodedError, DecisionReceipt, Grant, KillSwitchState, PolicyPack, TrustedKeyInfo,
    Verdict,
};
use grdr_ports::{PortSnapshot, StorePort};
use serde::{Deserialize, Serialize};

use crate::fs_hardening::{
    atomic_write_private, ensure_private_dir_all, open_nofollow_append_create,
    read_bounded_nofollow, redact_path_label,
};

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_FILE: &str = "state.json";
const EPOCH_FILE: &str = "store.epoch";
const SIGNING_KEY_FILE: &str = "signing.key";
const RECEIPT_WAL_FILE: &str = "receipts.wal.jsonl";
const MAX_SNAPSHOT_BYTES: usize = 16 * 1024 * 1024;
const MAX_WAL_BYTES: usize = 32 * 1024 * 1024;
const MAX_EPOCH_BYTES: usize = 128;

#[derive(Debug, thiserror::Error)]
pub enum StoreError {
    #[error("GRDR-LSTORE-0001: local store I/O failed at {path}: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-LSTORE-0002: local store JSON codec failed: {0}")]
    Codec(String),
    #[error("GRDR-LSTORE-0003: local store key initialization failed: {0}")]
    Key(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PersistedDaemonSnapshot {
    pub schema_version: u32,
    pub device_id: String,
    pub hostname: String,
    pub packs: Vec<PolicyPack>,
    pub grants: Vec<Grant>,
    #[serde(default)]
    pub revoked_grant_ids: Vec<String>,
    pub trusted_keys: Vec<TrustedKeyInfo>,
    pub kill_switch: KillSwitchState,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<DecisionReceipt>,
    pub pending_attempts: Vec<ActionAttempt>,
    pub pending_receipts: Vec<DecisionReceipt>,
}

#[derive(Debug, Clone)]
pub struct LocalStore {
    root_dir: PathBuf,
}

impl LocalStore {
    pub fn open(root_dir: PathBuf) -> Result<Self, StoreError> {
        ensure_private_dir_all(&root_dir).map_err(|detail| StoreError::Io {
            path: redact_path_label(&root_dir),
            detail,
        })?;
        Ok(Self { root_dir })
    }

    #[must_use]
    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn load_or_create_signing_key(&self) -> Result<SigningKeypair, StoreError> {
        load_or_create_keypair(&self.root_dir.join(SIGNING_KEY_FILE))
            .map_err(|e| StoreError::Key(e.to_string()))
    }

    pub fn current_epoch(&self) -> Result<u64, StoreError> {
        let path = self.root_dir.join(EPOCH_FILE);
        let raw = match read_bounded_nofollow(&path, MAX_EPOCH_BYTES) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(0),
            Err(err) => {
                return Err(StoreError::Io {
                    path: redact_path_label(&path),
                    detail: err.to_string(),
                });
            }
        };
        let text = std::str::from_utf8(&raw)
            .map_err(|e| StoreError::Codec(format!("invalid epoch UTF-8: {e}")))?;
        text.trim()
            .parse::<u64>()
            .map_err(|e| StoreError::Codec(format!("corrupt store epoch counter: {e}")))
    }

    pub fn advance_epoch(&self) -> Result<u64, StoreError> {
        let next = self
            .current_epoch()?
            .checked_add(1)
            .ok_or_else(|| StoreError::Codec("epoch counter overflow".to_string()))?;
        let path = self.root_dir.join(EPOCH_FILE);
        atomic_write_private(&path, format!("{next}\n").as_bytes()).map_err(|detail| {
            StoreError::Io {
                path: redact_path_label(&path),
                detail,
            }
        })?;
        Ok(next)
    }

    pub fn load_snapshot(&self) -> Result<Option<PersistedDaemonSnapshot>, StoreError> {
        let path = self.root_dir.join(SNAPSHOT_FILE);
        let raw = match read_bounded_nofollow(&path, MAX_SNAPSHOT_BYTES) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => {
                return Err(StoreError::Io {
                    path: redact_path_label(&path),
                    detail: err.to_string(),
                });
            }
        };
        let snap: PersistedDaemonSnapshot =
            serde_json::from_slice(&raw).map_err(|e| StoreError::Codec(e.to_string()))?;
        if snap.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(StoreError::Codec(format!(
                "unsupported snapshot schema_version {}",
                snap.schema_version
            )));
        }
        Ok(Some(snap))
    }

    pub fn save_snapshot(&self, snapshot: &PersistedDaemonSnapshot) -> Result<(), StoreError> {
        if snapshot.schema_version != SNAPSHOT_SCHEMA_VERSION {
            return Err(StoreError::Codec(format!(
                "unsupported snapshot schema_version {}",
                snapshot.schema_version
            )));
        }
        let path = self.root_dir.join(SNAPSHOT_FILE);
        let bytes =
            serde_json::to_vec_pretty(snapshot).map_err(|e| StoreError::Codec(e.to_string()))?;
        atomic_write_private(&path, &bytes).map_err(|detail| StoreError::Io {
            path: redact_path_label(&path),
            detail,
        })
    }

    pub fn append_receipt_wal(&self, receipt: &DecisionReceipt) -> Result<(), StoreError> {
        let wal_path = self.root_dir.join(RECEIPT_WAL_FILE);
        let mut line =
            serde_json::to_string(receipt).map_err(|e| StoreError::Codec(e.to_string()))?;
        line.push('\n');
        let line_len = u64::try_from(line.len()).unwrap_or(u64::MAX);
        let mut file = open_nofollow_append_create(&wal_path).map_err(|e| StoreError::Io {
            path: redact_path_label(&wal_path),
            detail: e.to_string(),
        })?;
        let current_len = file
            .metadata()
            .map_err(|e| StoreError::Io {
                path: redact_path_label(&wal_path),
                detail: e.to_string(),
            })?
            .len();
        let next_len = current_len.saturating_add(line_len);
        if next_len > u64::try_from(MAX_WAL_BYTES).unwrap_or(u64::MAX) {
            return Err(StoreError::Io {
                path: redact_path_label(&wal_path),
                detail: "receipt WAL exceeded maximum size cap".to_string(),
            });
        }
        file.write_all(line.as_bytes())
            .map_err(|e| StoreError::Io {
                path: redact_path_label(&wal_path),
                detail: e.to_string(),
            })?;
        if receipt.verdict != Verdict::Allow {
            file.sync_all().map_err(|e| StoreError::Io {
                path: redact_path_label(&wal_path),
                detail: e.to_string(),
            })?;
        }
        Ok(())
    }

    pub fn read_receipt_wal(&self) -> Result<Vec<DecisionReceipt>, StoreError> {
        let wal_path = self.root_dir.join(RECEIPT_WAL_FILE);
        let raw = match read_bounded_nofollow(&wal_path, MAX_WAL_BYTES) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
            Err(err) => {
                return Err(StoreError::Io {
                    path: redact_path_label(&wal_path),
                    detail: err.to_string(),
                });
            }
        };
        let reader = BufReader::new(std::io::Cursor::new(raw));
        let mut out = Vec::new();
        for line_res in reader.lines() {
            let line = line_res.map_err(|e| StoreError::Io {
                path: redact_path_label(&wal_path),
                detail: e.to_string(),
            })?;
            let trimmed = line.trim();
            if trimmed.is_empty() {
                continue;
            }
            let receipt: DecisionReceipt =
                serde_json::from_str(trimmed).map_err(|e| StoreError::Codec(e.to_string()))?;
            out.push(receipt);
        }
        Ok(out)
    }
}

impl From<StoreError> for CodedError {
    fn from(err: StoreError) -> Self {
        match err {
            StoreError::Codec(detail) => CodedError::new(
                CODE_STORE_CORRUPT,
                detail,
                "Check or remove corrupted store JSON state.",
            ),
            StoreError::Io { path, detail } => CodedError::new(
                CODE_STORE_IO,
                format!("{path}: {detail}"),
                "Verify directory permissions in daemon data dir.",
            ),
            StoreError::Key(detail) => CodedError::new(
                CODE_STORE_IO,
                detail,
                "Verify signing key permissions in daemon data dir.",
            ),
        }
    }
}

impl From<&PortSnapshot> for PersistedDaemonSnapshot {
    fn from(s: &PortSnapshot) -> Self {
        Self {
            schema_version: s.schema_version,
            device_id: s.device_id.clone(),
            hostname: s.hostname.clone(),
            packs: s.packs.clone(),
            grants: s.grants.clone(),
            revoked_grant_ids: Vec::new(),
            trusted_keys: s.trusted_keys.clone(),
            kill_switch: s.kill_switch.clone(),
            attempts: s.attempts.clone(),
            receipts: s.receipts.clone(),
            pending_attempts: s.pending_attempts.clone(),
            pending_receipts: s.pending_receipts.clone(),
        }
    }
}

impl From<PersistedDaemonSnapshot> for PortSnapshot {
    fn from(s: PersistedDaemonSnapshot) -> Self {
        Self {
            schema_version: s.schema_version,
            device_id: s.device_id,
            hostname: s.hostname,
            packs: s.packs,
            grants: s.grants,
            trusted_keys: s.trusted_keys,
            kill_switch: s.kill_switch,
            attempts: s.attempts,
            receipts: s.receipts,
            pending_attempts: s.pending_attempts,
            pending_receipts: s.pending_receipts,
        }
    }
}

impl StorePort for LocalStore {
    fn save_snapshot(&self, snapshot: &PortSnapshot) -> Result<(), CodedError> {
        let converted = PersistedDaemonSnapshot::from(snapshot);
        self.save_snapshot(&converted).map_err(CodedError::from)
    }

    fn load_snapshot(&self) -> Result<Option<PortSnapshot>, CodedError> {
        let loaded = self.load_snapshot().map_err(CodedError::from)?;
        Ok(loaded.map(PortSnapshot::from))
    }

    fn append_receipt(&self, receipt: &DecisionReceipt) -> Result<(), CodedError> {
        self.append_receipt_wal(receipt).map_err(CodedError::from)
    }

    fn read_receipts(&self) -> Result<Vec<DecisionReceipt>, CodedError> {
        self.read_receipt_wal().map_err(CodedError::from)
    }
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;
    use grdr_model::eval::essentials_pack;
    use grdr_model::{ActionClass, ControlPoint, Mode};
    use jiff::Timestamp;

    #[test]
    fn persists_snapshot_signing_key_and_fsynced_non_allow_wal() {
        let dir = std::env::temp_dir().join(format!("grdr-store-local-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);

        let store = LocalStore::open(dir.clone()).unwrap();
        let kp1 = store.load_or_create_signing_key().unwrap();
        assert!(store.load_snapshot().unwrap().is_none());

        let now = Timestamp::from_second(1_700_000_000).unwrap();
        let receipt = DecisionReceipt {
            receipt_id: "rcp-1".into(),
            attempt_id: "att-1".into(),
            session_id: "sess-1".into(),
            device_id: "dev-1".into(),
            agent_name: "claude-code".into(),
            action_class: ActionClass::FileWrite,
            control_point: ControlPoint::Hook,
            target: ".claude/settings.json".into(),
            verdict: Verdict::Deny,
            would_be: None,
            rule_id: Some("essentials.agent-control-files".into()),
            pack_id: Some("pack-essentials-slice0".into()),
            mode_applied: Some(Mode::Block),
            grant_id: None,
            reason: "Blocked".into(),
            next_step: "Pick safe path".into(),
            receipt_digest: "deadbeef".into(),
            decided_at: now,
            key_id: None,
            signature: None,
            signature_verified: None,
        };

        use grdr_model::SigningKeypairExt as _;
        let snapshot = PersistedDaemonSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            device_id: "dev-1".into(),
            hostname: "workstation".into(),
            packs: vec![essentials_pack()],
            grants: vec![],
            revoked_grant_ids: vec!["gr-revoked-1".into()],
            trusted_keys: vec![kp1.public_info()],
            kill_switch: KillSwitchState::Inactive,
            attempts: vec![],
            receipts: vec![receipt.clone()],
            pending_attempts: vec![],
            pending_receipts: vec![receipt.clone()],
        };
        store.save_snapshot(&snapshot).unwrap();
        store.append_receipt_wal(&receipt).unwrap();
        let epoch1 = store.advance_epoch().unwrap();
        assert_eq!(epoch1, 1);

        let reopened = LocalStore::open(dir.clone()).unwrap();
        let kp2 = reopened.load_or_create_signing_key().unwrap();
        assert_eq!(kp1.key_id(), kp2.key_id());
        assert_eq!(reopened.current_epoch().unwrap(), 1);

        let loaded = reopened.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.pending_receipts.len(), 1);
        assert_eq!(loaded.trusted_keys.len(), 1);
        assert_eq!(loaded.revoked_grant_ids, vec!["gr-revoked-1"]);

        let wal = reopened.read_receipt_wal().unwrap();
        assert_eq!(wal.len(), 1);
        assert_eq!(wal[0].receipt_id, "rcp-1");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn local_store_satisfies_store_port_contract() {
        let dir =
            std::env::temp_dir().join(format!("grdr-store-local-contract-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        let store = LocalStore::open(dir.clone()).unwrap();
        grdr_ports_testkit::assert_store_port_contract(&store).unwrap();
        let _ = fs::remove_dir_all(&dir);
    }
}
