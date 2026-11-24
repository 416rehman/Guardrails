// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use grdr_crypto::{SigningKeypair, load_or_create_keypair};
use grdr_model::error::{CODE_STORE_CORRUPT, CODE_STORE_IO};
use grdr_model::{
    ActionAttempt, CodedError, DecisionReceipt, Grant, KillSwitchState, PolicyPack, TrustedKeyInfo,
    Verdict,
};
use grdr_ports::{PortSnapshot, StorePort};

pub const SNAPSHOT_SCHEMA_VERSION: u32 = 1;
const SNAPSHOT_FILE: &str = "state.json";
const SIGNING_KEY_FILE: &str = "signing.key";
const RECEIPT_WAL_FILE: &str = "receipts.wal.jsonl";

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
pub struct PersistedDaemonSnapshot {
    pub schema_version: u32,
    pub device_id: String,
    pub hostname: String,
    pub packs: Vec<PolicyPack>,
    pub grants: Vec<Grant>,
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
        fs::create_dir_all(&root_dir).map_err(|e| StoreError::Io {
            path: root_dir.display().to_string(),
            detail: e.to_string(),
        })?;
        Ok(Self { root_dir })
    }

    pub fn root_dir(&self) -> &Path {
        &self.root_dir
    }

    pub fn load_or_create_signing_key(&self) -> Result<SigningKeypair, StoreError> {
        load_or_create_keypair(&self.root_dir.join(SIGNING_KEY_FILE))
            .map_err(|e| StoreError::Key(e.to_string()))
    }

    pub fn load_snapshot(&self) -> Result<Option<PersistedDaemonSnapshot>, StoreError> {
        let path = self.root_dir.join(SNAPSHOT_FILE);
        if !path.is_file() {
            return Ok(None);
        }
        let raw = fs::read_to_string(&path).map_err(|e| StoreError::Io {
            path: path.display().to_string(),
            detail: e.to_string(),
        })?;
        let parsed: PersistedDaemonSnapshot =
            serde_json::from_str(&raw).map_err(|e| StoreError::Codec(e.to_string()))?;
        Ok(Some(parsed))
    }

    pub fn save_snapshot(&self, snapshot: &PersistedDaemonSnapshot) -> Result<(), StoreError> {
        let final_path = self.root_dir.join(SNAPSHOT_FILE);
        let tmp_path = self.root_dir.join("state.json.tmp");
        let bytes =
            serde_json::to_vec_pretty(snapshot).map_err(|e| StoreError::Codec(e.to_string()))?;

        let mut file = OpenOptions::new()
            .create(true)
            .write(true)
            .truncate(true)
            .open(&tmp_path)
            .map_err(|e| StoreError::Io {
                path: tmp_path.display().to_string(),
                detail: e.to_string(),
            })?;
        file.write_all(&bytes).map_err(|e| StoreError::Io {
            path: tmp_path.display().to_string(),
            detail: e.to_string(),
        })?;
        file.sync_all().map_err(|e| StoreError::Io {
            path: tmp_path.display().to_string(),
            detail: e.to_string(),
        })?;
        drop(file);

        fs::rename(&tmp_path, &final_path).map_err(|e| StoreError::Io {
            path: final_path.display().to_string(),
            detail: e.to_string(),
        })?;
        Ok(())
    }

    pub fn append_receipt_wal(&self, receipt: &DecisionReceipt) -> Result<(), StoreError> {
        let wal_path = self.root_dir.join(RECEIPT_WAL_FILE);
        let line = serde_json::to_string(receipt).map_err(|e| StoreError::Codec(e.to_string()))?;

        let mut file = OpenOptions::new()
            .create(true)
            .append(true)
            .open(&wal_path)
            .map_err(|e| StoreError::Io {
                path: wal_path.display().to_string(),
                detail: e.to_string(),
            })?;
        writeln!(file, "{line}").map_err(|e| StoreError::Io {
            path: wal_path.display().to_string(),
            detail: e.to_string(),
        })?;
        if receipt.verdict != Verdict::Allow {
            file.sync_all().map_err(|e| StoreError::Io {
                path: wal_path.display().to_string(),
                detail: e.to_string(),
            })?;
        }
        Ok(())
    }

    pub fn read_receipt_wal(&self) -> Result<Vec<DecisionReceipt>, StoreError> {
        let wal_path = self.root_dir.join(RECEIPT_WAL_FILE);
        if !wal_path.is_file() {
            return Ok(Vec::new());
        }
        let file = fs::File::open(&wal_path).map_err(|e| StoreError::Io {
            path: wal_path.display().to_string(),
            detail: e.to_string(),
        })?;
        let reader = BufReader::new(file);
        let mut out = Vec::new();
        for line_res in reader.lines() {
            let line = line_res.map_err(|e| StoreError::Io {
                path: wal_path.display().to_string(),
                detail: e.to_string(),
            })?;
            if line.trim().is_empty() {
                continue;
            }
            let receipt: DecisionReceipt =
                serde_json::from_str(&line).map_err(|e| StoreError::Codec(e.to_string()))?;
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

        let snapshot = PersistedDaemonSnapshot {
            schema_version: SNAPSHOT_SCHEMA_VERSION,
            device_id: "dev-1".into(),
            hostname: "workstation".into(),
            packs: vec![essentials_pack()],
            grants: vec![],
            trusted_keys: vec![kp1.public_info()],
            kill_switch: KillSwitchState::Inactive,
            attempts: vec![],
            receipts: vec![receipt.clone()],
            pending_attempts: vec![],
            pending_receipts: vec![receipt.clone()],
        };
        store.save_snapshot(&snapshot).unwrap();
        store.append_receipt_wal(&receipt).unwrap();

        let reopened = LocalStore::open(dir.clone()).unwrap();
        let kp2 = reopened.load_or_create_signing_key().unwrap();
        assert_eq!(kp1.key_id(), kp2.key_id());

        let loaded = reopened.load_snapshot().unwrap().unwrap();
        assert_eq!(loaded.pending_receipts.len(), 1);
        assert_eq!(loaded.trusted_keys.len(), 1);

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
