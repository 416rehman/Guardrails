// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Persistent Ed25519-authenticated TUF root & monotonic watermark state (`tuf-state.journal.json`)
//! and strict cryptographic `FreshnessStatement` verification.

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_update::{
    FreshnessStatement, RootMetadata, SignedMetadata, SnapshotMetadata, TufRole, TufRootKind,
    canonical_sha256,
};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::dsse_guard::decode_ed25519_pubkey_b64_strict;
use crate::error::UpdaterError;
use crate::fs_safe::{atomic_write_bytes, path_exists_nofollow, read_bounded_bytes};

const TUF_JOURNAL_FILE: &str = "tuf-state.journal.json";
const TUF_JOURNAL_DOMAIN: &str = "grdr-tuf-state-v1";
const TUF_SIG_DOMAIN: &str = "tuf.metadata.v1";
const MAX_TUF_JOURNAL_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct TufJournalState {
    pub project_root: SignedMetadata<RootMetadata>,
    pub deployment_root: Option<SignedMetadata<RootMetadata>>,
    pub timestamps: BTreeMap<String, u64>,
    pub snapshots: BTreeMap<String, u64>,
    pub targets: BTreeMap<String, u64>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
struct SignedTufJournal {
    state: TufJournalState,
    key_id: String,
    signature_b64: String,
}

pub(crate) fn load_or_init_tuf_state(
    state_root: &Path,
    signer: &SigningKeypair,
    cli_project_root: SignedMetadata<RootMetadata>,
    cli_deployment_root: Option<SignedMetadata<RootMetadata>>,
) -> Result<TufJournalState, UpdaterError> {
    let journal_path = state_root.join(TUF_JOURNAL_FILE);
    if path_exists_nofollow(&journal_path)? {
        let loaded = load_verified_tuf_journal(&journal_path, signer)?;
        if cli_project_root.signed.version > loaded.project_root.signed.version {
            return Err(UpdaterError::TufVerification {
                detail: "CLI project root version cannot override persisted TUF root state"
                    .to_string(),
            });
        }
        if cli_project_root.signed.version < loaded.project_root.signed.version {
            return Err(UpdaterError::StaleOrRollback {
                detail: format!(
                    "refusing root version downgrade ({} < persisted {})",
                    cli_project_root.signed.version, loaded.project_root.signed.version
                ),
            });
        }
        if let (Some(cli_dep), Some(loaded_dep)) = (
            cli_deployment_root.as_ref(),
            loaded.deployment_root.as_ref(),
        ) && cli_dep.signed.version != loaded_dep.signed.version
        {
            return Err(UpdaterError::StaleOrRollback {
                detail: format!(
                    "CLI deployment root version {} mismatches persisted {}",
                    cli_dep.signed.version, loaded_dep.signed.version
                ),
            });
        }
        return Ok(loaded);
    }

    let state = TufJournalState {
        project_root: cli_project_root,
        deployment_root: cli_deployment_root,
        timestamps: BTreeMap::new(),
        snapshots: BTreeMap::new(),
        targets: BTreeMap::new(),
    };
    persist_tuf_journal(state_root, signer, &state)?;
    Ok(state)
}

pub(crate) fn persist_tuf_journal(
    state_root: &Path,
    signer: &SigningKeypair,
    state: &TufJournalState,
) -> Result<(), UpdaterError> {
    let canonical = serde_json::to_vec(state).map_err(|e| UpdaterError::Io {
        detail: format!("failed to canonicalize TUF journal: {e}"),
    })?;
    let sig = signer.sign_bytes(TUF_JOURNAL_DOMAIN, &canonical);
    let envelope = SignedTufJournal {
        state: state.clone(),
        key_id: signer.key_id().to_string(),
        signature_b64: sig,
    };
    let encoded = serde_json::to_vec_pretty(&envelope).map_err(|e| UpdaterError::Io {
        detail: format!("failed to encode TUF journal: {e}"),
    })?;
    atomic_write_bytes(&state_root.join(TUF_JOURNAL_FILE), &encoded)
}

fn load_verified_tuf_journal(
    path: &Path,
    signer: &SigningKeypair,
) -> Result<TufJournalState, UpdaterError> {
    let raw = read_bounded_bytes(path, MAX_TUF_JOURNAL_BYTES)?;
    let envelope: SignedTufJournal =
        serde_json::from_slice(&raw).map_err(|e| UpdaterError::TufVerification {
            detail: format!("corrupt TUF journal: {e}"),
        })?;
    if envelope.key_id != signer.key_id() {
        return Err(UpdaterError::TufVerification {
            detail: "TUF journal signer key_id mismatch".to_string(),
        });
    }
    let canonical = serde_json::to_vec(&envelope.state).map_err(|e| UpdaterError::Io {
        detail: format!("failed to canonicalize TUF journal: {e}"),
    })?;
    verify_bytes(
        &signer.public_key_b64(),
        TUF_JOURNAL_DOMAIN,
        &canonical,
        &envelope.signature_b64,
    )
    .map_err(|_| UpdaterError::TufVerification {
        detail: "TUF journal Ed25519 verification failed (tamper detected)".to_string(),
    })?;
    Ok(envelope.state)
}

pub(crate) fn check_persisted_versions(
    state: &TufJournalState,
    kind: TufRootKind,
    ts_ver: u64,
    snap_ver: u64,
    tgt_ver: u64,
    bin_ver: Option<u64>,
) -> Result<(), UpdaterError> {
    let kind_key = root_kind_key(kind);
    if let Some(&prev) = state.timestamps.get(kind_key)
        && ts_ver < prev
    {
        return Err(UpdaterError::StaleOrRollback {
            detail: format!("{kind_key}::timestamp rollback {ts_ver} < {prev}"),
        });
    }
    if let Some(&prev) = state.snapshots.get(kind_key)
        && snap_ver < prev
    {
        return Err(UpdaterError::StaleOrRollback {
            detail: format!("{kind_key}::snapshot rollback {snap_ver} < {prev}"),
        });
    }
    let tgt_key = format!("{kind_key}::targets");
    if let Some(&prev) = state.targets.get(&tgt_key)
        && tgt_ver < prev
    {
        return Err(UpdaterError::StaleOrRollback {
            detail: format!("{tgt_key} rollback {tgt_ver} < {prev}"),
        });
    }
    if let Some(bv) = bin_ver {
        let bin_key = format!("{kind_key}::binaries");
        if let Some(&prev) = state.targets.get(&bin_key)
            && bv < prev
        {
            return Err(UpdaterError::StaleOrRollback {
                detail: format!("{bin_key} rollback {bv} < {prev}"),
            });
        }
    }
    Ok(())
}

pub(crate) fn record_persisted_versions(
    state: &mut TufJournalState,
    kind: TufRootKind,
    ts_ver: u64,
    snap_ver: u64,
    tgt_ver: u64,
    bin_ver: Option<u64>,
) {
    let kind_key = root_kind_key(kind).to_string();
    state.timestamps.insert(kind_key.clone(), ts_ver);
    state.snapshots.insert(kind_key.clone(), snap_ver);
    state
        .targets
        .insert(format!("{kind_key}::targets"), tgt_ver);
    if let Some(bv) = bin_ver {
        state.targets.insert(format!("{kind_key}::binaries"), bv);
    }
}

pub(crate) fn root_kind_key(kind: TufRootKind) -> &'static str {
    match kind {
        TufRootKind::Project => "project",
        TufRootKind::Deployment => "deployment",
    }
}

pub(crate) fn verify_freshness_statement_strict(
    deployment_root: &RootMetadata,
    stmt: &SignedMetadata<FreshnessStatement>,
    snapshot: &SnapshotMetadata,
    project_root_version: u64,
    now: Timestamp,
) -> Result<(), UpdaterError> {
    if deployment_root.expires <= now {
        return Err(UpdaterError::StaleOrRollback {
            detail: "deployment root expired; cannot verify FreshnessStatement".to_string(),
        });
    }
    let role_def = deployment_root.roles.get(&TufRole::Fleet).ok_or_else(|| {
        UpdaterError::TufVerification {
            detail: "deployment root lacks Fleet role for FreshnessStatement".to_string(),
        }
    })?;
    if role_def.threshold == 0 || stmt.signatures.is_empty() {
        return Err(UpdaterError::TufVerification {
            detail: "FreshnessStatement missing required Fleet signatures".to_string(),
        });
    }
    let canonical =
        serde_json::to_vec(&stmt.signed).map_err(|e| UpdaterError::TufVerification {
            detail: format!("serialize FreshnessStatement: {e}"),
        })?;
    let mut seen_kids = BTreeSet::new();
    let mut seen_pks = BTreeSet::new();
    let mut valid = 0u32;
    for sig in &stmt.signatures {
        if !seen_kids.insert(sig.keyid.as_str()) {
            continue;
        }
        if !role_def.key_ids.iter().any(|k| k == &sig.keyid) {
            continue;
        }
        let Some(info) = deployment_root.keys.get(&sig.keyid) else {
            continue;
        };
        let raw_pk = decode_ed25519_pubkey_b64_strict(&info.public_key_b64)?;
        if !seen_pks.insert(raw_pk) {
            continue;
        }
        if verify_bytes(&info.public_key_b64, TUF_SIG_DOMAIN, &canonical, &sig.sig).is_ok() {
            valid = valid.saturating_add(1);
        }
    }
    if valid < role_def.threshold {
        return Err(UpdaterError::TufVerification {
            detail: "FreshnessStatement Fleet signature verification failed".to_string(),
        });
    }
    if stmt.signed.expires <= now {
        return Err(UpdaterError::StaleOrRollback {
            detail: "FreshnessStatement is expired".to_string(),
        });
    }
    if stmt.signed.project_root_version != project_root_version
        || stmt.signed.project_snapshot_version != snapshot.version
    {
        return Err(UpdaterError::StaleOrRollback {
            detail: "FreshnessStatement snapshot or project root version mismatch".to_string(),
        });
    }
    let snap_bytes = serde_json::to_vec(snapshot).map_err(|e| UpdaterError::TufVerification {
        detail: format!("serialize SnapshotMetadata: {e}"),
    })?;
    if canonical_sha256(&snap_bytes) != stmt.signed.project_snapshot_sha256 {
        return Err(UpdaterError::StaleOrRollback {
            detail: "FreshnessStatement snapshot SHA-256 mismatch".to_string(),
        });
    }
    Ok(())
}
