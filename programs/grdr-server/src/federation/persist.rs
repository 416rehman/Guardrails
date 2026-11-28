// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};

use grdr_crypto::AeadKey;
use grdr_identity::locator::{is_reparse_or_symlink, open_regular_nofollow};
use grdr_identity::standards_adapters::TokenStatusList;
use grdr_model::CodedError;
use grdr_model::error::{CODE_STORE_CORRUPT, CODE_STORE_IO};
use jiff::Timestamp;
use zeroize::Zeroizing;

use crate::store::StorageBackend;

use super::runtime::api_internal;
use super::types::{
    FEDERATION_STATE_FILENAME, FedError, FederationDefaultsConfig, FederationLimits,
    FederationRuntime, PersistedFederationSnapshot,
};

const DEFAULTS_JSON: &str = include_str!("defaults.json");
const SNAPSHOT_DOMAIN: &str = "grdr.fed.snapshot.v1";

pub fn load_defaults_config() -> (FederationDefaultsConfig, FederationLimits) {
    let defaults: FederationDefaultsConfig =
        serde_json::from_str(DEFAULTS_JSON).unwrap_or_else(|_| FederationDefaultsConfig {
            default_spiffe_domains: vec!["org-default".to_string(), "local".to_string()],
            allowed_oidc_scopes: vec!["broker:lease".to_string(), "identity:read".to_string()],
            trusted_federated_issuers: vec![],
            ssf_events_requested: vec![],
            max_snapshot_bytes: 33_554_432,
            device_expires_secs: 600,
            device_poll_interval_secs: 5,
        });
    let schema_limits = grdr_schema::limits::load_embedded_limits().ok();
    let max_outcomes = schema_limits
        .as_ref()
        .map_or(4_096, |l| l.broker.circuit_breaker.max_outcomes);
    let max_devices = schema_limits
        .as_ref()
        .and_then(|l| usize::try_from(l.server.enrolment.max_devices_default).ok())
        .unwrap_or(10_000);
    let max_skew_secs = schema_limits
        .as_ref()
        .and_then(|l| i64::try_from(l.server.preflight.clock_skew_http_fail_s).ok())
        .unwrap_or(60);
    let limits = FederationLimits {
        max_device_codes: max_outcomes,
        max_ssf_events: max_outcomes,
        max_leases: max_outcomes.saturating_mul(2),
        max_devices,
        max_skew_secs,
        max_snapshot_bytes: defaults.max_snapshot_bytes,
        device_expires_secs: defaults.device_expires_secs,
        device_poll_interval_secs: defaults.device_poll_interval_secs,
    };
    (defaults, limits)
}

pub fn resolve_state_dir(backend: &StorageBackend) -> Option<PathBuf> {
    match backend {
        StorageBackend::Memory => None,
        StorageBackend::Disk(dir) => Some(dir.clone()),
        StorageBackend::Ha { state_dir, .. } | StorageBackend::Distributed { state_dir, .. } => {
            Some(state_dir.clone())
        }
    }
}

pub fn load_snapshot_strict(
    dir: &Path,
    snapshot_key: &AeadKey,
    max_bytes: usize,
    rt: &mut FederationRuntime,
) -> Result<(), CodedError> {
    let path = dir.join(FEDERATION_STATE_FILENAME);
    let meta = match fs::symlink_metadata(&path) {
        Ok(m) => m,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(CodedError::new(
                CODE_STORE_IO,
                format!(
                    "Failed stat on federation snapshot {}: {err}",
                    path.display()
                ),
                "Verify directory permissions for federation snapshot.",
            ));
        }
    };
    if is_reparse_or_symlink(&meta) || !meta.is_file() {
        return Err(CodedError::new(
            CODE_STORE_CORRUPT,
            format!(
                "Refusing symlink or non-regular snapshot {}",
                path.display()
            ),
            "Replace snapshot with a regular file before restarting.",
        ));
    }
    let file = open_regular_nofollow(&path).map_err(|err| {
        CodedError::new(
            CODE_STORE_CORRUPT,
            format!(
                "Failed safely opening federation snapshot {}: {err}",
                path.display()
            ),
            "Replace snapshot with a regular non-symlink file before restarting.",
        )
    })?;
    let opened_meta = file.metadata().map_err(|err| {
        CodedError::new(
            CODE_STORE_IO,
            format!("Failed reading opened metadata {}: {err}", path.display()),
            "Verify snapshot file permissions.",
        )
    })?;
    if is_reparse_or_symlink(&opened_meta) || !opened_meta.is_file() {
        return Err(CodedError::new(
            CODE_STORE_CORRUPT,
            format!(
                "Snapshot {} changed into symlink during open",
                path.display()
            ),
            "Inspect federation state directory for tampering.",
        ));
    }
    let cap = u64::try_from(max_bytes.saturating_add(1)).unwrap_or(u64::MAX);
    let mut raw = Vec::new();
    file.take(cap).read_to_end(&mut raw).map_err(|err| {
        CodedError::new(
            CODE_STORE_IO,
            format!(
                "Failed reading federation snapshot {}: {err}",
                path.display()
            ),
            "Verify disk health.",
        )
    })?;
    if raw.len() > max_bytes {
        return Err(CodedError::new(
            CODE_STORE_CORRUPT,
            format!(
                "Federation snapshot {} exceeds max allowed bytes",
                path.display()
            ),
            "Inspect oversized snapshot file.",
        ));
    }
    let sealed = String::from_utf8(raw).map_err(|_| {
        CodedError::new(
            CODE_STORE_CORRUPT,
            "Federation snapshot contains invalid UTF-8 envelope",
            "Restore backup snapshot or inspect tampering.",
        )
    })?;
    let bytes = Zeroizing::new(
        grdr_crypto::open_token(snapshot_key, SNAPSHOT_DOMAIN, b"snapshot", &sealed).map_err(
            |_| {
                CodedError::new(
                    CODE_STORE_CORRUPT,
                    "Federation snapshot AEAD verification failed (tampered or wrong key)",
                    "Restore valid snapshot matching signing key.",
                )
            },
        )?,
    );
    let snap: PersistedFederationSnapshot = serde_json::from_slice(&bytes).map_err(|err| {
        CodedError::new(
            CODE_STORE_CORRUPT,
            format!("Failed deserializing federation snapshot JSON: {err}"),
            "Restore valid snapshot before starting.",
        )
    })?;
    apply_snapshot(rt, snap)?;
    Ok(())
}

pub fn persist_snapshot_atomic(dir: &Path, rt: &FederationRuntime) -> Result<(), FedError> {
    fs::create_dir_all(dir)
        .map_err(|err| api_internal(&format!("failed to create federation dir: {err}")))?;
    let now_sec = Timestamp::now().as_second();
    let snap = PersistedFederationSnapshot {
        tenants: rt.tenants.clone(),
        active_jti_deny_list: rt.jti_deny_list.export_active(now_sec),
        active_id_jag_replay: rt.id_jag_replay.export_active(now_sec),
        active_ssf_jti_replay: rt.ssf_jti_replay.export_active(now_sec),
        active_oidc_enrol_replay: rt.oidc_enrol_jti_replay.export_active(now_sec),
        active_hw_nonce_replay: rt.hw_nonce_replay.export_active(now_sec),
    };
    let bytes = Zeroizing::new(
        serde_json::to_vec(&snap)
            .map_err(|e| api_internal(&format!("serialize federation snapshot: {e}")))?,
    );
    let sealed = Zeroizing::new(
        grdr_crypto::seal_token(&rt.snapshot_key, SNAPSHOT_DOMAIN, b"snapshot", &bytes)
            .map_err(|e| api_internal(&format!("encrypt federation snapshot: {e}")))?,
    );
    let target = dir.join(FEDERATION_STATE_FILENAME);
    let tmp = dir.join(format!("{FEDERATION_STATE_FILENAME}.tmp"));

    if let Ok(meta) = fs::symlink_metadata(&target)
        && is_reparse_or_symlink(&meta)
    {
        return Err(api_internal(
            "refusing symlink target for federation snapshot",
        ));
    }
    if let Ok(meta) = fs::symlink_metadata(&tmp) {
        if is_reparse_or_symlink(&meta) {
            return Err(api_internal(
                "refusing symlink tmp path for federation snapshot",
            ));
        }
        let _ = fs::remove_file(&tmp);
    }

    let mut opts = OpenOptions::new();
    opts.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut file = opts
        .open(&tmp)
        .map_err(|e| api_internal(&format!("create federation tmp snapshot: {e}")))?;
    file.write_all(sealed.as_bytes())
        .map_err(|e| api_internal(&format!("write federation snapshot: {e}")))?;
    file.sync_all()
        .map_err(|e| api_internal(&format!("sync federation snapshot: {e}")))?;
    drop(file);

    fs::rename(&tmp, &target)
        .map_err(|e| api_internal(&format!("rename federation snapshot: {e}")))?;
    Ok(())
}

fn apply_snapshot(
    rt: &mut FederationRuntime,
    mut snap: PersistedFederationSnapshot,
) -> Result<(), CodedError> {
    let now_sec = Timestamp::now().as_second();
    for tenant in snap.tenants.values_mut() {
        let mut status_list = if tenant.status_list_bytes.is_empty() {
            TokenStatusList::with_capacity_bits(4096)
        } else {
            TokenStatusList::from_bytes(tenant.status_list_bytes.clone()).map_err(|err| {
                CodedError::new(
                    CODE_STORE_CORRUPT,
                    format!("Corrupt status list in snapshot: {err}"),
                    "Restore valid federation snapshot.",
                )
            })?
        };
        for lease in &tenant.leases {
            if lease.revoked {
                let _ = rt.jti_deny_list.revoke(
                    lease.jti.clone(),
                    lease.expires_at.max(now_sec.saturating_add(900)),
                    now_sec,
                );
                status_list
                    .set_revoked(lease.status_index, true)
                    .map_err(|err| {
                        CodedError::new(
                            CODE_STORE_CORRUPT,
                            format!("Failed restoring status bit: {err}"),
                            "Restore valid federation snapshot.",
                        )
                    })?;
            }
            tenant.next_status_index = tenant
                .next_status_index
                .max(lease.status_index.saturating_add(1));
        }
        tenant.status_list_bytes = status_list.as_bytes().to_vec();
        tenant.status_list = status_list;
    }
    rt.tenants = snap.tenants;
    rt.jti_deny_list
        .import_active(snap.active_jti_deny_list, now_sec);
    rt.id_jag_replay
        .import_active(snap.active_id_jag_replay, now_sec);
    rt.ssf_jti_replay
        .import_active(snap.active_ssf_jti_replay, now_sec);
    rt.oidc_enrol_jti_replay
        .import_active(snap.active_oidc_enrol_replay, now_sec);
    rt.hw_nonce_replay
        .import_active(snap.active_hw_nonce_replay, now_sec);
    Ok(())
}
