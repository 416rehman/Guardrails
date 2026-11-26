// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

//! Ephemeral and strictly read-only `--self-test` routines for `grdr-daemon`.

use std::path::Path;

use grdr_crypto::load_or_create_keypair;
use grdr_fastpath::FastVerdict;
use grdr_model::InstallProfile;
use grdr_os_clock::{Clock, SystemClock};
use grdr_peer_os::fs_open::create_private_dir_all;
use grdr_store_local::LocalStore;
use grdr_store_local::checkpoint::load_and_verify_checkpoint_checked;
use grdr_store_local::fs_hardening::read_bounded_nofollow;
use grdr_wire::floor_bin::{FloorTableFreshness, MAX_FLOOR_BYTES, verify_and_decode_floor_table};
use grdr_wire::messages::{DecideRequestFrame, WireActionClass, WireControlPoint, WireVerdict};

use crate::DaemonError;
use crate::floor_compiler::CompiledFloorCache;
use crate::state::DaemonState;

pub(crate) fn run_ephemeral_self_test(state_override: Option<&Path>) -> Result<(), DaemonError> {
    let nonce = grdr_wire::generate_nonce().map_err(|e| {
        DaemonError::InitFailed(format!("ephemeral self-test nonce RNG failed: {e}"))
    })?;
    let short: String = nonce.chars().take(16).collect();
    let base =
        crate::dir_guard::private_ephemeral_base_dir().join(format!(".grdr-daem-self-{short}"));
    create_private_dir_all(&base).map_err(|e| DaemonError::InitFailed(e.to_string()))?;
    let state_dir = state_override
        .map(ToOwned::to_owned)
        .unwrap_or_else(|| base.join("state"));
    let test_res = (|| -> Result<(), DaemonError> {
        let state = DaemonState::initialize(base.clone(), state_dir, InstallProfile::User)
            .map_err(DaemonError::InitFailed)?;
        let _health = state.health_summary();
        let req = self_test_decide_request();
        let verdict = state
            .decide_request(&req, None)
            .map_err(DaemonError::RuntimeFailed)?;
        if verdict.verdict != WireVerdict::Block as i32 || !verdict.audit_fsynced {
            return Err(DaemonError::RuntimeFailed(
                "expected fsynced Block floor verdict in daemon self-test".to_string(),
            ));
        }
        Ok(())
    })();
    if let Err(err) = std::fs::remove_dir_all(&base) {
        tracing::warn!(error = %err, "cleanup ephemeral self-test dir failed");
    }
    test_res
}

pub(crate) fn run_readonly_self_test(data_dir: &Path, state_dir: &Path) -> Result<(), DaemonError> {
    let key_path = data_dir.join("daemon-signing.key");
    let floor_path = state_dir.join("floor.bin");
    let pub_path = state_dir.join("floor.pub");
    if !key_path.is_file() || !floor_path.is_file() || !pub_path.is_file() {
        return Err(DaemonError::InitFailed(
            "read-only self-test requires existing initialized --data-dir and --state-dir"
                .to_string(),
        ));
    }
    let key = load_or_create_keypair(&key_path)
        .map_err(|e| DaemonError::InitFailed(format!("verify signing key read-only: {e}")))?;
    let store = LocalStore::open(data_dir.join("snapshot-store"))
        .map_err(|e| DaemonError::InitFailed(e.to_string()))?;
    let _snap = store
        .load_snapshot()
        .map_err(|e| DaemonError::InitFailed(format!("verify snapshot read-only: {e}")))?;
    let raw_floor = read_bounded_nofollow(&floor_path, MAX_FLOOR_BYTES)
        .map_err(|e| DaemonError::InitFailed(format!("read floor.bin: {e}")))?;
    let now_s = SystemClock::new()
        .now_wall()
        .map_err(|e| DaemonError::InitFailed(format!("clock unavailable: {e}")))?
        .as_second();
    let pub_b64 = key.public_key_b64();
    let pubkeys = [(key.key_id(), pub_b64.as_str())];
    let verified = verify_and_decode_floor_table(&raw_floor, &pubkeys, now_s)
        .map_err(|e| DaemonError::InitFailed(format!("verify floor.bin: {e}")))?;
    if !matches!(verified.freshness, FloorTableFreshness::Fresh) {
        return Err(DaemonError::InitFailed(
            "floor.bin expired during read-only self-test".to_string(),
        ));
    }
    let _ckpt =
        load_and_verify_checkpoint_checked(state_dir.join("audit.checkpoint"), &pub_b64, "", 0)
            .map_err(|e| DaemonError::InitFailed(format!("verify audit checkpoint: {e}")))?;
    let cache = CompiledFloorCache {
        epoch: verified.document.epoch,
        digest_hex: grdr_crypto::sha256_hex(&raw_floor),
        doc: verified.document,
    };
    let req = self_test_decide_request();
    let (v, _, _) = cache.evaluate_overload_fallback(
        req.action_class,
        &req.agent,
        &req.target,
        &req.command_line,
    );
    if v != FastVerdict::Deny {
        return Err(DaemonError::RuntimeFailed(
            "read-only floor self-test failed to block test rule".to_string(),
        ));
    }
    Ok(())
}

fn self_test_decide_request() -> DecideRequestFrame {
    DecideRequestFrame {
        request_id: "self-decide-1".to_string(),
        hook_seq: 1,
        agent: "claude-code".to_string(),
        control_point: WireControlPoint::Hook as i32,
        action_class: WireActionClass::Exec as i32,
        session_id: "self-sess".to_string(),
        target: "git commit --no-verify".to_string(),
        summary: "Bash".to_string(),
        command_line: "git commit --no-verify".to_string(),
        cwd: "/".to_string(),
        sha256: String::new(),
        emitted_mono_ms: 1,
        tool_name: "Bash".to_string(),
        raw_payload: Vec::new(),
    }
}
