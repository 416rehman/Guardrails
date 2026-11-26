// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::error::Error;
use std::process::{Child, Command, Stdio};

use grdr_crypto::SigningKeypair;
use grdr_ipc_os::proto_io::{DuplexPipe, ProtoIpcStream};
use grdr_model::api::TrustedKeyInfo;
use grdr_os_clock::ManualClock;
use grdr_update::{
    DsseTargetStatement, PackKind, RootKeyRole, RootMetadata, SnapshotMetadata, SnapshotTargetRef,
    TargetDescriptor, TargetsMetadata, TimestampMetadata, TufRole, TufRootKind, UpdateSlot,
    canonical_sha256, sign_dsse_envelope, sign_metadata,
};
use grdr_updater::slots::UpdateAuthority;
use grdr_updater::worker::{UpdaterWorkerConfig, UpdaterWorkerState};
use grdr_wire::frame::{IPC_WIRE_VERSION, WireFrame, WirePayload};
use grdr_wire::messages::{
    ChannelProfileKind, EndpointServiceKind, HeartbeatFrame, HelloFrame, UpdaterCommandFrame,
};
use grdr_wire::peer_auth::{ClientIdentityPolicy, OsPeerClaims, Profile, open};

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn updater_daemon_worker_handles_handshake_slots_p7_reject_and_handover_marker() {
    let res = run_updater_worker_test();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn updater_worker_enforces_pinned_roots_signed_floor_and_3crash_rollback() {
    let res = run_updater_worker_pinned_security_checks();
    assert!(res.is_ok(), "{res:?}");
}

fn run_updater_worker_test() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-updater");
    let root = std::env::temp_dir().join(format!("grdr-updater-it-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    std::fs::create_dir_all(&root)?;

    let cand_bin = root.join("candidate-slot-b.bin");
    std::fs::write(&cand_bin, b"untrusted-candidate")?;
    let init_slot_a = root.join("slot_a.bin");
    let init_sha = canonical_sha256(b"grdr-initial-slot-a");

    let mut child = ChildGuard(
        Command::new(exe)
            .args(["daemon-worker", "--state-root"])
            .arg(&root)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let stdin = child.0.stdin.take().ok_or("missing stdin")?;
    let stdout = child.0.stdout.take().ok_or("missing stdout")?;

    let (mut chan, ready) = open(
        ProtoIpcStream::new(DuplexPipe::new(stdout, stdin)),
        &OsPeerClaims::Inherited,
        0,
        &ClientIdentityPolicy {
            profile: Profile::Inherited,
            allowed_server_uids: Vec::new(),
            expected_windows_sids: Vec::new(),
            minimum_integrity_rid: 0,
            require_start_time_before_connect: false,
            require_kernel_peer_token: false,
        },
        HelloFrame {
            protocol_version: IPC_WIRE_VERSION,
            service: EndpointServiceKind::ProviderUpdater as i32,
            profile: ChannelProfileKind::Inherited as i32,
            client_nonce: uuid::Uuid::now_v7().as_bytes().to_vec(),
            pid: std::process::id(),
            capabilities: vec!["updater.v1".to_string()],
        },
        1_048_576,
    )?;
    if ready.protocol_version != IPC_WIRE_VERSION {
        return Err("unexpected updater ReadyFrame version".into());
    }

    chan.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::Heartbeat(HeartbeatFrame {
            seq: 1,
            monotonic_ms: 100,
            rss_bytes: 0,
            queue_depth: 0,
            epoch: 1,
        }),
    ))?;
    let hb = chan.recv_frame()?;
    let Some(WirePayload::Heartbeat(hb_frame)) = hb.payload else {
        return Err("expected Heartbeat reply from updater".into());
    };
    if hb_frame.rss_bytes == 0 {
        return Err("updater heartbeat must report live nonzero RSS".into());
    }

    chan.send_frame(WireFrame::with_payload(
        1,
        2,
        WirePayload::UpdaterCommand(UpdaterCommandFrame {
            command_id: "upd-slots-1".to_string(),
            action: "query_slots".to_string(),
            security_floor: 1,
            payload: Vec::new(),
        }),
    ))?;
    let q_reply = chan.recv_frame()?;
    let Some(WirePayload::UpdaterEvent(q_ev)) = q_reply.payload else {
        return Err("expected UpdaterEvent on query_slots".into());
    };
    if !q_ev.ok || q_ev.active_slot != "slot_a" || q_ev.security_floor < 1 || q_ev.handover_active {
        return Err(format!("unexpected slot state: {q_ev:?}").into());
    }

    // Wrong slot / wrong path must be refused.
    for (id, payload) in [
        (
            "bad-slot",
            serde_json::to_vec(&serde_json::json!({
                "slot": "slot_b",
                "binary_path": cand_bin,
                "expected_sha256": canonical_sha256(b"untrusted-candidate"),
                "window_ms": 1800
            }))?,
        ),
        (
            "bad-path",
            serde_json::to_vec(&serde_json::json!({
                "slot": "slot_a",
                "binary_path": cand_bin,
                "expected_sha256": init_sha,
                "window_ms": 1800
            }))?,
        ),
        (
            "bad-digest",
            serde_json::to_vec(&serde_json::json!({
                "slot": "slot_a",
                "binary_path": init_slot_a,
                "expected_sha256": canonical_sha256(b"wrong"),
                "window_ms": 1800
            }))?,
        ),
    ] {
        chan.send_frame(WireFrame::with_payload(
            1,
            3,
            WirePayload::UpdaterCommand(UpdaterCommandFrame {
                command_id: id.to_string(),
                action: "prepare_handover".to_string(),
                security_floor: 1,
                payload,
            }),
        ))?;
        let reply = chan.recv_frame()?;
        let Some(WirePayload::UpdaterEvent(ev)) = reply.payload else {
            return Err("expected UpdaterEvent".into());
        };
        if ev.ok {
            return Err(format!("{id} prepare_handover must fail closed: {ev:?}").into());
        }
    }

    // Valid active slot handover marker creation + non-destructive query_slots check.
    let handover_json = serde_json::json!({
        "slot": "slot_a",
        "binary_path": init_slot_a,
        "expected_sha256": init_sha,
        "window_ms": 1800
    });
    chan.send_frame(WireFrame::with_payload(
        1,
        4,
        WirePayload::UpdaterCommand(UpdaterCommandFrame {
            command_id: "upd-ho-1".to_string(),
            action: "prepare_handover".to_string(),
            security_floor: 1,
            payload: serde_json::to_vec(&handover_json)?,
        }),
    ))?;
    let ho_reply = chan.recv_frame()?;
    let Some(WirePayload::UpdaterEvent(ho_ev)) = ho_reply.payload else {
        return Err("expected UpdaterEvent on prepare_handover".into());
    };
    if !ho_ev.ok || !ho_ev.handover_active || !root.join("handover").is_file() {
        return Err(format!("handover marker creation failed: {ho_ev:?}").into());
    }

    chan.send_frame(WireFrame::with_payload(
        1,
        5,
        WirePayload::UpdaterCommand(UpdaterCommandFrame {
            command_id: "upd-slots-preserve".to_string(),
            action: "query_slots".to_string(),
            security_floor: 1,
            payload: Vec::new(),
        }),
    ))?;
    let q2 = chan.recv_frame()?;
    let Some(WirePayload::UpdaterEvent(q2_ev)) = q2.payload else {
        return Err("expected UpdaterEvent on query_slots".into());
    };
    if !q2_ev.handover_active {
        return Err("query_slots must be non-destructive to active handover marker".into());
    }

    // Verify P7 pack purity enforcement rejects forbidden fields fail-closed.
    chan.send_frame(WireFrame::with_payload(
        1,
        6,
        WirePayload::UpdaterCommand(UpdaterCommandFrame {
            command_id: "upd-p7-1".to_string(),
            action: "verify_pack_p7".to_string(),
            security_floor: 1,
            payload: br#"{"executablePath":"/bin/sh"}"#.to_vec(),
        }),
    ))?;
    let p7_reply = chan.recv_frame()?;
    let Some(WirePayload::UpdaterEvent(p7_ev)) = p7_reply.payload else {
        return Err("expected UpdaterEvent on verify_pack_p7".into());
    };
    if p7_ev.ok || p7_ev.error_code != "GRDR-UPDATER-0003" {
        return Err(format!("expected P7 purity rejection, got {p7_ev:?}").into());
    }

    drop(chan);
    drop(child);
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn run_updater_worker_pinned_security_checks() -> Result<(), Box<dyn Error>> {
    let now = jiff::Timestamp::from_second(1_760_000_000)?;
    let clock = ManualClock::new(now, std::time::Duration::from_secs(10));
    let root = std::env::temp_dir().join(format!("grdr-updater-pin-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);

    let root_signer = SigningKeypair::generate()?;
    let role_signer = SigningKeypair::generate()?;
    let mut keys = std::collections::BTreeMap::new();
    keys.insert(
        root_signer.key_id().to_string(),
        TrustedKeyInfo {
            key_id: root_signer.key_id().to_string(),
            public_key_b64: root_signer.public_key_b64(),
        },
    );
    keys.insert(
        role_signer.key_id().to_string(),
        TrustedKeyInfo {
            key_id: role_signer.key_id().to_string(),
            public_key_b64: role_signer.public_key_b64(),
        },
    );
    let expires = now.checked_add(jiff::Span::new().seconds(86_400))?;
    let mut roles = std::collections::BTreeMap::new();
    for r in [
        TufRole::Root,
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
        TufRole::Binaries,
    ] {
        roles.insert(
            r,
            RootKeyRole {
                key_ids: vec![if r == TufRole::Root {
                    root_signer.key_id().to_string()
                } else {
                    role_signer.key_id().to_string()
                }],
                threshold: 1,
            },
        );
    }
    let project_root = sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Project,
            version: 1,
            expires,
            keys,
            roles,
        },
        &[&root_signer],
    )?;

    // Unpinned worker must refuse verify_and_activate.
    let unpinned_dir = root.join("unpinned");
    let mut unpinned = UpdaterWorkerState::open(unpinned_dir)?;
    let unpinned_ev = unpinned.handle_command(
        &UpdaterCommandFrame {
            command_id: "unpinned-1".to_string(),
            action: "verify_and_activate".to_string(),
            security_floor: 1,
            payload: b"{}".to_vec(),
        },
        &clock,
    );
    if unpinned_ev.ok {
        return Err("unpinned worker must reject verify_and_activate".into());
    }

    // Pinned worker activates v2 cleanly on SlotB and rejects disallowed DSSE payload_type.
    let pinned_dir = root.join("pinned");
    let mut pinned = UpdaterWorkerState::open_with_config(
        pinned_dir,
        UpdaterWorkerConfig {
            authority: UpdateAuthority::SelfManaged,
            project_root: Some(project_root.clone()),
            deployment_root: None,
        },
        &clock,
    )?;

    let v2 = b"signed-slot-b-v2";
    let sha_v2 = canonical_sha256(v2);
    let mut targets_map = std::collections::BTreeMap::new();
    targets_map.insert(
        "bin/grdrd".to_string(),
        TargetDescriptor {
            role: TufRole::Binaries,
            pack_kind: PackKind::Binary,
            signer_class: grdr_update::SignerClass::ProjectBinaries,
            version: "0.2.0".to_string(),
            generation: 2,
            sha256: sha_v2.clone(),
            length: u64::try_from(v2.len())?,
        },
    );
    let bins = sign_metadata(
        TargetsMetadata {
            role: TufRole::Binaries,
            version: 2,
            expires,
            targets: targets_map.clone(),
        },
        &[&role_signer],
    )?;
    let targets = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 2,
            expires,
            targets: targets_map,
        },
        &[&role_signer],
    )?;
    let bin_bytes = serde_json::to_vec(&bins.signed)?;
    let tgt_bytes = serde_json::to_vec(&targets.signed)?;
    let mut snap_meta_map = std::collections::BTreeMap::new();
    snap_meta_map.insert(
        TufRole::Targets,
        SnapshotTargetRef {
            version: 2,
            sha256: canonical_sha256(&tgt_bytes),
            length: u64::try_from(tgt_bytes.len())?,
        },
    );
    snap_meta_map.insert(
        TufRole::Binaries,
        SnapshotTargetRef {
            version: 2,
            sha256: canonical_sha256(&bin_bytes),
            length: u64::try_from(bin_bytes.len())?,
        },
    );
    let snapshot = sign_metadata(
        SnapshotMetadata {
            version: 2,
            expires,
            meta: snap_meta_map,
        },
        &[&role_signer],
    )?;
    let snap_bytes = serde_json::to_vec(&snapshot.signed)?;
    let timestamp = sign_metadata(
        TimestampMetadata {
            version: 2,
            expires,
            snapshot: SnapshotTargetRef {
                version: 2,
                sha256: canonical_sha256(&snap_bytes),
                length: u64::try_from(snap_bytes.len())?,
            },
        },
        &[&role_signer],
    )?;

    let stmt_bytes = serde_json::to_vec(&DsseTargetStatement {
        target_path: "bin/grdrd".to_string(),
        sha256: sha_v2.clone(),
        length: u64::try_from(v2.len())?,
    })?;
    let bad_dsse = sign_dsse_envelope(
        "application/vnd.evil.unknown+json",
        &stmt_bytes,
        &[&role_signer],
    )?;
    let bad_ev = pinned.handle_command(
        &UpdaterCommandFrame {
            command_id: "bad-dsse-type".to_string(),
            action: "verify_and_activate".to_string(),
            security_floor: 99,
            payload: serde_json::to_vec(&serde_json::json!({
                "channel": "binary",
                "target_path": "bin/grdrd",
                "component_name": "grdr-daemon",
                "snapshot_published_unix_s": now.as_second(),
                "artifact_bytes": v2.to_vec(),
                "timestamp": timestamp,
                "snapshot": snapshot,
                "targets": targets,
                "binaries_targets": bins,
                "dsse_envelope": bad_dsse
            }))?,
        },
        &clock,
    );
    if bad_ev.ok {
        return Err("disallowed DSSE payload_type must fail closed".into());
    }

    // Idle confirm_commit must fail closed, and UNC handover path must fail before canonicalize.
    let idle_commit = pinned.handle_command(
        &UpdaterCommandFrame {
            command_id: "idle-commit".to_string(),
            action: "confirm_commit".to_string(),
            security_floor: 1,
            payload: Vec::new(),
        },
        &clock,
    );
    if idle_commit.ok {
        return Err("confirm_commit without pending activation must fail closed".into());
    }
    let unc_ho = pinned.handle_command(
        &UpdaterCommandFrame {
            command_id: "unc-handover".to_string(),
            action: "prepare_handover".to_string(),
            security_floor: 1,
            payload: serde_json::to_vec(&serde_json::json!({
                "slot": "slot_a",
                "binary_path": r"\\attacker.example\share\grdrd.exe",
                "expected_sha256": canonical_sha256(b"grdr-initial-slot-a"),
                "window_ms": 1800
            }))?,
        },
        &clock,
    );
    if unc_ho.ok {
        return Err("UNC network path in prepare_handover must fail closed".into());
    }

    // Signed statement security_floor > artifact generation must fail closed cleanly.
    let over_floor_stmt = serde_json::to_vec(&serde_json::json!({
        "target_path": "bin/grdrd",
        "sha256": sha_v2,
        "length": v2.len(),
        "security_floor": 99
    }))?;
    let over_floor_dsse = sign_dsse_envelope(
        "application/vnd.grdr.binary-manifest+json",
        &over_floor_stmt,
        &[&role_signer],
    )?;
    let over_floor_ev = pinned.handle_command(
        &UpdaterCommandFrame {
            command_id: "over-floor".to_string(),
            action: "verify_and_activate".to_string(),
            security_floor: 1,
            payload: serde_json::to_vec(&serde_json::json!({
                "channel": "binary",
                "target_path": "bin/grdrd",
                "component_name": "grdr-daemon",
                "snapshot_published_unix_s": now.as_second(),
                "artifact_bytes": v2.to_vec(),
                "timestamp": timestamp,
                "snapshot": snapshot,
                "targets": targets,
                "binaries_targets": bins,
                "dsse_envelope": over_floor_dsse
            }))?,
        },
        &clock,
    );
    if over_floor_ev.ok {
        return Err("signed floor exceeding target generation must fail closed".into());
    }

    // Unsigned cmd.security_floor = 99 must be ignored when DSSE statement does not sign it.
    let ok_dsse = sign_dsse_envelope(
        "application/vnd.grdr.binary-manifest+json",
        &stmt_bytes,
        &[&role_signer],
    )?;
    let ok_ev = pinned.handle_command(
        &UpdaterCommandFrame {
            command_id: "activate-v2".to_string(),
            action: "verify_and_activate".to_string(),
            security_floor: 99,
            payload: serde_json::to_vec(&serde_json::json!({
                "channel": "binary",
                "target_path": "bin/grdrd",
                "component_name": "grdr-daemon",
                "snapshot_published_unix_s": now.as_second(),
                "artifact_bytes": v2.to_vec(),
                "timestamp": timestamp,
                "snapshot": snapshot,
                "targets": targets,
                "binaries_targets": bins,
                "dsse_envelope": ok_dsse
            }))?,
        },
        &clock,
    );
    if !ok_ev.ok
        || ok_ev.active_slot != "slot_b"
        || ok_ev.security_floor != 1
        || !ok_ev.detail.contains(&sha_v2)
    {
        return Err(format!("expected SlotB activation preserving floor=1, got {ok_ev:?}").into());
    }

    // Drop and reopen worker on same state_root: persisted TUF watermarks survive restart and block v1 rollback.
    drop(pinned);
    let mut reopened = UpdaterWorkerState::open_with_config(
        root.join("pinned"),
        UpdaterWorkerConfig {
            authority: UpdateAuthority::SelfManaged,
            project_root: Some(project_root.clone()),
            deployment_root: None,
        },
        &clock,
    )?;
    let old_targets = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires,
            targets: std::collections::BTreeMap::new(),
        },
        &[&role_signer],
    )?;
    let stale_replay = reopened.handle_command(
        &UpdaterCommandFrame {
            command_id: "stale-tuf-after-restart".to_string(),
            action: "verify_and_activate".to_string(),
            security_floor: 1,
            payload: serde_json::to_vec(&serde_json::json!({
                "channel": "binary",
                "target_path": "bin/grdrd",
                "component_name": "grdr-daemon",
                "snapshot_published_unix_s": now.as_second(),
                "artifact_bytes": v2.to_vec(),
                "timestamp": timestamp,
                "snapshot": snapshot,
                "targets": old_targets,
                "binaries_targets": bins,
                "dsse_envelope": ok_dsse
            }))?,
        },
        &clock,
    );
    if stale_replay.ok {
        return Err("reopened updater must reject TUF metadata version rollback".into());
    }

    // 3 crashes within stabilization window auto-rollback cleanly to initial SlotA binary.
    for i in 1..=2 {
        let ev = reopened.handle_command(
            &UpdaterCommandFrame {
                command_id: format!("crash-{i}"),
                action: "record_crash".to_string(),
                security_floor: 1,
                payload: Vec::new(),
            },
            &clock,
        );
        if ev.active_slot != "slot_b" {
            return Err(format!("should not rollback before 3 crashes: {ev:?}").into());
        }
    }
    let crash3 = reopened.handle_command(
        &UpdaterCommandFrame {
            command_id: "crash-3".to_string(),
            action: "record_crash".to_string(),
            security_floor: 1,
            payload: Vec::new(),
        },
        &clock,
    );
    if !crash3.ok
        || crash3.active_slot != "slot_a"
        || !crash3.detail.contains("rolled-back-to:slot_a")
    {
        return Err(format!("3rd crash must rollback to real slot_a.bin: {crash3:?}").into());
    }
    let _ = UpdateSlot::SlotA;
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

#[test]
fn updater_rejects_duplicate_dsse_keys_and_tampered_freshness_statement() {
    use grdr_compat::CompatMatrix;
    use grdr_update::{DsseLimits, FreshnessStatement};
    use grdr_updater::verify::{DualRootVerifier, StagedUpdateBundle};

    let now = jiff::Timestamp::from_second(1_760_000_000).unwrap();
    let expires = now.checked_add(jiff::Span::new().seconds(86_400)).unwrap();
    let root_kp = SigningKeypair::generate().unwrap();
    let dup_kp = SigningKeypair::generate().unwrap();
    let fleet_kp = SigningKeypair::generate().unwrap();

    // Build root where two distinct key_ids carry identical [u8; 32] public key material (with whitespace).
    let mut keys = std::collections::BTreeMap::new();
    keys.insert(
        root_kp.key_id().to_string(),
        TrustedKeyInfo {
            key_id: root_kp.key_id().to_string(),
            public_key_b64: root_kp.public_key_b64(),
        },
    );
    keys.insert(
        "alias-1".to_string(),
        TrustedKeyInfo {
            key_id: "alias-1".to_string(),
            public_key_b64: dup_kp.public_key_b64(),
        },
    );
    keys.insert(
        "alias-2".to_string(),
        TrustedKeyInfo {
            key_id: "alias-2".to_string(),
            public_key_b64: format!(" {} ", dup_kp.public_key_b64()),
        },
    );
    let mut roles = std::collections::BTreeMap::new();
    for r in [
        TufRole::Root,
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
    ] {
        roles.insert(
            r,
            RootKeyRole {
                key_ids: vec![root_kp.key_id().to_string()],
                threshold: 1,
            },
        );
    }
    roles.insert(
        TufRole::Binaries,
        RootKeyRole {
            key_ids: vec!["alias-1".to_string(), "alias-2".to_string()],
            threshold: 2,
        },
    );
    let dup_proj_root = sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Project,
            version: 1,
            expires,
            keys: keys.clone(),
            roles,
        },
        &[&root_kp],
    )
    .unwrap();
    let mut dup_verifier = DualRootVerifier::with_timestamp(dup_proj_root, None, now).unwrap();
    let bin = b"dup-key-test";
    let sha = canonical_sha256(bin);
    let mut tmap = std::collections::BTreeMap::new();
    tmap.insert(
        "bin/grdrd".to_string(),
        TargetDescriptor {
            role: TufRole::Binaries,
            pack_kind: PackKind::Binary,
            signer_class: grdr_update::SignerClass::ProjectBinaries,
            version: "0.2.0".to_string(),
            generation: 2,
            sha256: sha.clone(),
            length: u64::try_from(bin.len()).unwrap(),
        },
    );
    let bins = sign_metadata(
        TargetsMetadata {
            role: TufRole::Binaries,
            version: 1,
            expires,
            targets: tmap.clone(),
        },
        &[&root_kp],
    )
    .unwrap();
    let tgts = sign_metadata(
        TargetsMetadata {
            role: TufRole::Targets,
            version: 1,
            expires,
            targets: tmap,
        },
        &[&root_kp],
    )
    .unwrap();
    let bins_b = serde_json::to_vec(&bins.signed).unwrap();
    let tgts_b = serde_json::to_vec(&tgts.signed).unwrap();
    let mut smap = std::collections::BTreeMap::new();
    smap.insert(
        TufRole::Targets,
        SnapshotTargetRef {
            version: 1,
            sha256: canonical_sha256(&tgts_b),
            length: u64::try_from(tgts_b.len()).unwrap(),
        },
    );
    smap.insert(
        TufRole::Binaries,
        SnapshotTargetRef {
            version: 1,
            sha256: canonical_sha256(&bins_b),
            length: u64::try_from(bins_b.len()).unwrap(),
        },
    );
    let snap = sign_metadata(
        SnapshotMetadata {
            version: 1,
            expires,
            meta: smap,
        },
        &[&root_kp],
    )
    .unwrap();
    let snap_b = serde_json::to_vec(&snap.signed).unwrap();
    let ts = sign_metadata(
        TimestampMetadata {
            version: 1,
            expires,
            snapshot: SnapshotTargetRef {
                version: 1,
                sha256: canonical_sha256(&snap_b),
                length: u64::try_from(snap_b.len()).unwrap(),
            },
        },
        &[&root_kp],
    )
    .unwrap();
    let stmt_b = serde_json::to_vec(&DsseTargetStatement {
        target_path: "bin/grdrd".to_string(),
        sha256: sha,
        length: u64::try_from(bin.len()).unwrap(),
    })
    .unwrap();
    let dsse = sign_dsse_envelope(
        "application/vnd.grdr.binary-manifest+json",
        &stmt_b,
        &[&dup_kp],
    )
    .unwrap();
    let matrix = CompatMatrix::default_v1();
    assert!(
        dup_verifier
            .verify_bundle(
                &StagedUpdateBundle {
                    root_kind: TufRootKind::Project,
                    pack_kind: PackKind::Binary,
                    channel: "binary",
                    target_path: "bin/grdrd",
                    component_name: "grdr-daemon",
                    snapshot_published_unix_s: now.as_second(),
                    artifact_bytes: bin,
                    timestamp: &ts,
                    snapshot: &snap,
                    targets: &tgts,
                    binaries_targets: Some(&bins),
                    freshness: None,
                    dsse_envelope: &dsse,
                    compat_matrix: &matrix,
                },
                now,
            )
            .is_err(),
        "duplicate/whitespace [u8; 32] keys must fail closed before reaching threshold=2"
    );

    // Tampered FreshnessStatement on otherwise valid unexpired chain must fail closed.
    let mut clean_keys = std::collections::BTreeMap::new();
    clean_keys.insert(
        root_kp.key_id().to_string(),
        TrustedKeyInfo {
            key_id: root_kp.key_id().to_string(),
            public_key_b64: root_kp.public_key_b64(),
        },
    );
    let mut clean_roles = std::collections::BTreeMap::new();
    for r in [
        TufRole::Root,
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
        TufRole::Binaries,
    ] {
        clean_roles.insert(
            r,
            RootKeyRole {
                key_ids: vec![root_kp.key_id().to_string()],
                threshold: 1,
            },
        );
    }
    let clean_proj = sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Project,
            version: 1,
            expires,
            keys: clean_keys,
            roles: clean_roles,
        },
        &[&root_kp],
    )
    .unwrap();
    let mut dep_keys = std::collections::BTreeMap::new();
    dep_keys.insert(
        fleet_kp.key_id().to_string(),
        TrustedKeyInfo {
            key_id: fleet_kp.key_id().to_string(),
            public_key_b64: fleet_kp.public_key_b64(),
        },
    );
    let mut dep_roles = std::collections::BTreeMap::new();
    for r in [
        TufRole::Root,
        TufRole::Timestamp,
        TufRole::Snapshot,
        TufRole::Targets,
        TufRole::Fleet,
    ] {
        dep_roles.insert(
            r,
            RootKeyRole {
                key_ids: vec![fleet_kp.key_id().to_string()],
                threshold: 1,
            },
        );
    }
    let dep_root = sign_metadata(
        RootMetadata {
            root_kind: TufRootKind::Deployment,
            version: 1,
            expires,
            keys: dep_keys,
            roles: dep_roles,
        },
        &[&fleet_kp],
    )
    .unwrap();
    let mut fv = DualRootVerifier::with_timestamp(clean_proj, Some(dep_root), now)
        .unwrap()
        .with_dsse_limits(DsseLimits::default());
    let valid_dsse = sign_dsse_envelope(
        "application/vnd.grdr.binary-manifest+json",
        &stmt_b,
        &[&root_kp],
    )
    .unwrap();
    let mut bad_freshness = sign_metadata(
        FreshnessStatement {
            deployment_id: "dep-1".to_string(),
            issued_at: now,
            expires,
            project_root_version: 1,
            project_snapshot_version: 1,
            project_snapshot_sha256: canonical_sha256(&snap_b),
            imported_at: now,
        },
        &[&fleet_kp],
    )
    .unwrap();
    bad_freshness.signatures[0].sig = "AAAA".to_string();
    assert!(
        fv.verify_bundle(
            &StagedUpdateBundle {
                root_kind: TufRootKind::Project,
                pack_kind: PackKind::Binary,
                channel: "binary",
                target_path: "bin/grdrd",
                component_name: "grdr-daemon",
                snapshot_published_unix_s: now.as_second(),
                artifact_bytes: bin,
                timestamp: &ts,
                snapshot: &snap,
                targets: &tgts,
                binaries_targets: Some(&bins),
                freshness: Some(&bad_freshness),
                dsse_envelope: &valid_dsse,
                compat_matrix: &matrix,
            },
            now,
        )
        .is_err(),
        "tampered FreshnessStatement signature must fail closed"
    );
}
