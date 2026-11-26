// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::error::Error;
use std::io::Write;
use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

use grdr_crypto::load_or_create_keypair;
use grdr_ipc_os::LocalEndpointAddress;
use grdr_ipc_os::proto_io::ProtoIpcStream;
use grdr_ipc_os::transport::{Connector, FixedTimestampSource, IpcDeadline, SystemConnector};
use grdr_model::{
    ActionClass, ApprovalGrade, Grant, GrantScope, SigningKeypairExt, verify_receipt,
};
use grdr_os_clock::{Clock, SystemClock};
use grdr_os_service::pipe_dacl::{
    NamedPipeAccessRight, PipeMandatoryLabel, PipeSecurityProfile, build_named_pipe_dacl,
};
use grdr_store_local::LocalStore;
use grdr_store_local::daemon_codecs::{
    decode_history_entries_json, decode_receipt_list_json, encode_grant_json,
};
use grdr_wire::frame::{IPC_WIRE_VERSION, WireFrame, WirePayload};
use grdr_wire::messages::{
    ChannelProfileKind, DecideRequestFrame, EndpointServiceKind, HelloFrame, LocalCommandKind,
    LocalRequestFrame, WireActionClass, WireControlPoint, WireVerdict,
};
use grdr_wire::peer_auth::{ClientIdentityPolicy, OsPeerClaims, Profile, open};
use jiff::Timestamp;
use prost::Message;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn daemon_self_test_non_destructive_and_cross_crate_dacl_contract() {
    let res = run_daemon_self_test_and_dacl_checks();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn daemon_serves_peer_authenticated_decide_local_grants_killswitch_and_audit() {
    let res = run_live_daemon_ipc_e2e();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn daemon_rejects_corrupt_snapshot_fail_closed() {
    let root = test_root_dir(std::process::id().saturating_add(300_000));
    let _ = std::fs::remove_dir_all(&root);
    let data_dir = root.join("data");
    let state_dir = root.join("state");
    let snap_dir = data_dir.join("snapshot-store");
    let create_res = grdr_peer_os::fs_open::create_private_dir_all(&snap_dir);
    assert!(create_res.is_ok(), "{create_res:?}");
    let write_res = std::fs::write(snap_dir.join("state.json"), b"{corrupt-json");
    assert!(write_res.is_ok(), "{write_res:?}");

    let daemon_exe = PathBuf::from(env!("CARGO_BIN_EXE_grdr-daemon"));
    let (decide_ep, local_ep) = test_endpoints(&root, std::process::id().saturating_add(300_000));
    let out = Command::new(&daemon_exe)
        .args(["--profile", "user", "--data-dir"])
        .arg(&data_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .args(["--decide-endpoint", &decide_ep])
        .args(["--local-endpoint", &local_ep])
        .output();
    assert!(out.is_ok(), "{out:?}");
    if let Ok(output) = out {
        assert!(
            !output.status.success(),
            "corrupt snapshot store must fail closed at startup"
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}

#[test]
fn daemon_rejects_protected_cli_overrides_at_startup() {
    let daemon_exe = PathBuf::from(env!("CARGO_BIN_EXE_grdr-daemon"));
    let out = Command::new(&daemon_exe)
        .args(["--profile", "protected", "--server", "https://evil.example"])
        .output();
    assert!(out.is_ok(), "{out:?}");
    if let Ok(output) = out {
        assert!(!output.status.success(), "Protected must reject --server");
    }
}

#[test]
fn daemon_persists_revoked_grant_ids_across_daemon_restart() {
    let res = run_daemon_restart_grant_replay_check();
    assert!(res.is_ok(), "{res:?}");
}

fn run_daemon_restart_grant_replay_check() -> Result<(), Box<dyn Error>> {
    let daemon_exe = PathBuf::from(env!("CARGO_BIN_EXE_grdr-daemon"));
    let base_id = std::process::id().saturating_add(400_000);
    let root = test_root_dir(base_id);
    let _ = std::fs::remove_dir_all(&root);
    let data_dir = root.join("data");
    let state_dir = root.join("state");
    let (d1, l1) = test_endpoints(&root, base_id);
    let (d2, l2) = test_endpoints(&root, base_id.saturating_add(500));

    let daemon1 = ChildGuard(
        Command::new(&daemon_exe)
            .args(["--profile", "user", "--data-dir"])
            .arg(&data_dir)
            .args(["--state-dir"])
            .arg(&state_dir)
            .args(["--decide-endpoint", &d1])
            .args(["--local-endpoint", &l1])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );

    let mut ch1 = connect_and_open(&endpoint_to_addr(&l1), EndpointServiceKind::Local)?;
    let keypair = load_or_create_keypair(&data_dir.join("daemon-signing.key"))?;
    let pub_hex = grdr_crypto::sha256_hex(keypair.public_key_b64().as_bytes());
    let short_hex = pub_hex.get(..24).unwrap_or(&pub_hex);
    let dev_id = format!("dev-{short_hex}");
    let now_ts = SystemClock::new().now_wall()?;
    let mut grant = Grant {
        grant_id: "gr-restart-e2e-1".to_string(),
        rule_id: "essentials.credential-read".to_string(),
        session_id: "sess-restart-e2e".to_string(),
        device_id: dev_id,
        action_class: ActionClass::FileRead,
        target_pattern: "/home/user/.ssh/id_rsa".to_string(),
        scope: GrantScope::Session,
        grade: ApprovalGrade::G1,
        granted_at: now_ts,
        expires_at: None,
        remaining_uses: Some(2),
        note: "restart anti-replay test".to_string(),
        key_id: None,
        signature: None,
    };
    keypair.sign_grant(&mut grant)?;
    ch1.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "restart-issue-1".to_string(),
            kind: LocalCommandKind::IssueGrant as i32,
            argument: String::new(),
            payload: encode_grant_json(&grant)?,
            limit: 0,
        }),
    ))?;
    let issued = ch1.recv_frame()?;
    if !matches!(issued.payload, Some(WirePayload::LocalResponse(ref r)) if r.ok) {
        return Err(format!("initial IssueGrant failed: {issued:?}").into());
    }
    ch1.send_frame(WireFrame::with_payload(
        1,
        2,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "restart-revoke-1".to_string(),
            kind: LocalCommandKind::RevokeGrant as i32,
            argument: "gr-restart-e2e-1".to_string(),
            payload: Vec::new(),
            limit: 0,
        }),
    ))?;
    let revoked = ch1.recv_frame()?;
    if !matches!(revoked.payload, Some(WirePayload::LocalResponse(ref r)) if r.ok) {
        return Err(format!("RevokeGrant failed: {revoked:?}").into());
    }
    drop(ch1);
    drop(daemon1);

    let daemon2 = ChildGuard(
        Command::new(&daemon_exe)
            .args(["--profile", "user", "--data-dir"])
            .arg(&data_dir)
            .args(["--state-dir"])
            .arg(&state_dir)
            .args(["--decide-endpoint", &d2])
            .args(["--local-endpoint", &l2])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut ch2 = connect_and_open(&endpoint_to_addr(&l2), EndpointServiceKind::Local)?;
    ch2.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "restart-replay-1".to_string(),
            kind: LocalCommandKind::IssueGrant as i32,
            argument: String::new(),
            payload: encode_grant_json(&grant)?,
            limit: 0,
        }),
    ))?;
    let replayed = ch2.recv_frame()?;
    if !matches!(replayed.payload, Some(WirePayload::LocalResponse(ref r)) if !r.ok) {
        return Err(
            format!("revoked grant replay across daemon restart must fail: {replayed:?}").into(),
        );
    }
    drop(ch2);
    drop(daemon2);
    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn run_daemon_self_test_and_dacl_checks() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-daemon");
    let ephemeral_out = Command::new(exe).args(["--self-test"]).output()?;
    if !ephemeral_out.status.success() {
        let stderr = String::from_utf8_lossy(&ephemeral_out.stderr);
        return Err(format!("ephemeral daemon --self-test failed: {stderr}").into());
    }

    let prot_out = Command::new(exe)
        .args(["--self-test", "--profile", "protected"])
        .output()?;
    if prot_out.status.success() {
        return Err("Protected --self-test must fail closed".into());
    }

    // Verify cross-crate build_named_pipe_dacl + five-right/forbidden-right enforcement.
    let spec = build_named_pipe_dacl(
        r"\\.\pipe\grdr-test-dacl",
        &PipeSecurityProfile::ProtectedService {
            service_sid: "S-1-5-18".to_string(),
            mandatory_label: PipeMandatoryLabel::Medium,
        },
        &[
            NamedPipeAccessRight::FileReadData,
            NamedPipeAccessRight::FileWriteData,
            NamedPipeAccessRight::FileReadAttributes,
            NamedPipeAccessRight::ReadControl,
            NamedPipeAccessRight::Synchronize,
        ],
    )?;
    if !spec.sddl.contains("O:S-1-5-18") {
        return Err(format!("unexpected protected SDDL: {}", spec.sddl).into());
    }
    if build_named_pipe_dacl(
        r"\\.\pipe\grdr-test-dacl",
        &PipeSecurityProfile::UserSession {
            user_sid: "S-1-5-21-1000-1000-1000-1001".to_string(),
        },
        &[NamedPipeAccessRight::FileCreatePipeInstance],
    )
    .is_ok()
    {
        return Err("build_named_pipe_dacl must reject FileCreatePipeInstance for clients".into());
    }
    Ok(())
}

fn run_live_daemon_ipc_e2e() -> Result<(), Box<dyn Error>> {
    let daemon_exe = PathBuf::from(env!("CARGO_BIN_EXE_grdr-daemon"));
    let bin_dir = daemon_exe.parent();
    let engine_exe = bin_dir
        .map(|p| p.join(format!("grdr-engine{}", std::env::consts::EXE_SUFFIX)))
        .filter(|p| p.is_file());
    let hook_exe = bin_dir
        .map(|p| p.join(format!("grdr-hook{}", std::env::consts::EXE_SUFFIX)))
        .filter(|p| p.is_file());
    let uplink_exe = bin_dir
        .map(|p| p.join(format!("grdr-uplink{}", std::env::consts::EXE_SUFFIX)))
        .filter(|p| p.is_file());
    let updater_exe = bin_dir
        .map(|p| p.join(format!("grdr-updater{}", std::env::consts::EXE_SUFFIX)))
        .filter(|p| p.is_file());

    let root = test_root_dir(std::process::id());
    let _ = std::fs::remove_dir_all(&root);
    let data_dir = root.join("data");
    let state_dir = root.join("state");

    let (decide_ep, local_ep) = test_endpoints(&root, std::process::id());
    let mut cmd = Command::new(&daemon_exe);
    cmd.args(["--profile", "user", "--data-dir"])
        .arg(&data_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .args(["--decide-endpoint", &decide_ep])
        .args(["--local-endpoint", &local_ep])
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some(ref eng) = engine_exe {
        cmd.args(["--engine-bin"]).arg(eng);
    }
    if let Some(ref up) = uplink_exe {
        cmd.args(["--uplink-bin"]).arg(up);
    }
    if let Some(ref upd) = updater_exe {
        cmd.args(["--updater-bin"]).arg(upd);
    }
    let _daemon = ChildGuard(cmd.spawn()?);

    let decide_addr = endpoint_to_addr(&decide_ep);
    let local_addr = endpoint_to_addr(&local_ep);

    // 1. Live DecideRequest -> DecideAck + DecideVerdict over OS IPC.
    let mut chan = connect_and_open(&decide_addr, EndpointServiceKind::Decide)?;
    chan.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::DecideRequest(DecideRequestFrame {
            request_id: "e2e-decide-1".to_string(),
            hook_seq: 1,
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::Exec as i32,
            session_id: "sess-e2e".to_string(),
            target: "git commit --no-verify".to_string(),
            summary: "Bash".to_string(),
            command_line: "git commit --no-verify".to_string(),
            cwd: "/".to_string(),
            sha256: String::new(),
            emitted_mono_ms: 10,
            tool_name: "Bash".to_string(),
            raw_payload: Vec::new(),
        }),
    ))
    .map_err(|e| format!("step1 send: {e}"))?;

    let first = chan.recv_frame().map_err(|e| format!("step1 recv1: {e}"))?;
    if !matches!(first.payload, Some(WirePayload::DecideAck(_))) {
        return Err("expected DecideAck frame before DecideVerdict".into());
    }
    let second = chan.recv_frame().map_err(|e| format!("step1 recv2: {e}"))?;
    let Some(WirePayload::DecideVerdict(verdict)) = second.payload else {
        return Err("expected DecideVerdict frame after DecideAck".into());
    };
    let expected_non_allow = verdict.verdict == WireVerdict::Block as i32
        || (engine_exe.is_some() && verdict.verdict == WireVerdict::Ask as i32);
    if !expected_non_allow || !verdict.audit_fsynced {
        return Err(format!("expected fsynced enforcement verdict, got {verdict:?}").into());
    }
    if engine_exe.is_some() && verdict.floor_fallback {
        return Err(
            format!("expected live engine verdict, got floor fallback: {verdict:?}").into(),
        );
    }
    drop(chan);

    // 2. Live Local commands: Status, Evaluate, Grant signing/validation/replay, scoped ListReceipts, QueryHistory.
    let mut local_chan = connect_and_open(&local_addr, EndpointServiceKind::Local)?;
    local_chan.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-status-1".to_string(),
            kind: LocalCommandKind::Status as i32,
            argument: String::new(),
            payload: Vec::new(),
            limit: 10,
        }),
    ))?;
    let status_reply = local_chan
        .recv_frame()
        .map_err(|e| format!("step2 status_recv: {e}"))?;
    let Some(WirePayload::LocalResponse(lresp)) = status_reply.payload else {
        return Err("expected LocalResponse for Status".into());
    };
    if !lresp.ok
        || lresp
            .health
            .as_ref()
            .is_none_or(|h| h.receipts_total < 1 || h.spool_bytes == 0)
    {
        return Err(format!("unexpected daemon health summary: {lresp:?}").into());
    }

    let eval_req = DecideRequestFrame {
        request_id: "local-eval-2".to_string(),
        hook_seq: 2,
        agent: "cursor".to_string(),
        control_point: WireControlPoint::Hook as i32,
        action_class: WireActionClass::FileRead as i32,
        session_id: "sess-other".to_string(),
        target: "/Users/alice/.ssh/id_rsa".to_string(),
        summary: "read_file".to_string(),
        command_line: String::new(),
        cwd: "/tmp".to_string(),
        sha256: String::new(),
        emitted_mono_ms: 20,
        tool_name: "read_file".to_string(),
        raw_payload: Vec::new(),
    };
    local_chan.send_frame(WireFrame::with_payload(
        1,
        2,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-eval-2".to_string(),
            kind: LocalCommandKind::Evaluate as i32,
            argument: String::new(),
            payload: eval_req.encode_to_vec(),
            limit: 0,
        }),
    ))?;
    let eval_reply = local_chan.recv_frame()?;
    let Some(WirePayload::LocalResponse(eval_resp)) = eval_reply.payload else {
        return Err("expected LocalResponse for Evaluate".into());
    };
    if !eval_resp.ok {
        return Err(format!("local evaluate failed: {eval_resp:?}").into());
    }

    // Scoped ListReceipts must return ONLY sess-e2e P8-redacted receipts and verify canonical signature.
    local_chan.send_frame(WireFrame::with_payload(
        1,
        3,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-rcp-1".to_string(),
            kind: LocalCommandKind::ListReceipts as i32,
            argument: "sess-e2e".to_string(),
            payload: Vec::new(),
            limit: 10,
        }),
    ))?;
    let rcp_reply = local_chan.recv_frame()?;
    let Some(WirePayload::LocalResponse(rcp_resp)) = rcp_reply.payload else {
        return Err("expected LocalResponse for ListReceipts".into());
    };
    let receipts = decode_receipt_list_json(&rcp_resp.payload)?;
    let first_rcp = receipts
        .first()
        .ok_or("ListReceipts returned no receipts")?;
    if receipts.len() != 1
        || first_rcp.session_id != "sess-e2e"
        || !first_rcp.target.starts_with("sha256:")
    {
        return Err(format!("ListReceipts scoping/P8 check failed: {receipts:?}").into());
    }
    let daemon_pub = std::fs::read_to_string(state_dir.join("floor.pub"))?;
    let (pub_kid, pub_b64) = daemon_pub
        .trim()
        .split_once(':')
        .ok_or("floor.pub missing key_id:pubkey format")?;
    let verified = verify_receipt(
        first_rcp,
        &[grdr_model::TrustedKeyInfo {
            key_id: pub_kid.to_string(),
            public_key_b64: pub_b64.to_string(),
        }],
    );
    if first_rcp.key_id.as_deref() != Some(pub_kid)
        || verified != grdr_model::SignatureStatus::Verified
    {
        return Err("daemon receipt failed canonical signature verification".into());
    }

    // IssueGrant must reject unsigned and wildcard grants, accept signed device-scoped grant, and block replay.
    let keypair = load_or_create_keypair(&data_dir.join("daemon-signing.key"))?;
    let derived_device_id = first_rcp.device_id.clone();
    let now_ts = SystemClock::new().now_wall()?;
    let unsigned_grant = Grant {
        grant_id: "gr-unsigned".to_string(),
        rule_id: "essentials.credential-read".to_string(),
        session_id: "sess-e2e".to_string(),
        device_id: derived_device_id.clone(),
        action_class: ActionClass::FileRead,
        target_pattern: "/home/user/.ssh/id_rsa".to_string(),
        scope: GrantScope::Once,
        grade: ApprovalGrade::G1,
        granted_at: now_ts,
        expires_at: None,
        remaining_uses: Some(1),
        note: "unsigned".to_string(),
        key_id: None,
        signature: None,
    };
    local_chan.send_frame(WireFrame::with_payload(
        1,
        4,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-grant-unsigned".to_string(),
            kind: LocalCommandKind::IssueGrant as i32,
            argument: String::new(),
            payload: encode_grant_json(&unsigned_grant)?,
            limit: 0,
        }),
    ))?;
    let ug = local_chan.recv_frame()?;
    if !matches!(ug.payload, Some(WirePayload::LocalResponse(ref r)) if !r.ok) {
        return Err(format!("unsigned grant must be rejected: {ug:?}").into());
    }

    let mut wildcard_grant = unsigned_grant.clone();
    wildcard_grant.grant_id = "gr-wildcard".to_string();
    wildcard_grant.target_pattern = "*".to_string();
    keypair.sign_grant(&mut wildcard_grant)?;
    local_chan.send_frame(WireFrame::with_payload(
        1,
        5,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-grant-wildcard".to_string(),
            kind: LocalCommandKind::IssueGrant as i32,
            argument: String::new(),
            payload: encode_grant_json(&wildcard_grant)?,
            limit: 0,
        }),
    ))?;
    let wg = local_chan.recv_frame()?;
    if !matches!(wg.payload, Some(WirePayload::LocalResponse(ref r)) if !r.ok) {
        return Err(format!("wildcard grant must be rejected: {wg:?}").into());
    }

    let mut grant = Grant {
        grant_id: "gr-local-1".to_string(),
        rule_id: "essentials.credential-read".to_string(),
        session_id: "sess-e2e".to_string(),
        device_id: derived_device_id,
        action_class: ActionClass::FileRead,
        target_pattern: "/home/user/.ssh/id_rsa".to_string(),
        scope: GrantScope::Session,
        grade: ApprovalGrade::G1,
        granted_at: now_ts,
        expires_at: None,
        remaining_uses: Some(2),
        note: "test grant".to_string(),
        key_id: None,
        signature: None,
    };
    keypair.sign_grant(&mut grant)?;
    local_chan.send_frame(WireFrame::with_payload(
        1,
        6,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-grant-issue".to_string(),
            kind: LocalCommandKind::IssueGrant as i32,
            argument: String::new(),
            payload: encode_grant_json(&grant)?,
            limit: 0,
        }),
    ))?;
    let g1 = local_chan.recv_frame()?;
    if !matches!(g1.payload, Some(WirePayload::LocalResponse(ref r)) if r.ok && r.message == "grant-issued:gr-local-1")
    {
        return Err(format!("IssueGrant failed: {g1:?}").into());
    }
    local_chan.send_frame(WireFrame::with_payload(
        1,
        7,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-grant-revoke".to_string(),
            kind: LocalCommandKind::RevokeGrant as i32,
            argument: "gr-local-1".to_string(),
            payload: Vec::new(),
            limit: 0,
        }),
    ))?;
    let g2 = local_chan.recv_frame()?;
    if !matches!(g2.payload, Some(WirePayload::LocalResponse(ref r)) if r.ok && r.message == "grant-revoked:gr-local-1")
    {
        return Err(format!("RevokeGrant failed: {g2:?}").into());
    }

    // Replaying a revoked grant ID must fail closed.
    local_chan.send_frame(WireFrame::with_payload(
        1,
        8,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-grant-replay".to_string(),
            kind: LocalCommandKind::IssueGrant as i32,
            argument: String::new(),
            payload: encode_grant_json(&grant)?,
            limit: 0,
        }),
    ))?;
    let greplay = local_chan.recv_frame()?;
    if !matches!(greplay.payload, Some(WirePayload::LocalResponse(ref r)) if !r.ok) {
        return Err(format!("replayed revoked grant must fail: {greplay:?}").into());
    }

    // QueryHistory returns real JSON rows with domain-hashed session IDs (no raw cleartext).
    local_chan.send_frame(WireFrame::with_payload(
        1,
        9,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "local-hist-1".to_string(),
            kind: LocalCommandKind::QueryHistory as i32,
            argument: "sess-e2e".to_string(),
            payload: Vec::new(),
            limit: 10,
        }),
    ))?;
    let hist_reply = local_chan.recv_frame()?;
    let Some(WirePayload::LocalResponse(hresp)) = hist_reply.payload else {
        return Err("expected LocalResponse for QueryHistory".into());
    };
    let hist_items = decode_history_entries_json(&hresp.payload)?;
    if !hresp.ok
        || !hresp.message.starts_with("history_entries:")
        || hist_items.is_empty()
        || hist_items
            .iter()
            .any(|item| item.session_id == "sess-e2e" || item.payload_utf8.contains("alice"))
    {
        return Err(format!("unexpected history response/P8 leak: {hresp:?}").into());
    }
    drop(local_chan);

    // 3. Verify read-only self-test leaves initialized data-dir untouched and monotonic epoch > 0.
    let store = LocalStore::open(data_dir.join("snapshot-store"))?;
    let epoch_before = store.current_epoch()?;
    let ro_out = Command::new(&daemon_exe)
        .args(["--self-test", "--data-dir"])
        .arg(&data_dir)
        .args(["--state-dir"])
        .arg(&state_dir)
        .output()?;
    if !ro_out.status.success() {
        return Err(format!(
            "read-only --self-test on live dir failed: {}",
            String::from_utf8_lossy(&ro_out.stderr)
        )
        .into());
    }
    if store.current_epoch()? != epoch_before {
        return Err("read-only --self-test mutated store.epoch".into());
    }
    if !state_dir.join("floor.bin").is_file()
        || !state_dir.join("floor.pub").is_file()
        || !data_dir.join("recorder.db").is_file()
        || !state_dir.join("audit.checkpoint").is_file()
    {
        return Err("expected floor.bin, floor.pub, recorder.db, and audit.checkpoint".into());
    }

    // 4. Live grdr-hook subprocess check against running grdr-daemon.
    if let Some(hook) = hook_exe {
        let mut hcmd = Command::new(hook)
            .args(["--agent", "claude-code", "--state-dir"])
            .arg(&state_dir)
            .args(["--socket", &decide_ep])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()?;
        if let Some(mut stdin) = hcmd.stdin.take() {
            stdin.write_all(
                br#"{"hook_event_name":"PreToolUse","tool_name":"Bash","tool_input":{"command":"rm -rf /etc"},"session_id":"hook-e2e"}"#,
            )?;
        }
        let out = hcmd.wait_with_output()?;
        if out.status.code() != Some(2) {
            return Err(format!(
                "expected live grdr-hook exit 2, got {:?}",
                out.status.code()
            )
            .into());
        }
    }

    drop(_daemon);

    // 5. Verify overload floor fallback AND SetKillSwitch precedence under overload when engine is absent.
    let (ov_decide, ov_local) = test_endpoints(&root, std::process::id().saturating_add(100_000));
    let ov_root = root.join("overload");
    let _ov_daemon = ChildGuard(
        Command::new(&daemon_exe)
            .args(["--profile", "user", "--data-dir"])
            .arg(ov_root.join("data"))
            .args(["--state-dir"])
            .arg(ov_root.join("state"))
            .args(["--decide-endpoint", &ov_decide])
            .args(["--local-endpoint", &ov_local])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()?,
    );
    let mut ov_chan = connect_and_open(&endpoint_to_addr(&ov_decide), EndpointServiceKind::Decide)?;
    ov_chan.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::DecideRequest(DecideRequestFrame {
            request_id: "ov-decide-1".to_string(),
            hook_seq: 1,
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::Exec as i32,
            session_id: "sess-ov".to_string(),
            target: "git commit --no-verify".to_string(),
            summary: "Bash".to_string(),
            command_line: "git commit --no-verify".to_string(),
            cwd: "/".to_string(),
            sha256: String::new(),
            emitted_mono_ms: 10,
            tool_name: "Bash".to_string(),
            raw_payload: Vec::new(),
        }),
    ))?;
    let _ack = ov_chan.recv_frame()?;
    let ov_reply = ov_chan.recv_frame()?;
    let Some(WirePayload::DecideVerdict(ov_verdict)) = ov_reply.payload else {
        return Err("expected overload DecideVerdict".into());
    };
    if ov_verdict.verdict != WireVerdict::Block as i32
        || !ov_verdict.floor_fallback
        || ov_verdict.degraded_reason != "overload"
        || !ov_verdict.audit_fsynced
    {
        return Err(format!("unexpected overload verdict: {ov_verdict:?}").into());
    }

    // Activate kill switch on local endpoint and ensure benign `git status` is blocked even under overload.
    let mut ov_local_chan =
        connect_and_open(&endpoint_to_addr(&ov_local), EndpointServiceKind::Local)?;
    ov_local_chan.send_frame(WireFrame::with_payload(
        1,
        1,
        WirePayload::LocalRequest(LocalRequestFrame {
            request_id: "ov-ks-on".to_string(),
            kind: LocalCommandKind::SetKillSwitch as i32,
            argument: "emergency freeze".to_string(),
            payload: Vec::new(),
            limit: 0,
        }),
    ))?;
    let _ks_resp = ov_local_chan.recv_frame()?;

    ov_chan.send_frame(WireFrame::with_payload(
        1,
        2,
        WirePayload::DecideRequest(DecideRequestFrame {
            request_id: "ov-decide-ks".to_string(),
            hook_seq: 2,
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::Exec as i32,
            session_id: "sess-ov".to_string(),
            target: "git status".to_string(),
            summary: "Bash".to_string(),
            command_line: "git status".to_string(),
            cwd: "/".to_string(),
            sha256: String::new(),
            emitted_mono_ms: 20,
            tool_name: "Bash".to_string(),
            raw_payload: Vec::new(),
        }),
    ))?;
    let _ack2 = ov_chan.recv_frame()?;
    let ks_reply = ov_chan.recv_frame()?;
    let Some(WirePayload::DecideVerdict(ks_verdict)) = ks_reply.payload else {
        return Err("expected kill-switch DecideVerdict".into());
    };
    if ks_verdict.verdict != WireVerdict::Block as i32 || ks_verdict.rule_id != "system.kill-switch"
    {
        return Err(format!("kill switch failed to block under overload: {ks_verdict:?}").into());
    }
    drop(ov_local_chan);
    drop(ov_chan);
    drop(_ov_daemon);

    let _ = std::fs::remove_dir_all(&root);
    Ok(())
}

fn connect_and_open(
    addr: &LocalEndpointAddress,
    service: EndpointServiceKind,
) -> Result<
    grdr_wire::peer_auth::AuthenticatedChannel<ProtoIpcStream<PlatformTestLink>>,
    Box<dyn Error>,
> {
    let pre_scm = probe_pre_scm();
    let link = connect_with_retry(addr)?;
    let (claims, connected_at, _hold) = read_server_claims(&link, &pre_scm)?;
    let mut nonce = [0u8; 32];
    grdr_wire::fill_random_bytes(&mut nonce)?;
    let (chan, _) = open(
        ProtoIpcStream::new(link),
        &claims,
        connected_at,
        &test_client_policy()?,
        HelloFrame {
            protocol_version: IPC_WIRE_VERSION,
            service: service as i32,
            profile: ChannelProfileKind::User as i32,
            client_nonce: nonce.to_vec(),
            pid: std::process::id(),
            capabilities: vec![format!("{service:?}")],
        },
        1_048_576,
    )?;
    Ok(chan)
}

fn test_root_dir(pid: u32) -> PathBuf {
    #[cfg(unix)]
    {
        if let Some(xdg) = std::env::var_os("XDG_RUNTIME_DIR")
            && !xdg.is_empty()
        {
            return PathBuf::from(xdg).join(format!("grdr-it-{pid}"));
        }
        if let Some(home) = std::env::var_os("HOME")
            && !home.is_empty()
        {
            return PathBuf::from(home).join(format!(".grdr-it-{pid}"));
        }
    }
    std::env::temp_dir().join(format!("grdr-daemon-live-{pid}"))
}

fn test_endpoints(root: &std::path::Path, pid: u32) -> (String, String) {
    if cfg!(windows) {
        (
            format!(r"\\.\pipe\grdr-it-decide-{pid}"),
            format!(r"\\.\pipe\grdr-it-local-{pid}"),
        )
    } else {
        (
            root.join(format!("d-{pid}.sock")).display().to_string(),
            root.join(format!("l-{pid}.sock")).display().to_string(),
        )
    }
}

fn endpoint_to_addr(raw: &str) -> LocalEndpointAddress {
    if cfg!(windows) {
        LocalEndpointAddress::WindowsPipe {
            pipe_name: raw.to_string(),
        }
    } else {
        LocalEndpointAddress::UnixSocket {
            path: PathBuf::from(raw),
        }
    }
}

#[cfg(windows)]
type PlatformTestLink = grdr_ipc_os::windows_pipe::WindowsNamedPipeLink;
#[cfg(unix)]
type PlatformTestLink = grdr_ipc_os::unix_domain::UnixDomainLink;

#[cfg(unix)]
type TestHold = Option<grdr_peer_os::unix_peer::UnixPeerHold>;
#[cfg(not(unix))]
type TestHold = ();

#[cfg(windows)]
type TestPreScm = Vec<Option<grdr_peer_os::win_peer::ScmServiceProbe>>;
#[cfg(not(windows))]
type TestPreScm = ();

fn probe_pre_scm() -> TestPreScm {
    #[cfg(windows)]
    {
        grdr_peer_os::win_peer::probe_scm_services(&["Guardrails", "GuardrailsHandover"])
    }
}

fn connect_with_retry(addr: &LocalEndpointAddress) -> Result<PlatformTestLink, Box<dyn Error>> {
    let connector = SystemConnector::default();
    let clock = SystemClock::new();
    for _ in 0..120 {
        let ts = FixedTimestampSource::new(clock.now_wall().unwrap_or(Timestamp::UNIX_EPOCH));
        if let Ok(link) =
            connector.connect(addr, IpcDeadline::from_millis_capped(2_000, 2_000), &ts)
        {
            return Ok(link);
        }
        std::thread::sleep(Duration::from_millis(50));
    }
    let ts = FixedTimestampSource::new(clock.now_wall().unwrap_or(Timestamp::UNIX_EPOCH));
    Ok(connector.connect(addr, IpcDeadline::from_millis_capped(2_000, 2_000), &ts)?)
}

fn read_server_claims(
    link: &PlatformTestLink,
    pre: &TestPreScm,
) -> Result<(OsPeerClaims, u64, TestHold), Box<dyn Error>> {
    #[cfg(windows)]
    {
        let connected_at = grdr_peer_os::win_peer::current_filetime_100ns();
        let claims = grdr_peer_os::win_peer::read_windows_pipe_server(
            link.borrowed_handle(),
            Profile::User,
            &["Guardrails", "GuardrailsHandover"],
            pre,
        )?;
        Ok((OsPeerClaims::Windows(claims), connected_at, ()))
    }
    #[cfg(unix)]
    {
        let _ = pre;
        let clock = SystemClock::new();
        let stamp = grdr_peer_os::unix_peer::UnixConnectStamp {
            boot_uptime_ms: clock
                .boot_uptime()
                .map_or(0, |d| u64::try_from(d.as_millis()).unwrap_or(u64::MAX)),
            wall_unix_us: clock
                .now_wall()
                .ok()
                .and_then(|t| u64::try_from(t.as_microsecond()).ok())
                .unwrap_or(0),
        };
        let hold = grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)?;
        let claims = hold.claims.clone();
        Ok((OsPeerClaims::Unix(claims), stamp.for_platform(), Some(hold)))
    }
}

fn test_client_policy() -> Result<ClientIdentityPolicy, Box<dyn Error>> {
    let uid = grdr_peer_os::unix_peer::current_effective_ids().map_or(u32::MAX, |ids| ids.0);
    #[cfg(windows)]
    let expected_windows_sids = vec![grdr_peer_os::win_peer::current_process_sid()?];
    #[cfg(not(windows))]
    let expected_windows_sids = Vec::new();
    Ok(ClientIdentityPolicy {
        profile: Profile::User,
        allowed_server_uids: vec![uid, 0],
        expected_windows_sids,
        minimum_integrity_rid: 0x2000,
        require_start_time_before_connect: true,
        require_kernel_peer_token: true,
    })
}
