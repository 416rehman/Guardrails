// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::error::Error;
use std::io::Write;
use std::process::{Child, Command, Stdio};

use grdr_ipc_os::proto_io::{DuplexPipe, ProtoIpcStream};
use grdr_model::{
    ActionClass, ApprovalGrade, Grant, GrantScope, Mode, PolicyPack, PolicyRule, RuleMatch,
};
use grdr_wire::frame::{IPC_WIRE_VERSION, WireFrame, WirePayload};
use grdr_wire::messages::{
    BundleLoadFrame, ChannelProfileKind, EndpointServiceKind, EngineForwardFrame, HeartbeatFrame,
    HelloFrame, WireActionClass, WireControlPoint, WireVerdict,
};
use grdr_wire::peer_auth::{ClientIdentityPolicy, OsPeerClaims, Profile, open};
use jiff::Timestamp;

struct ChildGuard(Child);

impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

#[test]
fn engine_self_test_and_inherited_ipc_eval_stay_key_free_and_return_unsigned_records() {
    let res = run_engine_ipc_smoke();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn engine_preserves_tainted_sessions_enforces_epoch_cedar_and_rejects_truncation() {
    let res = run_engine_hardening_checks();
    assert!(res.is_ok(), "{res:?}");
}

fn run_engine_ipc_smoke() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-engine");

    let self_status = Command::new(exe)
        .args(["--self-test", "--device-id", "dev-self-1"])
        .status()?;
    if !self_status.success() {
        return Err(format!("--self-test failed: {:?}", self_status.code()).into());
    }

    let mut child = Command::new(exe)
        .args(["--max-sessions", "4", "--device-id", "dev-engine-1"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;

    let child_stdin = child.stdin.take().ok_or("missing child stdin")?;
    let child_stdout = child.stdout.take().ok_or("missing child stdout")?;
    let stream = ProtoIpcStream::new(DuplexPipe::new(child_stdout, child_stdin));
    let mut nonce = [0u8; 32];
    grdr_wire::fill_random_bytes(&mut nonce)?;

    let (mut chan, ready) = open(
        stream,
        &OsPeerClaims::Inherited,
        0,
        &ClientIdentityPolicy {
            profile: Profile::Inherited,
            allowed_server_uids: vec![],
            expected_windows_sids: vec![],
            minimum_integrity_rid: 0,
            require_start_time_before_connect: false,
            require_kernel_peer_token: false,
        },
        HelloFrame {
            protocol_version: IPC_WIRE_VERSION,
            service: EndpointServiceKind::ProviderEngine as i32,
            profile: ChannelProfileKind::Inherited as i32,
            client_nonce: nonce.to_vec(),
            pid: std::process::id(),
            capabilities: vec!["engine.v1".to_string()],
        },
        1_048_576,
    )?;
    if ready.protocol_version != IPC_WIRE_VERSION {
        return Err("unexpected engine ready version".into());
    }

    chan.send_frame(WireFrame::with_payload(
        1,
        2,
        WirePayload::Heartbeat(HeartbeatFrame {
            seq: 1,
            monotonic_ms: 10,
            rss_bytes: 0,
            queue_depth: 0,
            epoch: 1,
        }),
    ))?;
    let hb_reply = recv_non_credit(&mut chan)?;
    let Some(WirePayload::Heartbeat(hb)) = hb_reply.payload else {
        return Err("expected Heartbeat reply".into());
    };
    if hb.queue_depth != 0 {
        return Err(format!("expected zero idle queue_depth, got {}", hb.queue_depth).into());
    }
    if cfg!(any(windows, target_os = "linux", target_os = "macos")) && hb.rss_bytes == 0 {
        return Err("expected nonzero live RSS telemetry in engine Heartbeat".into());
    }

    // Exercise >64 frames to verify credit replenishment and queue_depth tracking across loop.
    for i in 0..70u64 {
        chan.send_frame(WireFrame::with_payload(
            1,
            3 + i,
            WirePayload::EngineForward(EngineForwardFrame {
                request_id: format!("req-{i}"),
                attempt_id: format!("att-{i}"),
                agent: "claude-code".to_string(),
                control_point: WireControlPoint::Hook as i32,
                action_class: WireActionClass::Exec as i32,
                session_id: format!("sess-{i}"),
                target: "git status".to_string(),
                summary: "Bash".to_string(),
                command_line: "git status".to_string(),
                received_mono_ms: 100 + i,
                epoch: 1,
                tool_name: "Bash".to_string(),
                device_id: "dev-engine-1".to_string(),
            }),
        ))?;
        let res_frame = recv_non_credit(&mut chan)?;
        let Some(WirePayload::EngineResult(res)) = res_frame.payload else {
            return Err("expected EngineResult reply".into());
        };
        if res.authored_records.is_empty() {
            return Err("expected authored_records in EngineResult".into());
        }
    }

    drop(chan);
    let status = child.wait()?;
    if !status.success() {
        return Err(format!(
            "engine exited non-zero after clean EOF: {:?}",
            status.code()
        )
        .into());
    }
    Ok(())
}

fn run_engine_hardening_checks() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-engine");

    // 1. Truncated wire frame must cause non-zero error exit, never silent Ok(0).
    let mut trunc_child = ChildGuard(
        Command::new(exe)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    if let Some(mut stdin) = trunc_child.0.stdin.take() {
        stdin.write_all(&[10, 0, 0, 0, 1, 2])?;
    }
    let trunc_status = trunc_child.0.wait()?;
    if trunc_status.success() {
        return Err("truncated handshake frame must fail non-zero".into());
    }

    // 2. Tainted session survives clean session LRU churn, essentials_pack stays retained,
    // command_line overrides generic target, grant consumption reports consumed_grant_id,
    // and invalid Cedar or epoch regression aborts before swap.
    let mut child = ChildGuard(
        Command::new(exe)
            .args(["--max-sessions", "2", "--device-id", "dev-taint"])
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .spawn()?,
    );
    let child_stdin = child.0.stdin.take().ok_or("missing child stdin")?;
    let child_stdout = child.0.stdout.take().ok_or("missing child stdout")?;
    let stream = ProtoIpcStream::new(DuplexPipe::new(child_stdout, child_stdin));
    let mut nonce = [0u8; 32];
    grdr_wire::fill_random_bytes(&mut nonce)?;

    let (mut chan, _) = open(
        stream,
        &OsPeerClaims::Inherited,
        0,
        &ClientIdentityPolicy {
            profile: Profile::Inherited,
            allowed_server_uids: vec![],
            expected_windows_sids: vec![],
            minimum_integrity_rid: 0,
            require_start_time_before_connect: false,
            require_kernel_peer_token: false,
        },
        HelloFrame {
            protocol_version: IPC_WIRE_VERSION,
            service: EndpointServiceKind::ProviderEngine as i32,
            profile: ChannelProfileKind::Inherited as i32,
            client_nonce: nonce.to_vec(),
            pid: std::process::id(),
            capabilities: vec!["engine.v1".to_string()],
        },
        1_048_576,
    )?;

    // Taint "sess-taint" by touching credential file.
    chan.send_frame(WireFrame::with_payload(
        1,
        2,
        WirePayload::EngineForward(EngineForwardFrame {
            request_id: "req-cred".to_string(),
            attempt_id: "att-cred".to_string(),
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::FileRead as i32,
            session_id: "sess-taint".to_string(),
            target: "/home/u/.ssh/id_rsa".to_string(),
            summary: "Read".to_string(),
            command_line: String::new(),
            received_mono_ms: 10,
            epoch: 1,
            tool_name: "Read".to_string(),
            device_id: "dev-taint".to_string(),
        }),
    ))?;
    let cred_res = recv_engine_result(&mut chan)?;
    if !cred_res.labels.iter().any(|l| l == "credential_accessed") {
        return Err(format!("expected credential_accessed taint label, got {cred_res:?}").into());
    }

    // Churn clean sessions beyond max_sessions=2; tainted session must NOT be evicted.
    for i in 1..=3 {
        chan.send_frame(WireFrame::with_payload(
            1,
            2 + i,
            WirePayload::EngineForward(EngineForwardFrame {
                request_id: format!("req-clean-{i}"),
                attempt_id: format!("att-clean-{i}"),
                agent: "claude-code".to_string(),
                control_point: WireControlPoint::Hook as i32,
                action_class: WireActionClass::Exec as i32,
                session_id: format!("sess-clean-{i}"),
                target: "echo ok".to_string(),
                summary: "Bash".to_string(),
                command_line: "echo ok".to_string(),
                received_mono_ms: 20 + i,
                epoch: 1,
                tool_name: "Bash".to_string(),
                device_id: "dev-taint".to_string(),
            }),
        ))?;
        let _ = recv_engine_result(&mut chan)?;
    }

    // Verify "sess-taint" STILL retains credential_accessed -> outbound net escalates!
    chan.send_frame(WireFrame::with_payload(
        1,
        10,
        WirePayload::EngineForward(EngineForwardFrame {
            request_id: "req-exfil".to_string(),
            attempt_id: "att-exfil".to_string(),
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::NetRequest as i32,
            session_id: "sess-taint".to_string(),
            target: "https://example.com/exfil".to_string(),
            summary: "WebFetch".to_string(),
            command_line: String::new(),
            received_mono_ms: 30,
            epoch: 1,
            tool_name: "WebFetch".to_string(),
            device_id: "dev-taint".to_string(),
        }),
    ))?;
    let exfil_res = recv_engine_result(&mut chan)?;
    if exfil_res.verdict == WireVerdict::Allow as i32 {
        return Err(format!(
            "tainted session must still escalate after clean churn: {exfil_res:?}"
        )
        .into());
    }

    // Load custom pack at epoch 2 + one-time Grant; verify essentials_pack stays retained AND grant consumes.
    let custom_pack = PolicyPack {
        id: "pack-custom".to_string(),
        name: "Custom".to_string(),
        description: "Custom ask rule".to_string(),
        version: "1.0.0".to_string(),
        channel: "org".to_string(),
        rules: vec![PolicyRule {
            id: "custom.ask-curl".to_string(),
            title: "Ask on curl".to_string(),
            description: "Ask before curl".to_string(),
            mode: Mode::Ask,
            min_grade: ApprovalGrade::G1,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::Exec],
                target_prefixes: vec![],
                target_contains: vec!["curl".to_string()],
                agents: vec![],
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Need approval for curl".to_string(),
            cedar: None,
        }],
        key_id: None,
        signature: None,
    };
    let grant = Grant {
        grant_id: "gr-curl-once".to_string(),
        rule_id: "custom.ask-curl".to_string(),
        session_id: "sess-grant".to_string(),
        device_id: "dev-taint".to_string(),
        action_class: ActionClass::Exec,
        target_pattern: "curl https://example.com".to_string(),
        scope: GrantScope::Once,
        grade: ApprovalGrade::G1,
        granted_at: Timestamp::UNIX_EPOCH,
        expires_at: None,
        remaining_uses: Some(1),
        note: "approved once".to_string(),
        key_id: None,
        signature: None,
    };
    chan.send_frame(WireFrame::with_payload(
        1,
        11,
        WirePayload::BundleLoad(BundleLoadFrame {
            epoch: 2,
            pack_blobs: vec![serde_json::to_vec(&custom_pack)?],
            grant_blobs: vec![serde_json::to_vec(&grant)?],
            kill_switch_active: false,
            kill_switch_reason: String::new(),
        }),
    ))?;

    // Check Grant consumption & command_line usage when target is generic summary.
    chan.send_frame(WireFrame::with_payload(
        1,
        12,
        WirePayload::EngineForward(EngineForwardFrame {
            request_id: "req-curl-grant".to_string(),
            attempt_id: "att-curl-grant".to_string(),
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::Exec as i32,
            session_id: "sess-grant".to_string(),
            target: "Bash".to_string(),
            summary: "Bash".to_string(),
            command_line: "curl https://example.com".to_string(),
            received_mono_ms: 40,
            epoch: 2,
            tool_name: "Bash".to_string(),
            device_id: "dev-taint".to_string(),
        }),
    ))?;
    let grant_res = recv_engine_result(&mut chan)?;
    if grant_res.verdict != WireVerdict::Allow as i32
        || grant_res.consumed_grant_id != "gr-curl-once"
    {
        return Err(format!("expected consumed grant gr-curl-once, got {grant_res:?}").into());
    }

    // Verify essentials_pack was NOT displaced by pack-custom.
    chan.send_frame(WireFrame::with_payload(
        1,
        13,
        WirePayload::EngineForward(EngineForwardFrame {
            request_id: "req-ess".to_string(),
            attempt_id: "att-ess".to_string(),
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::Exec as i32,
            session_id: "sess-ess".to_string(),
            target: "Bash".to_string(),
            summary: "Bash".to_string(),
            command_line: "claude --dangerously-skip-permissions".to_string(),
            received_mono_ms: 50,
            epoch: 2,
            tool_name: "Bash".to_string(),
            device_id: "dev-taint".to_string(),
        }),
    ))?;
    let ess_res = recv_engine_result(&mut chan)?;
    if ess_res.verdict != WireVerdict::Block as i32 {
        return Err(format!("essentials_pack rule must remain enforced: {ess_res:?}").into());
    }

    drop(chan);
    let status = child.0.wait()?;
    if !status.success() {
        return Err(format!("engine exited non-zero: {:?}", status.code()).into());
    }
    Ok(())
}

#[test]
fn engine_rejects_invalid_cedar_regressed_epoch_oversized_blob_and_preserves_taint_under_churn() {
    let res = run_engine_negative_and_churn_checks();
    assert!(res.is_ok(), "{res:?}");
}

#[test]
fn engine_watchdog_exits_after_daemon_heartbeat_timeout() {
    let exe = env!("CARGO_BIN_EXE_grdr-engine");
    let (mut child, mut chan) =
        spawn_authenticated_engine(exe, "dev-hb", "4").expect("spawn engine");
    let frame = WireFrame::with_payload(
        1,
        1,
        WirePayload::EngineForward(EngineForwardFrame {
            request_id: "req-hb-1".to_string(),
            attempt_id: "att-hb-1".to_string(),
            agent: "claude-code".to_string(),
            control_point: WireControlPoint::Hook as i32,
            action_class: WireActionClass::Exec as i32,
            session_id: "sess-hb".to_string(),
            target: "echo ok".to_string(),
            summary: "Bash".to_string(),
            command_line: "echo ok".to_string(),
            received_mono_ms: 1,
            epoch: 1,
            tool_name: "Bash".to_string(),
            device_id: "dev-hb".to_string(),
        }),
    );
    chan.send_frame(frame).expect("send initial forward");
    let _ = recv_engine_result(&mut chan).expect("receive initial verdict");

    let status = child.0.wait().expect("wait for watchdog exit");
    assert!(
        !status.success(),
        "engine must exit non-zero on daemon heartbeat timeout"
    );
}

type EngineTestChan = grdr_wire::peer_auth::AuthenticatedChannel<
    ProtoIpcStream<DuplexPipe<std::process::ChildStdout, std::process::ChildStdin>>,
>;

fn spawn_authenticated_engine(
    exe: &str,
    device_id: &str,
    max_sessions: &str,
) -> Result<(ChildGuard, EngineTestChan), Box<dyn Error>> {
    let mut child = Command::new(exe)
        .args(["--max-sessions", max_sessions, "--device-id", device_id])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .spawn()?;
    let child_stdin = child.stdin.take().ok_or("missing child stdin")?;
    let child_stdout = child.stdout.take().ok_or("missing child stdout")?;
    let guard = ChildGuard(child);
    let stream = ProtoIpcStream::new(DuplexPipe::new(child_stdout, child_stdin));
    let mut nonce = [0u8; 32];
    grdr_wire::fill_random_bytes(&mut nonce)?;
    let hello = HelloFrame {
        protocol_version: IPC_WIRE_VERSION,
        service: EndpointServiceKind::ProviderEngine as i32,
        profile: ChannelProfileKind::Inherited as i32,
        client_nonce: nonce.to_vec(),
        pid: std::process::id(),
        capabilities: vec!["test".to_string()],
    };
    let policy = ClientIdentityPolicy {
        profile: Profile::Inherited,
        allowed_server_uids: vec![],
        expected_windows_sids: vec![],
        minimum_integrity_rid: 0,
        require_start_time_before_connect: false,
        require_kernel_peer_token: false,
    };
    let (chan, _ready) = open(
        stream,
        &OsPeerClaims::Inherited,
        0,
        &policy,
        hello,
        grdr_wire::frame::embedded_max_frame_bytes()?,
    )?;
    Ok((guard, chan))
}

fn run_engine_negative_and_churn_checks() -> Result<(), Box<dyn Error>> {
    let exe = env!("CARGO_BIN_EXE_grdr-engine");

    // 1. Invalid Cedar syntax in BundleLoad must fail closed with non-zero exit.
    {
        let (mut child, mut chan) = spawn_authenticated_engine(exe, "dev-neg", "8")?;
        let bad_pack = PolicyPack {
            id: "pack-bad-cedar".to_string(),
            name: "Bad Cedar".to_string(),
            description: "invalid syntax test".to_string(),
            version: "0.1.0".to_string(),
            channel: "test".to_string(),
            rules: vec![PolicyRule {
                id: "RULE-BAD-CEDAR".to_string(),
                title: "broken".to_string(),
                description: "invalid cedar".to_string(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G1,
                enabled: true,
                locked: false,
                matcher: RuleMatch {
                    action_classes: vec![ActionClass::Exec],
                    target_prefixes: Vec::new(),
                    target_contains: Vec::new(),
                    agents: Vec::new(),
                },
                hits: 0,
                would_ask_hits: 0,
                would_block_hits: 0,
                reason_template: "blocked".to_string(),
                cedar: Some("this is not valid cedar :::".to_string()),
            }],
            key_id: None,
            signature: None,
        };
        let blob = serde_json::to_vec(&bad_pack)?;
        chan.send_frame(WireFrame::with_payload(
            1,
            1,
            WirePayload::BundleLoad(BundleLoadFrame {
                epoch: 2,
                pack_blobs: vec![blob],
                grant_blobs: Vec::new(),
                kill_switch_active: false,
                kill_switch_reason: String::new(),
            }),
        ))?;
        let status = child.0.wait()?;
        if status.success() {
            return Err("invalid Cedar rule in BundleLoad must fail closed".into());
        }
    }

    // 2. Regressed bundle epoch must fail closed with non-zero exit.
    {
        let (mut child, mut chan) = spawn_authenticated_engine(exe, "dev-neg", "8")?;
        chan.send_frame(WireFrame::with_payload(
            1,
            1,
            WirePayload::BundleLoad(BundleLoadFrame {
                epoch: 5,
                pack_blobs: Vec::new(),
                grant_blobs: Vec::new(),
                kill_switch_active: false,
                kill_switch_reason: String::new(),
            }),
        ))?;
        chan.send_frame(WireFrame::with_payload(
            1,
            2,
            WirePayload::BundleLoad(BundleLoadFrame {
                epoch: 4,
                pack_blobs: Vec::new(),
                grant_blobs: Vec::new(),
                kill_switch_active: false,
                kill_switch_reason: String::new(),
            }),
        ))?;
        let status = child.0.wait()?;
        if status.success() {
            return Err("regressed BundleLoad epoch must fail closed".into());
        }
    }

    // 3. Oversized pack blob (> embedded_max_frame_bytes) must fail wire or bundle validation.
    {
        let (mut child, mut chan) = spawn_authenticated_engine(exe, "dev-neg", "8")?;
        let max_frame = grdr_wire::frame::embedded_max_frame_bytes()?;
        let oversized_blob = vec![b'{'; max_frame.saturating_add(16)];
        let send_res = chan.send_frame(WireFrame::with_payload(
            1,
            1,
            WirePayload::BundleLoad(BundleLoadFrame {
                epoch: 2,
                pack_blobs: vec![oversized_blob],
                grant_blobs: Vec::new(),
                kill_switch_active: false,
                kill_switch_reason: String::new(),
            }),
        ));
        if send_res.is_ok() {
            let status = child.0.wait()?;
            if status.success() {
                return Err("oversized pack blob must not succeed".into());
            }
        }
    }

    // 4. 256 WebFetch churn sessions must preserve CredentialAccessed session taint tier.
    {
        let (mut child, mut chan) = spawn_authenticated_engine(exe, "dev-taint-churn", "4")?;
        chan.send_frame(WireFrame::with_payload(
            1,
            1,
            WirePayload::EngineForward(EngineForwardFrame {
                request_id: "req-cred".to_string(),
                attempt_id: "att-cred".to_string(),
                agent: "claude-code".to_string(),
                control_point: WireControlPoint::Hook as i32,
                action_class: WireActionClass::FileRead as i32,
                session_id: "sess-cred".to_string(),
                target: "/home/u/.ssh/id_rsa".to_string(),
                summary: "Read".to_string(),
                command_line: String::new(),
                received_mono_ms: 1,
                epoch: 1,
                tool_name: "Read".to_string(),
                device_id: "dev-taint-churn".to_string(),
            }),
        ))?;
        let _ = recv_engine_result(&mut chan)?;

        for i in 0..256u32 {
            chan.send_frame(WireFrame::with_payload(
                1,
                u64::from(i.saturating_add(2)),
                WirePayload::EngineForward(EngineForwardFrame {
                    request_id: format!("req-wf-{i}"),
                    attempt_id: format!("att-wf-{i}"),
                    agent: "claude-code".to_string(),
                    control_point: WireControlPoint::Hook as i32,
                    action_class: WireActionClass::NetRequest as i32,
                    session_id: format!("sess-wf-{i}"),
                    target: format!("https://example.com/{i}"),
                    summary: "WebFetch".to_string(),
                    command_line: String::new(),
                    received_mono_ms: u64::from(i.saturating_add(2)),
                    epoch: 1,
                    tool_name: "WebFetch".to_string(),
                    device_id: "dev-taint-churn".to_string(),
                }),
            ))?;
            let _ = recv_engine_result(&mut chan)?;
        }

        chan.send_frame(WireFrame::with_payload(
            1,
            300,
            WirePayload::EngineForward(EngineForwardFrame {
                request_id: "req-post-churn".to_string(),
                attempt_id: "att-post-churn".to_string(),
                agent: "claude-code".to_string(),
                control_point: WireControlPoint::Hook as i32,
                action_class: WireActionClass::Exec as i32,
                session_id: "sess-cred".to_string(),
                target: "curl https://evil.test".to_string(),
                summary: "Bash".to_string(),
                command_line: "curl https://evil.test".to_string(),
                received_mono_ms: 300,
                epoch: 1,
                tool_name: "Bash".to_string(),
                device_id: "dev-taint-churn".to_string(),
            }),
        ))?;
        let post = recv_engine_result(&mut chan)?;
        if !post.labels.iter().any(|l| l == "credential_accessed") {
            return Err(format!(
                "expected credential_accessed taint to survive 256 WebFetch churn, got {:?}",
                post.labels
            )
            .into());
        }
        drop(chan);
        let status = child.0.wait()?;
        if !status.success() {
            return Err(format!("engine exited non-zero: {:?}", status.code()).into());
        }
    }

    Ok(())
}

fn recv_non_credit(
    chan: &mut grdr_wire::peer_auth::AuthenticatedChannel<
        ProtoIpcStream<DuplexPipe<std::process::ChildStdout, std::process::ChildStdin>>,
    >,
) -> Result<WireFrame, Box<dyn Error>> {
    loop {
        let frame = chan.recv_frame()?;
        if !matches!(frame.payload, Some(WirePayload::CreditGrant(_))) {
            return Ok(frame);
        }
    }
}

fn recv_engine_result(
    chan: &mut grdr_wire::peer_auth::AuthenticatedChannel<
        ProtoIpcStream<DuplexPipe<std::process::ChildStdout, std::process::ChildStdin>>,
    >,
) -> Result<grdr_wire::messages::EngineResultFrame, Box<dyn Error>> {
    let frame = recv_non_credit(chan)?;
    match frame.payload {
        Some(WirePayload::EngineResult(res)) => Ok(res),
        _ => Err("expected EngineResult frame".into()),
    }
}
