// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::io::Write as _;
use std::path::{Path, PathBuf};

use jiff::Timestamp;

use grdr_core::compile::compile_floor_table;
use grdr_core::policy::ReceiptDigestInput;
use grdr_core::policy::compute_receipt_digest;
use grdr_crypto::SigningKeypair;
use grdr_fastpath::{FastActionClass, FastVerdict};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, AssuranceLevel, InstallProfile, Mode, PolicyPack,
    PolicyRule, RuleMatch, SigningKeypairExt as _, Verdict,
};
use grdr_peer_os::fs_open::{OpenNofollowAccess, create_private_dir_all, open_nofollow_file};
use grdr_run::RunError;
use grdr_run::executor::execute_prepared_launch;
use grdr_run::gate::{
    GateDecisionSource, GateFuture, GateVerdict, IpcGateClient, LaunchGateClient, authorize_launch,
    authorize_launch_with_state_dir, redacted_command_and_cwd,
};
use grdr_run::planner::{
    ContainmentStrategy, HostOsKind, LaunchRequestSpec, PlatformContainmentPlan, build_launch_plan,
};
use grdr_run::planner_macos::{MacOsSuperviseConfig, MacOsSuperviseMissMode};
use grdr_sandbox_engine::policy::EnforcedMechanism;
use grdr_sensor_macos::{DeadlineMissPolicy, MacOsContainmentMode};
use grdr_sensor_windows::LaunchRoute;
use grdr_wire::floor_bin::{
    FloorMatchKind, FloorRuleRecord, FloorTableDocument, encode_signed_floor_table,
};
use grdr_wire::peer_auth::Profile;

struct StubGateClient {
    verdict: Option<Verdict>,
}

impl LaunchGateClient for StubGateClient {
    fn authorize<'a>(&'a self, attempt: &'a ActionAttempt) -> GateFuture<'a> {
        Box::pin(async move {
            let Some(v) = self.verdict else {
                return Err(RunError::GateUnavailable("daemon unreachable".into()));
            };
            let now = attempt.timestamp;
            let digest = compute_receipt_digest(&ReceiptDigestInput {
                attempt_id: &attempt.id,
                session_id: &attempt.session_id,
                agent_name: &attempt.agent_name,
                action_class: attempt.action_class,
                target: &attempt.target,
                verdict: v,
                rule_id: Some("gate.test"),
                decided_at: now,
            });
            Ok(grdr_model::DecisionReceipt {
                receipt_id: "rcp-gate-1".into(),
                attempt_id: attempt.id.clone(),
                session_id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                control_point: attempt.control_point,
                target: attempt.target.clone(),
                verdict: v,
                would_be: None,
                rule_id: Some("gate.test".into()),
                pack_id: Some("gate-pack".into()),
                mode_applied: None,
                grant_id: None,
                reason: "gate test".into(),
                next_step: "ok".into(),
                receipt_digest: digest,
                decided_at: now,
                key_id: None,
                signature: None,
                signature_verified: None,
            })
        })
    }
}

struct TestDirGuard(PathBuf);

impl Drop for TestDirGuard {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn canon_display_dir(path: &Path) -> String {
    let canon = std::fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf());
    let s = canon.to_string_lossy();
    s.strip_prefix("\\\\?\\").unwrap_or(&s).to_owned()
}

fn sample_req(
    strategy: ContainmentStrategy,
    host_os: HostOsKind,
    agent_name: &str,
    native_sandbox: bool,
) -> (LaunchRequestSpec, Option<TestDirGuard>) {
    let current_os = HostOsKind::current();
    let (workspace_root, protected_paths, state_dirs, guard) = if host_os == current_os {
        let root = private_test_root("ws");
        let ws = root.join("ws");
        let prot = root.join("protected");
        let state = root.join("state");
        let _ = create_private_dir_all(&ws);
        let _ = create_private_dir_all(&prot);
        let _ = create_private_dir_all(&state);
        let state_vec = if host_os == HostOsKind::Windows {
            Vec::new()
        } else {
            vec![canon_display_dir(&state)]
        };
        (
            canon_display_dir(&ws),
            vec![canon_display_dir(&prot)],
            state_vec,
            Some(TestDirGuard(root)),
        )
    } else if host_os == HostOsKind::Windows {
        (
            "C:\\workspace\\demo".into(),
            vec!["C:\\Users\\dev\\.ssh".into()],
            Vec::new(),
            None,
        )
    } else {
        (
            "/workspace/demo".into(),
            vec!["/home/dev/.ssh".into()],
            vec!["/home/dev/.claude".into()],
            None,
        )
    };
    (
        LaunchRequestSpec {
            session_id: "sess-run-01".into(),
            tool_call_id: (strategy == ContainmentStrategy::WrapTools).then(|| "tool-99".into()),
            agent_name: agent_name.into(),
            program: "echo".into(),
            args: vec!["ok".into()],
            workspace_root,
            protected_paths,
            state_dirs,
            strategy,
            agent_has_native_sandbox: native_sandbox,
            host_os,
            profile: InstallProfile::Protected,
            proxy_port: 18080,
            decide_socket_path: "/var/run/grdr/decide.sock".into(),
            sandbox_sid: "S-1-15-2-1001".into(),
            extra_allow_env: Vec::new(),
            macos_supervise: None,
        },
        guard,
    )
}

#[test]
fn plans_delegate_wrap_tools_wrap_agent_and_scrubs_secrets() {
    let mut env = BTreeMap::new();
    env.insert("PATH".into(), "/usr/bin".into());
    env.insert("OPENAI_API_KEY".into(), "secret-openai-value".into());
    env.insert("ANTHROPIC_API_KEY".into(), "secret-anthropic-value".into());

    // Explicit macOS WrapAgent retains WrapAgent + SBPL profile even when agent has native sandbox.
    let (mac_wrap, _g1) = sample_req(
        ContainmentStrategy::WrapAgent,
        HostOsKind::MacOs,
        "codex",
        true,
    );
    let (_, mac_wrap_plan) = build_launch_plan(&mac_wrap, &env).unwrap();
    assert_eq!(
        mac_wrap_plan.runtime_enforced_level,
        AssuranceLevel::Al2Guided
    );
    match mac_wrap_plan.platform {
        PlatformContainmentPlan::MacOs { launch, .. } => {
            assert_eq!(launch.containment_mode, MacOsContainmentMode::WrapAgent);
            assert!(launch.profile_sbpl.is_some());
        }
        _ => panic!("expected macOS WrapAgent plan"),
    }

    // macOS Delegate for native codex avoids nested Seatbelt conflict.
    let (mac_delegate, _g2) = sample_req(
        ContainmentStrategy::Delegate,
        HostOsKind::MacOs,
        "codex",
        true,
    );
    let (_, mac_plan) = build_launch_plan(&mac_delegate, &env).unwrap();
    assert_eq!(mac_plan.strategy, ContainmentStrategy::Delegate);
    assert_eq!(mac_plan.runtime_enforced_level, AssuranceLevel::Al2Guided);
    assert!(
        mac_plan
            .sandbox_report
            .stripped_env_vars
            .contains(&"OPENAI_API_KEY".into())
    );
    match mac_plan.platform {
        PlatformContainmentPlan::MacOs { launch, .. } => {
            assert_eq!(launch.containment_mode, MacOsContainmentMode::Delegate);
            assert!(launch.profile_sbpl.is_none());
        }
        _ => panic!("expected macOS plan"),
    }

    // Windows WrapTools selects GrdrRun route with AppContainer + WFP filters.
    let (win_tools, _g3) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::Windows,
        "cursor",
        false,
    );
    let (_, win_plan) = build_launch_plan(&win_tools, &env).unwrap();
    assert_eq!(win_plan.strategy, ContainmentStrategy::WrapTools);
    match win_plan.platform {
        PlatformContainmentPlan::Windows {
            containment,
            wfp,
            exec_level,
            ..
        } => {
            assert_eq!(containment.route, LaunchRoute::GrdrRun);
            assert!(wfp.is_some());
            assert!(exec_level >= AssuranceLevel::Al2Guided);
        }
        _ => panic!("expected Windows plan"),
    }

    // Linux WrapAgent emits seccomp, Landlock, and network unshare directives.
    let (lin_agent, _g4) = sample_req(
        ContainmentStrategy::WrapAgent,
        HostOsKind::Linux,
        "generic",
        false,
    );
    let (_, lin_plan) = build_launch_plan(&lin_agent, &env).unwrap();
    match lin_plan.platform {
        PlatformContainmentPlan::Linux { plan } => {
            assert!(plan.unshare_network_except_proxy);
            assert!(plan.seccomp_denied_syscalls.contains(&"ptrace"));
        }
        _ => panic!("expected Linux plan"),
    }
}

#[test]
fn wrap_tools_without_tool_call_id_fails_validation() {
    let (mut bad, _g1) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::Linux,
        "agent",
        false,
    );
    bad.tool_call_id = None;
    let env = BTreeMap::new();
    assert!(matches!(
        build_launch_plan(&bad, &env),
        Err(RunError::InvalidPlan(_))
    ));

    let (mut bad_agent, _g2) = sample_req(
        ContainmentStrategy::WrapAgent,
        HostOsKind::Linux,
        "agent",
        false,
    );
    bad_agent.tool_call_id = Some("spoofed-tool-id".into());
    assert!(matches!(
        build_launch_plan(&bad_agent, &env),
        Err(RunError::InvalidPlan(_))
    ));
}

#[test]
fn decides_include_redacted_command_line_and_cwd() {
    let (mut req, _g) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::Linux,
        "agent-x",
        false,
    );
    let synthetic_secret = format!("{}-test1234567890abcdefghijkl", "sk");
    req.program = "curl".into();
    req.args = vec![format!("Authorization: Bearer {synthetic_secret}")];
    let (cmdline, cwd) = redacted_command_and_cwd(&req);
    assert!(cmdline.starts_with("curl "));
    assert!(!cmdline.contains(&synthetic_secret));
    assert_eq!(cwd, req.workspace_root);
}

#[tokio::test]
async fn daemon_gate_falls_back_to_signed_floor_and_rejects_tampered_floor() {
    let now = Timestamp::now();
    let (req, _g1) = sample_req(
        ContainmentStrategy::WrapAgent,
        HostOsKind::Linux,
        "agent-x",
        false,
    );

    // Daemon explicit deny.
    let deny_client = StubGateClient {
        verdict: Some(Verdict::Deny),
    };
    let verdict = authorize_launch(&deny_client, &req, None, now)
        .await
        .unwrap();
    assert!(matches!(verdict, GateVerdict::Deny { .. }));

    // Daemon offline with valid signed floor blocking `danger-bin`.
    let offline_client = StubGateClient { verdict: None };
    let key = SigningKeypair::generate().unwrap();
    let pack = PolicyPack {
        id: "p1".into(),
        name: "floor".into(),
        description: "test floor".into(),
        version: "1.0.0".into(),
        channel: "test".into(),
        rules: vec![PolicyRule {
            id: "deny-danger".into(),
            title: "Deny danger binary".into(),
            description: "deny danger binary".into(),
            enabled: true,
            mode: Mode::Block,
            min_grade: ApprovalGrade::G1,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::AgentSpawn, ActionClass::Exec],
                agents: Vec::new(),
                target_prefixes: Vec::new(),
                target_contains: vec!["danger-bin".into()],
            },
            locked: true,
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "blocked by compiled floor".into(),
            cedar: None,
        }],
        key_id: None,
        signature: None,
    };
    let mut table = compile_floor_table(&[pack], now);
    key.sign_floor_table(&mut table).unwrap();

    // WrapAgent (AgentSpawn) ALWAYS fails closed when daemon is offline (D-15), even with valid floor.
    let session_denied = authorize_launch(
        &offline_client,
        &req,
        Some((&table, &[key.public_info()])),
        now,
    )
    .await
    .unwrap();
    assert!(matches!(
        session_denied,
        GateVerdict::Deny {
            source: GateDecisionSource::SignedCompiledFloor { degraded: true },
            ..
        }
    ));

    // WrapTools on danger-bin hits compiled floor rule in degraded mode.
    let (mut blocked_req, _g2) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::Linux,
        "agent-x",
        false,
    );
    blocked_req.program = "danger-bin".into();
    let floor_deny = authorize_launch(
        &offline_client,
        &blocked_req,
        Some((&table, &[key.public_info()])),
        now,
    )
    .await
    .unwrap();
    assert!(matches!(
        floor_deny,
        GateVerdict::Deny {
            source: GateDecisionSource::SignedCompiledFloor { degraded: true },
            ..
        }
    ));

    // Tampered floor fails closed with FloorUntrusted error.
    let mut tampered = table;
    tampered.rules.clear();
    assert!(matches!(
        authorize_launch(
            &offline_client,
            &req,
            Some((&tampered, &[key.public_info()])),
            now
        )
        .await,
        Err(RunError::FloorUntrusted)
    ));

    // Parent directory traversal and relative non-canonical paths rejected in protected_paths and state_dirs.
    let mut traversal = req.clone();
    traversal.protected_paths.push("../../etc/shadow".into());
    assert!(matches!(
        build_launch_plan(&traversal, &BTreeMap::new()),
        Err(RunError::InvalidPlan(_))
    ));

    let mut non_canon_protected = req.clone();
    non_canon_protected
        .protected_paths
        .push("relative/parent/.ssh".into());
    assert!(matches!(
        build_launch_plan(&non_canon_protected, &BTreeMap::new()),
        Err(RunError::InvalidPlan(_))
    ));

    let mut non_canon_state = req;
    non_canon_state.state_dirs.push("relative/state".into());
    assert!(matches!(
        build_launch_plan(&non_canon_state, &BTreeMap::new()),
        Err(RunError::InvalidPlan(_))
    ));
}

fn private_test_root(prefix: &str) -> PathBuf {
    let keys = if cfg!(windows) {
        ["LOCALAPPDATA", "USERPROFILE"]
    } else {
        ["XDG_RUNTIME_DIR", "HOME"]
    };
    let base_opt = keys.into_iter().find_map(|key| {
        std::env::var_os(key).and_then(|val| {
            let p = PathBuf::from(val);
            (!p.as_os_str().is_empty() && p.is_absolute()).then_some(p)
        })
    });
    assert!(
        base_opt.is_some(),
        "private_test_root requires XDG_RUNTIME_DIR/HOME on Unix or LOCALAPPDATA/USERPROFILE on Windows"
    );
    let base = base_opt.unwrap_or_else(|| PathBuf::from("missing-test-root"));
    let short_id = format!("{:012x}", uuid::Uuid::now_v7().as_u128() & 0xFFFF_FFFF_FFFF);
    base.join(format!(".{prefix}-{short_id}"))
}

#[tokio::test]
async fn ipc_gate_rejects_protected_override_and_verifies_disk_signed_floor() {
    let (mut protected_req, _g1) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::current(),
        "agent-x",
        false,
    );
    protected_req.profile = InstallProfile::Protected;
    let protected_client = IpcGateClient::new(
        Profile::Protected,
        Some("/var/run/evil/decide.sock".into()),
        300,
    );
    let err = authorize_launch(&protected_client, &protected_req, None, Timestamp::now())
        .await
        .unwrap_err();
    assert!(matches!(err, RunError::PolicyDenied(_)));

    let state_dir = private_test_root("grdr-run-floor");
    let _ = create_private_dir_all(&state_dir).unwrap();

    let kp = SigningKeypair::generate().unwrap();
    let pub_info = kp.public_info();
    let now_s = Timestamp::now().as_second();
    let doc = FloorTableDocument {
        epoch: 1,
        expires_at_unix_s: now_s + 3_600,
        signer_key_id: pub_info.key_id.clone(),
        rules: vec![FloorRuleRecord {
            action_class: FastActionClass::Exec,
            verdict: FastVerdict::Deny,
            match_kind: FloorMatchKind::Contains,
            rule_id: "floor-deny-danger".into(),
            pattern: "danger-bin".into(),
            agents: Vec::new(),
        }],
    };
    let signed_bytes = encode_signed_floor_table(&doc, &kp).unwrap();
    {
        let mut f = open_nofollow_file(
            &state_dir.join("floor.bin"),
            OpenNofollowAccess::TruncateCreate,
            0o600,
        )
        .unwrap();
        f.write_all(&signed_bytes).unwrap();
        let mut p = open_nofollow_file(
            &state_dir.join("floor.pub"),
            OpenNofollowAccess::TruncateCreate,
            0o600,
        )
        .unwrap();
        p.write_all(format!("{}:{}\n", pub_info.key_id, pub_info.public_key_b64).as_bytes())
            .unwrap();
    }

    let unreachable_client = StubGateClient { verdict: None };
    let (mut danger_req, _g2) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::current(),
        "agent-x",
        false,
    );
    danger_req.program = "danger-bin".into();

    let deny_verdict = authorize_launch_with_state_dir(
        &unreachable_client,
        &danger_req,
        None,
        Some(&state_dir),
        Profile::User,
        Timestamp::now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        deny_verdict,
        GateVerdict::Deny {
            source: GateDecisionSource::SignedCompiledFloor { degraded: true },
            ..
        }
    ));

    let (spawn_req, _g3) = sample_req(
        ContainmentStrategy::WrapAgent,
        HostOsKind::current(),
        "agent-x",
        false,
    );
    let d15_verdict = authorize_launch_with_state_dir(
        &unreachable_client,
        &spawn_req,
        None,
        Some(&state_dir),
        Profile::User,
        Timestamp::now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        d15_verdict,
        GateVerdict::Deny {
            source: GateDecisionSource::SignedCompiledFloor { degraded: true },
            ..
        }
    ));

    let mut tampered = signed_bytes;
    if let Some(byte) = tampered.get_mut(16) {
        *byte ^= 0x01;
    }
    {
        let mut f = open_nofollow_file(
            &state_dir.join("floor.bin"),
            OpenNofollowAccess::TruncateCreate,
            0o600,
        )
        .unwrap();
        f.write_all(&tampered).unwrap();
    }
    let untrusted = authorize_launch_with_state_dir(
        &unreachable_client,
        &danger_req,
        None,
        Some(&state_dir),
        Profile::User,
        Timestamp::now(),
    )
    .await;
    assert!(matches!(untrusted, Err(RunError::FloorUntrusted)));

    // Stale signed floor table (expired within grace period) must fail closed even on Allow rule.
    let stale_doc = FloorTableDocument {
        epoch: 2,
        expires_at_unix_s: now_s - 60,
        signer_key_id: pub_info.key_id.clone(),
        rules: vec![FloorRuleRecord {
            action_class: FastActionClass::Exec,
            verdict: FastVerdict::Allow,
            match_kind: FloorMatchKind::Contains,
            rule_id: "floor-allow-echo".into(),
            pattern: "echo".into(),
            agents: Vec::new(),
        }],
    };
    let stale_bytes = encode_signed_floor_table(&stale_doc, &kp).unwrap();
    {
        let mut f = open_nofollow_file(
            &state_dir.join("floor.bin"),
            OpenNofollowAccess::TruncateCreate,
            0o600,
        )
        .unwrap();
        f.write_all(&stale_bytes).unwrap();
    }
    let (echo_req, _g4) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::current(),
        "agent-x",
        false,
    );
    let stale_verdict = authorize_launch_with_state_dir(
        &unreachable_client,
        &echo_req,
        None,
        Some(&state_dir),
        Profile::User,
        Timestamp::now(),
    )
    .await
    .unwrap();
    assert!(matches!(
        stale_verdict,
        GateVerdict::Deny {
            source: GateDecisionSource::SignedCompiledFloor { degraded: true },
            ..
        }
    ));

    // Shared temp state directory override must fail closed.
    let unsafe_temp_dir = std::env::temp_dir().join("grdr-unsafe-floor-state");
    let unsafe_res = authorize_launch_with_state_dir(
        &unreachable_client,
        &echo_req,
        None,
        Some(&unsafe_temp_dir),
        Profile::User,
        Timestamp::now(),
    )
    .await;
    assert!(matches!(unsafe_res, Err(RunError::PolicyDenied(_))));

    let _ = std::fs::remove_dir_all(&state_dir);
}

#[test]
fn execute_prepared_launch_enforces_real_os_containment_and_clears_secrets() {
    let (mut req, _ws_guard) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::current(),
        "agent-x",
        false,
    );
    if cfg!(windows) {
        req.program = "C:\\Windows\\System32\\cmd.exe".into();
        req.args = vec!["/C".into(), "exit".into(), "0".into()];
    } else {
        req.program = "/bin/sh".into();
        req.args = vec!["-c".into(), "exit 0".into()];
    }

    let mut env = BTreeMap::new();
    env.insert("PATH".into(), std::env::var("PATH").unwrap_or_default());
    env.insert("GITHUB_TOKEN".into(), "ghp_should_strip".into());

    let (_cmd, plan) = build_launch_plan(&req, &env).unwrap();
    let env_vec: Vec<(String, String)> = env.into_iter().collect();
    let report = execute_prepared_launch(&req, &plan, &env_vec).unwrap();
    assert!(report.success);
    assert_eq!(report.exit_code, 0);
    assert!(
        report
            .sandbox_report
            .stripped_env_vars
            .contains(&"GITHUB_TOKEN".to_string())
    );
    if cfg!(windows) {
        assert!(
            report
                .enforced_mechanisms
                .contains(&EnforcedMechanism::WindowsJobObject)
        );
        assert!(
            report
                .enforced_mechanisms
                .contains(&EnforcedMechanism::WindowsRestrictedToken)
        );
    } else if cfg!(target_os = "linux") {
        assert!(
            report
                .enforced_mechanisms
                .contains(&EnforcedMechanism::NoNewPrivs)
        );
    }
}

#[tokio::test]
async fn live_peer_verified_ipc_gate_roundtrip() {
    use grdr_ipc_os::proto_io::ProtoIpcStream;
    use grdr_wire::frame::{WireFrame, WirePayload};
    use grdr_wire::messages::{
        DecideAckFrame, DecideVerdictFrame, EndpointServiceKind, HandoverStage, WireVerdict,
    };
    use grdr_wire::peer_auth::{OsPeerClaims, ServerIdentityPolicy};
    use std::time::Duration;

    #[cfg(windows)]
    let (endpoint_str, cleanup_dir, srv_handle) = {
        use grdr_ipc_os::windows_pipe_server::{WindowsNamedPipeAcceptor, WindowsServerPipeStream};
        use grdr_wire::peer_auth::{Evidence, Refusal, accept_deferred_windows};

        let pipe_name = format!(r"\\.\pipe\grdr-run-ipc-test-{}", std::process::id());
        let mut acceptor = WindowsNamedPipeAcceptor::bind(
            &pipe_name,
            "D:(A;;GA;;;OW)(A;;0x00120083;;;AU)S:(ML;;NW;;;ME)",
        )
        .unwrap();
        let handle = std::thread::spawn(move || -> Result<(), String> {
            let link = acceptor
                .accept(Duration::from_secs(3))
                .map_err(|e| e.to_string())?;
            let connected_at = link.connected_at_100ns();
            let (pre_claims, proc_hold) =
                grdr_peer_os::win_peer::read_windows_pipe_client_pre(link.borrowed_handle())
                    .map_err(|e| e.to_string())?;
            let expected_pid = pre_claims.pid;
            let expected_sid = pre_claims.peer_sid;
            let policy = ServerIdentityPolicy {
                profile: Profile::User,
                allowed_client_uids: vec![],
                allowed_windows_sids: vec![expected_sid.clone()],
                minimum_integrity_rid: 0x2000,
                reject_app_container: true,
                require_start_time_before_connect: true,
                require_open_as_self_pipe_check: true,
                require_kernel_peer_token: false,
            };
            let pending = accept_deferred_windows(ProtoIpcStream::new(link), connected_at, &policy)
                .map_err(|e| e.to_string())?;
            let (mut chan, _) = pending
                .first_frame_with_claims(
                    EndpointServiceKind::Decide,
                    "sha256:test",
                    1,
                    HandoverStage::Normal,
                    1_048_576,
                    Some(move |s: &mut ProtoIpcStream<WindowsServerPipeStream>| {
                        let verified =
                            grdr_peer_os::win_peer::verify_windows_pipe_client_post_read(
                                s.get_ref().borrowed_handle(),
                                &proc_hold,
                                expected_pid,
                                &expected_sid,
                            )
                            .map_err(|err| {
                                Refusal::UnauthenticatedPeer(Evidence::MissingPeerToken {
                                    detail: err.to_string(),
                                })
                            })?;
                        Ok(OsPeerClaims::Windows(verified))
                    }),
                )
                .map_err(|e| e.to_string())?;
            let req_frame = chan.recv_frame().map_err(|e| e.to_string())?;
            let req_id = match req_frame.payload {
                Some(WirePayload::DecideRequest(r)) => {
                    if !r.command_line.contains("echo ok") || r.cwd.trim().is_empty() {
                        return Err(format!(
                            "missing command_line/cwd in DecideRequest: cmd={} cwd={}",
                            r.command_line, r.cwd
                        ));
                    }
                    r.request_id
                }
                other => return Err(format!("expected DecideRequest, got {other:?}")),
            };
            chan.send_credit_grant(4).map_err(|e| e.to_string())?;
            chan.send_frame(WireFrame::with_payload(
                1,
                1,
                WirePayload::DecideAck(DecideAckFrame {
                    request_id: req_id.clone(),
                    epoch: 1,
                    accepted_at_mono_ms: 5,
                    handover_stage: HandoverStage::Normal as i32,
                }),
            ))
            .map_err(|e| e.to_string())?;
            chan.send_frame(WireFrame::with_payload(
                1,
                2,
                WirePayload::DecideVerdict(DecideVerdictFrame {
                    request_id: req_id,
                    verdict: WireVerdict::Allow as i32,
                    rule_id: "R-IPC-ALLOW".into(),
                    reason: "peer verified".into(),
                    receipt_id: "rcp-ipc-1".into(),
                    floor_fallback: false,
                    degraded_reason: String::new(),
                    audit_fsynced: true,
                    labels: Vec::new(),
                }),
            ))
            .map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(50));
            Ok(())
        });
        (pipe_name, Option::<PathBuf>::None, handle)
    };

    #[cfg(unix)]
    let (endpoint_str, cleanup_dir, srv_handle) = {
        use grdr_ipc_os::LocalEndpointAddress;
        use grdr_ipc_os::transport::{Acceptor, FixedTimestampSource, IpcDeadline};
        use grdr_ipc_os::unix_domain::UnixDomainAcceptor;
        use grdr_os_clock::{Clock, SystemClock};
        use grdr_wire::peer_auth::accept;

        let sock_dir = private_test_root("gr");
        let _ = create_private_dir_all(&sock_dir).unwrap();
        let sock_path = sock_dir.join("d.sock");
        let addr_str = sock_path.to_string_lossy().into_owned();
        let mut acceptor = UnixDomainAcceptor::bind_with_mode(
            LocalEndpointAddress::UnixSocket { path: sock_path },
            0o600,
        )
        .unwrap();
        let handle = std::thread::spawn(move || -> Result<(), String> {
            let clock = SystemClock::new();
            let now = clock.now_wall().map_err(|e| e.to_string())?;
            let link = acceptor
                .accept(
                    IpcDeadline::from_millis_capped(3_000, 3_000),
                    &FixedTimestampSource::new(now),
                )
                .map_err(|e| e.to_string())?;
            let (uid, _) = grdr_peer_os::unix_peer::current_effective_ids()
                .ok_or_else(|| "uid unavailable".to_string())?;
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
            let hold = grdr_peer_os::unix_peer::read_unix_socket_peer(link.borrowed_fd(), stamp)
                .map_err(|e| e.to_string())?;
            let policy = ServerIdentityPolicy {
                profile: Profile::User,
                allowed_client_uids: vec![uid, 0],
                allowed_windows_sids: vec![],
                minimum_integrity_rid: 0,
                reject_app_container: false,
                require_start_time_before_connect: true,
                require_open_as_self_pipe_check: false,
                require_kernel_peer_token: true,
            };
            let pending = accept(
                ProtoIpcStream::new(link),
                &OsPeerClaims::Unix(hold.claims.clone()),
                stamp.for_platform(),
                &policy,
            )
            .map_err(|e| e.to_string())?;
            let (mut chan, _) = pending
                .first_frame(
                    EndpointServiceKind::Decide,
                    "sha256:test",
                    1,
                    HandoverStage::Normal,
                    1_048_576,
                )
                .map_err(|e| e.to_string())?;
            let req_frame = chan.recv_frame().map_err(|e| e.to_string())?;
            let req_id = match req_frame.payload {
                Some(WirePayload::DecideRequest(r)) => {
                    if !r.command_line.contains("echo ok") || r.cwd.trim().is_empty() {
                        return Err(format!(
                            "missing command_line/cwd in DecideRequest: cmd={} cwd={}",
                            r.command_line, r.cwd
                        ));
                    }
                    r.request_id
                }
                other => return Err(format!("expected DecideRequest, got {other:?}")),
            };
            chan.send_credit_grant(4).map_err(|e| e.to_string())?;
            chan.send_frame(WireFrame::with_payload(
                1,
                1,
                WirePayload::DecideAck(DecideAckFrame {
                    request_id: req_id.clone(),
                    epoch: 1,
                    accepted_at_mono_ms: 5,
                    handover_stage: HandoverStage::Normal as i32,
                }),
            ))
            .map_err(|e| e.to_string())?;
            chan.send_frame(WireFrame::with_payload(
                1,
                2,
                WirePayload::DecideVerdict(DecideVerdictFrame {
                    request_id: req_id,
                    verdict: WireVerdict::Allow as i32,
                    rule_id: "R-IPC-ALLOW".into(),
                    reason: "peer verified".into(),
                    receipt_id: "rcp-ipc-1".into(),
                    floor_fallback: false,
                    degraded_reason: String::new(),
                    audit_fsynced: true,
                    labels: Vec::new(),
                }),
            ))
            .map_err(|e| e.to_string())?;
            std::thread::sleep(Duration::from_millis(50));
            Ok(())
        });
        let _ = Duration::from_millis(1);
        (addr_str, Some(sock_dir), handle)
    };

    let (mut req, _ws_guard) = sample_req(
        ContainmentStrategy::WrapAgent,
        HostOsKind::current(),
        "agent-x",
        false,
    );
    req.profile = InstallProfile::User;
    let client = IpcGateClient::new(Profile::User, Some(endpoint_str), 2_000);
    let verdict = authorize_launch(&client, &req, None, Timestamp::now())
        .await
        .unwrap();
    srv_handle.join().unwrap().unwrap();
    if let Some(dir) = cleanup_dir {
        let _ = std::fs::remove_dir_all(dir);
    }
    assert!(matches!(
        verdict,
        GateVerdict::Allow {
            source: GateDecisionSource::Daemon
        }
    ));
}

#[tokio::test]
async fn active_peer_auth_failure_fails_closed_even_when_floor_exists() {
    use std::time::Duration;

    let state_dir = private_test_root("grfl");
    let _ = create_private_dir_all(&state_dir).unwrap();
    let kp = SigningKeypair::generate().unwrap();
    let pub_info = kp.public_info();
    let doc = FloorTableDocument {
        epoch: 1,
        expires_at_unix_s: Timestamp::now().as_second() + 3_600,
        signer_key_id: pub_info.key_id.clone(),
        rules: vec![FloorRuleRecord {
            action_class: FastActionClass::Exec,
            verdict: FastVerdict::Allow,
            match_kind: FloorMatchKind::Contains,
            rule_id: "floor-allow-all".into(),
            pattern: "echo".into(),
            agents: Vec::new(),
        }],
    };
    let signed_bytes = encode_signed_floor_table(&doc, &kp).unwrap();
    {
        let mut f = open_nofollow_file(
            &state_dir.join("floor.bin"),
            OpenNofollowAccess::TruncateCreate,
            0o600,
        )
        .unwrap();
        f.write_all(&signed_bytes).unwrap();
        let mut p = open_nofollow_file(
            &state_dir.join("floor.pub"),
            OpenNofollowAccess::TruncateCreate,
            0o600,
        )
        .unwrap();
        p.write_all(format!("{}:{}\n", pub_info.key_id, pub_info.public_key_b64).as_bytes())
            .unwrap();
    }

    #[cfg(windows)]
    let (endpoint_str, cleanup_dir, srv_handle) = {
        use grdr_ipc_os::windows_pipe_server::WindowsNamedPipeAcceptor;
        let pipe_name = format!(r"\\.\pipe\grdr-run-bad-peer-{}", std::process::id());
        let mut acceptor = WindowsNamedPipeAcceptor::bind(
            &pipe_name,
            "D:(A;;GA;;;OW)(A;;0x00120083;;;AU)S:(ML;;NW;;;ME)",
        )
        .unwrap();
        let handle = std::thread::spawn(move || {
            if let Ok(mut link) = acceptor.accept(Duration::from_secs(3)) {
                let _ = std::io::Write::write_all(&mut link, b"INVALID_GARBAGE_FRAME");
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        (pipe_name, Option::<PathBuf>::None, handle)
    };

    #[cfg(unix)]
    let (endpoint_str, cleanup_dir, srv_handle) = {
        use grdr_ipc_os::LocalEndpointAddress;
        use grdr_ipc_os::transport::{Acceptor, FixedTimestampSource, IpcDeadline};
        use grdr_ipc_os::unix_domain::UnixDomainAcceptor;
        use grdr_os_clock::{Clock, SystemClock};
        let sock_dir = private_test_root("gb");
        let _ = create_private_dir_all(&sock_dir).unwrap();
        let sock_path = sock_dir.join("b.sock");
        let addr_str = sock_path.to_string_lossy().into_owned();
        let mut acceptor = UnixDomainAcceptor::bind_with_mode(
            LocalEndpointAddress::UnixSocket { path: sock_path },
            0o600,
        )
        .unwrap();
        let handle = std::thread::spawn(move || {
            let clock = SystemClock::new();
            let now = clock.now_wall().unwrap_or(Timestamp::UNIX_EPOCH);
            if let Ok(mut link) = acceptor.accept(
                IpcDeadline::from_millis_capped(3_000, 3_000),
                &FixedTimestampSource::new(now),
            ) {
                let _ = std::io::Write::write_all(&mut link, b"INVALID_GARBAGE_FRAME");
                std::thread::sleep(Duration::from_millis(50));
            }
        });
        let _ = Duration::from_millis(1);
        (addr_str, Some(sock_dir), handle)
    };

    let (mut req, _ws_guard) = sample_req(
        ContainmentStrategy::WrapTools,
        HostOsKind::current(),
        "agent-x",
        false,
    );
    req.profile = InstallProfile::User;
    let client = IpcGateClient::new(Profile::User, Some(endpoint_str), 2_000);
    let res = authorize_launch_with_state_dir(
        &client,
        &req,
        None,
        Some(&state_dir),
        Profile::User,
        Timestamp::now(),
    )
    .await;
    let _ = srv_handle.join();
    if let Some(dir) = cleanup_dir {
        let _ = std::fs::remove_dir_all(dir);
    }
    let _ = std::fs::remove_dir_all(&state_dir);
    assert!(matches!(res, Err(RunError::PolicyDenied(_))));
}

#[test]
fn plans_macos_supervise_descendants_budget_and_scoped_tmpdir() {
    let env = BTreeMap::new();
    let (mut req, _guard) = sample_req(
        ContainmentStrategy::WrapAgent,
        HostOsKind::MacOs,
        "cursor",
        false,
    );
    req.macos_supervise = Some(MacOsSuperviseConfig {
        deadline_floor_ms: 5_000,
        miss_mode: MacOsSuperviseMissMode::FailClosed,
    });
    let (_, plan) = build_launch_plan(&req, &env).expect("valid macOS supervise plan");
    assert!(plan.proxy_env.contains_key("TMPDIR"));
    assert_eq!(
        plan.proxy_env.get("GRDR_MAC_SUPERVISE").map(String::as_str),
        Some("1")
    );
    assert_eq!(
        plan.proxy_env
            .get("GRDR_MAC_SUPERVISE_HOLD_CAP_MS")
            .map(String::as_str),
        Some("4000")
    );
    assert_eq!(
        plan.proxy_env
            .get("GRDR_MAC_SUPERVISE_FAIL_CLOSED")
            .map(String::as_str),
        Some("1")
    );
    match plan.platform {
        PlatformContainmentPlan::MacOs {
            supervisor: Some(sup),
            exec_assurance,
            ..
        } => {
            assert!(sup.descendants_mode);
            assert_eq!(sup.deadline_floor_ms, 5_000);
            assert_eq!(sup.hold_cap_ms, 4_000);
            assert_eq!(sup.miss_policy, DeadlineMissPolicy::DescendantsFailClosed);
            if sup.es_verified_live {
                assert_eq!(exec_assurance.level(), AssuranceLevel::Al4Enforced);
            } else {
                assert_eq!(exec_assurance.level(), AssuranceLevel::Al3Contained);
                assert!(exec_assurance.level() < AssuranceLevel::Al4Enforced);
            }
        }
        other => panic!("expected MacOs supervisor plan, got {other:?}"),
    }

    // Invalid floor within 10s guard of u32::MAX must fail validation.
    req.macos_supervise = Some(MacOsSuperviseConfig {
        deadline_floor_ms: u64::from(u32::MAX),
        miss_mode: MacOsSuperviseMissMode::FailOpen,
    });
    assert!(build_launch_plan(&req, &env).is_err());
}
