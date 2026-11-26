// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use jiff::Timestamp;

use grdr_core::compile::compile_floor_table;
use grdr_core::policy::ReceiptDigestInput;
use grdr_core::policy::compute_receipt_digest;
use grdr_crypto::SigningKeypair;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, AssuranceLevel, InstallProfile, Mode, PolicyPack,
    PolicyRule, RuleMatch, SigningKeypairExt as _, Verdict,
};
use grdr_run::RunError;
use grdr_run::gate::{
    GateDecisionSource, GateFuture, GateVerdict, LaunchGateClient, authorize_launch,
};
use grdr_run::planner::{
    ContainmentStrategy, HostOsKind, LaunchRequestSpec, PlatformContainmentPlan, build_launch_plan,
};
use grdr_sensor_macos::MacOsContainmentMode;
use grdr_sensor_windows::LaunchRoute;

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

fn sample_req(
    strategy: ContainmentStrategy,
    host_os: HostOsKind,
    agent_name: &str,
    native_sandbox: bool,
) -> LaunchRequestSpec {
    let raw_tmp =
        std::env::temp_dir().join(format!("grdr-run-ws-{}", uuid::Uuid::now_v7().simple()));
    let _ = std::fs::create_dir_all(&raw_tmp);
    let canon_tmp = std::fs::canonicalize(&raw_tmp).unwrap_or(raw_tmp);
    let canon_str = canon_tmp.to_string_lossy();
    let real_tmp_str = canon_str.strip_prefix("\\\\?\\").unwrap_or(&canon_str);
    let current_os = HostOsKind::current();
    LaunchRequestSpec {
        session_id: "sess-run-01".into(),
        tool_call_id: (strategy == ContainmentStrategy::WrapTools).then(|| "tool-99".into()),
        agent_name: agent_name.into(),
        program: "echo".into(),
        args: vec!["ok".into()],
        workspace_root: if host_os == current_os {
            real_tmp_str.to_owned()
        } else if host_os == HostOsKind::Windows {
            "C:\\workspace\\demo".into()
        } else {
            "/tmp/workspace/demo".into()
        },
        protected_paths: if host_os == HostOsKind::Windows {
            vec!["C:\\Users\\dev\\.ssh".into()]
        } else {
            vec!["/Users/dev/.ssh".into()]
        },
        state_dirs: if host_os == HostOsKind::Windows {
            vec![]
        } else {
            vec!["/Users/dev/.claude".into()]
        },
        strategy,
        agent_has_native_sandbox: native_sandbox,
        host_os,
        profile: InstallProfile::Protected,
        proxy_port: 18080,
        decide_socket_path: "/var/run/grdr/decide.sock".into(),
        sandbox_sid: "S-1-15-2-1001".into(),
        extra_allow_env: Vec::new(),
    }
}

#[test]
fn plans_delegate_wrap_tools_wrap_agent_and_scrubs_secrets() {
    let mut env = BTreeMap::new();
    env.insert("PATH".into(), "/usr/bin".into());
    env.insert("OPENAI_API_KEY".into(), "secret-openai-value".into());
    env.insert("ANTHROPIC_API_KEY".into(), "secret-anthropic-value".into());

    // Explicit macOS WrapAgent retains WrapAgent + SBPL profile even when agent has native sandbox.
    let mac_wrap = sample_req(
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
    let mac_delegate = sample_req(
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
    let win_tools = sample_req(
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
    let lin_agent = sample_req(
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
    let mut bad = sample_req(
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
}

#[tokio::test]
async fn daemon_gate_falls_back_to_signed_floor_and_rejects_tampered_floor() {
    let now = Timestamp::now();
    let req = sample_req(
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
    let mut blocked_req = sample_req(
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
