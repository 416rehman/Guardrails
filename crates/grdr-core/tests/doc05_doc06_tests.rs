// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;

use grdr_core::discover::{
    BehaviorVerdict, BehavioralObservation, ClassifierConfig, ExecutionEnvironmentSignal,
    IdentityHints, Pass1MatchState, ProgramIdentity, ScanBlockedReason, classify_agentic_loop,
    evaluate_pass1_routes,
};
use grdr_core::session::{
    AttributionRecord, ChildSpawnRequest, CorrelationKeyKind, DivergenceKind, EdgeKind,
    EvidenceGrade, GraphNodeKind, HookObservation, HostSharingMode, JoinCandidate,
    JoinConsumptionState, JoinContext, JoinResult, K4MatchStrength, LineageEdge, LineageGraph,
    ProcessRoleHint, ProvenanceKind, ReconciliationInput, SensorObservation, SessionActorKind,
    SessionCloseTrigger, SessionConstraints, SessionLifecyclePhase, SessionRegistry, StartBasis,
    grade_for_evidence, reconcile_session_evidence, resolve_correlation_join,
    satisfies_unless_floor, supersede_attribution, try_format_outward_identity,
};
use grdr_model::{ActionClass, ApprovalGrade, IdentityMode, Mode};

#[test]
fn doc05_program_identity_routes_classifier_and_abom_drift() {
    let signed = ProgramIdentity::from_hints(&IdentityHints {
        code_signer: Some("Anthropic, Inc.".into()),
        binary_digest: Some("abc123".into()),
        ecosystem: Some("npm".into()),
        package_name: Some("@anthropic-ai/claude-code".into()),
        executable_path: "/usr/local/bin/claude".into(),
        ..IdentityHints::default()
    });
    assert_eq!(signed.canonical_id(), "sig:Anthropic, Inc.:abc123");

    let pkg = ProgramIdentity::from_hints(&IdentityHints {
        ecosystem: Some("npm".into()),
        package_name: Some("@openai/codex".into()),
        package_version: Some("1.2.0".into()),
        executable_path: "/usr/bin/codex".into(),
        ..IdentityHints::default()
    });
    assert_eq!(pkg.canonical_id(), "pkg:npm:@openai/codex@1.2.0");

    assert_eq!(evaluate_pass1_routes(0), Pass1MatchState::NotFound);
    assert_eq!(evaluate_pass1_routes(1), Pass1MatchState::Candidate);
    assert_eq!(evaluate_pass1_routes(2), Pass1MatchState::InstalledMatched);

    let cfg = ClassifierConfig::default();
    assert!(cfg.validate().is_ok());

    let llm_only = classify_agentic_loop(
        &BehavioralObservation {
            process_name: "curl-llm".into(),
            llm_request_timestamps_ms: vec![1_000, 5_000, 10_000],
            tool_effect_timestamps_ms: vec![],
            ..BehavioralObservation::default()
        },
        &cfg,
    );
    assert_eq!(llm_only.verdict, BehaviorVerdict::LlmClient);
    assert!(llm_only.is_advisory_only());

    let mut signals = BTreeSet::new();
    signals.insert(ExecutionEnvironmentSignal::WorkspaceOrSandbox);
    signals.insert(ExecutionEnvironmentSignal::HeadlessEnvMarker);
    let agentic = classify_agentic_loop(
        &BehavioralObservation {
            process_name: "python-agent".into(),
            llm_request_timestamps_ms: vec![10_000, 15_000, 20_000, 25_000],
            tool_effect_timestamps_ms: vec![10_400, 15_500, 20_300, 25_600],
            environment_signals: signals,
            orchestrator_blocks: vec!["langgraph".into()],
            ..BehavioralObservation::default()
        },
        &cfg,
    );
    assert_eq!(agentic.verdict, BehaviorVerdict::AgentClassified);
    assert_eq!(agentic.cycle_count, 4);
    assert_eq!(agentic.coincidence_ratio_bp, 10_000);
    assert!(agentic.is_advisory_only());

    let blocked = classify_agentic_loop(
        &BehavioralObservation {
            process_name: "sealed-proc".into(),
            scan_blocked: Some(ScanBlockedReason::ProtectedContainer),
            ..BehavioralObservation::default()
        },
        &cfg,
    );
    assert_eq!(
        blocked.verdict,
        BehaviorVerdict::ScanBlocked(ScanBlockedReason::ProtectedContainer)
    );
}

#[test]
fn doc06_session_lifecycle_boot_isolation_and_resume_taint() {
    let mut reg = SessionRegistry::new("boot-1");
    let rec = reg
        .open_session(
            "s-1",
            "claude-code",
            StartBasis::Launched,
            SessionConstraints::default(),
            100,
        )
        .unwrap();
    assert_eq!(rec.phase, SessionLifecyclePhase::Active);

    // SessionEnd hook claim alone moves Active -> Draining, never Ended.
    let after_claim = reg
        .apply_close_trigger("s-1", SessionCloseTrigger::HookSessionEnd, 200)
        .unwrap();
    assert_eq!(after_claim, SessionLifecyclePhase::Draining);

    let after_exit = reg
        .apply_close_trigger("s-1", SessionCloseTrigger::ProcessExit, 300)
        .unwrap();
    assert_eq!(after_exit, SessionLifecyclePhase::Ended);

    reg.open_session(
        "s-2",
        "codex",
        StartBasis::ObservedExec,
        SessionConstraints::default(),
        400,
    )
    .unwrap();
    reg.add_taint("s-2", "secret-read").unwrap();
    reg.record_denial("s-2").unwrap();

    // Cross-boot transition closes all prior-boot open sessions.
    let closed = reg.record_boot_transition("boot-2", 500);
    assert_eq!(closed, 1);
    assert!(!reg.get("s-2").unwrap().accepts_events("boot-2"));

    let resumed = reg.resume_session("s-2", "s-3", 600).unwrap();
    assert!(resumed.taint_labels.contains("secret-read"));
    assert_eq!(resumed.prior_denials, 1);
    assert_eq!(resumed.resumed_from_session_id.as_deref(), Some("s-2"));
    assert_eq!(resumed.boot_id, "boot-2");
}

#[test]
fn doc06_k1_k6_join_tie_breaks_provenance_floors_and_supersession() {
    let ctx = JoinContext {
        process_boot_id: "boot-a".into(),
        actor_user_id: "alice".into(),
        provenance: ProvenanceKind::ObservedKernel,
        host_sharing: HostSharingMode::IsolatedAgentTree,
        process_role: ProcessRoleHint::AgentOrSubprocess,
    };
    let candidates = vec![
        JoinCandidate {
            session_id: "sess-k3".into(),
            boot_id: "boot-a".into(),
            key_kind: CorrelationKeyKind::K3HookMetadata,
            k4_strength: K4MatchStrength::PatternOnly,
            consumption: JoinConsumptionState::Unconsumed,
            start_delta_ms: 1,
            user_id: "alice".into(),
        },
        JoinCandidate {
            session_id: "sess-k4-exact".into(),
            boot_id: "boot-a".into(),
            key_kind: CorrelationKeyKind::K4ProcessLineage,
            k4_strength: K4MatchStrength::ExactPidStartTime,
            consumption: JoinConsumptionState::Unconsumed,
            start_delta_ms: 5,
            user_id: "alice".into(),
        },
        JoinCandidate {
            session_id: "sess-other-boot".into(),
            boot_id: "boot-old".into(),
            key_kind: CorrelationKeyKind::K1WrapperEnv,
            k4_strength: K4MatchStrength::ExactPidStartTime,
            consumption: JoinConsumptionState::Unconsumed,
            start_delta_ms: 0,
            user_id: "alice".into(),
        },
    ];

    match resolve_correlation_join(&candidates, &ctx) {
        JoinResult::Matched {
            session_id,
            key_kind,
            grade,
            actor_kind,
            ..
        } => {
            assert_eq!(session_id, "sess-k4-exact");
            assert_eq!(key_kind, CorrelationKeyKind::K4ProcessLineage);
            assert_eq!(grade, EvidenceGrade::Grade4);
            assert_eq!(actor_kind, SessionActorKind::Agent);
        }
        other => panic!("expected exact K4 winner, got {other:?}"),
    }

    // Equal-rank candidates must return Ambiguous Grade0 + Undetermined instead of guessing.
    let tied = vec![
        JoinCandidate {
            session_id: "s-left".into(),
            boot_id: "boot-a".into(),
            key_kind: CorrelationKeyKind::K5CgroupKey,
            k4_strength: K4MatchStrength::PatternOnly,
            consumption: JoinConsumptionState::Unconsumed,
            start_delta_ms: 10,
            user_id: "alice".into(),
        },
        JoinCandidate {
            session_id: "s-right".into(),
            boot_id: "boot-a".into(),
            key_kind: CorrelationKeyKind::K5CgroupKey,
            k4_strength: K4MatchStrength::PatternOnly,
            consumption: JoinConsumptionState::Unconsumed,
            start_delta_ms: 10,
            user_id: "alice".into(),
        },
    ];
    match resolve_correlation_join(&tied, &ctx) {
        JoinResult::Ambiguous {
            grade, actor_kind, ..
        } => {
            assert_eq!(grade, EvidenceGrade::Grade0);
            assert_eq!(actor_kind, SessionActorKind::Undetermined);
        }
        other => panic!("expected Ambiguous, got {other:?}"),
    }

    // Provenance floors: ObservedUser/Claimed cannot pass >= Grade2 without ObservedKernel/Mediated.
    let claimed_grade = grade_for_evidence(
        ProvenanceKind::Claimed,
        CorrelationKeyKind::K1WrapperEnv,
        K4MatchStrength::ExactPidStartTime,
        true,
    );
    assert_eq!(claimed_grade, EvidenceGrade::Grade1);
    assert!(!satisfies_unless_floor(
        EvidenceGrade::Grade2,
        ProvenanceKind::ObservedUser,
        EvidenceGrade::Grade2
    ));
    assert!(satisfies_unless_floor(
        EvidenceGrade::Grade3,
        ProvenanceKind::ObservedKernel,
        EvidenceGrade::Grade2
    ));

    // Shared-host K3 claim does not wrongly attribute human activity to an agent.
    let shared_ctx = JoinContext {
        host_sharing: HostSharingMode::SharedHostProcess,
        ..ctx.clone()
    };
    match resolve_correlation_join(&candidates[..1], &shared_ctx) {
        JoinResult::Unmatched { actor_kind, .. } => assert_eq!(actor_kind, SessionActorKind::Human),
        other => panic!("expected Human shared-host fallback, got {other:?}"),
    }

    // Late stronger correlation supersedes provisional claim and flags attribution_late.
    let prior = AttributionRecord {
        session_id: Some("sess-k3".into()),
        key_kind: Some(CorrelationKeyKind::K3HookMetadata),
        provenance: ProvenanceKind::Claimed,
        grade: EvidenceGrade::Grade1,
        actor_kind: SessionActorKind::Agent,
        superseded_previous: None,
        attribution_late: false,
    };
    let late = resolve_correlation_join(&candidates, &ctx);
    let updated = supersede_attribution(&prior, &late, ProvenanceKind::ObservedKernel);
    assert!(updated.attribution_late);
    assert_eq!(updated.superseded_previous.as_deref(), Some("sess-k3"));
    assert_eq!(updated.session_id.as_deref(), Some("sess-k4-exact"));
    assert_eq!(updated.grade, EvidenceGrade::Grade4);
}

#[test]
fn doc06_lineage_graph_constraints_outward_identity_and_reconciliation() {
    let mut graph = LineageGraph::new();
    let parent_constraints = SessionConstraints {
        max_depth: 3,
        current_depth: 0,
        ceiling_mode: Mode::Ask,
        disallowed_classes: vec![ActionClass::Elevate],
    };
    let parent_labels: BTreeSet<String> = ["secret-read".to_owned()].into_iter().collect();
    let child_plan = graph
        .spawn_child_session(&ChildSpawnRequest {
            parent_id: "sess-parent",
            child_id: "sess-child",
            parent_constraints: &parent_constraints,
            parent_labels: &parent_labels,
            requested_max_depth: 5,
            requested_ceiling: Mode::Watch,
            extra_disallowed: &[ActionClass::NetConnect],
            grade: ApprovalGrade::G3,
            observed_at_ms: 1_000,
        })
        .unwrap();
    // Constraints strictly tighten on child: depth bounded by parent-1, stricter ceiling preserved.
    assert_eq!(child_plan.constraints.max_depth, 2);
    assert_eq!(child_plan.constraints.current_depth, 1);
    assert_eq!(child_plan.constraints.ceiling_mode, Mode::Ask);
    assert!(
        child_plan
            .constraints
            .disallowed_classes
            .contains(&ActionClass::Elevate)
    );
    assert!(
        child_plan
            .constraints
            .disallowed_classes
            .contains(&ActionClass::NetConnect)
    );
    assert!(child_plan.inherited_labels.contains("secret-read"));

    graph
        .add_edge(LineageEdge {
            from_id: "sess-child".into(),
            from_kind: GraphNodeKind::Subagent,
            to_id: "sess-parent".into(),
            to_kind: GraphNodeKind::Session,
            kind: EdgeKind::InfluencedBy,
            grade: ApprovalGrade::G2,
            observed_at_ms: 1_100,
            labels_carried: BTreeSet::new(),
        })
        .unwrap();
    assert_eq!(
        graph.descendants_bounded("sess-parent", 8),
        vec!["sess-child"]
    );

    let outward_key = b"0123456789abcdef0123456789abcdef";
    let p_named =
        try_format_outward_identity(IdentityMode::Named, "sess-123", outward_key).unwrap();
    let p_pseudo =
        try_format_outward_identity(IdentityMode::Pseudonymous, "sess-123", outward_key).unwrap();
    assert_eq!(
        try_format_outward_identity(IdentityMode::Pseudonymous, "sess-123", b"short")
            .unwrap_err()
            .code,
        "GRDR-SESS-0003"
    );
    assert_eq!(p_named, "sess-123");
    assert!(p_pseudo.starts_with("ses_"));
    assert_ne!(p_pseudo, "sess-123");

    let mut reg = SessionRegistry::new("boot-1");
    reg.open_session(
        "sess-active",
        "claude-code",
        StartBasis::Launched,
        parent_constraints,
        100,
    )
    .unwrap();
    let findings = reconcile_session_evidence(&ReconciliationInput {
        now_ms: 5_000,
        hook_dark_threshold_ms: 1_000,
        sessions: reg.sessions().values().cloned().collect(),
        hooks: vec![HookObservation {
            session_id: "sess-active".into(),
            claimed_session_id: Some("sess-spoofed".into()),
            target_digest: Some("sha-hook".into()),
            last_hook_ms: Some(1_000),
            hook_calls_count: 2,
        }],
        sensors: vec![
            SensorObservation {
                attributed_session_id: Some("sess-active".into()),
                observed_at_ms: 4_000,
                effect_digest: Some("sha-sensor-diff".into()),
                socket_tag_owner_sessions: vec!["s1".into(), "s2".into()],
                via_unregistered_hop: true,
                looks_like_agent_process: true,
            },
            SensorObservation {
                attributed_session_id: None,
                observed_at_ms: 4_500,
                effect_digest: None,
                socket_tag_owner_sessions: vec![],
                via_unregistered_hop: false,
                looks_like_agent_process: true,
            },
        ],
    });
    let kinds: BTreeSet<DivergenceKind> = findings.iter().map(|f| f.kind).collect();
    assert!(kinds.contains(&DivergenceKind::SessionClaimMismatch));
    assert!(kinds.contains(&DivergenceKind::TagConflict));
    assert!(kinds.contains(&DivergenceKind::UndeclaredHop));
    assert!(kinds.contains(&DivergenceKind::HookDark));
    assert!(kinds.contains(&DivergenceKind::EffectMismatch));
    assert!(kinds.contains(&DivergenceKind::UndeclaredActivity));
}

#[test]
fn doc05_doc06_security_invariants_freeze_downgrade_missing_hook_and_cycles() {
    // 1. Frozen session cannot be unfrozen by ProcessExit / SocketSilenceTimeout or resumed.
    let mut reg = SessionRegistry::new("boot-sec");
    reg.open_session(
        "s-frozen",
        "codex",
        StartBasis::Launched,
        SessionConstraints::default(),
        10,
    )
    .unwrap();
    assert!(
        reg.open_session(
            "s-frozen",
            "codex",
            StartBasis::Launched,
            SessionConstraints::default(),
            20,
        )
        .is_err()
    );
    reg.freeze_session("s-frozen").unwrap();
    assert_eq!(
        reg.apply_close_trigger("s-frozen", SessionCloseTrigger::ProcessExit, 30)
            .unwrap(),
        SessionLifecyclePhase::Frozen
    );
    assert_eq!(
        reg.apply_close_trigger("s-frozen", SessionCloseTrigger::SocketSilenceTimeout, 40)
            .unwrap(),
        SessionLifecyclePhase::Frozen
    );
    assert!(reg.resume_session("s-frozen", "s-resumed", 50).is_err());

    // 2. Attribution supersession never downgrades a higher grade.
    let strong_prior = AttributionRecord {
        session_id: Some("sess-strong".into()),
        key_kind: Some(CorrelationKeyKind::K4ProcessLineage),
        provenance: ProvenanceKind::ObservedKernel,
        grade: EvidenceGrade::Grade4,
        actor_kind: SessionActorKind::Agent,
        superseded_previous: None,
        attribution_late: false,
    };
    let weaker = JoinResult::Matched {
        session_id: "sess-spoof".into(),
        key_kind: CorrelationKeyKind::K3HookMetadata,
        grade: EvidenceGrade::Grade1,
        actor_kind: SessionActorKind::Agent,
        tie_break_reason: "claimed".into(),
    };
    assert_eq!(
        supersede_attribution(&strong_prior, &weaker, ProvenanceKind::Claimed),
        strong_prior
    );

    // 3. Reconciler detects HookSilent when zero HookObservations exist past threshold,
    // and retains multiple HookObservations for the same session.
    let mut reg2 = SessionRegistry::new("boot-2");
    reg2.open_session(
        "s-no-hooks",
        "claude-code",
        StartBasis::Launched,
        SessionConstraints::default(),
        100,
    )
    .unwrap();
    let silent_findings = reconcile_session_evidence(&ReconciliationInput {
        now_ms: 5_000,
        hook_dark_threshold_ms: 500,
        sessions: reg2.sessions().values().cloned().collect(),
        hooks: vec![],
        sensors: vec![SensorObservation {
            attributed_session_id: Some("s-no-hooks".into()),
            observed_at_ms: 2_000,
            effect_digest: None,
            socket_tag_owner_sessions: vec![],
            via_unregistered_hop: false,
            looks_like_agent_process: true,
        }],
    });
    assert!(
        silent_findings
            .iter()
            .any(|f| f.kind == DivergenceKind::HookSilent && f.session_id == "s-no-hooks")
    );

    // 4. Same-ms parallel tool events and future outlier tool timestamps stay accurate.
    let mut cfg = ClassifierConfig {
        min_cycles: 2,
        ..Default::default()
    };
    let res = classify_agentic_loop(
        &BehavioralObservation {
            process_name: "parallel-agent".into(),
            llm_request_timestamps_ms: vec![1_000, 1_000],
            tool_effect_timestamps_ms: vec![1_000, 1_000, 999_999_999],
            orchestrator_blocks: vec!["langgraph".into()],
            ..BehavioralObservation::default()
        },
        &cfg,
    );
    assert_eq!(res.verdict, BehaviorVerdict::AgentClassified);
    assert_eq!(res.cycle_count, 2);

    cfg.weights.orchestrator_package_bp = 10_001;
    assert!(cfg.validate().is_err());

    // 5. LineageGraph rejects self-edges, detects PidReuseMismatch, and avoids salt collision.
    let mut g = LineageGraph::new();
    assert!(
        g.add_edge(LineageEdge {
            from_id: "p1".into(),
            from_kind: GraphNodeKind::Process,
            to_id: "p1".into(),
            to_kind: GraphNodeKind::Process,
            kind: EdgeKind::Exec,
            grade: ApprovalGrade::G1,
            observed_at_ms: 100,
            labels_carried: BTreeSet::new(),
        })
        .is_err()
    );
    g.add_edge(LineageEdge {
        from_id: "root-a".into(),
        from_kind: GraphNodeKind::Session,
        to_id: "pid-42".into(),
        to_kind: GraphNodeKind::Process,
        kind: EdgeKind::Fork,
        grade: ApprovalGrade::G2,
        observed_at_ms: 100,
        labels_carried: BTreeSet::new(),
    })
    .unwrap();
    g.add_edge(LineageEdge {
        from_id: "root-b".into(),
        from_kind: GraphNodeKind::Session,
        to_id: "pid-42".into(),
        to_kind: GraphNodeKind::Process,
        kind: EdgeKind::Fork,
        grade: ApprovalGrade::G2,
        observed_at_ms: 200,
        labels_carried: BTreeSet::new(),
    })
    .unwrap();
    let known: BTreeSet<String> = ["root-a", "root-b", "pid-42"]
        .into_iter()
        .map(str::to_owned)
        .collect();
    let breaks = g.detect_lineage_breaks(&known);
    assert!(breaks.iter().any(|(id, kind)| id == "pid-42"
        && *kind == grdr_core::session::LineageBreakKind::PidReuseMismatch));
    let key_a = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa1";
    let key_b = b"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa2";
    assert_ne!(
        try_format_outward_identity(IdentityMode::Pseudonymous, "c", key_a).unwrap(),
        try_format_outward_identity(IdentityMode::Pseudonymous, "b:c", key_b).unwrap()
    );
    assert!(
        !try_format_outward_identity(IdentityMode::Named, "ok\u{202E}bad", key_a)
            .unwrap()
            .contains('\u{202E}')
    );

    // Aggregating multiple HookObservations on the same session suppresses false
    // HookSilent/HookDark when one active hook record has recent calls.
    let mut reg_agg = SessionRegistry::new("boot-h6");
    reg_agg
        .open_session(
            "s-agg",
            "claude-code",
            StartBasis::Launched,
            SessionConstraints::default(),
            100,
        )
        .unwrap();
    let agg_findings = reconcile_session_evidence(&ReconciliationInput {
        now_ms: 2_500,
        hook_dark_threshold_ms: 500,
        sessions: reg_agg.sessions().values().cloned().collect(),
        hooks: vec![
            HookObservation {
                session_id: "s-agg".into(),
                claimed_session_id: None,
                target_digest: None,
                last_hook_ms: None,
                hook_calls_count: 0,
            },
            HookObservation {
                session_id: "s-agg".into(),
                claimed_session_id: None,
                target_digest: None,
                last_hook_ms: Some(2_300),
                hook_calls_count: 3,
            },
        ],
        sensors: vec![SensorObservation {
            attributed_session_id: Some("s-agg".into()),
            observed_at_ms: 2_450,
            effect_digest: None,
            socket_tag_owner_sessions: vec![],
            via_unregistered_hop: false,
            looks_like_agent_process: true,
        }],
    });
    assert!(
        !agg_findings.iter().any(|f| matches!(
            f.kind,
            DivergenceKind::HookDark | DivergenceKind::HookSilent
        )),
        "active hook observation on session must prevent false HookSilent/HookDark: {agg_findings:?}"
    );

    // Git notes glob refspecs flag outside-org transfers across wildcard and character classes.
    for risky_ref in [
        "refs/notes/g*",
        "refs/n*",
        "refs/notes/?rdr",
        "refs/notes/[g]rdr",
        "+refs/*:refs/notes/backup",
    ] {
        assert_eq!(
            grdr_core::session::assess_git_notes_push(&["push", "origin", risky_ref], false),
            grdr_core::session::GitNotesPushAssessment::PushOutsideOrgViolation,
            "expected notes push detection for `{risky_ref}`"
        );
    }
    assert_eq!(
        grdr_core::session::assess_git_notes_push(&["push", "origin", "refs/heads/main"], false),
        grdr_core::session::GitNotesPushAssessment::NotesNotTransferred
    );
}
