// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_core::policy::essentials_pack;
use grdr_ffi::{
    AssuranceKind, BrandManifestDto, CapabilityPresence, FfiEngine, HostProfileDto,
    RequiredHostSignal, evaluate_json_str,
};
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, KillSwitchState, Mode, PolicyPack, PolicyRule,
    RuleMatch, Verdict,
};
use jiff::Timestamp;

fn sample_attempt(id: &str, action_class: ActionClass, target: &str) -> ActionAttempt {
    ActionAttempt {
        id: id.into(),
        session_id: "sess-oem".into(),
        device_id: "dev-oem".into(),
        device_name: "oem-host".into(),
        agent_name: "claude-code".into(),
        action_class,
        control_point: ControlPoint::Hook,
        target: target.into(),
        summary: "test step".into(),
        timestamp: Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH),
        ..Default::default()
    }
}

#[test]
fn ffi_engine_step_rollback_snapshot_restore_and_host_profile() {
    let mut engine = FfiEngine::new(2);
    let interest = engine
        .load(
            vec![essentials_pack()],
            Vec::new(),
            KillSwitchState::Inactive,
            HostProfileDto::full_endpoint(),
            "bundle-digest-01".into(),
        )
        .unwrap();
    assert!(!interest.action_classes.is_empty());

    let snap = engine.snapshot("cp-1".into());
    assert_eq!(snap.steps_executed, 0);

    let step1 = engine
        .step(&sample_attempt(
            "a1",
            ActionClass::FileWrite,
            ".claude/settings.json",
        ))
        .unwrap();
    assert_eq!(step1.receipt.verdict, Verdict::Deny);
    assert_eq!(step1.steps_executed, 1);

    // Invalid empty-target step rolls back state cleanly (EM-6).
    let pre_err = engine.checkpoint();
    let err = engine
        .step(&sample_attempt("a-bad", ActionClass::FileRead, ""))
        .unwrap_err();
    assert!(err.message.contains("rolled back"));
    assert_eq!(engine.checkpoint().steps_executed, pre_err.steps_executed);
    assert_eq!(engine.checkpoint().session, pre_err.session);

    // Second valid step consumes budget (budget = 2).
    let step2 = engine
        .step(&sample_attempt("a2", ActionClass::FileRead, "README.md"))
        .unwrap();
    assert_eq!(step2.steps_executed, 2);

    // Exceeding step budget rolls back byte-identically.
    let pre_budget = engine.checkpoint();
    assert!(
        engine
            .step(&sample_attempt("a3", ActionClass::FileRead, "Cargo.toml"))
            .is_err()
    );
    assert_eq!(engine.checkpoint().session, pre_budget.session);

    // Snapshot restore reverts to pre-step-1 state cleanly.
    let restored = engine.restore("cp-1").unwrap();
    assert_eq!(restored.steps_executed, 0);
    assert_eq!(restored.denial_count, 0);
}

#[test]
fn ffi_engine_reports_not_evaluable_for_absent_host_capabilities() {
    let sample_grade = essentials_pack().rules[0].min_grade;
    let user_dependent_pack = PolicyPack {
        id: "user-pack".into(),
        name: "User Pack".into(),
        description: "Requires user identity".into(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules: vec![PolicyRule {
            id: "r.user.gate".into(),
            title: "User gate".into(),
            description: "Needs Grdr::User".into(),
            mode: Mode::Block,
            min_grade: sample_grade,
            enabled: true,
            locked: false,
            matcher: RuleMatch {
                action_classes: vec![ActionClass::NetRequest],
                target_prefixes: Vec::new(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "blocked".into(),
            cedar: Some(
                r#"forbid(principal is Grdr::User, action == Grdr::Action::"net.request", resource) when { context.session.tainted };"#
                    .into(),
            ),
        }],
        key_id: None,
        signature: None,
    };

    let minimal_profile = HostProfileDto {
        principal_attestation: CapabilityPresence::Present,
        user_identity: CapabilityPresence::Absent,
        os_file_sensor: CapabilityPresence::Present,
        net_egress_sensor: CapabilityPresence::Absent,
        command_parser: CapabilityPresence::Present,
        session_store: CapabilityPresence::Absent,
    };

    let mut engine = FfiEngine::default();
    engine
        .load(
            vec![user_dependent_pack],
            Vec::new(),
            KillSwitchState::Inactive,
            minimal_profile,
            String::new(),
        )
        .unwrap();

    let report = engine.assess_host_profile();
    assert_eq!(report.len(), 1);
    assert_eq!(report[0].assurance, AssuranceKind::NotEvaluable);
    assert!(
        engine
            .step(&sample_attempt(
                "a-net",
                ActionClass::NetRequest,
                "https://x.test"
            ))
            .is_err()
    );
}

#[test]
fn ffi_brand_manifest_supports_white_label_swap() {
    let custom_json = serde_json::json!({
        "op": "brand_manifest",
        "brand_toml": "schema = \"grdr.brand.v1alpha1\"\nnamespace = \"acme\"\nproduct_name = \"Acme Guard\"\nshort_name = \"Acme\"\npublisher = \"Acme Inc\"\ndomain = \"acme.example\"\ncopyright_holder = \"Acme Inc\"\n"
    });
    let out = evaluate_json_str(&custom_json.to_string());
    let dto: BrandManifestDto = serde_json::from_str(&out).unwrap();
    assert_eq!(dto.product_name, "Acme Guard");
    assert_eq!(dto.publisher, "Acme Inc");
}

#[test]
fn ffi_host_profile_defaults_minimal_and_gates_file_exec_labels_and_multipack() {
    let def = HostProfileDto::default();
    assert_eq!(def, HostProfileDto::minimal_sandbox());
    assert_eq!(def.user_identity, CapabilityPresence::Absent);
    assert_eq!(def.net_egress_sensor, CapabilityPresence::Absent);
    assert_eq!(def.session_store, CapabilityPresence::Absent);

    let sample_grade = essentials_pack().rules[0].min_grade;
    let mk_rule = |id: &str, mode: Mode, ac: ActionClass, cedar: Option<&str>| PolicyRule {
        id: id.into(),
        title: id.into(),
        description: id.into(),
        mode,
        min_grade: sample_grade,
        enabled: true,
        locked: false,
        matcher: RuleMatch {
            action_classes: vec![ac],
            target_prefixes: Vec::new(),
            target_contains: Vec::new(),
            agents: Vec::new(),
        },
        hits: 0,
        would_ask_hits: 0,
        would_block_hits: 0,
        reason_template: "gated".into(),
        cedar: cedar.map(str::to_owned),
    };
    let mk_pack = |id: &str, rules: Vec<PolicyRule>| PolicyPack {
        id: id.into(),
        name: id.into(),
        description: id.into(),
        version: "1.0.0".into(),
        channel: "custom".into(),
        rules,
        key_id: None,
        signature: None,
    };

    // File rule requires os_file_sensor.
    let file_pack = mk_pack(
        "file-pack",
        vec![mk_rule("r.file", Mode::Block, ActionClass::FileWrite, None)],
    );
    let mut no_file = HostProfileDto::full_endpoint();
    no_file.os_file_sensor = CapabilityPresence::Absent;
    let mut engine = FfiEngine::default();
    let interest = engine
        .load(
            vec![file_pack.clone()],
            Vec::new(),
            KillSwitchState::Inactive,
            no_file,
            String::new(),
        )
        .unwrap();
    assert!(
        interest
            .required_signals
            .contains(&RequiredHostSignal::FileSensor)
    );
    assert_eq!(
        engine.assess_host_profile()[0].assurance,
        AssuranceKind::NotEvaluable
    );
    let pre = engine.checkpoint();
    assert!(
        engine
            .step(&sample_attempt("f1", ActionClass::FileWrite, "secret.txt"))
            .is_err()
    );
    assert_eq!(engine.checkpoint().steps_executed, pre.steps_executed);

    // Exec rule requires command_parser.
    let exec_pack = mk_pack(
        "exec-pack",
        vec![mk_rule("r.exec", Mode::Block, ActionClass::Exec, None)],
    );
    let mut no_exec = HostProfileDto::full_endpoint();
    no_exec.command_parser = CapabilityPresence::Absent;
    let exec_interest = engine
        .load(
            vec![exec_pack],
            Vec::new(),
            KillSwitchState::Inactive,
            no_exec,
            String::new(),
        )
        .unwrap();
    assert!(
        exec_interest
            .required_signals
            .contains(&RequiredHostSignal::CommandParser)
    );
    assert_eq!(
        engine.assess_host_profile()[0].assurance,
        AssuranceKind::NotEvaluable
    );
    assert!(
        engine
            .step(&sample_attempt("e1", ActionClass::Exec, "rm -rf /"))
            .is_err()
    );

    // Cedar `labels.` expression requires session_store.
    let label_pack = mk_pack(
        "label-pack",
        vec![mk_rule(
            "r.labels",
            Mode::Block,
            ActionClass::FileRead,
            Some(r#"forbid(principal, action, resource) when { context.labels.tainted };"#),
        )],
    );
    let mut no_session = HostProfileDto::full_endpoint();
    no_session.session_store = CapabilityPresence::Absent;
    let label_interest = engine
        .load(
            vec![label_pack],
            Vec::new(),
            KillSwitchState::Inactive,
            no_session,
            String::new(),
        )
        .unwrap();
    assert!(
        label_interest
            .required_signals
            .contains(&RequiredHostSignal::SessionStore)
    );
    assert_eq!(
        engine.assess_host_profile()[0].assurance,
        AssuranceKind::NotEvaluable
    );
    assert!(
        engine
            .step(&sample_attempt("l1", ActionClass::FileRead, "a.txt"))
            .is_err()
    );

    // Multi-pack worst-case assurance: WatchOnly + Enforced => WatchOnly.
    let watch_pack = mk_pack(
        "watch-pack",
        vec![mk_rule("r.watch", Mode::Watch, ActionClass::FileRead, None)],
    );
    engine
        .load(
            vec![file_pack, watch_pack],
            Vec::new(),
            KillSwitchState::Inactive,
            HostProfileDto::default(),
            String::new(),
        )
        .unwrap();
    let step = engine
        .step(&sample_attempt("w1", ActionClass::FileRead, "README.md"))
        .unwrap();
    assert_eq!(step.assurance, AssuranceKind::WatchOnly);
}
