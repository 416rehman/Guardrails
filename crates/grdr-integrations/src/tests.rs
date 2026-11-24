// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::{ActionClass, AssuranceLevel, ControlPoint, ProvenanceSource};
use jiff::Timestamp;
use serde_json::json;

use crate::{
    AuthScheme, CaptureCeiling, CircuitBreakerConfig, CircuitState, CodecKind, ConfigFieldSpec,
    ConfigFieldType, ConnectorDirection, ConnectorHealth, ConnectorKind, ConnectorManifest,
    DeliveryOutcome, ExportEnvelope, ExportStream, GrcControlStatus, GrcEvidenceInput,
    GrcPushPayload, GrcTarget, IntegrationError, IntegrationHost, IntegrationInstance,
    OutboxItemState, OutboxLimits, OutboxQueue, RateBudgetTracker, RetryPolicy, SaasParseLimits,
    SecretRef, StabilityClass, SupportTier, VendorApiCompat, build_grc_evidence_push,
    connector_assurance, parse_anthropic_compliance_page,
    parse_anthropic_compliance_page_with_limits, parse_openai_compliance_page, sanitize_inert_text,
    validate_egress_url,
};

fn ts(sec: i64) -> Timestamp {
    Timestamp::from_second(sec).expect("valid timestamp")
}

fn valid_sink_manifest() -> ConnectorManifest {
    ConnectorManifest {
        integration: "splunk-hec".into(),
        publisher: "com.example".into(),
        version: "1.0.0".into(),
        kind: ConnectorKind::Sink,
        family: "siem-http".into(),
        direction: ConnectorDirection::Out,
        support_tier: SupportTier::Tier1,
        stability: StabilityClass::Beta,
        vendor_api: VendorApiCompat {
            name: "splunk-hec".into(),
            tested: ">=9.1 <11".into(),
            verified: true,
            sunset: None,
        },
        config: vec![
            ConfigFieldSpec {
                key: "base_url".into(),
                field_type: ConfigFieldType::HttpsUrl,
                required: true,
                host_constraints: vec![".example.test".into()],
            },
            ConfigFieldSpec {
                key: "token".into(),
                field_type: ConfigFieldType::SecretRef,
                required: true,
                host_constraints: Vec::new(),
            },
        ],
        auth_scheme: AuthScheme::HeaderToken,
        codec: CodecKind::HecEvent,
        request_path: "/services/collector/event".into(),
        data_classes_read: vec!["identifier".into(), "structural".into()],
        capture_max: CaptureCeiling::Metadata,
        required_scopes: vec!["hec:write".into()],
        prohibited_commands: Vec::new(),
        prohibited_env_sets: Vec::new(),
    }
}

#[test]
fn integration_host_enforces_manifest_and_ssrf_rules() {
    let mut host = IntegrationHost::new();
    let mut bad_url_manifest = valid_sink_manifest();
    bad_url_manifest.request_path = "https://evil.test/steal".into();
    assert!(matches!(
        host.register_manifest(bad_url_manifest),
        Err(IntegrationError::InvalidManifest(_))
    ));

    let mut bad_tier = valid_sink_manifest();
    bad_tier.vendor_api.verified = false;
    assert!(matches!(
        host.register_manifest(bad_tier),
        Err(IntegrationError::InvalidManifest(_))
    ));

    let mut bad_action = valid_sink_manifest();
    bad_action.kind = ConnectorKind::Action;
    bad_action.required_scopes = vec!["falcon:script_execution".into()];
    assert!(matches!(
        host.register_manifest(bad_action),
        Err(IntegrationError::ForbiddenScope(_))
    ));

    let key = host
        .register_manifest(valid_sink_manifest())
        .expect("register valid manifest");

    let mut secrets = BTreeMap::new();
    secrets.insert(
        "token".into(),
        SecretRef {
            key: "splunk_hec_token".into(),
            store: "openbao".into(),
        },
    );
    let ssrf_instance = IntegrationInstance {
        instance_id: "inst-ssrf".into(),
        org_id: "org_1".into(),
        manifest_key: key.clone(),
        base_url: "https://169.254.169.254/latest".into(),
        secret_refs: secrets.clone(),
        allow_private_ranges: false,
        health: ConnectorHealth::Healthy,
    };
    assert!(matches!(
        host.create_instance(ssrf_instance),
        Err(IntegrationError::EgressDenied(_))
    ));

    let valid_instance = IntegrationInstance {
        instance_id: "inst-ok".into(),
        org_id: "org_1".into(),
        manifest_key: key,
        base_url: "https://hec.example.test".into(),
        secret_refs: secrets,
        allow_private_ranges: false,
        health: ConnectorHealth::Healthy,
    };
    host.create_instance(valid_instance)
        .expect("create instance");
    assert!(host.instance("inst-ok").is_some());
}

#[test]
fn parses_anthropic_and_openai_compliance_payloads_at_al1_connector() {
    assert_eq!(connector_assurance().level(), AssuranceLevel::Al1Observed);

    let anth_json = br#"{
        "data": [{
            "id": "act_01",
            "type": "mcp_tool_call",
            "created_at": "2026-11-24T12:00:00Z",
            "actor": { "type": "user", "id": "usr_42", "email_address": "alice@example.test" },
            "session_id": "ses_anth_1",
            "tool_name": "github.create_issue",
            "target": "repo/org/app",
            "summary": "Created\u202E issue"
        }],
        "has_more": false
    }"#;
    let anth = parse_anthropic_compliance_page(anth_json, "dev-saas", "Anthropic API")
        .expect("parse anthropic");
    let first_anth = anth.first().expect("anthropic event");
    assert_eq!(first_anth.control_point, ControlPoint::Connector);
    assert_eq!(first_anth.action_class, ActionClass::McpCall);
    assert_eq!(first_anth.provenance, ProvenanceSource::Observed);
    assert!(!first_anth.summary.contains('\u{202E}'));

    let oai_json = br#"{
        "data": [{
            "id": "oai_01",
            "event_type": "tool_call",
            "timestamp": 1760000000,
            "user_id": "usr_99",
            "conversation_id": "conv_7",
            "tool_name": "code_interpreter",
            "target": "python_sandbox",
            "summary": "Ran analysis"
        }],
        "has_more": false
    }"#;
    let oai =
        parse_openai_compliance_page(oai_json, "dev-saas", "OpenAI Logs").expect("parse openai");
    let first_oai = oai.first().expect("openai event");
    assert_eq!(first_oai.control_point, ControlPoint::Connector);
    assert_eq!(first_oai.action_class, ActionClass::Exec);
    assert_eq!(first_oai.session_id, "conv_7");

    let mut tracker = RateBudgetTracker::new(600, 60, ts(1_760_000_000));
    assert_eq!(
        tracker
            .try_acquire(300, ts(1_760_000_010))
            .expect("acquire 300"),
        300
    );
    assert!(matches!(
        tracker.try_acquire(301, ts(1_760_000_020)),
        Err(IntegrationError::RateBudgetExceeded)
    ));
}

#[test]
fn builds_ciso_assistant_and_probo_grc_evidence_pushes() {
    let input = GrcEvidenceInput {
        organization_id: "org_01".into(),
        control_id: "CTRL-AI-04".into(),
        framework: "SOC2".into(),
        control_title: "Agent credential containment".into(),
        summary: "Containment enforced across 24 sessions".into(),
        assurance_level: AssuranceLevel::Al3Contained,
        finding_count: 2,
        blocked_count: 5,
        evidence_digest: "deadbeef01234567".into(),
        collected_at: ts(1_760_000_000),
        artifact_refs: vec!["s3://bucket/ev-1.json".into()],
    };

    let ciso = build_grc_evidence_push(GrcTarget::CisoAssistant, &input).expect("ciso");
    assert!(
        ciso.dedup_key
            .starts_with("grc:ciso_assistant:org_01:CTRL-AI-04:")
    );
    assert!(matches!(
        ciso.payload,
        GrcPushPayload::CisoAssistant(ref p) if p.status == GrcControlStatus::Active
    ));

    let probo = build_grc_evidence_push(GrcTarget::Probo, &input).expect("probo");
    assert!(probo.dedup_key.starts_with("grc:probo:org_01:CTRL-AI-04:"));
    assert!(matches!(
        probo.payload,
        GrcPushPayload::Probo(ref p) if p.framework == "SOC2" && p.blocked_count == 5
    ));
}

#[test]
fn outbox_circuit_breaker_transitions_closed_open_half_open_closed() {
    let mut queue = OutboxQueue::new(
        "dest-webhook-1",
        RetryPolicy::export_delivery_default(),
        CircuitBreakerConfig {
            failure_threshold: 2,
            open_cooldown_secs: 60,
            half_open_success_threshold: 2,
        },
    );
    assert_eq!(queue.retry_policy().name, "export-delivery");

    let t0 = ts(1_760_000_000);
    let id1 = queue
        .enqueue(
            ExportEnvelope {
                grdr_export: "1".into(),
                stream: ExportStream::Finding,
                record_id: "fnd_1".into(),
                revision: 1,
                dedup_key: "finding:fnd_1:1".into(),
                emitted_at: t0,
                organisation: "org_01".into(),
                replay: false,
                record: json!({"severity": "high"}),
            },
            t0,
        )
        .expect("enqueue 1");
    let id2 = queue
        .enqueue(
            ExportEnvelope {
                grdr_export: "1".into(),
                stream: ExportStream::Finding,
                record_id: "fnd_2".into(),
                revision: 2,
                dedup_key: "finding:fnd_2:2".into(),
                emitted_at: t0,
                organisation: "org_01".into(),
                replay: false,
                record: json!({"severity": "critical"}),
            },
            t0,
        )
        .expect("enqueue 2");

    assert_eq!(queue.poll_dispatchable(t0).expect("poll").len(), 2);

    queue
        .record_delivery(
            &id1,
            DeliveryOutcome::RetryableFailure {
                retry_after_secs: Some(5),
                reason: "503".into(),
            },
            t0,
        )
        .expect("record 1");
    assert!(matches!(
        queue.circuit_state(),
        CircuitState::Closed {
            consecutive_failures: 1
        }
    ));

    queue
        .record_delivery(
            &id2,
            DeliveryOutcome::RetryableFailure {
                retry_after_secs: Some(5),
                reason: "503".into(),
            },
            t0,
        )
        .expect("record 2");
    assert!(matches!(queue.circuit_state(), CircuitState::Open { .. }));

    assert!(matches!(
        queue.poll_dispatchable(ts(t0.as_second().saturating_add(10))),
        Err(IntegrationError::CircuitOpen { .. })
    ));

    let t_probe = ts(t0.as_second().saturating_add(65));
    let probes = queue.poll_dispatchable(t_probe).expect("half-open probe");
    assert_eq!(probes.len(), 1);
    assert!(matches!(
        queue.circuit_state(),
        CircuitState::HalfOpen { .. }
    ));

    // A failed probe in HalfOpen trips immediately back to Open.
    queue
        .record_delivery(
            &id1,
            DeliveryOutcome::RetryableFailure {
                retry_after_secs: Some(5),
                reason: "502".into(),
            },
            t_probe,
        )
        .expect("half-open failure");
    assert!(matches!(queue.circuit_state(), CircuitState::Open { .. }));

    let t_probe2 = ts(t_probe.as_second().saturating_add(65));
    assert_eq!(
        queue.poll_dispatchable(t_probe2).expect("re-probe"),
        vec![id1.clone()]
    );
    // Second poll while probe 1 is in flight must return zero items.
    assert!(
        queue
            .poll_dispatchable(t_probe2)
            .expect("probe in flight")
            .is_empty()
    );
    assert!(matches!(
        queue.circuit_state(),
        CircuitState::HalfOpen { .. }
    ));

    queue
        .record_delivery(&id1, DeliveryOutcome::Success, t_probe2)
        .expect("probe 1 ok");
    assert_eq!(
        queue.poll_dispatchable(t_probe2).expect("re-probe 2"),
        vec![id2.clone()]
    );
    queue
        .record_delivery(
            &id2,
            DeliveryOutcome::Success,
            ts(t_probe2.as_second().saturating_add(1)),
        )
        .expect("probe 2 ok");
    assert!(matches!(
        queue.circuit_state(),
        CircuitState::Closed {
            consecutive_failures: 0
        }
    ));
    assert_eq!(
        queue
            .cursor(ExportStream::Finding)
            .expect("cursor")
            .last_acked_revision,
        2
    );

    let id3 = queue
        .enqueue(
            ExportEnvelope {
                grdr_export: "1".into(),
                stream: ExportStream::Decision,
                record_id: "dec_1".into(),
                revision: 1,
                dedup_key: "decision:dec_1:1".into(),
                emitted_at: t_probe2,
                organisation: "org_01".into(),
                replay: false,
                record: json!({}),
            },
            t_probe2,
        )
        .expect("enqueue 3");
    queue
        .record_delivery(
            &id3,
            DeliveryOutcome::NonRetryableFailure {
                status_code: 400,
                reason: "bad schema".into(),
            },
            t_probe2,
        )
        .expect("dead-letter");
    assert!(matches!(
        queue.item(&id3).expect("item3").state,
        OutboxItemState::DeadLettered { .. }
    ));
}

#[test]
fn rejects_ssrf_bypasses_manifest_injection_grc_delimiters_and_outbox_overwrites() {
    for bad_url in [
        "https://[::ffff:169.254.169.254]/latest",
        "https://[::127.0.0.1]/admin",
        "https://[fe80::1]/meta",
        "https://100.64.0.1/cgnat",
        "https://0.0.0.1/zero",
        "https://2130706433/decimal",
        "https://0x7f000001/hex",
        "https://localhost./admin",
        "https://api.example.test?redirect=1",
        "https://api.example.test#frag",
        "https://api.example.test\\evil",
        "https://[::1%25eth0]/zone",
    ] {
        assert!(
            matches!(
                validate_egress_url(bad_url, &[], false),
                Err(IntegrationError::EgressDenied(_))
            ),
            "expected SSRF guard to deny {bad_url}"
        );
    }

    // Reject unknown fields, protocol-relative request_path, and hyphenated deny_scopes.
    let mut host = IntegrationHost::new();
    let mut bad_path = valid_sink_manifest();
    bad_path.request_path = "//evil.test/collect".into();
    assert!(matches!(
        host.register_manifest(bad_path),
        Err(IntegrationError::InvalidManifest(_))
    ));
    for enc_path in ["/.%2e/admin", "/%2e./admin", "/v1/%2f../admin"] {
        let mut bad_enc = valid_sink_manifest();
        bad_enc.request_path = enc_path.into();
        assert!(matches!(
            host.register_manifest(bad_enc),
            Err(IntegrationError::InvalidManifest(_))
        ));
    }

    let mut bad_act = valid_sink_manifest();
    bad_act.kind = ConnectorKind::Ticket;
    bad_act.direction = ConnectorDirection::Act;
    bad_act.required_scopes = vec!["falcon:script-execution".into()];
    assert!(matches!(
        host.register_manifest(bad_act),
        Err(IntegrationError::ForbiddenScope(_))
    ));

    let raw_unknown = r#"{"key":"k","store":"s","extra":"smuggled"}"#;
    assert!(serde_json::from_str::<SecretRef>(raw_unknown).is_err());

    // Sanitizer strips expanded invisible/bidi controls and parser enforces payload limits.
    let cleaned = sanitize_inert_text("ok\u{061C}\u{200B}\u{FEFF}\u{E0041}end", 64);
    assert_eq!(cleaned, "okend");
    assert!(matches!(
        parse_anthropic_compliance_page_with_limits(
            br#"{"data":[],"has_more":false}"#,
            "dev",
            "Anthropic",
            SaasParseLimits {
                max_payload_bytes: 8,
                max_events_per_page: 10,
            }
        ),
        Err(IntegrationError::MalformedPayload(_))
    ));

    // GRC identifier validation rejects delimiter injection.
    let bad_grc = GrcEvidenceInput {
        organization_id: "org:injected".into(),
        control_id: "CTRL-1".into(),
        framework: "SOC2".into(),
        control_title: "t".into(),
        summary: "s".into(),
        assurance_level: AssuranceLevel::Al3Contained,
        finding_count: 0,
        blocked_count: 0,
        evidence_digest: "abcd".into(),
        collected_at: ts(1_760_000_000),
        artifact_refs: Vec::new(),
    };
    assert!(matches!(
        build_grc_evidence_push(GrcTarget::Probo, &bad_grc),
        Err(IntegrationError::InvalidGrcInput(_))
    ));

    // Outbox enqueue is idempotent and enforces max_items.
    let t0 = ts(1_760_000_000);
    let mut queue = OutboxQueue::new(
        "dest",
        RetryPolicy::export_delivery_default(),
        CircuitBreakerConfig::default(),
    )
    .with_limits(OutboxLimits {
        max_items: 1,
        max_cursors: 8,
    });
    let env = ExportEnvelope {
        grdr_export: "1".into(),
        stream: ExportStream::Finding,
        record_id: "f1".into(),
        revision: 1,
        dedup_key: "finding:f1:1".into(),
        emitted_at: t0,
        organisation: "org_1".into(),
        replay: false,
        record: json!({}),
    };
    let id = queue.enqueue(env.clone(), t0).expect("first enqueue");
    queue
        .record_delivery(&id, DeliveryOutcome::Success, t0)
        .expect("deliver");
    queue.enqueue(env, t0).expect("idempotent re-enqueue");
    assert!(matches!(
        queue.item(&id).expect("item").state,
        OutboxItemState::Delivered { .. }
    ));
    assert!(matches!(
        queue.enqueue(
            ExportEnvelope {
                dedup_key: "finding:f2:1".into(),
                record_id: "f2".into(),
                ..queue.item(&id).expect("item").envelope.clone()
            },
            t0
        ),
        Err(IntegrationError::OutboxState(_))
    ));
}
