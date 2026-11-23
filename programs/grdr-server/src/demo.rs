// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_core::{detect, policy};
use grdr_model::eval::add_seconds;
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, ApprovalRequest, ApprovalState, AssuranceRecord,
    AuditEntry, ControlPoint, ControlStrength, Device, DiscoveredAgent, Finding, Grant,
    InstallProfile, KillSwitchState, McpServerEntry, OnFailure, PolicyPack, TamperGrade, Verdict,
    Visibility,
};

pub struct SeedSnapshot {
    pub packs: Vec<PolicyPack>,
    pub devices: Vec<Device>,
    pub attempts: Vec<ActionAttempt>,
    pub receipts: Vec<grdr_model::DecisionReceipt>,
    pub approvals: Vec<ApprovalRequest>,
    pub grants: Vec<Grant>,
    pub findings: Vec<Finding>,
    pub audit: Vec<AuditEntry>,
}

pub fn build_demo_seed(now: Timestamp) -> SeedSnapshot {
    let packs = vec![policy::essentials_pack()];
    let assurance_al3 = AssuranceRecord {
        visibility: Visibility::Observed,
        control: ControlStrength::ScopedBoundary,
        on_failure: OnFailure::Closed,
        tamper: TamperGrade::Admin,
    };
    let assurance_al1 = AssuranceRecord {
        visibility: Visibility::Claimed,
        control: ControlStrength::None,
        on_failure: OnFailure::Open,
        tamper: TamperGrade::User,
    };

    let devices = vec![Device {
        id: "dev-demo-01".into(),
        hostname: "dev-macbook-pro".into(),
        os: "macos".into(),
        arch: "aarch64".into(),
        install_profile: InstallProfile::Protected,
        daemon_version: env!("CARGO_PKG_VERSION").into(),
        online: true,
        hook_effective: true,
        agents: vec![
            DiscoveredAgent {
                id: "demo-claude-code".into(),
                name: "Claude Code".into(),
                kind: "claude-code".into(),
                config_path: "~/.claude/settings.json".into(),
                hook_installed: true,
                mcp_count: 2,
                assurance_level: assurance_al3.level(),
                assurance: assurance_al3,
                sponsor: Some("platform-eng".into()),
                detected_at: add_seconds(now, -3600),
            },
            DiscoveredAgent {
                id: "demo-cursor".into(),
                name: "Cursor".into(),
                kind: "cursor".into(),
                config_path: "~/.cursor/mcp.json".into(),
                hook_installed: false,
                mcp_count: 1,
                assurance_level: assurance_al1.level(),
                assurance: assurance_al1,
                sponsor: None,
                detected_at: add_seconds(now, -1800),
            },
        ],
        mcp_servers: vec![
            McpServerEntry {
                name: "filesystem".into(),
                transport: "stdio".into(),
                command: "mcp-server-filesystem".into(),
                source_agent: "Claude Code".into(),
                config_path: "~/.claude/settings.json".into(),
                pinned: true,
            },
            McpServerEntry {
                name: "github".into(),
                transport: "stdio".into(),
                command: "npx".into(),
                source_agent: "Cursor".into(),
                config_path: "~/.cursor/mcp.json".into(),
                pinned: false,
            },
        ],
        last_seen: add_seconds(now, -12),
    }];

    let raw_attempts = vec![
        (
            "att-demo-1",
            "sess-demo-refactor",
            "Claude Code",
            ActionClass::Exec,
            ControlPoint::Hook,
            "git status --short",
            "Inspect repository working tree",
            -900,
        ),
        (
            "att-demo-2",
            "sess-demo-refactor",
            "Claude Code",
            ActionClass::FileWrite,
            ControlPoint::Hook,
            ".claude/settings.json",
            "Attempted edit to Claude hook configuration",
            -720,
        ),
        (
            "att-demo-3",
            "sess-demo-refactor",
            "Claude Code",
            ActionClass::Exec,
            ControlPoint::Proxy,
            "curl -X POST https://webhook.site/probe",
            "Outbound HTTP transfer via curl",
            -540,
        ),
        (
            "att-demo-4",
            "sess-demo-triage",
            "Cursor",
            ActionClass::McpCall,
            ControlPoint::McpBroker,
            "mcp__github__create_issue",
            "Invoke write-capable GitHub MCP tool",
            -360,
        ),
        (
            "att-demo-5",
            "sess-demo-triage",
            "Claude Code",
            ActionClass::FileRead,
            ControlPoint::Hook,
            "~/.ssh/id_rsa",
            "Read private SSH key material",
            -180,
        ),
        (
            "att-demo-6",
            "sess-demo-refactor",
            "Claude Code",
            ActionClass::Exec,
            ControlPoint::Hook,
            "cargo test --workspace",
            "Run workspace verification suite",
            -60,
        ),
    ];

    let mut attempts = Vec::new();
    let mut receipts = Vec::new();
    let mut approvals = Vec::new();
    let mut findings = Vec::new();

    for (id, sess, agent, class, cp, target, summary, offset) in raw_attempts {
        let ts = add_seconds(now, offset);
        let attempt = ActionAttempt {
            id: id.into(),
            session_id: sess.into(),
            device_id: "dev-demo-01".into(),
            device_name: "dev-macbook-pro".into(),
            agent_name: agent.into(),
            action_class: class,
            control_point: cp,
            target: target.into(),
            summary: summary.into(),
            timestamp: ts,
        };
        let receipt = policy::evaluate(&attempt, &packs, &[], &KillSwitchState::Inactive, ts);
        if receipt.verdict == Verdict::StepUp {
            approvals.push(ApprovalRequest {
                id: format!("apr-demo-{id}"),
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
        devices,
        attempts,
        receipts,
        approvals,
        grants: Vec::new(),
        findings,
        audit,
    }
}
