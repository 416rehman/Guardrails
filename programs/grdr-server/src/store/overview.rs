// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;

use grdr_core::{detect, discover, session};
use grdr_model::{
    ApprovalState, FindingLifecycle, InsightTile, Mode, OverviewResponse, ServerHealth, SetupStep,
    summarize_sessions,
};

use super::AppState;

impl AppState {
    pub async fn overview(&self) -> OverviewResponse {
        let guard = self.inner.read().await;
        let now = Timestamp::now();
        let coverage = discover::summarize_coverage(&guard.devices);
        let online_devices = guard.devices.iter().filter(|d| d.online).count();
        let total_mcp_servers: usize = guard
            .devices
            .iter()
            .map(|d| d.mcp_servers.len())
            .fold(0usize, usize::saturating_add);
        let active_sessions = summarize_sessions(&guard.attempts, &guard.receipts).len();
        let pending_approvals = guard
            .approvals
            .iter()
            .filter(
                |a| matches!(a.state, ApprovalState::Pending { expires_at } if expires_at > now),
            )
            .count();
        let open_findings = guard
            .findings
            .iter()
            .filter(|f| f.lifecycle != FindingLifecycle::Resolved)
            .count();
        let session_states = session::replay_session_states(&guard.attempts, &guard.receipts);
        let open_incidents = detect::correlate_incidents(&guard.findings, &session_states)
            .into_iter()
            .filter(|inc| inc.lifecycle != FindingLifecycle::Resolved)
            .count();

        let watch_hits: u64 = guard
            .receipts
            .iter()
            .filter(|r| r.mode_applied == Some(Mode::Watch))
            .count() as u64;

        let has_daemon = !guard.devices.is_empty();
        let has_hook = guard
            .devices
            .iter()
            .any(|d| d.agents.iter().any(|a| a.hook_installed));

        let tiles = vec![
            InsightTile {
                id: "tile-coverage".into(),
                headline: format!(
                    "Coverage is {}%: {} of {} agent instances reach AL2 Guided or higher.",
                    coverage.coverage_percent, coverage.guided_or_higher, coverage.total_agents
                ),
                metric: format!("{}%", coverage.coverage_percent),
                comparison: "Measured across enrolled endpoints".into(),
                action_label: "Inspect inventory".into(),
                route: "inventory".into(),
                tone: if coverage.coverage_percent >= 80 {
                    "success".into()
                } else {
                    "warning".into()
                },
            },
            InsightTile {
                id: "tile-approvals".into(),
                headline: format!(
                    "{pending_approvals} step-up approvals waiting; {} grants active.",
                    guard.grants.iter().filter(|g| g.is_active(now)).count()
                ),
                metric: pending_approvals.to_string(),
                comparison: "G1/G2 scoped grants expire automatically".into(),
                action_label: "Review queue".into(),
                route: "respond".into(),
                tone: if pending_approvals > 0 {
                    "warning".into()
                } else {
                    "neutral".into()
                },
            },
            InsightTile {
                id: "tile-findings".into(),
                headline: format!(
                    "{open_findings} open findings recorded across {active_sessions} sessions."
                ),
                metric: open_findings.to_string(),
                comparison: format!("{watch_hits} Watch-mode telemetry hits ready for replay"),
                action_label: "Open findings".into(),
                route: "respond".into(),
                tone: if open_findings > 0 {
                    "danger".into()
                } else {
                    "success".into()
                },
            },
            InsightTile {
                id: "tile-essentials".into(),
                headline: format!(
                    "Essentials pack enforces {} active policy rules locally on endpoints.",
                    guard
                        .packs
                        .iter()
                        .map(|p| p.rules.iter().filter(|r| r.enabled).count())
                        .fold(0usize, usize::saturating_add)
                ),
                metric: guard.packs.len().to_string(),
                comparison: "Cached on endpoint daemons for offline evaluation".into(),
                action_label: "Configure rules".into(),
                route: "protect".into(),
                tone: "info".into(),
            },
        ];

        let setup_steps = vec![
            SetupStep {
                id: "step-server".into(),
                label: "API server started".into(),
                done: true,
                detail: format!("Storage backend: {}", self.backend.storage_mode().label()),
            },
            SetupStep {
                id: "step-essentials".into(),
                label: "Essentials baseline policy active".into(),
                done: true,
                detail: "Block control-file edits and hook bypass by default".into(),
            },
            SetupStep {
                id: "step-agent".into(),
                label: "Endpoint daemon checked in".into(),
                done: has_daemon,
                detail: if has_daemon {
                    format!("{online_devices} device(s) reporting telemetry")
                } else {
                    "Run `cargo run -p grdr-daemon -- --server http://127.0.0.1:8787`".into()
                },
            },
            SetupStep {
                id: "step-hook".into(),
                label: "Agent hook shim configured".into(),
                done: has_hook,
                detail: if has_hook {
                    "Claude Code PreToolUse hook verified".into()
                } else {
                    "Run `cargo run -p grdr -- install-hook --agent claude-code`".into()
                },
            },
            SetupStep {
                id: "step-promote".into(),
                label: "Replay and promote one Watch rule".into(),
                done: guard
                    .audit
                    .iter()
                    .any(|a| a.kind == "policy.rule.mode_updated"),
                detail: "Simulate impact in Protect before enabling Ask or Block".into(),
            },
        ];

        OverviewResponse {
            server_status: ServerHealth::Healthy,
            total_devices: guard.devices.len(),
            online_devices,
            total_agents: coverage.total_agents,
            total_mcp_servers,
            active_sessions,
            pending_approvals,
            open_findings,
            open_incidents,
            kill_switch: guard.kill_switch.clone(),
            tiles,
            setup_steps,
        }
    }
}
