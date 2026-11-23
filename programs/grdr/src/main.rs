// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use jiff::Timestamp;
use uuid::Uuid;

use grdr_agents::discover_local_agents;
use grdr_core::policy;
use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, DecideInput, DecisionReceipt, InstallProfile,
    KillSwitchState, Verdict,
};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    User,
    Protected,
}

#[derive(Debug, Parser)]
#[command(name = "grdr", about = "Guardrails ADR endpoint CLI")]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Debug, Subcommand)]
enum Command {
    /// Discover installed AI coding agents and MCP servers locally (read-only).
    Scan {
        #[arg(long, default_value_t = false)]
        json: bool,

        #[arg(long, value_enum, default_value_t = ProfileArg::User)]
        profile: ProfileArg,
    },
    /// Show status from the local grdr-daemon endpoint agent.
    Status {
        #[arg(long, env = "GRDR_DAEMON_URL", default_value = "http://127.0.0.1:8788")]
        daemon: String,
    },
    /// Evaluate an action attempt via local daemon or offline Essentials policy.
    Check {
        #[arg(long)]
        action: String,

        #[arg(long)]
        target: String,

        #[arg(long, default_value = "claude-code")]
        agent: String,

        #[arg(long, env = "GRDR_DAEMON_URL", default_value = "http://127.0.0.1:8788")]
        daemon: String,
    },
    /// Print Claude Code PreToolUse hook configuration pointing to grdr-hook.
    InstallHook {
        #[arg(long, default_value = "claude-code")]
        agent: String,

        #[arg(long, default_value_t = true)]
        dry_run: bool,
    },
}

fn main() -> ExitCode {
    let cli = Cli::parse();
    match cli.command {
        Command::Scan { json, profile } => run_scan(json, profile),
        Command::Status { daemon } => run_status(&daemon),
        Command::Check {
            action,
            target,
            agent,
            daemon,
        } => run_check(&action, &target, &agent, &daemon),
        Command::InstallHook { agent, dry_run } => run_install_hook(&agent, dry_run),
    }
}

fn run_scan(json: bool, profile: ProfileArg) -> ExitCode {
    let install_profile = match profile {
        ProfileArg::User => InstallProfile::User,
        ProfileArg::Protected => InstallProfile::Protected,
    };
    let report = discover_local_agents(install_profile);

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(out) => {
                println!("{out}");
                return ExitCode::SUCCESS;
            }
            Err(err) => {
                eprintln!("Failed serializing discovery report: {err}");
                return ExitCode::FAILURE;
            }
        }
    }

    println!(
        "Guardrails ADR discovery ({}, {} / {}, profile: {:?})",
        report.device_name, report.os, report.arch, report.install_profile
    );
    if report.agents.is_empty() {
        println!("No local AI agents detected in standard paths.");
    } else {
        for agent in &report.agents {
            println!(
                "  - {} [{}] hook={} mcp={} ({})",
                agent.name,
                agent.assurance_level.label(),
                agent.hook_installed,
                agent.mcp_count,
                agent.config_path
            );
        }
    }
    if !report.mcp_servers.is_empty() {
        println!("MCP servers ({}):", report.mcp_servers.len());
        for server in &report.mcp_servers {
            println!(
                "  - {} ({}, cmd={}) from {}",
                server.name, server.transport, server.command, server.source_agent
            );
        }
    }
    ExitCode::SUCCESS
}

fn run_status(daemon: &str) -> ExitCode {
    let url = format!("{}/local/v1/status", daemon.trim_end_matches('/'));
    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build();
    let Ok(client) = client else {
        eprintln!("Failed building HTTP client.");
        return ExitCode::FAILURE;
    };

    match client.get(&url).send() {
        Ok(resp) if resp.status().is_success() => {
            let text = resp.text().unwrap_or_default();
            println!("{text}");
            ExitCode::SUCCESS
        }
        Ok(resp) => {
            eprintln!("Daemon returned HTTP {} at {url}", resp.status());
            ExitCode::FAILURE
        }
        Err(err) => {
            eprintln!("Daemon unreachable at {url}: {err}");
            ExitCode::FAILURE
        }
    }
}

fn run_check(action: &str, target: &str, agent: &str, daemon: &str) -> ExitCode {
    let url = format!("{}/local/v1/decide", daemon.trim_end_matches('/'));
    let payload = DecideInput {
        session_id: Some("sess-cli-check".into()),
        device_id: None,
        device_name: None,
        agent_name: agent.into(),
        action_class: ActionClass::from_name(action),
        control_point: Some(ControlPoint::Hook),
        target: target.into(),
        summary: Some(format!("grdr check {action}")),
    };

    let client = reqwest::blocking::Client::builder()
        .timeout(Duration::from_secs(2))
        .build();

    let (receipt, source) = if let Ok(client) = client
        && let Ok(resp) = client.post(&url).json(&payload).send()
        && resp.status().is_success()
        && let Ok(parsed) = resp.json::<DecisionReceipt>()
    {
        (parsed, "daemon")
    } else {
        let now = Timestamp::now();
        let attempt = ActionAttempt {
            id: format!("att_{}", Uuid::now_v7().simple()),
            session_id: "sess-cli-check".into(),
            device_id: "dev-offline".into(),
            device_name: "local".into(),
            agent_name: agent.into(),
            action_class: ActionClass::from_name(action),
            control_point: ControlPoint::Hook,
            target: target.into(),
            summary: "grdr check offline fallback".into(),
            timestamp: now,
        };
        let packs = vec![policy::essentials_pack()];
        (
            policy::evaluate(&attempt, &packs, &[], &KillSwitchState::Inactive, now),
            "offline-essentials",
        )
    };

    println!(
        "Verdict: {:?} | Rule: {} | Source: {}\nReason: {}\nNext step: {}\nReceipt: {}",
        receipt.verdict,
        receipt.rule_id.as_deref().unwrap_or("none"),
        source,
        receipt.reason,
        receipt.next_step,
        receipt.receipt_digest
    );

    match receipt.verdict {
        Verdict::Allow | Verdict::Modify => ExitCode::SUCCESS,
        Verdict::Deny | Verdict::StepUp | Verdict::Defer => ExitCode::from(2),
    }
}

fn run_install_hook(agent: &str, _dry_run: bool) -> ExitCode {
    let hook_json = serde_json::json!({
        "hooks": {
            "PreToolUse": [
                {
                    "matcher": "Bash|PowerShell|Read|Write|Edit|MultiEdit|WebFetch|mcp__.*",
                    "hooks": [
                        {
                            "type": "command",
                            "command": "grdr-hook",
                            "timeout": 2
                        }
                    ]
                }
            ]
        }
    });
    println!("Add the following snippet for `{agent}` settings:\n");
    if let Ok(pretty) = serde_json::to_string_pretty(&hook_json) {
        println!("{pretty}");
    }
    ExitCode::SUCCESS
}
