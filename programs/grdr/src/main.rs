// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

mod audit;
mod doctor;
mod hook;
mod mcp_proxy;
mod runner;

use std::path::PathBuf;
use std::process::ExitCode;
use std::time::Duration;

use clap::{Parser, Subcommand, ValueEnum};
use jiff::Timestamp;
use uuid::Uuid;

use grdr_agents::discover_local_agents;
use grdr_model::{ActionAttempt, ActionClass, ControlPoint, InstallProfile, Verdict};

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
enum HookCommand {
    /// Report hook installation status for an agent harness.
    Status {
        #[arg(long, default_value = "claude-code")]
        agent: String,

        #[arg(long, default_value_t = false)]
        json: bool,
    },
    /// Install or preview Guardrails ADR PreToolUse hooks for an agent harness.
    Install {
        #[arg(long, default_value = "claude-code")]
        agent: String,

        #[arg(long, default_value = "grdr-hook")]
        command: String,

        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Restore original agent configuration from backup journal and remove Guardrails hooks.
    Uninstall {
        #[arg(long, default_value = "claude-code")]
        agent: String,
    },
}

#[derive(Debug, Subcommand)]
enum AuditCommand {
    /// Verify the hash-chained JSONL local audit log.
    Verify {
        #[arg(long, default_value_t = false)]
        json: bool,

        #[arg(long)]
        path: Option<PathBuf>,
    },
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
    /// Inspect, install, or uninstall agent hooks.
    Hook {
        #[command(subcommand)]
        action: HookCommand,
    },
    /// Verify local audit log integrity.
    Audit {
        #[command(subcommand)]
        action: AuditCommand,
    },
    /// Install or preview Guardrails ADR PreToolUse hooks for an agent harness.
    InstallHook {
        #[arg(long, default_value = "claude-code")]
        agent: String,

        #[arg(long, default_value = "grdr-hook")]
        command: String,

        #[arg(long, default_value_t = false)]
        apply: bool,
    },
    /// Restore original agent configuration from backup journal and remove Guardrails hooks.
    UninstallHook {
        #[arg(long, default_value = "claude-code")]
        agent: String,
    },
    /// Wrap a stdio MCP server and enforce policy on JSON-RPC tools/call requests.
    McpProxy {
        #[arg(long, default_value = "default")]
        server_name: String,

        #[arg(long, default_value = "claude-code")]
        agent: String,

        #[arg(long, default_value = "sess-mcp-proxy")]
        session_id: String,

        #[arg(long, env = "GRDR_DAEMON_URL", default_value = "http://127.0.0.1:8788")]
        daemon: String,

        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Launch a command with policy enforcement and environment secret stripping.
    Run {
        #[arg(long, default_value_t = true)]
        contain: bool,

        #[arg(long)]
        workdir: Option<PathBuf>,

        #[arg(long, default_value = "claude-code")]
        agent: String,

        #[arg(long, default_value = "sess-sandbox-run")]
        session_id: String,

        #[arg(long, env = "GRDR_DAEMON_URL", default_value = "http://127.0.0.1:8788")]
        daemon: String,

        #[arg(long = "allow-env")]
        allow_env: Vec<String>,

        #[arg(trailing_var_arg = true, required = true)]
        command: Vec<String>,
    },
    /// Inspect local endpoint readiness, agent discovery, and Windows telemetry exposure (read-only).
    Doctor {
        #[arg(long, default_value_t = false)]
        json: bool,

        #[arg(long, value_enum, default_value_t = ProfileArg::User)]
        profile: ProfileArg,

        #[arg(long, default_value_t = false)]
        strict: bool,
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
        Command::Hook { action } => match action {
            HookCommand::Status { agent, json } => hook::run_hook_status(&agent, json),
            HookCommand::Install {
                agent,
                command,
                apply,
            } => hook::run_install_hook(&agent, &command, apply),
            HookCommand::Uninstall { agent } => hook::run_uninstall_hook(&agent),
        },
        Command::Audit { action } => match action {
            AuditCommand::Verify { json, path } => audit::run_audit_verify(json, path),
        },
        Command::InstallHook {
            agent,
            command,
            apply,
        } => hook::run_install_hook(&agent, &command, apply),
        Command::UninstallHook { agent } => hook::run_uninstall_hook(&agent),
        Command::McpProxy {
            server_name,
            agent,
            session_id,
            daemon,
            command,
        } => mcp_proxy::run_mcp_proxy(&server_name, &agent, &session_id, &daemon, &command),
        Command::Run {
            contain,
            workdir,
            agent,
            session_id,
            daemon,
            allow_env,
            command,
        } => runner::run_contained_command(
            contain,
            workdir,
            &agent,
            &session_id,
            &daemon,
            &allow_env,
            &command,
        ),
        Command::Doctor {
            json,
            profile,
            strict,
        } => {
            let install_profile = match profile {
                ProfileArg::User => InstallProfile::User,
                ProfileArg::Protected => InstallProfile::Protected,
            };
            doctor::run_doctor(json, install_profile, strict)
        }
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
        summary: format!("grdr check {action}"),
        timestamp: now,
        ..Default::default()
    };
    let (receipt, source) = mcp_proxy::evaluate_via_daemon_or_offline(&attempt, daemon);

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
