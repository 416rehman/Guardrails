// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use clap::{Parser, ValueEnum};
use jiff::Timestamp;
use tracing_subscriber::EnvFilter;

use grdr_model::InstallProfile;
use grdr_run::RunError;
use grdr_run::gate::{
    DEFAULT_DAEMON_PORT, DEFAULT_GATE_TIMEOUT_MS, GateVerdict, LoopbackGateClient, authorize_launch,
};
use grdr_run::planner::{ContainmentStrategy, HostOsKind, LaunchRequestSpec, build_launch_plan};

#[derive(Debug, Clone, Copy, ValueEnum)]
enum StrategyArg {
    Delegate,
    WrapTools,
    WrapAgent,
    RequestOnly,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ProfileArg {
    User,
    Protected,
}

#[derive(Debug, Clone, Copy, ValueEnum)]
enum ExecModeArg {
    Spawn,
    PlanJson,
}

#[derive(Debug, Parser)]
#[command(
    name = "grdr-run",
    about = "D-21 session-container and tool-containment launcher"
)]
struct Cli {
    /// Session identifier owning this launch.
    #[arg(long)]
    session: String,
    /// Optional tool call identifier required for WrapTools mode.
    #[arg(long)]
    tool_call: Option<String>,
    /// Agent identifier (e.g. codex, claude-code, cursor).
    #[arg(long, default_value = "generic-agent")]
    agent: String,
    /// Workspace root allowed read/write inside containment.
    #[arg(long)]
    workspace: String,
    /// Containment strategy.
    #[arg(long, value_enum, default_value_t = StrategyArg::WrapAgent)]
    strategy: StrategyArg,
    /// Whether the wrapped agent already activates its own outer OS sandbox.
    #[arg(long)]
    native_sandbox: bool,
    /// Install profile tier (`user` or `protected`).
    #[arg(long, value_enum, default_value_t = ProfileArg::User)]
    profile: ProfileArg,
    /// Protected directories explicitly denied inside the workspace.
    #[arg(long)]
    protect_path: Vec<String>,
    /// State directories permitted for agent metadata writes on macOS/Linux.
    #[arg(long)]
    state_dir: Vec<String>,
    /// Loopback proxy port to route outbound requests through.
    #[arg(long, default_value_t = 0)]
    proxy_port: u16,
    /// Loopback daemon port for pre-launch authorization.
    #[arg(long, default_value_t = DEFAULT_DAEMON_PORT)]
    daemon_port: u16,
    /// Windows AppContainer or sandbox SID used in Windows containment planning.
    #[arg(long, default_value = "S-1-15-2-1001")]
    sandbox_sid: String,
    /// Output containment plan JSON without spawning, or authorize and spawn.
    #[arg(long, value_enum, default_value_t = ExecModeArg::Spawn)]
    exec_mode: ExecModeArg,
    /// Socket path passed to containment policies for daemon decision endpoint access.
    #[arg(long, default_value = "/var/run/grdr/decide.sock")]
    decide_socket: String,
    /// Target executable and trailing arguments after `--`.
    #[arg(required = true, trailing_var_arg = true)]
    command: Vec<String>,
}

impl From<StrategyArg> for ContainmentStrategy {
    fn from(arg: StrategyArg) -> Self {
        match arg {
            StrategyArg::Delegate => Self::Delegate,
            StrategyArg::WrapTools => Self::WrapTools,
            StrategyArg::WrapAgent => Self::WrapAgent,
            StrategyArg::RequestOnly => Self::RequestOnly,
        }
    }
}

impl From<ProfileArg> for InstallProfile {
    fn from(arg: ProfileArg) -> Self {
        match arg {
            ProfileArg::User => Self::User,
            ProfileArg::Protected => Self::Protected,
        }
    }
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .with_writer(std::io::stderr)
        .init();

    let cli = Cli::parse();
    let Some(program) = cli.command.first().cloned() else {
        return Err(RunError::InvalidPlan("command binary missing".into()).into());
    };
    let args: Vec<String> = cli.command.iter().skip(1).cloned().collect();
    let req = LaunchRequestSpec {
        session_id: cli.session,
        tool_call_id: cli.tool_call,
        agent_name: cli.agent,
        program,
        args,
        workspace_root: cli.workspace,
        protected_paths: cli.protect_path,
        state_dirs: cli.state_dir,
        strategy: cli.strategy.into(),
        agent_has_native_sandbox: cli.native_sandbox,
        host_os: HostOsKind::current(),
        profile: cli.profile.into(),
        proxy_port: cli.proxy_port,
        decide_socket_path: cli.decide_socket,
        sandbox_sid: cli.sandbox_sid,
        extra_allow_env: Vec::new(),
    };

    let inherited: BTreeMap<String, String> = std::env::vars().collect();
    let (cmd, plan) = build_launch_plan(&req, &inherited)?;

    if matches!(cli.exec_mode, ExecModeArg::PlanJson) {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }

    let client = LoopbackGateClient::from_loopback_port(cli.daemon_port, DEFAULT_GATE_TIMEOUT_MS)?;
    match authorize_launch(&client, &req, None, Timestamp::now()).await? {
        GateVerdict::Allow { .. } => {}
        GateVerdict::Deny { reason, .. } => {
            return Err(RunError::PolicyDenied(reason).into());
        }
    }

    let status = execute_contained_command(&req, &plan, cmd)?;
    if !status.success() {
        return Err(RunError::SpawnFailed(format!("child exited with status {status}")).into());
    }
    Ok(())
}

fn execute_contained_command(
    req: &LaunchRequestSpec,
    plan: &grdr_run::planner::PreparedLaunchPlan,
    mut cmd: std::process::Command,
) -> Result<std::process::ExitStatus, RunError> {
    if let grdr_run::planner::PlatformContainmentPlan::MacOs { launch, .. } = &plan.platform
        && let Some(sbpl) = &launch.profile_sbpl
        && cfg!(target_os = "macos")
    {
        let mut sb_cmd = std::process::Command::new("/usr/bin/sandbox-exec");
        sb_cmd.arg("-p").arg(sbpl).arg(&req.program).args(&req.args);
        if let Some(dir) = cmd.get_current_dir() {
            sb_cmd.current_dir(dir);
        }
        sb_cmd.env_clear();
        for (k, v) in cmd.get_envs() {
            if let Some(val) = v {
                sb_cmd.env(k, val);
            }
        }
        return sb_cmd
            .status()
            .map_err(|e| RunError::SpawnFailed(format!("sandbox-exec failed: {e}")));
    }

    cmd.status()
        .map_err(|e| RunError::SpawnFailed(e.to_string()))
}
