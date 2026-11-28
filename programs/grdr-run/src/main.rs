// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::path::PathBuf;

use clap::{Parser, ValueEnum};
use jiff::Timestamp;
use tracing_subscriber::EnvFilter;

use grdr_model::InstallProfile;
use grdr_run::RunError;
use grdr_run::executor::execute_prepared_launch;
use grdr_run::gate::{
    GateVerdict, IpcGateClient, authorize_launch_with_state_dir, default_gate_timeout_ms,
};
use grdr_run::ipc_transport::default_decide_endpoint_display;
use grdr_run::planner::{ContainmentStrategy, HostOsKind, LaunchRequestSpec, build_launch_plan};
use grdr_run::planner_macos::{MacOsSuperviseConfig, MacOsSuperviseMissMode};
use grdr_wire::peer_auth::Profile;

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

#[derive(Debug, Clone, Copy, ValueEnum)]
enum DescendantsMissArg {
    Open,
    Closed,
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
    /// State root used to look up signed offline `floor.bin` + `floor.pub` in user profile.
    #[arg(long)]
    state_dir_root: Option<PathBuf>,
    /// Loopback proxy port to route outbound requests through.
    #[arg(long, default_value_t = 0)]
    proxy_port: u16,
    /// IPC authorization timeout in milliseconds (defaults to embedded limits.toml read_timeout_ms).
    #[arg(long)]
    timeout_ms: Option<u64>,
    /// Windows AppContainer or sandbox SID used in Windows containment planning.
    #[arg(long, default_value = "S-1-15-2-1001")]
    sandbox_sid: String,
    /// Output containment plan JSON without spawning, or authorize and spawn.
    #[arg(long, value_enum, default_value_t = ExecModeArg::Spawn)]
    exec_mode: ExecModeArg,
    /// Optional explicit peer-verified IPC Decide endpoint path or pipe name (user profile only).
    #[arg(long)]
    decide_socket: Option<String>,
    /// Enable macOS 27 DescendantsSupervisor Endpoint Security containment mode.
    #[arg(long)]
    supervise: bool,
    /// Configure DescendantsSupervisor deadline miss policy (`open` or `closed`).
    #[arg(long, value_enum, default_value_t = DescendantsMissArg::Open)]
    descendants_deadline_miss: DescendantsMissArg,
    /// Explicit DescendantsSupervisor kernel deadline floor in ms.
    #[arg(long)]
    descendants_deadline_floor_ms: Option<u64>,
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

impl From<ProfileArg> for Profile {
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
    let wire_profile: Profile = cli.profile.into();
    let decide_socket_for_plan = match cli.decide_socket.clone() {
        Some(explicit) if !explicit.trim().is_empty() => explicit,
        _ => default_decide_endpoint_display(wire_profile)?,
    };
    let timeout_ms = match cli.timeout_ms {
        Some(ms) => ms,
        None => default_gate_timeout_ms()?,
    };
    let macos_supervise = cli.supervise.then(|| MacOsSuperviseConfig {
        deadline_floor_ms: cli.descendants_deadline_floor_ms.unwrap_or(0),
        miss_mode: match cli.descendants_deadline_miss {
            DescendantsMissArg::Closed => MacOsSuperviseMissMode::FailClosed,
            DescendantsMissArg::Open => MacOsSuperviseMissMode::FailOpen,
        },
    });
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
        decide_socket_path: decide_socket_for_plan,
        sandbox_sid: cli.sandbox_sid,
        extra_allow_env: Vec::new(),
        macos_supervise,
    };

    let inherited: BTreeMap<String, String> = std::env::vars().collect();
    let (_cmd, plan) = build_launch_plan(&req, &inherited)?;

    if matches!(cli.exec_mode, ExecModeArg::PlanJson) {
        println!("{}", serde_json::to_string_pretty(&plan)?);
        return Ok(());
    }

    let client = IpcGateClient::new(wire_profile, cli.decide_socket, timeout_ms);
    match authorize_launch_with_state_dir(
        &client,
        &req,
        None,
        cli.state_dir_root.as_deref(),
        wire_profile,
        Timestamp::now(),
    )
    .await?
    {
        GateVerdict::Allow { .. } => {}
        GateVerdict::Deny { reason, .. } => {
            return Err(RunError::PolicyDenied(reason).into());
        }
    }

    let env_pairs: Vec<(String, String)> = inherited.into_iter().collect();
    let exec_report = execute_prepared_launch(&req, &plan, &env_pairs)?;
    if !exec_report.success {
        return Err(RunError::SpawnFailed(format!(
            "contained child exited with status {}",
            exec_report.exit_code
        ))
        .into());
    }
    Ok(())
}
