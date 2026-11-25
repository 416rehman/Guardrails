// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Cross-OS containment strategy planning (`Delegate`, `WrapTools`, `WrapAgent`).

use std::collections::BTreeMap;
use std::path::PathBuf;
use std::process::Command;

use serde::{Deserialize, Serialize};

use grdr_model::{ActionClass, AssuranceLevel, AssuranceRecord, InstallProfile};
use grdr_sandbox_engine::{ContainmentMode, SandboxReport, SandboxSpec, prepare_contained_command};
use grdr_sensor_macos::{
    MacOsCapabilityFlags, MacOsContainmentMode, MacOsTier, SeatbeltLaunchPlan, SeatbeltProfileSpec,
    SlotRung, compute_macos_assurance, es_tree::EsClientStatus, generate_sbpl_profile,
    plan_macos_launch,
};
use grdr_sensor_windows::{
    LaunchRoute, SandboxPrincipalKind, ToolContainmentPlan, WfpPrincipalKey, WfpSublayerPlan,
    WindowsTier, compute_windows_assurance, plan_session_wfp_filters, plan_tool_containment,
    validate_sid_syntax,
};

use crate::RunError;

pub const DEFAULT_MEMORY_LIMIT_BYTES: u64 = 2 * 1024 * 1024 * 1024;
pub const DEFAULT_CGROUP_PIDS_MAX: u32 = 256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentStrategy {
    Delegate,
    WrapTools,
    WrapAgent,
    RequestOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostOsKind {
    Windows,
    MacOs,
    Linux,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaunchRequestSpec {
    pub session_id: String,
    pub tool_call_id: Option<String>,
    pub agent_name: String,
    pub program: String,
    pub args: Vec<String>,
    pub workspace_root: String,
    pub protected_paths: Vec<String>,
    pub state_dirs: Vec<String>,
    pub strategy: ContainmentStrategy,
    pub agent_has_native_sandbox: bool,
    pub host_os: HostOsKind,
    pub profile: InstallProfile,
    pub proxy_port: u16,
    pub decide_socket_path: String,
    pub sandbox_sid: String,
    pub extra_allow_env: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LinuxContainmentPlan {
    pub strategy: ContainmentStrategy,
    pub landlock_rw_paths: Vec<String>,
    pub landlock_deny_paths: Vec<String>,
    pub seccomp_denied_syscalls: Vec<&'static str>,
    pub cgroup_memory_bytes: u64,
    pub cgroup_pids_max: u32,
    pub unshare_network_except_proxy: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "os", rename_all = "snake_case")]
pub enum PlatformContainmentPlan {
    Windows {
        containment: ToolContainmentPlan,
        wfp: Option<WfpSublayerPlan>,
        exec_assurance: AssuranceRecord,
        exec_level: AssuranceLevel,
    },
    MacOs {
        launch: SeatbeltLaunchPlan,
        exec_assurance: AssuranceRecord,
        net_assurance: AssuranceRecord,
        exec_level: AssuranceLevel,
    },
    Linux {
        plan: LinuxContainmentPlan,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PreparedLaunchPlan {
    pub strategy: ContainmentStrategy,
    pub sandbox_mode: ContainmentMode,
    pub runtime_enforced_level: AssuranceLevel,
    pub session_id: String,
    pub tool_call_id: Option<String>,
    pub sandbox_report: SandboxReport,
    pub platform: PlatformContainmentPlan,
    pub proxy_env: BTreeMap<String, String>,
}

impl HostOsKind {
    #[must_use]
    pub const fn current() -> Self {
        if cfg!(target_os = "windows") {
            Self::Windows
        } else if cfg!(target_os = "macos") {
            Self::MacOs
        } else {
            Self::Linux
        }
    }
}

impl ContainmentStrategy {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Delegate => "delegate",
            Self::WrapTools => "wrap_tools",
            Self::WrapAgent => "wrap_agent",
            Self::RequestOnly => "request_only",
        }
    }

    #[must_use]
    pub const fn to_sandbox_mode(self) -> ContainmentMode {
        match self {
            Self::Delegate | Self::WrapTools | Self::WrapAgent => {
                ContainmentMode::WorkspaceContained
            }
            Self::RequestOnly => ContainmentMode::SanitizedEnv,
        }
    }
}

pub fn build_launch_plan(
    req: &LaunchRequestSpec,
    inherited_env: &BTreeMap<String, String>,
) -> Result<(Command, PreparedLaunchPlan), RunError> {
    validate_launch_request(req)?;

    let effective_strategy = resolve_effective_strategy(req);
    let mut allow_env = req.extra_allow_env.clone();
    for key in ["GRDR_SESSION_ID", "GRDR_RUN_STRATEGY", "GRDR_TOOL_CALL_ID"] {
        if !allow_env.iter().any(|existing| existing == key) {
            allow_env.push(key.to_owned());
        }
    }

    let spec = SandboxSpec {
        session_id: req.session_id.clone(),
        agent_name: req.agent_name.clone(),
        mode: effective_strategy.to_sandbox_mode(),
        workdir: (req.host_os == HostOsKind::current()).then(|| PathBuf::from(&req.workspace_root)),
        extra_allow_env: allow_env,
        strip_secret_env: true,
    };

    let env_pairs: Vec<(String, String)> = inherited_env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();
    let (mut cmd, sandbox_report) =
        prepare_contained_command(&req.program, &req.args, &spec, &env_pairs)
            .map_err(|e| RunError::InvalidPlan(e.to_string()))?;

    let mut proxy_env = BTreeMap::new();
    proxy_env.insert("GRDR_SESSION_ID".into(), req.session_id.clone());
    proxy_env.insert(
        "GRDR_RUN_STRATEGY".into(),
        effective_strategy.as_str().into(),
    );
    if let Some(call_id) = req.tool_call_id.as_deref() {
        proxy_env.insert("GRDR_TOOL_CALL_ID".into(), call_id.to_owned());
    }
    if req.proxy_port > 0 {
        let local_host = std::net::IpAddr::V4(std::net::Ipv4Addr::LOCALHOST);
        let url = format!("http://{local_host}:{}", req.proxy_port);
        proxy_env.insert("GRDR_PROXY_URL".into(), url.clone());
        proxy_env.insert("HTTPS_PROXY".into(), url.clone());
        proxy_env.insert("HTTP_PROXY".into(), url);
    }
    for (k, v) in &proxy_env {
        cmd.env(k, v);
    }

    let platform = build_platform_plan(req, effective_strategy)?;
    let runtime_enforced_level = compute_runtime_enforced_level(req, effective_strategy);
    let plan = PreparedLaunchPlan {
        strategy: effective_strategy,
        sandbox_mode: effective_strategy.to_sandbox_mode(),
        runtime_enforced_level,
        session_id: req.session_id.clone(),
        tool_call_id: req.tool_call_id.clone(),
        sandbox_report,
        platform,
        proxy_env,
    };
    Ok((cmd, plan))
}

fn validate_launch_request(req: &LaunchRequestSpec) -> Result<(), RunError> {
    if req.session_id.trim().is_empty() {
        return Err(RunError::InvalidPlan("session_id cannot be empty".into()));
    }
    if req.program.trim().is_empty() {
        return Err(RunError::InvalidPlan("program cannot be empty".into()));
    }
    let check_symlinks = req.host_os == HostOsKind::current();
    validate_path_entry(
        "workspace_root",
        &req.workspace_root,
        Some(req.host_os),
        check_symlinks,
    )?;
    for path in &req.protected_paths {
        validate_path_entry("protected_paths", path, Some(req.host_os), check_symlinks)?;
    }
    for dir in &req.state_dirs {
        validate_path_entry("state_dirs", dir, Some(req.host_os), check_symlinks)?;
    }
    validate_path_entry("decide_socket_path", &req.decide_socket_path, None, false)?;
    let sock_trimmed = req.decide_socket_path.trim();
    if sock_trimmed.starts_with("/tmp/") || sock_trimmed == "/tmp" {
        return Err(RunError::InvalidPlan(
            "decide_socket_path must not use shared /tmp directory".into(),
        ));
    }
    validate_sid_syntax(&req.sandbox_sid)
        .map_err(|e| RunError::InvalidPlan(format!("invalid sandbox_sid: {e}")))?;
    if req.strategy == ContainmentStrategy::WrapTools
        && req
            .tool_call_id
            .as_deref()
            .is_none_or(|id| id.trim().is_empty())
    {
        return Err(RunError::InvalidPlan(
            "wrap_tools strategy requires a non-empty tool_call_id".into(),
        ));
    }
    Ok(())
}

fn is_absolute_for_os(host_os: Option<HostOsKind>, path: &str) -> bool {
    let b = path.as_bytes();
    let is_win = matches!(
        (b.first(), b.get(1), b.get(2)),
        (Some(d), Some(b':'), Some(b'\\') | Some(b'/')) if d.is_ascii_alphabetic()
    ) || path.starts_with("\\\\");
    match host_os {
        Some(HostOsKind::Windows) => is_win,
        Some(HostOsKind::Linux | HostOsKind::MacOs) => path.starts_with('/'),
        None => path.starts_with('/') || is_win,
    }
}

fn validate_path_entry(
    field: &str,
    raw: &str,
    target_os: Option<HostOsKind>,
    check_host_symlinks: bool,
) -> Result<(), RunError> {
    let trimmed = raw.trim();
    if trimmed.is_empty() || trimmed.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(RunError::InvalidPlan(format!(
            "{field} contains empty, NUL, or control characters"
        )));
    }
    if trimmed.split(['/', '\\']).any(|seg| seg == "..") {
        return Err(RunError::InvalidPlan(format!(
            "{field} `{trimmed}` cannot contain parent `..` traversal"
        )));
    }
    if !is_absolute_for_os(target_os, trimmed) {
        return Err(RunError::InvalidPlan(format!(
            "{field} `{trimmed}` must be an absolute path"
        )));
    }
    if check_host_symlinks {
        let p = std::path::Path::new(trimmed);
        let mut deepest_existing: Option<&std::path::Path> = None;
        for anc in p.ancestors() {
            if anc.as_os_str().is_empty() {
                continue;
            }
            if let Ok(meta) = std::fs::symlink_metadata(anc) {
                if meta.file_type().is_symlink() {
                    return Err(RunError::InvalidPlan(format!(
                        "{field} `{trimmed}` contains symlink component `{}`",
                        anc.display()
                    )));
                }
                if deepest_existing.is_none() {
                    deepest_existing = Some(anc);
                }
            }
        }
        if let Some(existing) = deepest_existing
            && let Ok(canon) = std::fs::canonicalize(existing)
        {
            let canon_raw = canon.to_string_lossy();
            let canon_clean = canon_raw.strip_prefix("\\\\?\\").unwrap_or(&canon_raw);
            if canon_clean != existing.to_string_lossy().as_ref() {
                return Err(RunError::InvalidPlan(format!(
                    "{field} `{trimmed}` must be canonical"
                )));
            }
        }
    }
    Ok(())
}

fn compute_runtime_enforced_level(
    req: &LaunchRequestSpec,
    strategy: ContainmentStrategy,
) -> AssuranceLevel {
    if strategy == ContainmentStrategy::RequestOnly {
        return AssuranceLevel::Al1Observed;
    }
    if cfg!(target_os = "macos")
        && req.host_os == HostOsKind::MacOs
        && matches!(
            strategy,
            ContainmentStrategy::WrapAgent | ContainmentStrategy::WrapTools
        )
    {
        return AssuranceLevel::Al2Guided;
    }
    // User-space Command + sanitized environment + canonical cwd provides AL2 Guided boundary
    // until privileged OS driver / Seatbelt / Landlock isolation wraps the child.
    AssuranceLevel::Al2Guided
}

fn resolve_effective_strategy(req: &LaunchRequestSpec) -> ContainmentStrategy {
    if req.strategy != ContainmentStrategy::Delegate {
        return req.strategy;
    }
    let lower = req.agent_name.trim().to_ascii_lowercase();
    if req.agent_has_native_sandbox && (lower == "codex" || lower == "claude-code") {
        ContainmentStrategy::Delegate
    } else if req.agent_has_native_sandbox {
        ContainmentStrategy::WrapTools
    } else {
        ContainmentStrategy::WrapAgent
    }
}

fn build_platform_plan(
    req: &LaunchRequestSpec,
    strategy: ContainmentStrategy,
) -> Result<PlatformContainmentPlan, RunError> {
    match req.host_os {
        HostOsKind::Windows => build_windows_plan(req, strategy),
        HostOsKind::MacOs => build_macos_plan(req, strategy),
        HostOsKind::Linux => Ok(build_linux_plan(req, strategy)),
    }
}

fn build_windows_plan(
    req: &LaunchRequestSpec,
    strategy: ContainmentStrategy,
) -> Result<PlatformContainmentPlan, RunError> {
    let route = match strategy {
        ContainmentStrategy::Delegate => LaunchRoute::Delegate,
        ContainmentStrategy::WrapTools => LaunchRoute::GrdrRun,
        ContainmentStrategy::WrapAgent => LaunchRoute::ProcessWrapper,
        ContainmentStrategy::RequestOnly => LaunchRoute::HookRewrite,
    };
    let containment = plan_tool_containment(
        &req.session_id,
        route,
        SandboxPrincipalKind::AppContainer,
        &req.sandbox_sid,
        &req.workspace_root,
        &req.protected_paths,
        DEFAULT_MEMORY_LIMIT_BYTES,
    )
    .map_err(|e| RunError::InvalidPlan(e.to_string()))?;

    let wfp = if req.proxy_port > 0 {
        let plan = plan_session_wfp_filters(
            WfpPrincipalKey::SandboxSid {
                sid: req.sandbox_sid.clone(),
            },
            req.proxy_port,
            None,
        )
        .map_err(|e| RunError::InvalidPlan(e.to_string()))?;
        Some(plan)
    } else {
        None
    };

    let tier = match req.profile {
        InstallProfile::User => WindowsTier::W0Observe,
        InstallProfile::Protected => WindowsTier::W1Contain,
    };
    let exec_assurance =
        compute_windows_assurance(tier, req.profile, route, ActionClass::Exec, false);
    let exec_level = exec_assurance.level();
    Ok(PlatformContainmentPlan::Windows {
        containment,
        wfp,
        exec_assurance,
        exec_level,
    })
}

fn build_macos_plan(
    req: &LaunchRequestSpec,
    strategy: ContainmentStrategy,
) -> Result<PlatformContainmentPlan, RunError> {
    let sb_spec = SeatbeltProfileSpec {
        session_id: req.session_id.clone(),
        workspace_root: req.workspace_root.clone(),
        state_dirs: req.state_dirs.clone(),
        protected_paths: req.protected_paths.clone(),
        decide_socket_path: req.decide_socket_path.clone(),
        proxy_port: req.proxy_port,
        deny_elevation_binaries: true,
    };
    let launch = match strategy {
        ContainmentStrategy::Delegate => {
            plan_macos_launch(&req.agent_name, req.agent_has_native_sandbox, &sb_spec)
                .map_err(|e| RunError::InvalidPlan(e.to_string()))?
        }
        ContainmentStrategy::WrapTools => SeatbeltLaunchPlan {
            containment_mode: MacOsContainmentMode::WrapTools,
            visibility_is_claimed: true,
            on_failure_closed: true,
            profile_sbpl: Some(
                generate_sbpl_profile(&sb_spec)
                    .map_err(|e| RunError::InvalidPlan(e.to_string()))?,
            ),
            reason: "explicit WrapTools Seatbelt profile generated".into(),
        },
        ContainmentStrategy::WrapAgent => SeatbeltLaunchPlan {
            containment_mode: MacOsContainmentMode::WrapAgent,
            visibility_is_claimed: true,
            on_failure_closed: true,
            profile_sbpl: Some(
                generate_sbpl_profile(&sb_spec)
                    .map_err(|e| RunError::InvalidPlan(e.to_string()))?,
            ),
            reason: "explicit WrapAgent Seatbelt profile generated".into(),
        },
        ContainmentStrategy::RequestOnly => SeatbeltLaunchPlan {
            containment_mode: MacOsContainmentMode::RequestOnly,
            visibility_is_claimed: true,
            on_failure_closed: false,
            profile_sbpl: None,
            reason: "request-only fallback configured explicitly".into(),
        },
    };

    let caps = MacOsCapabilityFlags {
        profile: req.profile,
        tier: MacOsTier::Tier1HooksAndSeatbelt,
        containment: launch.containment_mode,
        content_filter_rung: SlotRung::Observe,
        es_status: EsClientStatus::MissingEntitlement,
    };
    let exec_assurance = compute_macos_assurance(&caps, ActionClass::Exec);
    let net_assurance = compute_macos_assurance(&caps, ActionClass::NetConnect);
    let exec_level = exec_assurance.level();
    Ok(PlatformContainmentPlan::MacOs {
        launch,
        exec_assurance,
        net_assurance,
        exec_level,
    })
}

fn build_linux_plan(
    req: &LaunchRequestSpec,
    strategy: ContainmentStrategy,
) -> PlatformContainmentPlan {
    let mut rw_paths = vec![req.workspace_root.clone()];
    rw_paths.extend(req.state_dirs.clone());
    let plan = LinuxContainmentPlan {
        strategy,
        landlock_rw_paths: rw_paths,
        landlock_deny_paths: req.protected_paths.clone(),
        seccomp_denied_syscalls: vec![
            "ptrace",
            "process_vm_readv",
            "process_vm_writev",
            "kexec_load",
            "init_module",
            "finit_module",
            "mount",
            "umount2",
        ],
        cgroup_memory_bytes: DEFAULT_MEMORY_LIMIT_BYTES,
        cgroup_pids_max: DEFAULT_CGROUP_PIDS_MAX,
        unshare_network_except_proxy: strategy != ContainmentStrategy::RequestOnly,
    };
    PlatformContainmentPlan::Linux { plan }
}
