// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::path::{Path, PathBuf};

use grdr_sandbox_engine::policy::{
    LinuxNamespaceMode, OsContainmentSpec, PrivilegePolicy, SandboxExecutionReport,
    WindowsTokenMode,
};
use grdr_sandbox_engine::{ContainmentMode, execute_contained_command};

use crate::RunError;
use crate::planner::{
    ContainmentStrategy, LaunchRequestSpec, PlatformContainmentPlan, PreparedLaunchPlan,
    sandbox_default_limits,
};

fn resolve_session_cgroup_dir(session_id: &str, mode: ContainmentMode) -> Option<PathBuf> {
    if mode == ContainmentMode::ObserveOnly {
        return None;
    }
    if let Ok(explicit) = std::env::var("GRDR_CGROUP_DIR")
        && !explicit.trim().is_empty()
    {
        return Some(PathBuf::from(explicit));
    }
    let clean_session: String = session_id
        .chars()
        .map(|c| {
            if c.is_ascii_alphanumeric() || c == '-' || c == '_' {
                c
            } else {
                '_'
            }
        })
        .take(64)
        .collect();
    if clean_session.is_empty() {
        return None;
    }
    let parent = Path::new("/sys/fs/cgroup/grdr-run");
    if parent.is_dir() {
        return Some(parent.join(clean_session));
    }
    None
}

pub fn build_os_containment_spec(
    req: &LaunchRequestSpec,
    plan: &PreparedLaunchPlan,
) -> Result<OsContainmentSpec, RunError> {
    let (default_mem, default_pids, max_seccomp_rules) = sandbox_default_limits()?;
    let workdir_path = PathBuf::from(&req.workspace_root);
    let mut writable_paths = Vec::new();
    for state_dir in &req.state_dirs {
        let p = PathBuf::from(state_dir);
        if p != workdir_path && !writable_paths.contains(&p) {
            writable_paths.push(p);
        }
    }

    let deny_paths: Vec<PathBuf> = req.protected_paths.iter().map(PathBuf::from).collect();

    let (
        memory_limit_bytes,
        active_process_limit,
        seccomp_denied_syscalls,
        linux_namespace,
        unshare_network,
        macos_seatbelt_sbpl,
        windows_sandbox_sid,
    ) = match &plan.platform {
        PlatformContainmentPlan::Linux { plan: linux_plan } => (
            linux_plan.cgroup_memory_bytes,
            linux_plan.cgroup_pids_max,
            linux_plan
                .seccomp_denied_syscalls
                .iter()
                .map(|s| (*s).to_string())
                .collect(),
            if linux_plan.unshare_network_except_proxy
                && plan.strategy == ContainmentStrategy::WrapAgent
            {
                LinuxNamespaceMode::Bubblewrap
            } else {
                LinuxNamespaceMode::Direct
            },
            linux_plan.unshare_network_except_proxy,
            None,
            None,
        ),
        PlatformContainmentPlan::MacOs { launch, .. } => (
            default_mem,
            default_pids,
            Vec::new(),
            LinuxNamespaceMode::Direct,
            false,
            launch.profile_sbpl.clone(),
            None,
        ),
        PlatformContainmentPlan::Windows { containment, .. } => (
            containment.job.memory_limit_bytes,
            containment.job.active_process_limit.unwrap_or(default_pids),
            Vec::new(),
            LinuxNamespaceMode::Direct,
            false,
            None,
            Some(containment.token.sandbox_sid.clone()),
        ),
    };

    let extra_env: Vec<(String, String)> = plan
        .proxy_env
        .iter()
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect();

    let windows_token = if plan.strategy == ContainmentStrategy::RequestOnly {
        WindowsTokenMode::StandardJobOnly
    } else {
        WindowsTokenMode::Restricted
    };

    Ok(OsContainmentSpec {
        session_id: req.session_id.clone(),
        agent_name: req.agent_name.clone(),
        mode: plan.sandbox_mode,
        workdir: Some(PathBuf::from(&req.workspace_root)),
        writable_paths,
        read_only_paths: Vec::new(),
        deny_paths,
        extra_allow_env: req.extra_allow_env.clone(),
        strip_secret_env: true,
        extra_env,
        memory_limit_bytes,
        active_process_limit,
        privilege: PrivilegePolicy::DropAll,
        linux_namespace,
        cgroup_dir: resolve_session_cgroup_dir(&req.session_id, plan.sandbox_mode),
        seccomp_denied_syscalls,
        max_seccomp_rules,
        unshare_network,
        macos_seatbelt_sbpl,
        windows_sandbox_sid,
        windows_token,
    })
}

pub fn execute_prepared_launch(
    req: &LaunchRequestSpec,
    plan: &PreparedLaunchPlan,
    inherited_env: &[(String, String)],
) -> Result<SandboxExecutionReport, RunError> {
    let os_spec = build_os_containment_spec(req, plan)?;
    execute_contained_command(&req.program, &req.args, &os_spec, inherited_env)
        .map_err(|err| RunError::SpawnFailed(err.to_string()))
}
