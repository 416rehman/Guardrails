// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Route, config, process, and assurance helpers for `discover.rs`.

use std::env;
use std::path::{Path, PathBuf};

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_core::discover::{IdentityHints, ProgramIdentity};
use grdr_model::{
    AssuranceRecord, ControlStrength, DiscoveryReport, InstallProfile, McpServerEntry, OnFailure,
    TamperGrade, Visibility,
};
use grdr_ports::{LocalFsPort, validate_safe_rel_path};

use crate::catalogue::AgentManifest;
use crate::parse::{
    display_path, extract_mcp_servers_by_key, extract_toml_mcp_headers, json_contains_hook_command,
    read_json,
};
use crate::windows_process_parse::{WindowsProcessEntry, executable_basename};

const MAX_CONFIG_READ_BYTES: u64 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ContainmentTier {
    #[default]
    HookOnly,
    PartialSandbox,
    ScopedSandbox,
    MandatoryKernelOpen,
    MandatoryKernelFailClosed,
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn scan_manifest_filesystem_routes(
    manifest: &AgentManifest,
    home: Option<&Path>,
    appdata: Option<&Path>,
    workspace: Option<&Path>,
    hook_command: &str,
    fs: &dyn LocalFsPort,
    matched_routes: &mut Vec<String>,
    primary_path: &mut Option<PathBuf>,
    hook_installed: &mut bool,
    mcp_servers: &mut Vec<McpServerEntry>,
    scanned_paths: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    if let Some(home_dir) = home {
        for rel in &manifest.routes.state_dirs {
            if validate_safe_rel_path(rel, false, false, false).is_err() {
                continue;
            }
            let candidate = home_dir.join(rel);
            if fs.is_regular_dir_nofollow(&candidate) {
                matched_routes.push(format!("state:{rel}"));
                if primary_path.is_none() {
                    *primary_path = Some(candidate);
                }
            }
        }
    }

    for rel in &manifest.routes.config_paths {
        let Some(path) = resolve_template_path(home, appdata, workspace, rel) else {
            continue;
        };
        scanned_paths.push(display_path(&path));
        if fs.is_regular_file_nofollow(&path) {
            matched_routes.push(format!("config:{rel}"));
            *primary_path = Some(path.clone());
            inspect_config_file(
                manifest,
                &path,
                hook_command,
                fs,
                hook_installed,
                mcp_servers,
                warnings,
            );
        }
    }

    for rel in &manifest.routes.mcp_config_paths {
        let Some(path) = resolve_template_path(home, appdata, workspace, rel) else {
            continue;
        };
        if !manifest.routes.config_paths.contains(rel) {
            scanned_paths.push(display_path(&path));
            if fs.is_regular_file_nofollow(&path) {
                matched_routes.push(format!("mcp:{rel}"));
                inspect_config_file(
                    manifest,
                    &path,
                    hook_command,
                    fs,
                    hook_installed,
                    mcp_servers,
                    warnings,
                );
            }
        }
    }

    if let Some(home_dir) = home
        && !manifest.hook.config_rel.is_empty()
        && !manifest
            .routes
            .config_paths
            .contains(&manifest.hook.config_rel)
        && validate_safe_rel_path(&manifest.hook.config_rel, false, false, false).is_ok()
    {
        let hook_cfg = home_dir.join(&manifest.hook.config_rel);
        if fs.is_regular_file_nofollow(&hook_cfg) {
            matched_routes.push(format!("hook:{}", manifest.hook.config_rel));
            if let Ok(val) = read_json(&hook_cfg, fs)
                && json_contains_hook_command(&val, &manifest.hook.root_key, hook_command)
            {
                *hook_installed = true;
            }
        }
    }
}

pub(crate) fn build_program_identity(manifest: &AgentManifest, exe_path: &str) -> ProgramIdentity {
    let pkg_name = manifest
        .routes
        .npm
        .first()
        .or_else(|| manifest.routes.pypi.first());
    let ecosystem = if !manifest.routes.npm.is_empty() {
        Some("npm".to_owned())
    } else if !manifest.routes.pypi.is_empty() {
        Some("pypi".to_owned())
    } else {
        None
    };
    ProgramIdentity::from_hints(&IdentityHints {
        ecosystem,
        package_name: pkg_name.cloned(),
        executable_path: exe_path.to_owned(),
        ..IdentityHints::default()
    })
}

fn resolve_template_path(
    home: Option<&Path>,
    appdata: Option<&Path>,
    workspace: Option<&Path>,
    rel: &str,
) -> Option<PathBuf> {
    if validate_safe_rel_path(rel, true, true, false).is_err() {
        return None;
    }
    if let Some(ws_rel) = rel.strip_prefix("$WORKSPACE/") {
        return workspace.map(|ws| ws.join(ws_rel));
    }
    if let Some(app_rel) = rel.strip_prefix("$APPDATA/") {
        return appdata.map(|app| app.join(app_rel));
    }
    home.map(|h| h.join(rel))
}

fn inspect_config_file(
    manifest: &AgentManifest,
    path: &Path,
    hook_command: &str,
    fs: &dyn LocalFsPort,
    hook_installed: &mut bool,
    mcp_servers: &mut Vec<McpServerEntry>,
    warnings: &mut Vec<String>,
) {
    let ext = path.extension().and_then(|s| s.to_str()).unwrap_or("");
    if ext.eq_ignore_ascii_case("toml") {
        if let Ok(raw) = fs.read_bounded_regular_string(path, MAX_CONFIG_READ_BYTES) {
            extract_toml_mcp_headers(&raw, &manifest.name, path, mcp_servers);
        }
        return;
    }
    if ext.eq_ignore_ascii_case("json") {
        match read_json(path, fs) {
            Ok(val) => {
                if json_contains_hook_command(&val, &manifest.hook.root_key, hook_command) {
                    *hook_installed = true;
                }
                extract_mcp_servers_by_key(
                    &val,
                    &manifest.routes.mcp_config_key,
                    &manifest.name,
                    path,
                    mcp_servers,
                );
            }
            Err(err) => warnings.push(format!("Could not parse {} ({err})", path.display())),
        }
    }
}

pub(crate) fn find_matching_process<'a>(
    manifest: &AgentManifest,
    processes: &'a [WindowsProcessEntry],
) -> Option<&'a WindowsProcessEntry> {
    processes.iter().find(|proc_entry| {
        let img = proc_entry.image_name.to_ascii_lowercase();
        let exe_base = proc_entry
            .executable_path
            .as_deref()
            .map(|p| executable_basename(p).to_ascii_lowercase());
        if manifest.routes.windows_exes.iter().any(|w| {
            let lw = w.to_ascii_lowercase();
            img == lw || exe_base.as_deref() == Some(lw.as_str())
        }) || manifest.routes.binaries.iter().any(|b| {
            let lb = b.to_ascii_lowercase();
            img == lb || exe_base.as_deref() == Some(lb.as_str())
        }) {
            return true;
        }
        if let Some(cmd) = &proc_entry.command_line {
            let cmd_lower = cmd.to_ascii_lowercase();
            return manifest
                .routes
                .cmdline_markers
                .iter()
                .any(|m| cmd_lower.contains(&m.to_ascii_lowercase()));
        }
        false
    })
}

#[must_use]
pub fn evaluate_hook_assurance(
    profile: InstallProfile,
    hook_installed: bool,
    health: crate::canary::HookHealthState,
    fail_closed_declared: bool,
    containment: ContainmentTier,
) -> AssuranceRecord {
    use crate::canary::HookHealthState;
    let tamper = match profile {
        InstallProfile::Protected => TamperGrade::Admin,
        InstallProfile::User => TamperGrade::User,
    };
    match containment {
        ContainmentTier::MandatoryKernelFailClosed => AssuranceRecord {
            visibility: Visibility::CrossChecked,
            control: ControlStrength::MandatoryBoundary,
            on_failure: OnFailure::Closed,
            tamper,
        },
        ContainmentTier::MandatoryKernelOpen => AssuranceRecord {
            visibility: Visibility::CrossChecked,
            control: ControlStrength::MandatoryBoundary,
            on_failure: OnFailure::Open,
            tamper,
        },
        ContainmentTier::ScopedSandbox => AssuranceRecord {
            visibility: Visibility::Observed,
            control: ControlStrength::ScopedBoundary,
            on_failure: OnFailure::Closed,
            tamper,
        },
        ContainmentTier::PartialSandbox | ContainmentTier::HookOnly => {
            // Doc 07: hooks provide Request-level (AL2) at most once passive canary passes,
            // never ScopedBoundary (AL3), even under InstallProfile::Protected.
            if hook_installed && health == HookHealthState::Effective {
                let on_failure = if profile == InstallProfile::Protected && fail_closed_declared {
                    OnFailure::Closed
                } else {
                    OnFailure::Open
                };
                AssuranceRecord {
                    visibility: Visibility::Claimed,
                    control: ControlStrength::Request,
                    on_failure,
                    tamper,
                }
            } else {
                AssuranceRecord {
                    visibility: Visibility::Claimed,
                    control: ControlStrength::None,
                    on_failure: OnFailure::Open,
                    tamper,
                }
            }
        }
    }
}

pub(crate) fn assurance_for_hook(hook_installed: bool, profile: InstallProfile) -> AssuranceRecord {
    // Static discovery only observes installed config entries; live canary corroboration
    // is required before claiming Request/AL2 effectiveness.
    let _ = hook_installed;
    evaluate_hook_assurance(
        profile,
        hook_installed,
        crate::canary::HookHealthState::Configured,
        false,
        ContainmentTier::HookOnly,
    )
}

pub(crate) fn empty_report(device_name: &str, profile: InstallProfile) -> DiscoveryReport {
    DiscoveryReport {
        device_name: device_name.into(),
        os: env::consts::OS.into(),
        arch: env::consts::ARCH.into(),
        install_profile: profile,
        agents: Vec::new(),
        mcp_servers: Vec::new(),
        artifacts: Vec::new(),
        scanned_paths: Vec::new(),
        warnings: vec!["Failed loading embedded P14 agent catalogue.".into()],
        scanned_at: Timestamp::now(),
    }
}
