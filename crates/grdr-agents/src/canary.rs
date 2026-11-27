// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Hook canary handshake verification and install health evaluation (`docs/design/07`).

use std::path::Path;

use serde::{Deserialize, Serialize};

use grdr_ports::LocalFsPort;

use crate::catalogue::{AgentCatalogue, AgentManifest};
use crate::hook_codec::parse_hook_stdin_with_catalogue;
use crate::install::{HookInstallState, HookTargetKind, hook_status_with_catalogue};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum HookHealthState {
    Effective,
    NotConfigured,
    HookDark,
    Tampered,
    CanaryFailed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CanaryStatus {
    Passed,
    Missed,
    Malformed,
    ProbeRejected,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HookCanaryReport {
    pub agent_id: String,
    pub health: HookHealthState,
    pub canary: CanaryStatus,
    pub detail: String,
}

pub fn verify_hook_canary(
    manifest: &AgentManifest,
    home_dir: &Path,
    hook_command: &str,
    probe_json: &str,
    catalogue: &AgentCatalogue,
    fs: &dyn LocalFsPort,
) -> HookCanaryReport {
    let target = HookTargetKind::from_manifest(manifest);
    let status = match hook_status_with_catalogue(&target, home_dir, hook_command, catalogue, fs) {
        Ok(st) => st,
        Err(err) => {
            return HookCanaryReport {
                agent_id: manifest.id.clone(),
                health: HookHealthState::Tampered,
                canary: CanaryStatus::Malformed,
                detail: err,
            };
        }
    };

    if status.state == HookInstallState::NotConfigured || !status.installed {
        return HookCanaryReport {
            agent_id: manifest.id.clone(),
            health: HookHealthState::NotConfigured,
            canary: CanaryStatus::Missed,
            detail: format!("hook entry absent from {}", status.config_path.display()),
        };
    }

    match parse_hook_stdin_with_catalogue(
        &manifest.hook.dialect,
        probe_json,
        "canary-host",
        catalogue,
    ) {
        Ok(attempt) => HookCanaryReport {
            agent_id: manifest.id.clone(),
            health: HookHealthState::Effective,
            canary: CanaryStatus::Passed,
            detail: format!(
                "canary verified for dialect `{}` (class={:?})",
                manifest.hook.dialect, attempt.action_class
            ),
        },
        Err(err) => HookCanaryReport {
            agent_id: manifest.id.clone(),
            health: HookHealthState::CanaryFailed,
            canary: CanaryStatus::ProbeRejected,
            detail: err,
        },
    }
}
