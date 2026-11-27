// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::process::ExitCode;

use serde::Serialize;

use grdr_agents::{
    HookInstallState, HookTargetKind, InstallOutcome, detect_home_dir, detect_state_dir,
    hook_status, install_hook, recorded_hook_command, uninstall_hook,
};

const CLI_API_VERSION: &str = "grdr.cli.v1alpha1";
const CLI_DEFAULT_HOOK_COMMAND: &str = "grdr-hook";
const HOOK_STATUS_TYPE: &str = "hook.status";

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
struct HookStatusEnvelope {
    api_version: &'static str,
    #[serde(rename = "type")]
    kind: &'static str,
    data: HookStatusPayload,
}

#[derive(Debug, Serialize)]
struct HookStatusPayload {
    agent: String,
    state: HookInstallState,
    installed: bool,
}

pub fn run_hook_status(agent: &str, json: bool) -> ExitCode {
    let target = match HookTargetKind::from_name(agent) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };
    let Some(home) = detect_home_dir() else {
        eprintln!("GRDR-CLI-0001: HOME or USERPROFILE environment variable is not set.");
        return ExitCode::from(2);
    };

    let fs = grdr_peer_os::OsLocalFs;
    let state_dir = detect_state_dir(&home);
    let recorded_cmd = recorded_hook_command(&target, &state_dir, &fs)
        .ok()
        .flatten();
    let hook_cmd = recorded_cmd.as_deref().unwrap_or(CLI_DEFAULT_HOOK_COMMAND);

    let report = match hook_status(target, &home, hook_cmd, &fs) {
        Ok(r) => r,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::from(2);
        }
    };

    if json {
        let payload = HookStatusEnvelope {
            api_version: CLI_API_VERSION,
            kind: HOOK_STATUS_TYPE,
            data: HookStatusPayload {
                agent: report.agent.clone(),
                state: report.state,
                installed: report.installed,
            },
        };
        match serde_json::to_string(&payload) {
            Ok(out) => println!("{out}"),
            Err(err) => {
                eprintln!("GRDR-CLI-0004: failed serializing hook status: {err}");
                return ExitCode::from(2);
            }
        }
    } else {
        let state_label = match report.state {
            HookInstallState::Effective => "effective",
            HookInstallState::NotConfigured => "not-configured",
        };
        println!(
            "Hook status for `{}`: {} (installed={}, config={})",
            report.agent,
            state_label,
            report.installed,
            report.config_path.display()
        );
    }

    if report.installed {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}

pub fn run_install_hook(agent: &str, command: &str, apply: bool) -> ExitCode {
    let target = match HookTargetKind::from_name(agent) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    let Some(home) = detect_home_dir() else {
        eprintln!("GRDR-CLI-0001: HOME or USERPROFILE environment variable is not set.");
        return ExitCode::FAILURE;
    };

    match install_hook(target, &home, command, !apply, &grdr_peer_os::OsLocalFs) {
        Ok(report) => {
            match report.outcome {
                InstallOutcome::DryRunPreview => {
                    println!(
                        "Dry run for `{}` ({}). Pass --apply to write atomically:\n{}",
                        report.agent,
                        report.config_path.display(),
                        report.preview_json
                    );
                }
                InstallOutcome::AlreadyInstalled => {
                    println!(
                        "Guardrails ADR hook already installed in {}.",
                        report.config_path.display()
                    );
                }
                InstallOutcome::Applied | InstallOutcome::Unchanged => {
                    println!(
                        "Installed Guardrails ADR hook in {} (backup journal: {}).",
                        report.config_path.display(),
                        report.journal_path.display()
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Failed installing hook: {err}");
            ExitCode::FAILURE
        }
    }
}

pub fn run_uninstall_hook(agent: &str) -> ExitCode {
    let target = match HookTargetKind::from_name(agent) {
        Ok(t) => t,
        Err(err) => {
            eprintln!("{err}");
            return ExitCode::FAILURE;
        }
    };
    let Some(home) = detect_home_dir() else {
        eprintln!("GRDR-CLI-0001: HOME or USERPROFILE environment variable is not set.");
        return ExitCode::FAILURE;
    };

    let fs = grdr_peer_os::OsLocalFs;
    let state_dir = detect_state_dir(&home);
    let fallback = if recorded_hook_command(&target, &state_dir, &fs)
        .ok()
        .flatten()
        .is_some()
    {
        None
    } else {
        Some(CLI_DEFAULT_HOOK_COMMAND)
    };

    match uninstall_hook(target, &home, fallback, &fs) {
        Ok(report) => {
            match report.outcome {
                InstallOutcome::Applied => {
                    println!(
                        "Restored {} from backup journal and removed Guardrails ADR hook.",
                        report.config_path.display()
                    );
                }
                InstallOutcome::Unchanged
                | InstallOutcome::AlreadyInstalled
                | InstallOutcome::DryRunPreview => {
                    println!(
                        "No Guardrails ADR hook found in {}.",
                        report.config_path.display()
                    );
                }
            }
            ExitCode::SUCCESS
        }
        Err(err) => {
            eprintln!("Failed uninstalling hook: {err}");
            ExitCode::FAILURE
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_agents::{install_hook_in_state_dir, uninstall_hook_in_state_dir};

    #[test]
    fn hook_status_envelope_matches_install_smoke_contract() {
        let home = std::env::temp_dir().join(format!("grdr-hook-cmd-{}", uuid::Uuid::now_v7()));
        let state_dir = home.join(".local").join("state").join("grdr");
        std::fs::create_dir_all(home.join(".claude")).unwrap();
        std::fs::write(
            home.join(".claude").join("settings.json"),
            r#"{"hooks":{"PreToolUse":[]}}"#,
        )
        .unwrap();

        let fs = grdr_peer_os::OsLocalFs;
        let before =
            grdr_agents::hook_status(HookTargetKind::ClaudeCode, &home, "grdr-hook", &fs).unwrap();
        let before_env = HookStatusEnvelope {
            api_version: CLI_API_VERSION,
            kind: HOOK_STATUS_TYPE,
            data: HookStatusPayload {
                agent: before.agent,
                state: before.state,
                installed: before.installed,
            },
        };
        let before_json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&before_env).unwrap()).unwrap();
        assert_eq!(before_json["apiVersion"], "grdr.cli.v1alpha1");
        assert_eq!(before_json["type"], "hook.status");
        assert_eq!(before_json["data"]["agent"], "claude-code");
        assert_eq!(before_json["data"]["state"], "not-configured");
        assert_eq!(before_json["data"]["installed"], false);

        install_hook_in_state_dir(
            HookTargetKind::ClaudeCode,
            &home,
            &state_dir,
            "/usr/local/bin/grdr-hook",
            false,
            &fs,
        )
        .unwrap();
        let after =
            grdr_agents::hook_status(HookTargetKind::ClaudeCode, &home, "grdr-hook", &fs).unwrap();
        let after_env = HookStatusEnvelope {
            api_version: CLI_API_VERSION,
            kind: HOOK_STATUS_TYPE,
            data: HookStatusPayload {
                agent: after.agent,
                state: after.state,
                installed: after.installed,
            },
        };
        let after_json: serde_json::Value =
            serde_json::from_str(&serde_json::to_string(&after_env).unwrap()).unwrap();
        assert_eq!(after_json["data"]["state"], "effective");
        assert_eq!(after_json["data"]["installed"], true);

        uninstall_hook_in_state_dir(HookTargetKind::ClaudeCode, &home, &state_dir, None, &fs)
            .unwrap();
        let _ = std::fs::remove_dir_all(&home);
    }
}
