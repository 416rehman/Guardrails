// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::process::Command;

#[cfg(target_os = "macos")]
use grdr_model::AssuranceLevel;

#[cfg(target_os = "macos")]
use crate::SandboxReport;
#[cfg(target_os = "macos")]
use crate::policy::build_filtered_env;
use crate::policy::{EnforcedMechanism, OsContainmentSpec, SandboxExecutionReport};
use crate::{ContainmentMode, SandboxError};

const SEATBELT_BIN: &str = "/usr/bin/sandbox-exec";

pub fn validate_sbpl_profile(sbpl: &str) -> Result<(), SandboxError> {
    let trimmed = sbpl.trim();
    if trimmed.is_empty() || trimmed.bytes().any(|b| b == 0) {
        return Err(SandboxError::InvalidPolicy(
            "Seatbelt SBPL profile cannot be empty or contain NUL".into(),
        ));
    }
    let mut forms: Vec<String> = Vec::new();
    let mut cur = String::new();
    let mut depth: i32 = 0;
    let mut in_string = false;
    let mut in_comment = false;
    let mut escaped = false;

    for ch in trimmed.chars() {
        if in_comment {
            if ch == '\n' {
                in_comment = false;
                if depth > 0 {
                    cur.push(' ');
                }
            }
            continue;
        }
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_string => escaped = true,
            '"' => in_string = !in_string,
            ';' if !in_string => in_comment = true,
            '(' if !in_string => {
                depth = depth.saturating_add(1);
                if depth == 1 {
                    cur.clear();
                } else {
                    cur.push('(');
                }
            }
            ')' if !in_string => {
                depth = depth.saturating_sub(1);
                if depth < 0 {
                    return Err(SandboxError::InvalidPolicy(
                        "Seatbelt SBPL profile has unmatched `)`".into(),
                    ));
                }
                if depth == 0 {
                    forms.push(cur.split_whitespace().collect::<Vec<_>>().join(" "));
                    cur.clear();
                } else {
                    cur.push(')');
                }
            }
            c if !in_string && depth > 0 => cur.push(c),
            _ => {}
        }
    }
    if in_string || depth != 0 {
        return Err(SandboxError::InvalidPolicy(
            "Seatbelt SBPL profile has unbalanced strings or parentheses".into(),
        ));
    }
    if forms.first().map(String::as_str) != Some("version 1")
        || !forms.iter().any(|form| form == "deny default")
    {
        return Err(SandboxError::InvalidPolicy(
            "Seatbelt SBPL profile must declare top-level `(version 1)` and `(deny default)`"
                .into(),
        ));
    }
    if forms.iter().any(|form| form == "allow default") {
        return Err(SandboxError::InvalidPolicy(
            "Seatbelt SBPL profile cannot declare top-level `(allow default)`".into(),
        ));
    }
    Ok(())
}

pub fn build_macos_seatbelt_command(
    program: &str,
    args: &[String],
    spec: &OsContainmentSpec,
    env_pairs: &[(String, String)],
) -> Result<(Command, Vec<EnforcedMechanism>, Vec<String>), SandboxError> {
    if program.trim().is_empty() || program.contains('\0') {
        return Err(SandboxError::EmptyProgram);
    }
    let mut mechanisms = vec![EnforcedMechanism::EnvSanitized];
    let mut warnings = Vec::new();
    let mut cmd = if let Some(sbpl) = spec.macos_seatbelt_sbpl.as_deref()
        && spec.mode == ContainmentMode::WorkspaceContained
    {
        validate_sbpl_profile(sbpl)?;
        mechanisms.push(EnforcedMechanism::MacOsSeatbelt);
        let mut sb = Command::new(SEATBELT_BIN);
        sb.arg("-p").arg(sbpl).arg("--").arg(program).args(args);
        sb
    } else {
        if spec.mode == ContainmentMode::WorkspaceContained {
            warnings
                .push("macOS Seatbelt SBPL profile absent; running env/workdir isolation".into());
        }
        let mut plain = Command::new(program);
        plain.args(args);
        plain
    };

    if let Some(dir) = &spec.workdir {
        cmd.current_dir(dir);
        mechanisms.push(EnforcedMechanism::WorkdirScoped);
    }
    cmd.env_clear();
    for (k, v) in env_pairs {
        cmd.env(k, v);
    }
    Ok((cmd, mechanisms, warnings))
}

#[cfg(target_os = "macos")]
pub fn execute_macos(
    program: &str,
    args: &[String],
    spec: &OsContainmentSpec,
    inherited_env: &[(String, String)],
) -> Result<SandboxExecutionReport, SandboxError> {
    let (env_pairs, stripped_env_vars) = build_filtered_env(spec, inherited_env);
    let (mut cmd, enforced_mechanisms, warnings) =
        build_macos_seatbelt_command(program, args, spec, &env_pairs)?;
    let status = cmd
        .status()
        .map_err(|err| SandboxError::ProcessLaunch(err.to_string()))?;
    let exit_code = status.code().unwrap_or(1);
    let effective_assurance = if enforced_mechanisms.contains(&EnforcedMechanism::MacOsSeatbelt) {
        AssuranceLevel::Al3Contained
    } else if spec.mode == ContainmentMode::ObserveOnly {
        AssuranceLevel::Al1Observed
    } else {
        AssuranceLevel::Al2Guided
    };
    let workdir = spec.workdir.as_ref().map(|d| d.display().to_string());
    Ok(SandboxExecutionReport {
        exit_code,
        success: status.success(),
        sandbox_report: SandboxReport {
            mode: spec.mode,
            effective_assurance,
            stripped_env_vars,
            workdir,
            partial_reason: if effective_assurance >= AssuranceLevel::Al3Contained {
                None
            } else {
                Some("macOS launch without active Seatbelt profile".into())
            },
        },
        enforced_mechanisms,
        warnings,
    })
}

#[cfg(not(target_os = "macos"))]
pub fn execute_macos(
    _program: &str,
    _args: &[String],
    _spec: &OsContainmentSpec,
    _inherited_env: &[(String, String)],
) -> Result<SandboxExecutionReport, SandboxError> {
    Err(SandboxError::ContainmentSetup(
        "macOS Seatbelt execution attempted on non-macOS host".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{LinuxNamespaceMode, PrivilegePolicy, WindowsTokenMode};

    #[test]
    fn validates_sbpl_and_builds_sandbox_exec_command() {
        let valid = "(version 1)\n(deny default)\n(allow process-exec*)";
        assert!(validate_sbpl_profile(valid).is_ok());
        assert!(validate_sbpl_profile("(version 1)").is_err());
        assert!(validate_sbpl_profile("(version 1)\n(deny default").is_err());
        assert!(validate_sbpl_profile("(version 1)\n; (deny default)\n(allow default)").is_err());
        assert!(validate_sbpl_profile("(version 1)\n(deny default)\n(allow default)").is_err());
        assert!(
            validate_sbpl_profile("(version 1)\n(allow process* (literal \"(deny default)\"))")
                .is_err()
        );

        let spec = OsContainmentSpec {
            session_id: "sess-mac".into(),
            agent_name: "agent".into(),
            mode: ContainmentMode::WorkspaceContained,
            workdir: None,
            writable_paths: Vec::new(),
            read_only_paths: Vec::new(),
            deny_paths: Vec::new(),
            extra_allow_env: Vec::new(),
            strip_secret_env: true,
            extra_env: Vec::new(),
            memory_limit_bytes: 0,
            active_process_limit: 0,
            privilege: PrivilegePolicy::DropAll,
            linux_namespace: LinuxNamespaceMode::Direct,
            cgroup_dir: None,
            seccomp_denied_syscalls: Vec::new(),
            max_seccomp_rules: 64,
            unshare_network: false,
            macos_seatbelt_sbpl: Some(valid.into()),
            windows_sandbox_sid: None,
            windows_token: WindowsTokenMode::Restricted,
        };
        let (cmd, mechs, warnings) =
            build_macos_seatbelt_command("echo", &["hi".into()], &spec, &[]).unwrap();
        assert_eq!(cmd.get_program(), "/usr/bin/sandbox-exec");
        assert!(cmd.get_args().any(|arg| arg == "--"));
        assert!(mechs.contains(&EnforcedMechanism::MacOsSeatbelt));
        assert!(warnings.is_empty());
    }
}
