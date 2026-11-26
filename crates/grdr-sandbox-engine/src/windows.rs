// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

#[cfg(windows)]
use std::ffi::OsStr;
#[cfg(windows)]
use std::os::windows::ffi::OsStrExt;

#[cfg(windows)]
use std::path::{Path, PathBuf};

#[cfg(windows)]
use grdr_model::AssuranceLevel;

use crate::SandboxError;
#[cfg(windows)]
use crate::policy::{EnforcedMechanism, build_filtered_env, check_deny_paths_against_allowed};
use crate::policy::{OsContainmentSpec, SandboxExecutionReport};
#[cfg(windows)]
use crate::windows_sys_rt::launch_and_wait_windows_contained;
#[cfg(windows)]
use crate::{ContainmentMode, SandboxReport};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WindowsJobPlan {
    pub kill_on_job_close: bool,
    pub memory_limit_bytes: u64,
    pub active_process_limit: u32,
}

pub fn quote_win_arg(arg: &str) -> String {
    if !arg.is_empty() && !arg.chars().any(|c| c == ' ' || c == '\t' || c == '"') {
        return arg.to_string();
    }
    let mut out = String::from("\"");
    let mut backslashes = 0usize;
    for ch in arg.chars() {
        if ch == '\\' {
            backslashes = backslashes.saturating_add(1);
        } else if ch == '"' {
            for _ in 0..backslashes.saturating_mul(2).saturating_add(1) {
                out.push('\\');
            }
            backslashes = 0;
            out.push('"');
        } else {
            for _ in 0..backslashes {
                out.push('\\');
            }
            backslashes = 0;
            out.push(ch);
        }
    }
    for _ in 0..backslashes.saturating_mul(2) {
        out.push('\\');
    }
    out.push('"');
    out
}

pub fn build_windows_command_line_utf16(
    program: &str,
    args: &[String],
) -> Result<Vec<u16>, SandboxError> {
    if program.trim().is_empty() || program.contains('\0') {
        return Err(SandboxError::EmptyProgram);
    }
    let mut parts = vec![quote_win_arg(program)];
    for arg in args {
        if arg.contains('\0') {
            return Err(SandboxError::InvalidPolicy(
                "command argument contains NUL".into(),
            ));
        }
        parts.push(quote_win_arg(arg));
    }
    let joined = parts.join(" ");
    let mut utf16: Vec<u16> = joined.encode_utf16().collect();
    utf16.push(0);
    Ok(utf16)
}

pub fn build_unicode_env_block_utf16(env: &[(String, String)]) -> Result<Vec<u16>, SandboxError> {
    let mut out = Vec::new();
    for (k, v) in env {
        if k.contains('\0') || k.contains('=') || v.contains('\0') {
            return Err(SandboxError::InvalidPolicy(
                "environment entry contains NUL or invalid `=` key".into(),
            ));
        }
        let line = format!("{k}={v}");
        out.extend(line.encode_utf16());
        out.push(0);
    }
    if out.is_empty() {
        out.push(0);
    }
    out.push(0);
    Ok(out)
}

#[cfg(windows)]
fn resolve_windows_app_utf16(program: &str) -> Result<Vec<u16>, SandboxError> {
    let trimmed = program.trim();
    if trimmed.is_empty() || trimmed.contains('\0') {
        return Err(SandboxError::EmptyProgram);
    }
    let direct = Path::new(trimmed);
    let candidate = if direct.components().count() > 1 || direct.is_absolute() {
        direct.is_file().then(|| direct.to_path_buf())
    } else {
        let Some(path_var) = std::env::var_os("PATH") else {
            return Err(SandboxError::ProcessLaunch(format!(
                "PATH unset while resolving Windows executable `{trimmed}`"
            )));
        };
        let exts = std::env::var("PATHEXT").unwrap_or_else(|_| ".EXE;.COM;.BAT;.CMD".into());
        let has_ext = direct.extension().is_some();
        let mut found: Option<PathBuf> = None;
        for dir in std::env::split_paths(&path_var) {
            let p = dir.join(trimmed);
            if p.is_file() {
                found = Some(p);
                break;
            }
            if !has_ext {
                for ext in exts.split(';').filter(|e| !e.trim().is_empty()) {
                    let with_ext = dir.join(format!("{trimmed}{ext}"));
                    if with_ext.is_file() {
                        found = Some(with_ext);
                        break;
                    }
                }
                if found.is_some() {
                    break;
                }
            }
        }
        found
    };
    let Some(resolved) = candidate else {
        return Err(SandboxError::ProcessLaunch(format!(
            "Windows executable `{trimmed}` not found as regular file"
        )));
    };
    let mut utf16: Vec<u16> = resolved.as_os_str().encode_wide().collect();
    utf16.push(0);
    Ok(utf16)
}

#[cfg(windows)]
pub fn execute_windows(
    program: &str,
    args: &[String],
    spec: &OsContainmentSpec,
    inherited_env: &[(String, String)],
) -> Result<SandboxExecutionReport, SandboxError> {
    if spec.mode == ContainmentMode::WorkspaceContained && !spec.deny_paths.is_empty() {
        let mut allowed: Vec<&Path> = Vec::new();
        if let Some(dir) = spec.workdir.as_deref() {
            allowed.push(dir);
        }
        for rw in &spec.writable_paths {
            allowed.push(rw.as_path());
        }
        for ro in &spec.read_only_paths {
            allowed.push(ro.as_path());
        }
        check_deny_paths_against_allowed(&spec.deny_paths, &allowed, "windows")?;
    }

    let (env_pairs, stripped_env_vars) = build_filtered_env(spec, inherited_env);
    let app_utf16 = resolve_windows_app_utf16(program)?;
    let cmd_utf16 = build_windows_command_line_utf16(program, args)?;
    let env_utf16 = build_unicode_env_block_utf16(&env_pairs)?;
    let workdir_utf16 = spec.workdir.as_deref().map(|dir| {
        let mut w: Vec<u16> = OsStr::new(dir).encode_wide().collect();
        w.push(0);
        w
    });

    let (exit_code, mut mechanisms) = launch_and_wait_windows_contained(
        app_utf16,
        cmd_utf16,
        env_utf16,
        workdir_utf16,
        spec.memory_limit_bytes,
        spec.active_process_limit,
        spec.windows_token,
    )?;

    mechanisms.push(EnforcedMechanism::EnvSanitized);
    if spec.workdir.is_some() {
        mechanisms.push(EnforcedMechanism::WorkdirScoped);
    }

    let mut warnings = Vec::new();
    let mut partial_parts = Vec::new();
    if spec.windows_sandbox_sid.is_some() {
        partial_parts.push("AppContainer SID not applied in standalone Job mode");
    }
    if !spec.deny_paths.is_empty() {
        partial_parts.push("deny_paths NTFS ACEs not isolated in standalone Job mode");
    }
    partial_parts.push("WFP network filters and Low Integrity SID not applied");
    let partial_summary = partial_parts.join("; ");

    let (effective_assurance, partial_reason) = if spec.mode == ContainmentMode::ObserveOnly {
        (
            AssuranceLevel::Al1Observed,
            Some("observe-only launch without kernel namespace".into()),
        )
    } else {
        warnings.push(partial_summary.clone());
        (AssuranceLevel::Al2Guided, Some(partial_summary))
    };

    Ok(SandboxExecutionReport {
        exit_code,
        success: exit_code == 0,
        sandbox_report: SandboxReport {
            mode: spec.mode,
            effective_assurance,
            stripped_env_vars,
            workdir: spec.workdir.as_ref().map(|d| d.display().to_string()),
            partial_reason,
        },
        enforced_mechanisms: mechanisms,
        warnings,
    })
}

#[cfg(not(windows))]
pub fn execute_windows(
    _program: &str,
    _args: &[String],
    _spec: &OsContainmentSpec,
    _inherited_env: &[(String, String)],
) -> Result<SandboxExecutionReport, SandboxError> {
    Err(SandboxError::ContainmentSetup(
        "Windows job containment attempted on non-Windows host".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(windows)]
    use crate::policy::{LinuxNamespaceMode, PrivilegePolicy, WindowsTokenMode};

    #[test]
    fn encodes_command_line_and_unicode_env_block() {
        let cmd = build_windows_command_line_utf16(
            "git",
            &["commit".into(), "-m".into(), "hello \"world\"".into()],
        )
        .unwrap();
        let decoded = String::from_utf16_lossy(&cmd);
        assert!(decoded.contains("\"hello \\\"world\\\"\"\0"));

        let empty_block = build_unicode_env_block_utf16(&[]).unwrap();
        assert_eq!(empty_block, vec![0, 0]);

        let block = build_unicode_env_block_utf16(&[
            ("PATH".into(), "C:\\Windows".into()),
            ("GRDR_CONTAINED".into(), "1".into()),
        ])
        .unwrap();
        assert!(block.ends_with(&[0, 0]));
    }

    #[cfg(windows)]
    #[test]
    fn executes_real_child_inside_job_object_and_restricted_token() {
        let workdir = std::env::temp_dir();
        let inherited: Vec<(String, String)> = std::env::vars().collect();
        let mut spec = OsContainmentSpec {
            session_id: "sess-win-job".into(),
            agent_name: "test-runner".into(),
            mode: ContainmentMode::WorkspaceContained,
            workdir: Some(workdir.clone()),
            writable_paths: Vec::new(),
            read_only_paths: Vec::new(),
            deny_paths: Vec::new(),
            extra_allow_env: Vec::new(),
            strip_secret_env: true,
            extra_env: Vec::new(),
            memory_limit_bytes: 512 * 1024 * 1024,
            active_process_limit: 8,
            privilege: PrivilegePolicy::DropAll,
            linux_namespace: LinuxNamespaceMode::Direct,
            cgroup_dir: None,
            seccomp_denied_syscalls: Vec::new(),
            max_seccomp_rules: 64,
            unshare_network: false,
            macos_seatbelt_sbpl: None,
            windows_sandbox_sid: None,
            windows_token: WindowsTokenMode::Restricted,
        };
        let mut env_with_secret = inherited.clone();
        env_with_secret.push(("GITHUB_TOKEN".into(), "secret_should_be_stripped".into()));

        let report = execute_windows(
            "C:\\Windows\\System32\\cmd.exe",
            &["/C".into(), "exit".into(), "0".into()],
            &spec,
            &env_with_secret,
        )
        .unwrap();
        assert!(report.success);
        assert_eq!(report.exit_code, 0);
        assert_eq!(
            report.sandbox_report.effective_assurance,
            AssuranceLevel::Al2Guided
        );
        assert!(report.sandbox_report.partial_reason.is_some());
        assert!(
            report
                .enforced_mechanisms
                .contains(&EnforcedMechanism::WindowsJobObject)
        );
        assert!(
            report
                .enforced_mechanisms
                .contains(&EnforcedMechanism::WindowsRestrictedToken)
        );
        assert!(
            report
                .enforced_mechanisms
                .contains(&EnforcedMechanism::WindowsMitigationPolicy)
        );
        assert!(
            report
                .sandbox_report
                .stripped_env_vars
                .contains(&"GITHUB_TOKEN".to_string())
        );

        spec.windows_token = WindowsTokenMode::StandardJobOnly;
        let fail_report = execute_windows(
            "C:\\Windows\\System32\\cmd.exe",
            &["/C".into(), "exit".into(), "7".into()],
            &spec,
            &inherited,
        )
        .unwrap();
        assert!(!fail_report.success);
        assert_eq!(fail_report.exit_code, 7);

        spec.deny_paths = vec![workdir.join("secret.env")];
        assert!(matches!(
            execute_windows(
                "C:\\Windows\\System32\\cmd.exe",
                &["/C".into(), "exit".into(), "0".into()],
                &spec,
                &inherited,
            ),
            Err(SandboxError::InvalidPolicy(_))
        ));

        spec.deny_paths.clear();
        assert!(matches!(
            execute_windows("grdr_nonexistent_binary_99999.exe", &[], &spec, &inherited),
            Err(SandboxError::ProcessLaunch(_))
        ));
    }
}
