// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

#[cfg(target_os = "macos")]
#[path = "macos_sys.rs"]
mod macos_sys;

#[cfg(target_os = "macos")]
use std::ffi::CString;
#[cfg(target_os = "macos")]
use std::os::unix::fs::DirBuilderExt;
#[cfg(target_os = "macos")]
use std::os::unix::process::CommandExt;
#[cfg(target_os = "macos")]
use std::path::Path;
use std::process::Command;

#[cfg(target_os = "macos")]
use grdr_model::AssuranceLevel;

#[cfg(target_os = "macos")]
use crate::SandboxReport;
#[cfg(target_os = "macos")]
use crate::policy::build_filtered_env;
use crate::policy::{EnforcedMechanism, OsContainmentSpec, SandboxExecutionReport};
use crate::{ContainmentMode, SandboxError};

const FORBIDDEN_BROAD_WRITE_PATHS: &[&str] = &[
    "/",
    "/tmp",
    "/private",
    "/private/tmp",
    "/var",
    "/private/var",
    "/var/tmp",
    "/private/var/tmp",
    "/Users",
    "/etc",
    "/private/etc",
    "/System",
    "/Library",
    "/bin",
    "/sbin",
    "/usr",
    "/dev",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MacOsSandboxBackend {
    LibSystemPreExecSeatbelt,
    EnvWorkdirOnly,
}

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
            if depth > 0 {
                cur.push(ch);
            }
            continue;
        }
        match ch {
            '\\' if in_string => {
                escaped = true;
                if depth > 0 {
                    cur.push(ch);
                }
            }
            '"' => {
                in_string = !in_string;
                if depth > 0 {
                    cur.push(ch);
                }
            }
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
            c if depth > 0 => cur.push(c),
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
    for form in &forms {
        if contains_forbidden_broad_write(form) {
            return Err(SandboxError::InvalidPolicy(
                "Seatbelt SBPL profile cannot grant broad or unscoped file-write* rules".into(),
            ));
        }
    }
    Ok(())
}

pub fn select_macos_sandbox_backend(spec: &OsContainmentSpec) -> MacOsSandboxBackend {
    if spec.mode == ContainmentMode::WorkspaceContained && spec.macos_seatbelt_sbpl.is_some() {
        MacOsSandboxBackend::LibSystemPreExecSeatbelt
    } else {
        MacOsSandboxBackend::EnvWorkdirOnly
    }
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
    let mut cmd = Command::new(program);
    cmd.args(args);

    if let Some(sbpl) = spec.macos_seatbelt_sbpl.as_deref()
        && spec.mode == ContainmentMode::WorkspaceContained
    {
        validate_sbpl_profile(sbpl)?;
        mechanisms.push(EnforcedMechanism::MacOsSeatbelt);
        #[cfg(target_os = "macos")]
        {
            let c_sbpl = CString::new(sbpl).map_err(|_| {
                SandboxError::InvalidPolicy(
                    "Seatbelt SBPL profile contains interior NUL byte".into(),
                )
            })?;
            #[allow(
                unsafe_code,
                reason = "Attach async-signal-safe pre_exec Seatbelt initialization hook before child exec."
            )]
            // SAFETY: c_sbpl is allocated prior to fork; apply_seatbelt_in_pre_exec performs zero heap allocations or locks in the child process.
            unsafe {
                cmd.pre_exec(move || macos_sys::apply_seatbelt_in_pre_exec(&c_sbpl));
            }
        }
    } else if spec.mode == ContainmentMode::WorkspaceContained {
        warnings.push("macOS Seatbelt SBPL profile absent; running env/workdir isolation".into());
    }

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
    if spec.mode == ContainmentMode::WorkspaceContained && spec.macos_seatbelt_sbpl.is_some() {
        ensure_scoped_tmpdir_from_env(&env_pairs)?;
    }
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

#[cfg(target_os = "macos")]
fn ensure_scoped_tmpdir_from_env(env_pairs: &[(String, String)]) -> Result<(), SandboxError> {
    let Some((_, tmpdir)) = env_pairs.iter().find(|(k, _)| k == "TMPDIR") else {
        return Ok(());
    };
    let trimmed = tmpdir.trim();
    if trimmed.is_empty()
        || trimmed.contains('\0')
        || !trimmed.starts_with('/')
        || trimmed.split('/').any(|seg| seg == "..")
    {
        return Err(SandboxError::InvalidPolicy(
            "TMPDIR must be an absolute canonical scoped path".into(),
        ));
    }
    let target = Path::new(trimmed);
    for anc in target.ancestors() {
        if anc.as_os_str().is_empty() {
            continue;
        }
        if let Ok(meta) = std::fs::symlink_metadata(anc)
            && meta.file_type().is_symlink()
        {
            return Err(SandboxError::ContainmentSetup(format!(
                "refusing symlink component `{}` in macOS TMPDIR",
                anc.display()
            )));
        }
    }
    let mut builder = std::fs::DirBuilder::new();
    builder.recursive(true).mode(0o700);
    builder.create(target).map_err(|err| {
        SandboxError::ContainmentSetup(format!(
            "failed creating scoped macOS TMPDIR `{}`: {err}",
            target.display()
        ))
    })
}

fn contains_forbidden_broad_write(normalized_form: &str) -> bool {
    let Some(rest) = normalized_form.strip_prefix("allow ") else {
        return false;
    };
    let rest_trim = rest.trim_start();
    let (top_ops, first_paren_idx) = extract_top_level_ops(rest_trim);
    let has_write_op = top_ops
        .iter()
        .any(|op| *op == "file*" || op.starts_with("file-write"));
    if !has_write_op {
        return false;
    }

    let Some(tail_start) = first_paren_idx else {
        return true;
    };
    let Some((_, raw_tail)) = rest_trim.split_at_checked(tail_start) else {
        return true;
    };
    let tail = raw_tail.trim_start();
    if tail.contains("regex ") || tail.contains("regex\"") || tail.contains("path-regex") {
        return true;
    }

    let literals = extract_quoted_literals(tail);
    if literals.is_empty() {
        return true;
    }
    for lit in literals {
        if lit.split('/').any(|seg| seg == ".." || seg == ".") {
            return true;
        }
        let norm = if lit == "/" {
            lit.as_str()
        } else {
            lit.trim_end_matches('/')
        };
        if FORBIDDEN_BROAD_WRITE_PATHS.contains(&norm) {
            return true;
        }
    }
    false
}

fn extract_top_level_ops(rest_trim: &str) -> (Vec<&str>, Option<usize>) {
    let mut ops = Vec::new();
    let mut depth: i32 = 0;
    let mut in_str = false;
    let mut escaped = false;
    let mut first_paren = None;
    let mut tok_start: Option<usize> = None;

    for (idx, ch) in rest_trim.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && in_str {
            escaped = true;
            continue;
        }
        if ch == '"' {
            in_str = !in_str;
            continue;
        }
        if in_str {
            continue;
        }
        if ch == '(' {
            if let Some(start) = tok_start.take()
                && let Some(op) = rest_trim.get(start..idx)
            {
                ops.push(op);
            }
            if first_paren.is_none() {
                first_paren = Some(idx);
            }
            depth = depth.saturating_add(1);
        } else if ch == ')' {
            depth = depth.saturating_sub(1);
        } else if depth == 0 {
            if ch.is_whitespace() {
                if let Some(start) = tok_start.take()
                    && let Some(op) = rest_trim.get(start..idx)
                {
                    ops.push(op);
                }
            } else if tok_start.is_none() {
                tok_start = Some(idx);
            }
        }
    }
    if let Some(start) = tok_start
        && let Some(op) = rest_trim.get(start..)
    {
        ops.push(op);
    }
    (ops, first_paren)
}

fn extract_quoted_literals(input: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut in_str = false;
    let mut escaped = false;
    let mut cur = String::new();
    for ch in input.chars() {
        if escaped {
            cur.push(ch);
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_str => escaped = true,
            '"' => {
                if in_str {
                    out.push(std::mem::take(&mut cur));
                }
                in_str = !in_str;
            }
            c if in_str => cur.push(c),
            _ => {}
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::policy::{LinuxNamespaceMode, PrivilegePolicy, WindowsTokenMode};

    #[test]
    fn validates_sbpl_and_builds_pre_exec_seatbelt_command() {
        let valid = "(version 1)\n(deny default)\n(allow process-exec*)\n(allow file-write* (literal \"/dev/null\"))\n(allow file-write* (subpath \"/private/var/tmp/grdr-sessions/s1/tmp\"))";
        assert!(validate_sbpl_profile(valid).is_ok());
        assert!(validate_sbpl_profile("(version 1)").is_err());
        assert!(validate_sbpl_profile("(version 1)\n(deny default").is_err());
        assert!(validate_sbpl_profile("(version 1)\n; (deny default)\n(allow default)").is_err());
        assert!(validate_sbpl_profile("(version 1)\n(deny default)\n(allow default)").is_err());
        assert!(
            validate_sbpl_profile("(version 1)\n(allow process* (literal \"(deny default)\"))")
                .is_err()
        );
        for bad in [
            "(version 1)\n(deny default)\n(allow file-write*)",
            "(version 1)\n(deny default)\n(allow file*)",
            "(version 1)\n(deny default)\n(allow file* (subpath \"/tmp/\"))",
            "(version 1)\n(deny default)\n(allow file-write-data (subpath \"/private/tmp\"))",
            "(version 1)\n(deny default)\n(allow file-write* (subpath \"/tmp\"))",
            "(version 1)\n(deny default)\n(allow file-write* (subpath \"/Users\"))",
            "(version 1)\n(deny default)\n(allow file-write* (subpath \"/var/tmp/\"))",
            "(version 1)\n(deny default)\n(allow file-write* (regex \"^/tmp\"))",
            "(version 1)\n(deny default)\n(allow file-write*(subpath \"/tmp\"))",
            "(version 1)\n(deny default)\n(allow file-read* file-write* (subpath \"/tmp\"))",
            "(version 1)\n(deny default)\n(allow file-read-data file-write-data (subpath \"/Users\"))",
            "(version 1)\n(deny default)\n(allow file-read* (subpath \"/usr\") file-write*)",
        ] {
            assert!(
                validate_sbpl_profile(bad).is_err(),
                "expected rejection for `{bad}`"
            );
        }

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
        assert_eq!(
            select_macos_sandbox_backend(&spec),
            MacOsSandboxBackend::LibSystemPreExecSeatbelt
        );
        let env = vec![("PATH".into(), "/usr/bin:/bin".into())];
        let (_cmd, mechanisms, warnings) =
            build_macos_seatbelt_command("/bin/echo", &["ok".into()], &spec, &env)
                .expect("command builds cleanly");
        assert!(mechanisms.contains(&EnforcedMechanism::MacOsSeatbelt));
        assert!(warnings.is_empty());
    }
}
