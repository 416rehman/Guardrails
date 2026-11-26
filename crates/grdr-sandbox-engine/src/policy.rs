// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::path::{Component, Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::{ContainmentMode, SandboxError, SandboxReport, is_sensitive_env_key};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LinuxNamespaceMode {
    Direct,
    Bubblewrap,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsTokenMode {
    Restricted,
    StandardJobOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PrivilegePolicy {
    DropAll,
    Preserve,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnforcedMechanism {
    EnvSanitized,
    WorkdirScoped,
    NoNewPrivs,
    LandlockRuleset,
    SeccompBpfFilter,
    CgroupV2Limits,
    BubblewrapNamespace,
    WindowsJobObject,
    WindowsRestrictedToken,
    WindowsMitigationPolicy,
    MacOsSeatbelt,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OsContainmentSpec {
    pub session_id: String,
    pub agent_name: String,
    pub mode: ContainmentMode,
    pub workdir: Option<PathBuf>,
    pub writable_paths: Vec<PathBuf>,
    pub read_only_paths: Vec<PathBuf>,
    pub deny_paths: Vec<PathBuf>,
    pub extra_allow_env: Vec<String>,
    pub strip_secret_env: bool,
    pub extra_env: Vec<(String, String)>,
    pub memory_limit_bytes: u64,
    pub active_process_limit: u32,
    pub privilege: PrivilegePolicy,
    pub linux_namespace: LinuxNamespaceMode,
    pub cgroup_dir: Option<PathBuf>,
    pub seccomp_denied_syscalls: Vec<String>,
    pub max_seccomp_rules: usize,
    pub unshare_network: bool,
    pub macos_seatbelt_sbpl: Option<String>,
    pub windows_sandbox_sid: Option<String>,
    pub windows_token: WindowsTokenMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SandboxExecutionReport {
    pub exit_code: i32,
    pub success: bool,
    pub sandbox_report: SandboxReport,
    pub enforced_mechanisms: Vec<EnforcedMechanism>,
    pub warnings: Vec<String>,
}

pub fn build_filtered_env(
    spec: &OsContainmentSpec,
    inherited_env: &[(String, String)],
) -> (Vec<(String, String)>, Vec<String>) {
    let mut env_out: Vec<(String, String)> = Vec::new();
    let mut stripped_env_vars: Vec<String> = Vec::new();

    if spec.mode != ContainmentMode::ObserveOnly && spec.strip_secret_env {
        for (key, val) in inherited_env {
            let explicitly_allowed = spec
                .extra_allow_env
                .iter()
                .any(|allowed| allowed.eq_ignore_ascii_case(key));
            if is_sensitive_env_key(key) && !explicitly_allowed {
                stripped_env_vars.push(key.clone());
            } else {
                env_out.push((key.clone(), val.clone()));
            }
        }
        stripped_env_vars.sort();
    } else {
        env_out.extend(inherited_env.iter().cloned());
    }

    upsert_env(&mut env_out, "GRDR_SESSION_ID", &spec.session_id);
    upsert_env(&mut env_out, "GRDR_AGENT_NAME", &spec.agent_name);
    if spec.mode != ContainmentMode::ObserveOnly {
        upsert_env(&mut env_out, "GRDR_CONTAINED", "1");
    }
    for (k, v) in &spec.extra_env {
        upsert_env(&mut env_out, k, v);
    }

    (env_out, stripped_env_vars)
}

fn upsert_env(env: &mut Vec<(String, String)>, key: &str, value: &str) {
    for (k, v) in env.iter_mut() {
        if k.eq_ignore_ascii_case(key) {
            *v = value.to_string();
            return;
        }
    }
    env.push((key.to_string(), value.to_string()));
}

pub fn normalize_lexical_or_canon(path: &Path) -> PathBuf {
    let mut stack: Vec<Component<'_>> = Vec::new();
    for comp in path.components() {
        match comp {
            Component::CurDir => {}
            Component::ParentDir => {
                if matches!(stack.last(), Some(Component::Normal(_))) {
                    let _ = stack.pop();
                } else if !matches!(
                    stack.last(),
                    Some(Component::RootDir | Component::Prefix(_))
                ) {
                    stack.push(comp);
                }
            }
            other => stack.push(other),
        }
    }
    let lexical: PathBuf = stack.into_iter().collect();
    let mut deepest_canon: Option<(PathBuf, PathBuf)> = None;
    for anc in lexical.ancestors() {
        if anc.as_os_str().is_empty() {
            continue;
        }
        if let Ok(canon) = std::fs::canonicalize(anc)
            && let Ok(rel) = lexical.strip_prefix(anc)
        {
            deepest_canon = Some((canon, rel.to_path_buf()));
            break;
        }
    }
    let combined = match deepest_canon {
        Some((canon, rel)) => {
            if rel.as_os_str().is_empty() {
                canon
            } else {
                canon.join(rel)
            }
        }
        None => lexical,
    };
    #[cfg(windows)]
    {
        let raw = combined.to_string_lossy();
        if let Some(stripped) = raw.strip_prefix("\\\\?\\") {
            return PathBuf::from(stripped.to_ascii_lowercase());
        }
        PathBuf::from(raw.to_ascii_lowercase())
    }
    #[cfg(not(windows))]
    combined
}

pub fn paths_overlap(a: &Path, b: &Path) -> bool {
    let na = normalize_lexical_or_canon(a);
    let nb = normalize_lexical_or_canon(b);
    na.starts_with(&nb) || nb.starts_with(&na)
}

pub fn check_deny_paths_against_allowed(
    deny_paths: &[PathBuf],
    allowed_paths: &[&Path],
    context: &str,
) -> Result<(), SandboxError> {
    for deny in deny_paths {
        let raw = deny.to_string_lossy();
        if raw.trim().is_empty() || raw.contains('\0') {
            return Err(SandboxError::InvalidPolicy(format!(
                "{context}: deny_paths contains empty or NUL path"
            )));
        }
        for allowed in allowed_paths {
            if paths_overlap(allowed, deny) {
                return Err(SandboxError::InvalidPolicy(format!(
                    "{context}: deny_path `{}` overlaps allowed path `{}` and cannot be subtracted safely",
                    deny.display(),
                    allowed.display()
                )));
            }
        }
    }
    Ok(())
}
