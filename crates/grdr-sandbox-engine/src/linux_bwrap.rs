// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::fs;
use std::path::{Component, Path, PathBuf};

use crate::SandboxError;
use crate::policy::{
    OsContainmentSpec, check_deny_paths_against_allowed, normalize_lexical_or_canon, paths_overlap,
};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CgroupV2Plan {
    pub dir: PathBuf,
    pub memory_max_bytes: Option<u64>,
    pub pids_max: Option<u32>,
}

pub fn build_cgroup_plan(spec: &OsContainmentSpec) -> Option<CgroupV2Plan> {
    let dir = spec.cgroup_dir.as_ref()?;
    Some(CgroupV2Plan {
        dir: dir.clone(),
        memory_max_bytes: (spec.memory_limit_bytes > 0).then_some(spec.memory_limit_bytes),
        pids_max: (spec.active_process_limit > 0).then_some(spec.active_process_limit),
    })
}

pub fn validate_cgroup_v2_dir_in(dir: &Path, allowed_root: &Path) -> Result<(), SandboxError> {
    let raw = dir.to_string_lossy();
    if raw.trim().is_empty() || raw.contains('\0') {
        return Err(SandboxError::InvalidPolicy(
            "cgroup_dir cannot be empty or contain NUL".into(),
        ));
    }
    if dir.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(SandboxError::InvalidPolicy(format!(
            "cgroup_dir `{}` cannot contain `..` traversal",
            dir.display()
        )));
    }
    for anc in dir.ancestors() {
        if anc.as_os_str().is_empty() {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(anc)
            && meta.file_type().is_symlink()
        {
            return Err(SandboxError::InvalidPolicy(format!(
                "cgroup_dir `{}` contains symlink `{}`",
                dir.display(),
                anc.display()
            )));
        }
    }
    let norm_dir = normalize_lexical_or_canon(dir);
    let norm_root = normalize_lexical_or_canon(allowed_root);
    if !norm_dir.starts_with(&norm_root) || norm_dir == norm_root {
        return Err(SandboxError::InvalidPolicy(format!(
            "cgroup_dir `{}` must stay strictly inside `{}`",
            dir.display(),
            allowed_root.display()
        )));
    }
    Ok(())
}

pub fn prepare_cgroup_v2_dir(plan: &CgroupV2Plan, allowed_root: &Path) -> Result<(), SandboxError> {
    validate_cgroup_v2_dir_in(&plan.dir, allowed_root)?;
    if !plan.dir.exists() {
        fs::create_dir_all(&plan.dir).map_err(|err| {
            SandboxError::ContainmentSetup(format!(
                "create cgroup v2 dir `{}`: {err}",
                plan.dir.display()
            ))
        })?;
    }
    if let Some(mem) = plan.memory_max_bytes {
        fs::write(plan.dir.join("memory.max"), format!("{mem}\n")).map_err(|err| {
            SandboxError::ContainmentSetup(format!("write cgroup memory.max: {err}"))
        })?;
    }
    if let Some(pids) = plan.pids_max {
        fs::write(plan.dir.join("pids.max"), format!("{pids}\n")).map_err(|err| {
            SandboxError::ContainmentSetup(format!("write cgroup pids.max: {err}"))
        })?;
    }
    Ok(())
}

pub fn attach_pid_to_cgroup_v2(dir: &Path, pid: u32) -> Result<(), SandboxError> {
    fs::write(dir.join("cgroup.procs"), format!("{pid}\n"))
        .map_err(|err| SandboxError::ContainmentSetup(format!("write cgroup.procs: {err}")))
}

fn verify_no_symlink_chain(path: &Path, context: &str) -> Result<(), SandboxError> {
    if path.components().any(|c| matches!(c, Component::ParentDir)) {
        return Err(SandboxError::InvalidPolicy(format!(
            "bwrap: {context} `{}` cannot contain `..` traversal",
            path.display()
        )));
    }
    let mut cur = PathBuf::new();
    for comp in path.components() {
        cur.push(comp);
        if cur == Path::new("/") || cur.as_os_str().is_empty() {
            continue;
        }
        if let Ok(meta) = fs::symlink_metadata(&cur)
            && meta.file_type().is_symlink()
        {
            return Err(SandboxError::InvalidPolicy(format!(
                "bwrap: {context} `{}` traverses symlink component `{}`",
                path.display(),
                cur.display()
            )));
        }
    }
    Ok(())
}

pub fn build_bwrap_args(
    program: &str,
    args: &[String],
    spec: &OsContainmentSpec,
    seccomp_fd: Option<i32>,
    check_host_paths: bool,
) -> Result<Vec<String>, SandboxError> {
    if program.trim().is_empty() || program.contains('\0') {
        return Err(SandboxError::EmptyProgram);
    }
    let mut bwrap_args: Vec<String> = vec![
        "--die-with-parent".into(),
        "--unshare-pid".into(),
        "--unshare-ipc".into(),
    ];
    if spec.unshare_network || spec.mode == crate::ContainmentMode::WorkspaceContained {
        bwrap_args.push("--unshare-net".into());
    }
    if let Some(fd) = seccomp_fd {
        bwrap_args.push("--seccomp".into());
        bwrap_args.push(fd.to_string());
    }

    let sys_ro_dirs = [
        "/usr",
        "/bin",
        "/lib",
        "/lib64",
        "/etc/ld.so.cache",
        "/etc/ssl",
    ];
    let mut bound_paths: Vec<PathBuf> = Vec::new();
    for sys_ro in sys_ro_dirs {
        let p = Path::new(sys_ro);
        if spec.deny_paths.iter().any(|d| paths_overlap(p, d)) {
            return Err(SandboxError::InvalidPolicy(format!(
                "bwrap: deny_path overlaps required system bind `{sys_ro}`"
            )));
        }
        if !check_host_paths || p.exists() {
            bwrap_args.push("--ro-bind".into());
            bwrap_args.push(sys_ro.into());
            bwrap_args.push(sys_ro.into());
            bound_paths.push(p.to_path_buf());
        }
    }
    bwrap_args.extend([
        "--proc".into(),
        "/proc".into(),
        "--dev".into(),
        "/dev".into(),
    ]);

    let mut seen_ro: Vec<PathBuf> = Vec::new();
    for ro in &spec.read_only_paths {
        if check_host_paths {
            verify_no_symlink_chain(ro, "read_only_paths")?;
        }
        let norm = normalize_lexical_or_canon(ro);
        if (!check_host_paths || ro.exists()) && !seen_ro.contains(&norm) {
            let s = ro.to_string_lossy().into_owned();
            bwrap_args.extend(["--ro-bind".into(), s.clone(), s]);
            bound_paths.push(ro.clone());
            seen_ro.push(norm);
        }
    }
    let mut seen_rw: Vec<PathBuf> = Vec::new();
    if let Some(dir) = &spec.workdir {
        if check_host_paths {
            verify_no_symlink_chain(dir, "workdir")?;
        }
        let s = dir.to_string_lossy().into_owned();
        bwrap_args.extend(["--bind".into(), s.clone(), s]);
        bound_paths.push(dir.clone());
        seen_rw.push(normalize_lexical_or_canon(dir));
    }
    for rw in &spec.writable_paths {
        if check_host_paths {
            verify_no_symlink_chain(rw, "writable_paths")?;
        }
        let norm = normalize_lexical_or_canon(rw);
        if (!check_host_paths || rw.exists()) && !seen_rw.contains(&norm) {
            let s = rw.to_string_lossy().into_owned();
            bwrap_args.extend(["--bind".into(), s.clone(), s]);
            bound_paths.push(rw.clone());
            seen_rw.push(norm);
        }
    }

    let bound_refs: Vec<&Path> = bound_paths.iter().map(PathBuf::as_path).collect();
    for deny in &spec.deny_paths {
        let norm_deny = normalize_lexical_or_canon(deny);
        let strict_inside = bound_refs.iter().any(|allowed| {
            let norm_a = normalize_lexical_or_canon(allowed);
            norm_deny != norm_a && norm_deny.starts_with(&norm_a)
        });
        let reverse_or_equal = bound_refs.iter().any(|allowed| {
            let norm_a = normalize_lexical_or_canon(allowed);
            norm_a == norm_deny || norm_a.starts_with(&norm_deny)
        });
        if reverse_or_equal {
            check_deny_paths_against_allowed(std::slice::from_ref(deny), &bound_refs, "bwrap")?;
        }
        if strict_inside {
            let deny_str = deny.to_string_lossy().into_owned();
            if check_host_paths {
                verify_no_symlink_chain(deny, "deny_path")?;
                let meta = fs::symlink_metadata(deny).map_err(|_| {
                    SandboxError::InvalidPolicy(format!(
                        "bwrap: deny_path `{}` inside workspace does not exist and cannot be safely masked",
                        deny.display()
                    ))
                })?;
                if meta.file_type().is_symlink() {
                    return Err(SandboxError::InvalidPolicy(format!(
                        "bwrap: deny_path `{}` cannot be a symlink",
                        deny.display()
                    )));
                }
                if meta.is_dir() {
                    bwrap_args.extend(["--tmpfs".into(), deny_str]);
                } else {
                    bwrap_args.extend(["--ro-bind".into(), "/dev/null".into(), deny_str]);
                }
            } else {
                bwrap_args.extend(["--tmpfs".into(), deny_str]);
            }
        }
    }

    bwrap_args.push("--".into());
    bwrap_args.push(program.to_string());
    bwrap_args.extend(args.iter().cloned());
    Ok(bwrap_args)
}
