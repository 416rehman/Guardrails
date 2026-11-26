// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

#[cfg(target_os = "linux")]
use std::ffi::CString;
#[cfg(target_os = "linux")]
use std::os::unix::ffi::OsStrExt;
#[cfg(target_os = "linux")]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
#[cfg(target_os = "linux")]
use std::process::Command;

use crate::SandboxError;
use crate::linux::BpfFilterInsn;
use crate::policy::{OsContainmentSpec, check_deny_paths_against_allowed, paths_overlap};

#[cfg(target_os = "linux")]
const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
#[cfg(target_os = "linux")]
const LANDLOCK_RULE_PATH_BENEATH: u32 = 1;
pub const LANDLOCK_ACCESS_FS_EXECUTE: u64 = 1 << 0;
pub const LANDLOCK_ACCESS_FS_WRITE_FILE: u64 = 1 << 1;
pub const LANDLOCK_ACCESS_FS_READ_FILE: u64 = 1 << 2;
pub const LANDLOCK_ACCESS_FS_READ_DIR: u64 = 1 << 3;
pub const LANDLOCK_ACCESS_FS_REMOVE_DIR: u64 = 1 << 4;
pub const LANDLOCK_ACCESS_FS_REMOVE_FILE: u64 = 1 << 5;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_CHAR: u64 = 1 << 6;
pub const LANDLOCK_ACCESS_FS_MAKE_DIR: u64 = 1 << 7;
pub const LANDLOCK_ACCESS_FS_MAKE_REG: u64 = 1 << 8;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_SOCK: u64 = 1 << 9;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_FIFO: u64 = 1 << 10;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_MAKE_BLOCK: u64 = 1 << 11;
pub const LANDLOCK_ACCESS_FS_MAKE_SYM: u64 = 1 << 12;
#[cfg(target_os = "linux")]
const LANDLOCK_ACCESS_FS_REFER: u64 = 1 << 13;
pub const LANDLOCK_ACCESS_FS_TRUNCATE: u64 = 1 << 14;
pub const LANDLOCK_FILE_ONLY_MASK: u64 = LANDLOCK_ACCESS_FS_EXECUTE
    | LANDLOCK_ACCESS_FS_WRITE_FILE
    | LANDLOCK_ACCESS_FS_READ_FILE
    | LANDLOCK_ACCESS_FS_TRUNCATE;

#[cfg(target_os = "linux")]
#[repr(C)]
struct LandlockRulesetAttr {
    handled_access_fs: u64,
}

#[cfg(target_os = "linux")]
#[repr(C, packed)]
struct LandlockPathBeneathAttr {
    allowed_access: u64,
    parent_fd: libc::c_int,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PlannedLandlockRule {
    pub path: PathBuf,
    pub access: u64,
    pub nofollow: bool,
    pub required: bool,
}

#[cfg(target_os = "linux")]
pub struct LandlockEntry {
    pub c_path: CString,
    pub access: u64,
    pub nofollow: bool,
    pub required: bool,
}

#[cfg(not(target_os = "linux"))]
pub struct LandlockEntry;

#[cfg(target_os = "linux")]
pub struct SeccompPipeGuard {
    read_fd: libc::c_int,
}

#[cfg(not(target_os = "linux"))]
pub struct SeccompPipeGuard;

#[cfg(target_os = "linux")]
impl Drop for SeccompPipeGuard {
    #[allow(unsafe_code, reason = "close inherited bwrap seccomp pipe descriptor")]
    fn drop(&mut self) {
        if self.read_fd >= 0 {
            // SAFETY: read_fd is an owned open pipe descriptor created by create_bwrap_seccomp_pipe.
            unsafe {
                libc::close(self.read_fd);
            }
        }
    }
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code, reason = "query Linux Landlock ABI version via syscall")]
pub fn probe_landlock_abi() -> Option<u32> {
    // SAFETY: passing null attr with LANDLOCK_CREATE_RULESET_VERSION queries only ABI version.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            0 as libc::c_long,
            0 as libc::c_long,
            libc::c_long::from(LANDLOCK_CREATE_RULESET_VERSION),
        )
    };
    if rc >= 1 {
        u32::try_from(rc).ok()
    } else {
        None
    }
}

#[cfg(not(target_os = "linux"))]
pub fn probe_landlock_abi() -> Option<u32> {
    None
}

fn push_rule(
    rules: &mut Vec<PlannedLandlockRule>,
    path: PathBuf,
    access: u64,
    nofollow: bool,
    required: bool,
) {
    rules.push(PlannedLandlockRule {
        path,
        access,
        nofollow,
        required,
    });
}

pub fn plan_landlock_rules(
    spec: &OsContainmentSpec,
) -> Result<Vec<PlannedLandlockRule>, SandboxError> {
    let ro_access =
        LANDLOCK_ACCESS_FS_EXECUTE | LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_READ_DIR;
    let rw_access = ro_access
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SYM
        | LANDLOCK_ACCESS_FS_TRUNCATE;

    let mut rules = Vec::new();
    for sys_ro in ["/usr", "/bin", "/lib", "/lib64", "/proc"] {
        let p = Path::new(sys_ro);
        if let Some(deny) = spec.deny_paths.iter().find(|d| paths_overlap(p, d)) {
            return Err(SandboxError::InvalidPolicy(format!(
                "landlock: deny_path `{}` overlaps required system RO directory `{sys_ro}`",
                deny.display()
            )));
        }
        push_rule(&mut rules, p.to_path_buf(), ro_access, false, false);
    }

    let etc_path = Path::new("/etc");
    if spec.deny_paths.iter().any(|d| paths_overlap(etc_path, d)) {
        for sub in [
            "/etc/ld.so.cache",
            "/etc/ssl",
            "/etc/ca-certificates",
            "/etc/resolv.conf",
            "/etc/hosts",
        ] {
            let p = Path::new(sub);
            if !spec.deny_paths.iter().any(|d| paths_overlap(p, d)) {
                push_rule(&mut rules, p.to_path_buf(), ro_access, false, false);
            }
        }
    } else {
        push_rule(&mut rules, etc_path.to_path_buf(), ro_access, false, false);
    }

    let dev_null = Path::new("/dev/null");
    if spec.deny_paths.iter().any(|d| paths_overlap(dev_null, d)) {
        return Err(SandboxError::InvalidPolicy(
            "landlock: deny_paths cannot block /dev/null".into(),
        ));
    }
    push_rule(
        &mut rules,
        dev_null.to_path_buf(),
        LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE,
        false,
        false,
    );

    let mut user_allowed: Vec<&Path> = Vec::new();
    for ro in &spec.read_only_paths {
        user_allowed.push(ro.as_path());
        push_rule(&mut rules, ro.clone(), ro_access, true, true);
    }
    if let Some(dir) = &spec.workdir {
        user_allowed.push(dir.as_path());
        push_rule(&mut rules, dir.clone(), rw_access, true, true);
    }
    for rw in &spec.writable_paths {
        user_allowed.push(rw.as_path());
        push_rule(&mut rules, rw.clone(), rw_access, true, true);
    }
    check_deny_paths_against_allowed(&spec.deny_paths, &user_allowed, "landlock")?;

    Ok(rules)
}

#[cfg(target_os = "linux")]
pub fn collect_landlock_c_paths(
    spec: &OsContainmentSpec,
) -> Result<Vec<LandlockEntry>, SandboxError> {
    let planned = plan_landlock_rules(spec)?;
    let mut entries = Vec::with_capacity(planned.len());
    for item in planned {
        let c_path = CString::new(item.path.as_os_str().as_bytes()).map_err(|_| {
            SandboxError::InvalidPolicy(format!(
                "landlock path contains NUL byte: `{}`",
                item.path.display()
            ))
        })?;
        entries.push(LandlockEntry {
            c_path,
            access: item.access,
            nofollow: item.nofollow,
            required: item.required,
        });
    }
    Ok(entries)
}

#[cfg(not(target_os = "linux"))]
pub fn collect_landlock_c_paths(
    spec: &OsContainmentSpec,
) -> Result<Vec<LandlockEntry>, SandboxError> {
    let _ = plan_landlock_rules(spec)?;
    Ok(Vec::new())
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "create pipe carrying seccomp-BPF filter bytes for bwrap --seccomp fd"
)]
pub fn create_bwrap_seccomp_pipe(
    insns: &[BpfFilterInsn],
) -> Result<(SeccompPipeGuard, libc::c_int), SandboxError> {
    let mut raw_bytes = Vec::with_capacity(insns.len().saturating_mul(8));
    for insn in insns {
        raw_bytes.extend_from_slice(&insn.code.to_ne_bytes());
        raw_bytes.push(insn.jt);
        raw_bytes.push(insn.jf);
        raw_bytes.extend_from_slice(&insn.k.to_ne_bytes());
    }
    let mut fds: [libc::c_int; 2] = [-1, -1];
    // SAFETY: fds points to stack array of two c_int initialized atomically with O_CLOEXEC by pipe2(2).
    if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
        return Err(SandboxError::ContainmentSetup(format!(
            "pipe2() failed for bwrap seccomp: {}",
            std::io::Error::last_os_error()
        )));
    }
    let [read_fd, write_fd] = fds;
    let mut written = 0usize;
    while let Some(rem) = raw_bytes.get(written..) {
        if rem.is_empty() {
            break;
        }
        // SAFETY: write_fd is an open pipe write end and rem points to valid initialized filter bytes.
        let n = unsafe { libc::write(write_fd, rem.as_ptr().cast::<libc::c_void>(), rem.len()) };
        if n < 0 {
            let err = std::io::Error::last_os_error();
            if err.kind() == std::io::ErrorKind::Interrupted {
                continue;
            }
            // SAFETY: close both pipe ends before propagating write error.
            unsafe {
                libc::close(write_fd);
                libc::close(read_fd);
            }
            return Err(SandboxError::ContainmentSetup(format!(
                "write() seccomp pipe failed: {err}"
            )));
        }
        written = written.saturating_add(usize::try_from(n).unwrap_or(0));
    }
    // SAFETY: close write_fd so bwrap sees EOF after reading full BPF program.
    unsafe {
        libc::close(write_fd);
    }
    Ok((SeccompPipeGuard { read_fd }, read_fd))
}

#[cfg(not(target_os = "linux"))]
pub fn create_bwrap_seccomp_pipe(
    _insns: &[BpfFilterInsn],
) -> Result<(SeccompPipeGuard, i32), SandboxError> {
    let _ = BpfFilterInsn {
        code: 0,
        jt: 0,
        jf: 0,
        k: 0,
    };
    Err(SandboxError::ContainmentSetup(
        "bwrap seccomp pipe unavailable on non-Linux target".into(),
    ))
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "register fork pre_exec hook applying PR_SET_NO_NEW_PRIVS, FD_CLOEXEC clearing for bwrap seccomp pipe, Landlock, and seccomp-BPF before child exec"
)]
pub fn install_linux_pre_exec(
    cmd: &mut Command,
    no_new_privs: bool,
    landlock_abi: Option<u32>,
    landlock_entries: Vec<LandlockEntry>,
    seccomp_insns: Option<Vec<BpfFilterInsn>>,
    bwrap_seccomp_fd: Option<libc::c_int>,
) -> Result<(), SandboxError> {
    let sock_filters: Option<Vec<libc::sock_filter>> = seccomp_insns.map(|insns| {
        insns
            .into_iter()
            .map(|i| libc::sock_filter {
                code: i.code,
                jt: i.jt,
                jf: i.jf,
                k: i.k,
            })
            .collect()
    });

    // SAFETY: closure runs post-fork pre-exec in child; all allocations occur pre-fork and only async-signal-safe syscalls run inside.
    unsafe {
        cmd.pre_exec(move || {
            if let Some(fd) = bwrap_seccomp_fd {
                // SAFETY: fd is the child copy of the O_CLOEXEC seccomp pipe read end; clearing FD_CLOEXEC inside this forked child avoids FD leaks in parent sibling threads.
                let fcntl_rc = unsafe { libc::fcntl(fd, libc::F_SETFD, 0) };
                if fcntl_rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if no_new_privs {
                // SAFETY: PR_SET_NO_NEW_PRIVS takes fixed integer constants (1, 0, 0, 0) and enables no_new_privs.
                let rc = unsafe {
                    libc::prctl(
                        libc::PR_SET_NO_NEW_PRIVS,
                        1 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                };
                if rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            if let Some(abi) = landlock_abi
                && !landlock_entries.is_empty()
            {
                apply_landlock_pre_exec(abi, &landlock_entries)?;
            }
            if let Some(filters) = &sock_filters {
                let len = u16::try_from(filters.len())
                    .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;
                let prog = libc::sock_fprog {
                    len,
                    filter: filters.as_ptr().cast_mut(),
                };
                // SAFETY: PR_SET_SECCOMP with SECCOMP_MODE_FILTER passes valid stack sock_fprog while PR_SET_NO_NEW_PRIVS is active.
                let sec_rc = unsafe {
                    libc::prctl(
                        libc::PR_SET_SECCOMP,
                        libc::SECCOMP_MODE_FILTER as libc::c_ulong,
                        (&raw const prog) as usize as libc::c_ulong,
                        0 as libc::c_ulong,
                        0 as libc::c_ulong,
                    )
                };
                if sec_rc != 0 {
                    return Err(std::io::Error::last_os_error());
                }
            }
            Ok(())
        });
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
pub fn install_linux_pre_exec(
    _cmd: &mut std::process::Command,
    _no_new_privs: bool,
    _landlock_abi: Option<u32>,
    _landlock_entries: Vec<LandlockEntry>,
    _seccomp_insns: Option<Vec<BpfFilterInsn>>,
    _bwrap_seccomp_fd: Option<i32>,
) -> Result<(), SandboxError> {
    Err(SandboxError::ContainmentSetup(
        "Linux pre_exec unavailable on non-Linux target".into(),
    ))
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "create and enforce Landlock ruleset inside child pre_exec hook"
)]
fn apply_landlock_pre_exec(abi: u32, entries: &[LandlockEntry]) -> std::io::Result<()> {
    let mut handled_fs = LANDLOCK_ACCESS_FS_EXECUTE
        | LANDLOCK_ACCESS_FS_WRITE_FILE
        | LANDLOCK_ACCESS_FS_READ_FILE
        | LANDLOCK_ACCESS_FS_READ_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_DIR
        | LANDLOCK_ACCESS_FS_REMOVE_FILE
        | LANDLOCK_ACCESS_FS_MAKE_CHAR
        | LANDLOCK_ACCESS_FS_MAKE_DIR
        | LANDLOCK_ACCESS_FS_MAKE_REG
        | LANDLOCK_ACCESS_FS_MAKE_SOCK
        | LANDLOCK_ACCESS_FS_MAKE_FIFO
        | LANDLOCK_ACCESS_FS_MAKE_BLOCK
        | LANDLOCK_ACCESS_FS_MAKE_SYM;
    if abi >= 2 {
        handled_fs |= LANDLOCK_ACCESS_FS_REFER;
    }
    if abi >= 3 {
        handled_fs |= LANDLOCK_ACCESS_FS_TRUNCATE;
    }
    let attr = LandlockRulesetAttr {
        handled_access_fs: handled_fs,
    };
    // SAFETY: attr points to a stack LandlockRulesetAttr matching kernel ABI size.
    let ruleset_fd = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            (&raw const attr) as usize as libc::c_long,
            core::mem::size_of::<LandlockRulesetAttr>() as libc::c_long,
            0 as libc::c_long,
        )
    };
    if ruleset_fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let ruleset_c_fd = libc::c_int::try_from(ruleset_fd)
        .map_err(|_| std::io::Error::from_raw_os_error(libc::EINVAL))?;

    for entry in entries {
        let mut open_flags = libc::O_PATH | libc::O_CLOEXEC;
        if entry.nofollow {
            open_flags |= libc::O_NOFOLLOW;
        }
        // SAFETY: c_path is a pre-allocated nul-terminated CString.
        let fd = unsafe { libc::open(entry.c_path.as_ptr(), open_flags) };
        if fd < 0 {
            if entry.required {
                // SAFETY: ruleset_c_fd is owned by this function.
                unsafe {
                    libc::close(ruleset_c_fd);
                }
                return Err(std::io::Error::last_os_error());
            }
            continue;
        }
        // SAFETY: libc::stat is POD and zeroed memory is overwritten by fstat(fd).
        let mut st: libc::stat = unsafe { core::mem::zeroed() };
        // SAFETY: fd is an open path descriptor and st is a valid writable stack struct.
        let stat_rc = unsafe { libc::fstat(fd, &raw mut st) };
        if stat_rc < 0 {
            // SAFETY: close fd and ruleset_c_fd before propagating fstat error.
            unsafe {
                libc::close(fd);
                libc::close(ruleset_c_fd);
            }
            return Err(std::io::Error::last_os_error());
        }
        let is_dir = (st.st_mode & libc::S_IFMT) == libc::S_IFDIR;
        let allowed = if is_dir {
            entry.access & handled_fs
        } else {
            entry.access & handled_fs & LANDLOCK_FILE_ONLY_MASK
        };
        if allowed == 0 {
            // SAFETY: fd is owned open descriptor with zero applicable rights.
            unsafe {
                libc::close(fd);
            }
            continue;
        }
        let rule_attr = LandlockPathBeneathAttr {
            allowed_access: allowed,
            parent_fd: fd,
        };
        // SAFETY: ruleset_c_fd and rule_attr refer to valid open descriptors.
        let rc = unsafe {
            libc::syscall(
                libc::SYS_landlock_add_rule,
                libc::c_long::from(ruleset_c_fd),
                libc::c_long::from(LANDLOCK_RULE_PATH_BENEATH),
                (&raw const rule_attr) as usize as libc::c_long,
                0 as libc::c_long,
            )
        };
        // SAFETY: fd was opened directly above and closed immediately.
        unsafe {
            libc::close(fd);
        }
        if rc < 0 {
            // SAFETY: ruleset_c_fd is owned by this function.
            unsafe {
                libc::close(ruleset_c_fd);
            }
            return Err(std::io::Error::last_os_error());
        }
    }

    // SAFETY: ruleset_c_fd is valid and PR_SET_NO_NEW_PRIVS is already active.
    let restrict_rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_restrict_self,
            libc::c_long::from(ruleset_c_fd),
            0 as libc::c_long,
        )
    };
    // SAFETY: ruleset_c_fd is unconditionally closed after restrict_self.
    unsafe {
        libc::close(ruleset_c_fd);
    }
    if restrict_rc < 0 {
        return Err(std::io::Error::last_os_error());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ContainmentMode;
    use crate::policy::{LinuxNamespaceMode, PrivilegePolicy, WindowsTokenMode};

    fn sample_linux_spec(workdir: PathBuf, deny_paths: Vec<PathBuf>) -> OsContainmentSpec {
        OsContainmentSpec {
            session_id: "sess-ll".into(),
            agent_name: "agent".into(),
            mode: ContainmentMode::WorkspaceContained,
            workdir: Some(workdir),
            writable_paths: Vec::new(),
            read_only_paths: Vec::new(),
            deny_paths,
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
            unshare_network: true,
            macos_seatbelt_sbpl: None,
            windows_sandbox_sid: None,
            windows_token: WindowsTokenMode::Restricted,
        }
    }

    #[test]
    fn landlock_plan_sets_file_only_access_on_dev_null_and_rejects_deny_overlap() {
        let workdir = std::env::temp_dir().join(format!("grdr-ll-plan-{}", std::process::id()));
        let spec = sample_linux_spec(workdir.clone(), Vec::new());
        let rules = plan_landlock_rules(&spec).unwrap();
        let dev_null = rules
            .iter()
            .find(|r| r.path == Path::new("/dev/null"))
            .unwrap();
        assert_eq!(dev_null.access & LANDLOCK_ACCESS_FS_READ_DIR, 0);
        assert_eq!(
            dev_null.access,
            LANDLOCK_ACCESS_FS_READ_FILE | LANDLOCK_ACCESS_FS_WRITE_FILE
        );
        let wd_rule = rules.iter().find(|r| r.path == workdir).unwrap();
        assert!(wd_rule.nofollow);
        assert!(wd_rule.required);

        let overlap = sample_linux_spec(workdir.clone(), vec![workdir.join(".env")]);
        assert!(matches!(
            plan_landlock_rules(&overlap),
            Err(SandboxError::InvalidPolicy(_))
        ));

        let etc_deny = sample_linux_spec(workdir, vec![PathBuf::from("/etc/shadow")]);
        let etc_rules = plan_landlock_rules(&etc_deny).unwrap();
        assert!(!etc_rules.iter().any(|r| r.path == Path::new("/etc")));
        assert!(etc_rules.iter().any(|r| r.path == Path::new("/etc/ssl")));
    }
}
