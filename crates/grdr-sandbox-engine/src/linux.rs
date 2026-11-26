// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

#[cfg(target_os = "linux")]
use std::path::Path;

#[cfg(target_os = "linux")]
use grdr_model::AssuranceLevel;

use crate::SandboxError;
#[cfg(target_os = "linux")]
pub use crate::linux_bwrap::build_bwrap_args;
pub use crate::linux_bwrap::{
    CgroupV2Plan, attach_pid_to_cgroup_v2, build_cgroup_plan, prepare_cgroup_v2_dir,
    validate_cgroup_v2_dir_in,
};
#[cfg(target_os = "linux")]
use crate::linux_sys::{
    collect_landlock_c_paths, create_bwrap_seccomp_pipe, install_linux_pre_exec, probe_landlock_abi,
};
use crate::policy::OsContainmentSpec;
use crate::policy::SandboxExecutionReport;
#[cfg(target_os = "linux")]
use crate::policy::{EnforcedMechanism, LinuxNamespaceMode, PrivilegePolicy, build_filtered_env};
#[cfg(target_os = "linux")]
use crate::{ContainmentMode, SandboxReport};

const AUDIT_ARCH_X86_64: u32 = 0xC000_003E;
const AUDIT_ARCH_AARCH64: u32 = 0xC000_00B7;
const BPF_LD_W_ABS: u16 = 0x20;
const BPF_JMP_JEQ_K: u16 = 0x15;
const BPF_RET_K: u16 = 0x06;
const SECCOMP_RET_KILL_PROCESS_VAL: u32 = 0x8000_0000;
const SECCOMP_RET_ERRNO_EPERM: u32 = 0x0005_0001;
const SECCOMP_RET_ERRNO_ENOSYS: u32 = 0x0005_0026;
const SECCOMP_RET_ALLOW_VAL: u32 = 0x7FFF_0000;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SeccompTargetArch {
    X86_64,
    Aarch64,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct BpfFilterInsn {
    pub code: u16,
    pub jt: u8,
    pub jf: u8,
    pub k: u32,
}

impl SeccompTargetArch {
    pub const fn current() -> Option<Self> {
        if cfg!(target_arch = "x86_64") {
            Some(Self::X86_64)
        } else if cfg!(target_arch = "aarch64") {
            Some(Self::Aarch64)
        } else {
            None
        }
    }

    pub const fn audit_arch(self) -> u32 {
        match self {
            Self::X86_64 => AUDIT_ARCH_X86_64,
            Self::Aarch64 => AUDIT_ARCH_AARCH64,
        }
    }
}

pub fn lookup_seccomp_syscall_nr(name: &str, arch: SeccompTargetArch) -> Option<u32> {
    let trimmed = name.trim();
    match (arch, trimmed) {
        (SeccompTargetArch::X86_64, "ptrace") => Some(101),
        (SeccompTargetArch::X86_64, "pivot_root") => Some(155),
        (SeccompTargetArch::X86_64, "mount") => Some(165),
        (SeccompTargetArch::X86_64, "umount2") => Some(166),
        (SeccompTargetArch::X86_64, "init_module") => Some(175),
        (SeccompTargetArch::X86_64, "kexec_load") => Some(246),
        (SeccompTargetArch::X86_64, "keyctl") => Some(250),
        (SeccompTargetArch::X86_64, "unshare") => Some(272),
        (SeccompTargetArch::X86_64, "setns") => Some(308),
        (SeccompTargetArch::X86_64, "process_vm_readv") => Some(310),
        (SeccompTargetArch::X86_64, "process_vm_writev") => Some(311),
        (SeccompTargetArch::X86_64, "finit_module") => Some(313),
        (SeccompTargetArch::X86_64, "bpf") => Some(321),
        (SeccompTargetArch::X86_64, "io_uring_setup") => Some(425),
        (SeccompTargetArch::X86_64, "io_uring_enter") => Some(426),
        (SeccompTargetArch::X86_64, "io_uring_register") => Some(427),
        (SeccompTargetArch::X86_64, "clone3") => Some(435),
        (SeccompTargetArch::Aarch64, "umount2") => Some(39),
        (SeccompTargetArch::Aarch64, "mount") => Some(40),
        (SeccompTargetArch::Aarch64, "pivot_root") => Some(41),
        (SeccompTargetArch::Aarch64, "unshare") => Some(97),
        (SeccompTargetArch::Aarch64, "kexec_load") => Some(104),
        (SeccompTargetArch::Aarch64, "init_module") => Some(105),
        (SeccompTargetArch::Aarch64, "ptrace") => Some(117),
        (SeccompTargetArch::Aarch64, "keyctl") => Some(219),
        (SeccompTargetArch::Aarch64, "setns") => Some(268),
        (SeccompTargetArch::Aarch64, "process_vm_readv") => Some(270),
        (SeccompTargetArch::Aarch64, "process_vm_writev") => Some(271),
        (SeccompTargetArch::Aarch64, "finit_module") => Some(273),
        (SeccompTargetArch::Aarch64, "bpf") => Some(280),
        (SeccompTargetArch::Aarch64, "io_uring_setup") => Some(425),
        (SeccompTargetArch::Aarch64, "io_uring_enter") => Some(426),
        (SeccompTargetArch::Aarch64, "io_uring_register") => Some(427),
        (SeccompTargetArch::Aarch64, "clone3") => Some(435),
        _ => None,
    }
}

pub fn build_seccomp_denylist_bpf(
    denied_syscalls: &[String],
    arch: SeccompTargetArch,
    max_rules: usize,
) -> Result<Vec<BpfFilterInsn>, SandboxError> {
    if max_rules == 0 {
        return Err(SandboxError::InvalidPolicy(
            "seccomp max_rules limit must be > 0".into(),
        ));
    }
    if denied_syscalls.len() > max_rules {
        return Err(SandboxError::InvalidPolicy(format!(
            "seccomp denied syscall count exceeds {max_rules}"
        )));
    }
    let mut eperm_nrs: Vec<u32> = Vec::new();
    let mut enosys_nrs: Vec<u32> = Vec::new();
    for name in denied_syscalls {
        let trimmed = name.trim();
        let Some(nr) = lookup_seccomp_syscall_nr(trimmed, arch) else {
            return Err(SandboxError::InvalidPolicy(format!(
                "unknown seccomp syscall `{name}` for {arch:?}"
            )));
        };
        let bucket = if trimmed == "clone3" {
            &mut enosys_nrs
        } else {
            &mut eperm_nrs
        };
        if !bucket.contains(&nr) {
            bucket.push(nr);
        }
    }
    if eperm_nrs.is_empty() && enosys_nrs.is_empty() {
        return Err(SandboxError::InvalidPolicy(
            "seccomp denied syscall list cannot be empty when filter is required".into(),
        ));
    }

    let total_nrs = eperm_nrs.len().saturating_add(enosys_nrs.len());
    let mut insns = Vec::with_capacity(total_nrs.saturating_add(7));
    insns.push(BpfFilterInsn {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 4,
    });
    insns.push(BpfFilterInsn {
        code: BPF_JMP_JEQ_K,
        jt: 1,
        jf: 0,
        k: arch.audit_arch(),
    });
    insns.push(BpfFilterInsn {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_KILL_PROCESS_VAL,
    });
    insns.push(BpfFilterInsn {
        code: BPF_LD_W_ABS,
        jt: 0,
        jf: 0,
        k: 0,
    });

    let has_eperm = !eperm_nrs.is_empty();
    let eperm_len = eperm_nrs.len();
    let enosys_len = enosys_nrs.len();
    for (idx, nr) in eperm_nrs.into_iter().enumerate() {
        let remaining_eperm = eperm_len.saturating_sub(idx).saturating_sub(1);
        let jump_to_eperm =
            u8::try_from(remaining_eperm.saturating_add(enosys_len).saturating_add(1))
                .map_err(|_| SandboxError::InvalidPolicy("seccomp jump offset overflow".into()))?;
        insns.push(BpfFilterInsn {
            code: BPF_JMP_JEQ_K,
            jt: jump_to_eperm,
            jf: 0,
            k: nr,
        });
    }
    for (idx, nr) in enosys_nrs.into_iter().enumerate() {
        let remaining_enosys = enosys_len.saturating_sub(idx).saturating_sub(1);
        let jump_to_enosys = u8::try_from(
            remaining_enosys
                .saturating_add(1)
                .saturating_add(usize::from(has_eperm)),
        )
        .map_err(|_| SandboxError::InvalidPolicy("seccomp jump offset overflow".into()))?;
        insns.push(BpfFilterInsn {
            code: BPF_JMP_JEQ_K,
            jt: jump_to_enosys,
            jf: 0,
            k: nr,
        });
    }
    insns.push(BpfFilterInsn {
        code: BPF_RET_K,
        jt: 0,
        jf: 0,
        k: SECCOMP_RET_ALLOW_VAL,
    });
    if has_eperm {
        insns.push(BpfFilterInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO_EPERM,
        });
    }
    if enosys_len > 0 {
        insns.push(BpfFilterInsn {
            code: BPF_RET_K,
            jt: 0,
            jf: 0,
            k: SECCOMP_RET_ERRNO_ENOSYS,
        });
    }
    Ok(insns)
}

#[cfg(target_os = "linux")]
pub fn execute_linux(
    program: &str,
    args: &[String],
    spec: &OsContainmentSpec,
    inherited_env: &[(String, String)],
) -> Result<SandboxExecutionReport, SandboxError> {
    let (env_pairs, stripped_env_vars) = build_filtered_env(spec, inherited_env);
    let mut mechanisms = vec![EnforcedMechanism::EnvSanitized];
    let mut warnings = Vec::new();

    let seccomp_insns =
        if spec.mode != ContainmentMode::ObserveOnly && !spec.seccomp_denied_syscalls.is_empty() {
            let arch = SeccompTargetArch::current().ok_or_else(|| {
                SandboxError::ContainmentSetup(
                    "seccomp BPF unsupported on target CPU architecture".into(),
                )
            })?;
            Some(build_seccomp_denylist_bpf(
                &spec.seccomp_denied_syscalls,
                arch,
                spec.max_seccomp_rules,
            )?)
        } else {
            None
        };

    let bwrap_path = Path::new("/usr/bin/bwrap");
    let use_bwrap = spec.linux_namespace == LinuxNamespaceMode::Bubblewrap
        && spec.mode == ContainmentMode::WorkspaceContained
        && bwrap_path.is_file();
    if spec.linux_namespace == LinuxNamespaceMode::Bubblewrap
        && spec.mode == ContainmentMode::WorkspaceContained
        && !bwrap_path.is_file()
    {
        warnings.push("bubblewrap `/usr/bin/bwrap` missing; using direct Landlock+seccomp".into());
    }

    let mut seccomp_pipe_guard = None;
    let (mut cmd, bwrap_seccomp_fd) = if use_bwrap {
        let pipe_fd = if let Some(insns) = &seccomp_insns {
            let (guard, fd) = create_bwrap_seccomp_pipe(insns)?;
            seccomp_pipe_guard = Some(guard);
            mechanisms.push(EnforcedMechanism::SeccompBpfFilter);
            Some(fd)
        } else {
            None
        };
        let bwrap_args = build_bwrap_args(program, args, spec, pipe_fd, true)?;
        mechanisms.push(EnforcedMechanism::BubblewrapNamespace);
        let mut bw = std::process::Command::new(bwrap_path);
        bw.args(bwrap_args);
        (bw, pipe_fd)
    } else {
        if spec.unshare_network && spec.mode == ContainmentMode::WorkspaceContained {
            warnings.push(
                "Direct Landlock+seccomp mode enforces FS/syscall containment without CLONE_NEWNET network isolation"
                    .into(),
            );
        }
        let mut plain = std::process::Command::new(program);
        plain.args(args);
        (plain, None)
    };

    if let Some(dir) = &spec.workdir {
        cmd.current_dir(dir);
        mechanisms.push(EnforcedMechanism::WorkdirScoped);
    }
    cmd.env_clear();
    for (k, v) in &env_pairs {
        cmd.env(k, v);
    }

    let cgroup_plan = build_cgroup_plan(spec);
    if let Some(plan) = &cgroup_plan {
        prepare_cgroup_v2_dir(plan, Path::new("/sys/fs/cgroup"))?;
        mechanisms.push(EnforcedMechanism::CgroupV2Limits);
    }

    let enforce_no_new_privs = spec.mode != ContainmentMode::ObserveOnly
        || matches!(spec.privilege, PrivilegePolicy::DropAll);
    if enforce_no_new_privs {
        mechanisms.push(EnforcedMechanism::NoNewPrivs);
    }

    if !use_bwrap {
        let landlock_entries = collect_landlock_c_paths(spec)?;
        let landlock_abi = if spec.mode == ContainmentMode::WorkspaceContained {
            probe_landlock_abi()
        } else {
            None
        };
        if landlock_abi.is_some() && !landlock_entries.is_empty() {
            mechanisms.push(EnforcedMechanism::LandlockRuleset);
        } else if spec.mode == ContainmentMode::WorkspaceContained {
            warnings.push("Landlock ABI unavailable; skipping Landlock ruleset".into());
        }
        if seccomp_insns.is_some() {
            mechanisms.push(EnforcedMechanism::SeccompBpfFilter);
        }
        install_linux_pre_exec(
            &mut cmd,
            enforce_no_new_privs,
            landlock_abi,
            landlock_entries,
            seccomp_insns,
            None,
        )?;
    } else if enforce_no_new_privs || bwrap_seccomp_fd.is_some() {
        install_linux_pre_exec(
            &mut cmd,
            enforce_no_new_privs,
            None,
            Vec::new(),
            None,
            bwrap_seccomp_fd,
        )?;
    }

    let mut child = cmd
        .spawn()
        .map_err(|err| SandboxError::ProcessLaunch(err.to_string()))?;
    drop(seccomp_pipe_guard);

    if let Some(plan) = &cgroup_plan
        && mechanisms.contains(&EnforcedMechanism::CgroupV2Limits)
        && let Err(err) = attach_pid_to_cgroup_v2(&plan.dir, child.id())
    {
        mechanisms.retain(|m| *m != EnforcedMechanism::CgroupV2Limits);
        warnings.push(format!("cgroup.procs attach skipped: {err}"));
    }
    let status = child
        .wait()
        .map_err(|err| SandboxError::ProcessLaunch(err.to_string()))?;

    let has_fs_boundary = mechanisms.contains(&EnforcedMechanism::LandlockRuleset)
        || mechanisms.contains(&EnforcedMechanism::BubblewrapNamespace);
    let has_seccomp = mechanisms.contains(&EnforcedMechanism::SeccompBpfFilter);
    let has_net_boundary =
        !spec.unshare_network || mechanisms.contains(&EnforcedMechanism::BubblewrapNamespace);

    let (effective_assurance, partial_reason) = if spec.mode == ContainmentMode::ObserveOnly {
        (
            AssuranceLevel::Al1Observed,
            Some("observe-only launch without containment".into()),
        )
    } else if spec.mode == ContainmentMode::WorkspaceContained
        && has_fs_boundary
        && has_seccomp
        && has_net_boundary
    {
        (AssuranceLevel::Al3Contained, None)
    } else if spec.mode == ContainmentMode::WorkspaceContained && has_fs_boundary && has_seccomp {
        (
            AssuranceLevel::Al2Guided,
            Some("direct Landlock+seccomp boundary enforces FS/syscall containment without CLONE_NEWNET network isolation".into()),
        )
    } else {
        (
            AssuranceLevel::Al2Guided,
            Some("linux launch without full Landlock/namespace + seccomp boundary".into()),
        )
    };

    Ok(SandboxExecutionReport {
        exit_code: status.code().unwrap_or(1),
        success: status.success(),
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

#[cfg(not(target_os = "linux"))]
pub fn execute_linux(
    _program: &str,
    _args: &[String],
    _spec: &OsContainmentSpec,
    _inherited_env: &[(String, String)],
) -> Result<SandboxExecutionReport, SandboxError> {
    let _ = build_cgroup_plan;
    Err(SandboxError::ContainmentSetup(
        "Linux containment execution attempted on non-Linux host".into(),
    ))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;

    use super::*;
    use crate::ContainmentMode;
    use crate::linux_bwrap::build_bwrap_args;
    use crate::policy::{LinuxNamespaceMode, PrivilegePolicy, WindowsTokenMode};

    fn test_spec(workdir: PathBuf, deny_paths: Vec<PathBuf>) -> OsContainmentSpec {
        OsContainmentSpec {
            session_id: "sess-lin".into(),
            agent_name: "agent".into(),
            mode: ContainmentMode::WorkspaceContained,
            workdir: Some(workdir),
            writable_paths: Vec::new(),
            read_only_paths: Vec::new(),
            deny_paths,
            extra_allow_env: Vec::new(),
            strip_secret_env: true,
            extra_env: Vec::new(),
            memory_limit_bytes: 512 * 1024 * 1024,
            active_process_limit: 16,
            privilege: PrivilegePolicy::DropAll,
            linux_namespace: LinuxNamespaceMode::Bubblewrap,
            cgroup_dir: None,
            seccomp_denied_syscalls: vec!["ptrace".into()],
            max_seccomp_rules: 64,
            unshare_network: true,
            macos_seatbelt_sbpl: None,
            windows_sandbox_sid: None,
            windows_token: WindowsTokenMode::Restricted,
        }
    }

    fn eval_seccomp_bpf(insns: &[BpfFilterInsn], arch: u32, nr: u32) -> u32 {
        let mut pc = 0usize;
        let mut acc = 0u32;
        while let Some(insn) = insns.get(pc) {
            match insn.code {
                BPF_LD_W_ABS => {
                    acc = if insn.k == 4 { arch } else { nr };
                    pc = pc.saturating_add(1);
                }
                BPF_JMP_JEQ_K => {
                    let jump = if acc == insn.k { insn.jt } else { insn.jf };
                    pc = pc.saturating_add(1).saturating_add(usize::from(jump));
                }
                BPF_RET_K => return insn.k,
                _ => return 0,
            }
        }
        0
    }

    #[test]
    fn builds_valid_seccomp_bpf_filter_rejects_unknown_and_includes_hardening_syscalls() {
        let denied = vec![
            "ptrace".into(),
            "mount".into(),
            "kexec_load".into(),
            "bpf".into(),
            "io_uring_setup".into(),
            "io_uring_enter".into(),
            "io_uring_register".into(),
            "unshare".into(),
            "setns".into(),
            "pivot_root".into(),
            "clone3".into(),
            "keyctl".into(),
        ];
        let x86_prog = build_seccomp_denylist_bpf(&denied, SeccompTargetArch::X86_64, 64).unwrap();
        assert_eq!(x86_prog.len(), 19);
        assert_eq!(x86_prog.first().map(|i| i.k), Some(4));
        assert_eq!(
            eval_seccomp_bpf(&x86_prog, AUDIT_ARCH_X86_64, 435),
            SECCOMP_RET_ERRNO_ENOSYS
        );
        assert_eq!(
            eval_seccomp_bpf(&x86_prog, AUDIT_ARCH_X86_64, 101),
            SECCOMP_RET_ERRNO_EPERM
        );
        assert_eq!(
            eval_seccomp_bpf(&x86_prog, AUDIT_ARCH_X86_64, 0),
            SECCOMP_RET_ALLOW_VAL
        );
        assert_eq!(
            eval_seccomp_bpf(&x86_prog, AUDIT_ARCH_AARCH64, 0),
            SECCOMP_RET_KILL_PROCESS_VAL
        );

        let clone3_only =
            build_seccomp_denylist_bpf(&["clone3".into()], SeccompTargetArch::X86_64, 64).unwrap();
        assert_eq!(
            eval_seccomp_bpf(&clone3_only, AUDIT_ARCH_X86_64, 435),
            SECCOMP_RET_ERRNO_ENOSYS
        );
        assert_eq!(
            eval_seccomp_bpf(&clone3_only, AUDIT_ARCH_X86_64, 101),
            SECCOMP_RET_ALLOW_VAL
        );

        let arm_prog = build_seccomp_denylist_bpf(&denied, SeccompTargetArch::Aarch64, 64).unwrap();
        assert_eq!(arm_prog.len(), 19);
        assert_eq!(arm_prog.get(1).map(|i| i.k), Some(AUDIT_ARCH_AARCH64));
        assert_eq!(
            eval_seccomp_bpf(&arm_prog, AUDIT_ARCH_AARCH64, 435),
            SECCOMP_RET_ERRNO_ENOSYS
        );

        assert!(matches!(
            build_seccomp_denylist_bpf(&["unknown_syscall".into()], SeccompTargetArch::X86_64, 64),
            Err(SandboxError::InvalidPolicy(_))
        ));
        assert!(matches!(
            build_seccomp_denylist_bpf(&[], SeccompTargetArch::X86_64, 64),
            Err(SandboxError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn builds_bwrap_args_with_unshare_net_seccomp_and_deny_tmpfs_overlay() {
        let wd = PathBuf::from("/workspace/demo");
        let mut spec = test_spec(wd.clone(), vec![wd.join(".env")]);
        spec.writable_paths.push(wd.clone());
        let args =
            build_bwrap_args("sh", &["-c".into(), "id".into()], &spec, Some(7), false).unwrap();
        assert!(args.iter().any(|a| a == "--unshare-net"));
        assert!(args.windows(2).any(|w| w == ["--seccomp", "7"]));
        assert!(
            args.windows(2)
                .any(|w| w[0] == "--tmpfs" && w[1].ends_with(".env"))
        );
        assert_eq!(
            args.windows(3)
                .filter(|w| w[0] == "--bind" && w[1] == wd.to_string_lossy().as_ref())
                .count(),
            1
        );

        let bad_parent = test_spec(wd.clone(), vec![wd]);
        assert!(matches!(
            build_bwrap_args("sh", &[], &bad_parent, None, false),
            Err(SandboxError::InvalidPolicy(_))
        ));
    }

    #[test]
    fn validates_and_writes_cgroup_v2_limits_under_allowed_root() {
        let root = std::env::temp_dir().join(format!("grdr-cg-root-{}", std::process::id()));
        let _ = fs::remove_dir_all(&root);
        fs::create_dir_all(&root).unwrap();
        let cg_dir = root.join("sess-1");
        let plan = CgroupV2Plan {
            dir: cg_dir.clone(),
            memory_max_bytes: Some(536_870_912),
            pids_max: Some(64),
        };
        prepare_cgroup_v2_dir(&plan, &root).unwrap();
        attach_pid_to_cgroup_v2(&cg_dir, 4242).unwrap();

        assert_eq!(
            fs::read_to_string(cg_dir.join("memory.max")).unwrap(),
            "536870912\n"
        );
        assert_eq!(fs::read_to_string(cg_dir.join("pids.max")).unwrap(), "64\n");
        assert_eq!(
            fs::read_to_string(cg_dir.join("cgroup.procs")).unwrap(),
            "4242\n"
        );

        let escape_plan = CgroupV2Plan {
            dir: root.join("../escape"),
            memory_max_bytes: None,
            pids_max: None,
        };
        assert!(matches!(
            prepare_cgroup_v2_dir(&escape_plan, &root),
            Err(SandboxError::InvalidPolicy(_))
        ));
        let _ = fs::remove_dir_all(&root);
    }
}
