// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeAttempt {
    Executed,
    Skipped,
    NotSupported,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BpfLsmSupport {
    Active,
    AbsentFromLsm,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LockdownState {
    None,
    Integrity,
    Confidentiality,
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BtfSupport {
    Present { size_bytes: u64 },
    Missing,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LandlockSupport {
    Supported { abi: u32 },
    Unsupported { errno: i32 },
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FanotifySupport {
    PreContent,
    ContentPerm,
    NotifyOnly,
    Unsupported { errno: i32 },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CgroupMode {
    UnifiedV2,
    Hybrid,
    LegacyV1,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SeccompKernelState {
    Disabled,
    Strict,
    Filter,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RuntimeEnvironment {
    BareMetalOrVm,
    Wsl2,
    Docker,
    Containerd,
    CriO,
    KubernetesPod,
    GVisor,
    Kata,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CiEnvironment {
    None,
    Ephemeral { provider: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HostTier {
    T1FullEnforce,
    T2MixedEnforce,
    T3DegradedObserve,
    T4Sidecar,
    T5RestrictedHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CiMarkerSpec {
    pub env_key: String,
    pub provider_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct KernelSysctls {
    pub unprivileged_bpf_disabled: Option<i32>,
    pub perf_event_paranoid: Option<i32>,
    pub max_user_namespaces: Option<i32>,
    pub config_bpf_lsm: Option<bool>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HostProfile {
    pub active_lsms: Vec<String>,
    pub bpf_lsm: BpfLsmSupport,
    pub bpf_lsm_load_probe: ProbeAttempt,
    pub lockdown: LockdownState,
    pub btf: BtfSupport,
    pub landlock: LandlockSupport,
    pub fanotify: FanotifySupport,
    pub cgroup: CgroupMode,
    pub seccomp: SeccompKernelState,
    pub sysctls: KernelSysctls,
    pub runtime: RuntimeEnvironment,
    pub ci: CiEnvironment,
    pub tier: HostTier,
}

pub trait SysProbeReader {
    fn read_text(&self, path: &str) -> Option<String>;
    fn file_size(&self, path: &str) -> Option<u64>;
    fn path_exists(&self, path: &str) -> bool;
    fn env_var(&self, key: &str) -> Option<String>;
    fn probe_bpf_lsm_load(&self) -> ProbeAttempt;
    fn probe_landlock(&self) -> LandlockSupport;
    fn probe_fanotify(&self) -> FanotifySupport;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct RealLinuxSysProbe;

#[derive(Debug, Clone, Default)]
pub struct SyntheticSysProbe {
    pub files: BTreeMap<String, String>,
    pub file_sizes: BTreeMap<String, u64>,
    pub paths: Vec<String>,
    pub env: BTreeMap<String, String>,
    pub bpf_lsm_load_result: Option<ProbeAttempt>,
    pub landlock_result: Option<LandlockSupport>,
    pub fanotify_result: Option<FanotifySupport>,
}

impl SysProbeReader for RealLinuxSysProbe {
    fn read_text(&self, path: &str) -> Option<String> {
        fs::read_to_string(path).ok()
    }

    fn file_size(&self, path: &str) -> Option<u64> {
        fs::metadata(path).ok().map(|meta| meta.len())
    }

    fn path_exists(&self, path: &str) -> bool {
        Path::new(path).exists()
    }

    fn env_var(&self, key: &str) -> Option<String> {
        std::env::var(key).ok()
    }

    fn probe_bpf_lsm_load(&self) -> ProbeAttempt {
        ProbeAttempt::NotSupported
    }

    fn probe_landlock(&self) -> LandlockSupport {
        probe_landlock_os()
    }

    fn probe_fanotify(&self) -> FanotifySupport {
        probe_fanotify_os()
    }
}

impl SysProbeReader for SyntheticSysProbe {
    fn read_text(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }

    fn file_size(&self, path: &str) -> Option<u64> {
        self.file_sizes.get(path).copied()
    }

    fn path_exists(&self, path: &str) -> bool {
        self.files.contains_key(path)
            || self.file_sizes.contains_key(path)
            || self.paths.iter().any(|p| p == path)
    }

    fn env_var(&self, key: &str) -> Option<String> {
        self.env.get(key).cloned()
    }

    fn probe_bpf_lsm_load(&self) -> ProbeAttempt {
        self.bpf_lsm_load_result
            .unwrap_or(ProbeAttempt::NotSupported)
    }

    fn probe_landlock(&self) -> LandlockSupport {
        self.landlock_result.unwrap_or(LandlockSupport::Unavailable)
    }

    fn probe_fanotify(&self) -> FanotifySupport {
        self.fanotify_result
            .unwrap_or(FanotifySupport::Unsupported { errno: 38 })
    }
}

pub fn probe_host_capabilities(
    reader: &dyn SysProbeReader,
    ci_markers: &[CiMarkerSpec],
) -> HostProfile {
    let active_lsms = reader
        .read_text("/sys/kernel/security/lsm")
        .map(|raw| {
            raw.trim()
                .split(',')
                .filter(|s| !s.is_empty())
                .map(ToString::to_string)
                .collect::<Vec<String>>()
        })
        .unwrap_or_default();

    let lockdown = parse_lockdown(reader.read_text("/sys/kernel/security/lockdown").as_deref());
    let (bpf_lsm, bpf_lsm_load_probe) = if active_lsms.is_empty() {
        (BpfLsmSupport::Unavailable, ProbeAttempt::Skipped)
    } else if !active_lsms.iter().any(|lsm| lsm == "bpf") {
        // Avoid EBADF/EINVAL probe calls when bpf is absent from /sys/kernel/security/lsm.
        (BpfLsmSupport::AbsentFromLsm, ProbeAttempt::Skipped)
    } else if matches!(lockdown, LockdownState::Confidentiality) {
        (BpfLsmSupport::Unavailable, ProbeAttempt::Skipped)
    } else {
        (BpfLsmSupport::Active, reader.probe_bpf_lsm_load())
    };

    let btf = match reader.file_size("/sys/kernel/btf/vmlinux") {
        Some(size_bytes) if size_bytes > 0 => BtfSupport::Present { size_bytes },
        _ => BtfSupport::Missing,
    };
    let landlock = reader.probe_landlock();
    let fanotify = reader.probe_fanotify();
    let cgroup = detect_cgroup_mode(reader);
    let seccomp = parse_seccomp(reader.read_text("/proc/self/status").as_deref());
    let sysctls = read_sysctls(reader);
    let runtime = detect_runtime(reader);
    let ci = detect_ci(reader, ci_markers);

    let tier = classify_host_tier(bpf_lsm, lockdown, btf, landlock, fanotify, cgroup, runtime);

    HostProfile {
        active_lsms,
        bpf_lsm,
        bpf_lsm_load_probe,
        lockdown,
        btf,
        landlock,
        fanotify,
        cgroup,
        seccomp,
        sysctls,
        runtime,
        ci,
        tier,
    }
}

pub fn classify_host_tier(
    bpf_lsm: BpfLsmSupport,
    lockdown: LockdownState,
    btf: BtfSupport,
    landlock: LandlockSupport,
    fanotify: FanotifySupport,
    cgroup: CgroupMode,
    runtime: RuntimeEnvironment,
) -> HostTier {
    if matches!(
        runtime,
        RuntimeEnvironment::GVisor | RuntimeEnvironment::Kata
    ) {
        return HostTier::T4Sidecar;
    }
    let has_btf = matches!(btf, BtfSupport::Present { .. });
    let has_landlock = matches!(landlock, LandlockSupport::Supported { .. });
    let has_cgroup_v2 = matches!(cgroup, CgroupMode::UnifiedV2 | CgroupMode::Hybrid);

    if matches!(lockdown, LockdownState::Confidentiality) {
        if has_landlock {
            return HostTier::T3DegradedObserve;
        }
        return HostTier::T5RestrictedHost;
    }
    if matches!(bpf_lsm, BpfLsmSupport::Active) && has_btf && has_cgroup_v2 {
        return HostTier::T1FullEnforce;
    }
    if has_btf
        && (has_landlock
            || matches!(
                fanotify,
                FanotifySupport::PreContent | FanotifySupport::ContentPerm
            ))
    {
        return HostTier::T2MixedEnforce;
    }
    if has_btf || has_landlock {
        return HostTier::T3DegradedObserve;
    }
    HostTier::T5RestrictedHost
}

fn parse_lockdown(raw: Option<&str>) -> LockdownState {
    let Some(text) = raw else {
        return LockdownState::Unknown;
    };
    if text.contains("[confidentiality]") {
        LockdownState::Confidentiality
    } else if text.contains("[integrity]") {
        LockdownState::Integrity
    } else if text.contains("[none]") {
        LockdownState::None
    } else {
        LockdownState::Unknown
    }
}

fn detect_cgroup_mode(reader: &dyn SysProbeReader) -> CgroupMode {
    if reader.path_exists("/sys/fs/cgroup/cgroup.controllers") {
        if reader.path_exists("/sys/fs/cgroup/memory") {
            return CgroupMode::Hybrid;
        }
        return CgroupMode::UnifiedV2;
    }
    if reader.path_exists("/proc/self/cgroup") {
        return CgroupMode::LegacyV1;
    }
    CgroupMode::Unavailable
}

fn parse_seccomp(status_raw: Option<&str>) -> SeccompKernelState {
    let Some(raw) = status_raw else {
        return SeccompKernelState::Unavailable;
    };
    for line in raw.lines() {
        if let Some(rest) = line.strip_prefix("Seccomp:") {
            return match rest.trim() {
                "0" => SeccompKernelState::Disabled,
                "1" => SeccompKernelState::Strict,
                "2" => SeccompKernelState::Filter,
                _ => SeccompKernelState::Unavailable,
            };
        }
    }
    SeccompKernelState::Unavailable
}

fn find_kernel_config_bpf_lsm(reader: &dyn SysProbeReader) -> Option<bool> {
    let mut candidates = Vec::new();
    if let Some(rel) = reader.read_text("/proc/sys/kernel/osrelease") {
        let trimmed = rel.trim();
        if !trimmed.is_empty()
            && !trimmed.contains('/')
            && !trimmed.contains("..")
            && !trimmed.contains('\0')
        {
            candidates.push(format!("/boot/config-{trimmed}"));
        }
    }
    candidates.push("/boot/config".into());
    candidates.push("/proc/config".into());

    for path in candidates {
        if let Some(cfg) = reader.read_text(&path) {
            for line in cfg.lines() {
                if line == "CONFIG_BPF_LSM=y" {
                    return Some(true);
                }
                if line == "CONFIG_BPF_LSM=n" || line == "# CONFIG_BPF_LSM is not set" {
                    return Some(false);
                }
            }
        }
    }
    None
}

fn read_sysctls(reader: &dyn SysProbeReader) -> KernelSysctls {
    KernelSysctls {
        unprivileged_bpf_disabled: parse_sysctl_i32(
            reader,
            "/proc/sys/kernel/unprivileged_bpf_disabled",
        ),
        perf_event_paranoid: parse_sysctl_i32(reader, "/proc/sys/kernel/perf_event_paranoid"),
        max_user_namespaces: parse_sysctl_i32(reader, "/proc/sys/user/max_user_namespaces"),
        config_bpf_lsm: find_kernel_config_bpf_lsm(reader),
    }
}

fn parse_sysctl_i32(reader: &dyn SysProbeReader, path: &str) -> Option<i32> {
    reader
        .read_text(path)
        .and_then(|s| s.trim().parse::<i32>().ok())
}

fn has_icase_marker(reader: &dyn SysProbeReader, path: &str, needles: &[&str]) -> bool {
    reader.read_text(path).is_some_and(|v| {
        let lower = v.to_ascii_lowercase();
        needles.iter().any(|n| lower.contains(n))
    })
}

fn detect_runtime(reader: &dyn SysProbeReader) -> RuntimeEnvironment {
    if reader.path_exists("/proc/sys/fs/binfmt_misc/WSLInterop")
        || has_icase_marker(
            reader,
            "/proc/sys/kernel/osrelease",
            &["microsoft-standard-wsl2", "wsl2"],
        )
        || has_icase_marker(reader, "/proc/version", &["microsoft-standard-wsl2"])
    {
        return RuntimeEnvironment::Wsl2;
    }
    if reader.path_exists("/.gvisor")
        || has_icase_marker(reader, "/proc/self/mountinfo", &["gvisor", "runsc"])
    {
        return RuntimeEnvironment::GVisor;
    }
    if has_icase_marker(reader, "/proc/cmdline", &["kata"]) {
        return RuntimeEnvironment::Kata;
    }
    if reader
        .env_var("KUBERNETES_SERVICE_HOST")
        .is_some_and(|v| !v.trim().is_empty())
    {
        return RuntimeEnvironment::KubernetesPod;
    }
    if reader.path_exists("/var/run/crio/crio.sock") || reader.path_exists("/run/crio/crio.sock") {
        return RuntimeEnvironment::CriO;
    }
    if reader.path_exists("/var/run/containerd/containerd.sock")
        || reader.path_exists("/run/containerd/containerd.sock")
    {
        return RuntimeEnvironment::Containerd;
    }
    if reader.path_exists("/.dockerenv") || reader.path_exists("/run/.containerenv") {
        return RuntimeEnvironment::Docker;
    }
    RuntimeEnvironment::BareMetalOrVm
}

fn detect_ci(reader: &dyn SysProbeReader, markers: &[CiMarkerSpec]) -> CiEnvironment {
    for marker in markers {
        if reader
            .env_var(&marker.env_key)
            .is_some_and(|val| val == "true" || !val.trim().is_empty())
        {
            return CiEnvironment::Ephemeral {
                provider: marker.provider_id.clone(),
            };
        }
    }
    if reader.env_var("CI").is_some_and(|v| v == "true") {
        return CiEnvironment::Ephemeral {
            provider: "generic-ci".into(),
        };
    }
    CiEnvironment::None
}

#[cfg(target_os = "linux")]
#[allow(unsafe_code, reason = "query Landlock ABI version via kernel syscall")]
fn probe_landlock_os() -> LandlockSupport {
    const LANDLOCK_CREATE_RULESET_VERSION: u32 = 1 << 0;
    // SAFETY: passing null attr and size 0 with LANDLOCK_CREATE_RULESET_VERSION only queries the supported Landlock ABI integer without modifying kernel or process state.
    let rc = unsafe {
        libc::syscall(
            libc::SYS_landlock_create_ruleset,
            0 as libc::c_long,
            0 as libc::c_long,
            libc::c_long::from(LANDLOCK_CREATE_RULESET_VERSION),
        )
    };
    if rc >= 1 {
        LandlockSupport::Supported {
            abi: u32::try_from(rc).unwrap_or(1),
        }
    } else {
        let errno = if rc == 0 {
            libc::ENOSYS
        } else {
            std::io::Error::last_os_error()
                .raw_os_error()
                .unwrap_or(libc::ENOSYS)
        };
        LandlockSupport::Unsupported { errno }
    }
}

#[cfg(not(target_os = "linux"))]
fn probe_landlock_os() -> LandlockSupport {
    LandlockSupport::Unavailable
}

#[cfg(target_os = "linux")]
#[allow(
    unsafe_code,
    reason = "probe Linux fanotify capability descriptor and immediately close it"
)]
fn probe_fanotify_os() -> FanotifySupport {
    for (flag, tier) in [
        (libc::FAN_CLASS_PRE_CONTENT, FanotifySupport::PreContent),
        (libc::FAN_CLASS_CONTENT, FanotifySupport::ContentPerm),
        (0u32, FanotifySupport::NotifyOnly),
    ] {
        // SAFETY: fanotify_init takes integer flags and returns a new fd or -1 with errno.
        let fd = unsafe {
            libc::fanotify_init(
                flag | libc::FAN_CLOEXEC,
                libc::c_uint::try_from(libc::O_RDONLY).unwrap_or(0),
            )
        };
        if fd >= 0 {
            // SAFETY: fd is an owned open descriptor returned immediately above.
            unsafe {
                libc::close(fd);
            }
            return tier;
        }
    }
    let errno = std::io::Error::last_os_error()
        .raw_os_error()
        .unwrap_or(libc::EPERM);
    FanotifySupport::Unsupported { errno }
}

#[cfg(not(target_os = "linux"))]
fn probe_fanotify_os() -> FanotifySupport {
    FanotifySupport::Unsupported { errno: 38 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn skips_bpf_lsm_probe_when_bpf_absent_from_lsm_list() {
        let mut sys = SyntheticSysProbe::default();
        sys.files.insert(
            "/sys/kernel/security/lsm".into(),
            "capability,yama,apparmor,landlock".into(),
        );
        sys.files.insert(
            "/sys/kernel/security/lockdown".into(),
            "[none] integrity".into(),
        );
        sys.file_sizes
            .insert("/sys/kernel/btf/vmlinux".into(), 4_194_304);
        sys.files.insert(
            "/sys/fs/cgroup/cgroup.controllers".into(),
            "cpu memory".into(),
        );
        sys.files.insert(
            "/proc/self/status".into(),
            "Name:\tgrdr\nSeccomp:\t2\n".into(),
        );
        sys.landlock_result = Some(LandlockSupport::Supported { abi: 4 });
        sys.fanotify_result = Some(FanotifySupport::ContentPerm);

        let profile = probe_host_capabilities(&sys, &[]);
        assert_eq!(profile.bpf_lsm, BpfLsmSupport::AbsentFromLsm);
        assert_eq!(profile.bpf_lsm_load_probe, ProbeAttempt::Skipped);
        assert_eq!(profile.tier, HostTier::T2MixedEnforce);
        assert_eq!(profile.seccomp, SeccompKernelState::Filter);
        assert_eq!(profile.lockdown, LockdownState::None);
    }

    #[test]
    fn detects_t1_wsl2_and_ci_markers() {
        let mut sys = SyntheticSysProbe::default();
        sys.files.insert(
            "/sys/kernel/security/lsm".into(),
            "capability,bpf,landlock".into(),
        );
        sys.file_sizes
            .insert("/sys/kernel/btf/vmlinux".into(), 5_000_000);
        sys.files.insert(
            "/sys/fs/cgroup/cgroup.controllers".into(),
            "cpu memory".into(),
        );
        sys.paths.push("/proc/sys/fs/binfmt_misc/WSLInterop".into());
        sys.files.insert(
            "/proc/self/mountinfo".into(),
            "25 1 0:20 / /mnt/c rw - 9p drvfs rw".into(),
        );
        sys.files.insert(
            "/proc/sys/kernel/osrelease".into(),
            "6.6.36-microsoft-standard-WSL2".into(),
        );
        sys.files.insert(
            "/boot/config-6.6.36-microsoft-standard-WSL2".into(),
            "CONFIG_BPF_LSM=y\n".into(),
        );
        sys.env.insert("TEST_CI_FLAG".into(), "true".into());
        sys.bpf_lsm_load_result = Some(ProbeAttempt::Executed);
        sys.landlock_result = Some(LandlockSupport::Supported { abi: 5 });

        let markers = vec![CiMarkerSpec {
            env_key: "TEST_CI_FLAG".into(),
            provider_id: "sample-ci".into(),
        }];
        let profile = probe_host_capabilities(&sys, &markers);
        assert_eq!(profile.bpf_lsm, BpfLsmSupport::Active);
        assert_eq!(profile.bpf_lsm_load_probe, ProbeAttempt::Executed);
        assert_eq!(profile.sysctls.config_bpf_lsm, Some(true));
        assert_eq!(profile.runtime, RuntimeEnvironment::Wsl2);
        assert_eq!(
            profile.ci,
            CiEnvironment::Ephemeral {
                provider: "sample-ci".into()
            }
        );
        assert_eq!(profile.tier, HostTier::T1FullEnforce);

        let mut locked = sys.clone();
        locked.files.insert(
            "/sys/kernel/security/lockdown".into(),
            "[confidentiality]".into(),
        );
        let locked_profile = probe_host_capabilities(&locked, &markers);
        assert_eq!(locked_profile.lockdown, LockdownState::Confidentiality);
        assert_eq!(locked_profile.tier, HostTier::T3DegradedObserve);
        assert_eq!(locked_profile.bpf_lsm_load_probe, ProbeAttempt::Skipped);

        let mut osrel_wsl = SyntheticSysProbe::default();
        osrel_wsl.files.insert(
            "/proc/sys/kernel/osrelease".into(),
            "6.6.36-microsoft-standard-WSL2".into(),
        );
        osrel_wsl.files.insert(
            "/proc/self/mountinfo".into(),
            "25 1 0:20 / /mnt/c rw - 9p drvfs rw".into(),
        );
        assert_eq!(
            probe_host_capabilities(&osrel_wsl, &[]).runtime,
            RuntimeEnvironment::Wsl2
        );
    }
}
