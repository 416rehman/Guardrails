// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![deny(clippy::arithmetic_side_effects)]

use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::SensorError;
use crate::fs_safe::read_nofollow_bounded_utf8;
use crate::probe::{
    BpfLsmSupport, BtfSupport, CgroupMode, FanotifySupport, HostProfile, HostTier, LockdownState,
    RuntimeEnvironment,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SlotRung {
    BpfLsmEnforce,
    FmodRetTracepoint,
    CgroupAndFanotify,
    AuditNetlinkAndProcfs,
    ProcfsObserveOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IncumbentRole {
    ExclusiveEnforcer,
    CoexistingTelemetry,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct IncumbentSignature {
    pub id: String,
    pub role: IncumbentRole,
    #[serde(default)]
    pub bpf_prog_prefixes: Vec<String>,
    #[serde(default)]
    pub proc_comm_prefixes: Vec<String>,
    #[serde(default)]
    pub bpffs_markers: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct IncumbentCatalogue {
    #[serde(default)]
    pub signatures: Vec<IncumbentSignature>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DetectedIncumbent {
    pub id: String,
    pub role: IncumbentRole,
    pub matched_by: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SlotBrokerInputs {
    pub host: HostProfile,
    pub active_bpf_progs: Vec<String>,
    pub active_proc_comms: Vec<String>,
    pub bpffs_pins: Vec<String>,
    pub trampoline_slots_used: u16,
    pub trampoline_cap: u16,
    pub trampoline_slots_enforce: u16,
    pub audit_netlink_readable: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SlotBrokerPlan {
    pub selected_tier: HostTier,
    pub primary_rung: SlotRung,
    pub active_rungs: Vec<SlotRung>,
    pub coexisting_sensors: Vec<DetectedIncumbent>,
    pub degradation_reasons: Vec<String>,
    pub trampoline_headroom: u16,
    pub enforcement_possible: bool,
}

impl IncumbentCatalogue {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn from_json_str(raw: &str, source_label: &str) -> Result<Self, SensorError> {
        serde_json::from_str(raw).map_err(|err| SensorError::CatalogueLoad {
            path: source_label.to_string(),
            detail: err.to_string(),
        })
    }

    pub fn load_json_file(path: &Path, max_file_bytes: u64) -> Result<Self, SensorError> {
        let raw = read_nofollow_bounded_utf8(path, max_file_bytes, "incumbent catalogue")?;
        Self::from_json_str(&raw, &path.display().to_string())
    }
}

pub fn broker_linux_slots(
    inputs: &SlotBrokerInputs,
    catalogue: &IncumbentCatalogue,
) -> SlotBrokerPlan {
    let coexisting_sensors = detect_incumbents(inputs, catalogue);
    let mut degradation_reasons = Vec::new();
    let cap = inputs.trampoline_cap;
    let trampoline_headroom = cap.saturating_sub(inputs.trampoline_slots_used);

    if matches!(
        inputs.host.runtime,
        RuntimeEnvironment::GVisor | RuntimeEnvironment::Kata
    ) {
        degradation_reasons.push(
            "gVisor/Kata runtime enforces inside VM/user-space kernel; using sidecar sensor".into(),
        );
        return SlotBrokerPlan {
            selected_tier: HostTier::T4Sidecar,
            primary_rung: SlotRung::ProcfsObserveOnly,
            active_rungs: vec![SlotRung::ProcfsObserveOnly],
            coexisting_sensors,
            degradation_reasons,
            trampoline_headroom,
            enforcement_possible: false,
        };
    }

    let has_btf = matches!(inputs.host.btf, BtfSupport::Present { .. });
    let confidentiality_lockdown = matches!(inputs.host.lockdown, LockdownState::Confidentiality);
    let has_exclusive_incumbent = coexisting_sensors
        .iter()
        .any(|s| matches!(s.role, IncumbentRole::ExclusiveEnforcer));

    if confidentiality_lockdown {
        degradation_reasons.push("kernel lockdown confidentiality mode blocks eBPF loading".into());
    }
    if has_exclusive_incumbent {
        degradation_reasons.push(
            "exclusive incumbent security sensor detected; yielding primary enforcement hooks"
                .into(),
        );
    }
    if !matches!(inputs.host.bpf_lsm, BpfLsmSupport::Active) {
        degradation_reasons.push("bpf missing from /sys/kernel/security/lsm".into());
    }
    if !has_btf {
        degradation_reasons.push("/sys/kernel/btf/vmlinux unavailable".into());
    }
    if inputs.trampoline_cap == 0 || inputs.trampoline_slots_enforce == 0 {
        degradation_reasons.push("trampoline slot budget unconfigured".into());
    } else if trampoline_headroom < inputs.trampoline_slots_enforce {
        degradation_reasons.push(format!(
            "bpf trampoline headroom {trampoline_headroom} below required {}",
            inputs.trampoline_slots_enforce
        ));
    }

    let mut active_rungs = Vec::new();
    let can_bpf_lsm = !confidentiality_lockdown
        && matches!(inputs.host.bpf_lsm, BpfLsmSupport::Active)
        && has_btf
        && !has_exclusive_incumbent
        && inputs.trampoline_slots_enforce > 0
        && trampoline_headroom >= inputs.trampoline_slots_enforce;

    if can_bpf_lsm {
        active_rungs.push(SlotRung::BpfLsmEnforce);
    } else if !confidentiality_lockdown && has_btf && trampoline_headroom >= 4 {
        active_rungs.push(SlotRung::FmodRetTracepoint);
    }

    if matches!(
        inputs.host.cgroup,
        CgroupMode::UnifiedV2 | CgroupMode::Hybrid
    ) || matches!(
        inputs.host.fanotify,
        FanotifySupport::PreContent | FanotifySupport::ContentPerm
    ) {
        active_rungs.push(SlotRung::CgroupAndFanotify);
    }

    if inputs.audit_netlink_readable {
        active_rungs.push(SlotRung::AuditNetlinkAndProcfs);
    } else {
        active_rungs.push(SlotRung::ProcfsObserveOnly);
    }

    let primary_rung = active_rungs
        .first()
        .copied()
        .unwrap_or(SlotRung::ProcfsObserveOnly);

    let selected_tier = match primary_rung {
        SlotRung::BpfLsmEnforce => HostTier::T1FullEnforce,
        SlotRung::FmodRetTracepoint => HostTier::T2MixedEnforce,
        SlotRung::CgroupAndFanotify
        | SlotRung::AuditNetlinkAndProcfs
        | SlotRung::ProcfsObserveOnly => HostTier::T3DegradedObserve,
    };

    let enforcement_possible = matches!(
        selected_tier,
        HostTier::T1FullEnforce | HostTier::T2MixedEnforce
    );

    SlotBrokerPlan {
        selected_tier,
        primary_rung,
        active_rungs,
        coexisting_sensors,
        degradation_reasons,
        trampoline_headroom,
        enforcement_possible,
    }
}

fn detect_incumbents(
    inputs: &SlotBrokerInputs,
    catalogue: &IncumbentCatalogue,
) -> Vec<DetectedIncumbent> {
    let mut found = Vec::new();
    for sig in &catalogue.signatures {
        if let Some(matched) = find_first_prefix(&inputs.active_bpf_progs, &sig.bpf_prog_prefixes) {
            found.push(DetectedIncumbent {
                id: sig.id.clone(),
                role: sig.role,
                matched_by: format!("bpf_prog:{matched}"),
            });
            continue;
        }
        if let Some(matched) = find_first_prefix(&inputs.active_proc_comms, &sig.proc_comm_prefixes)
        {
            found.push(DetectedIncumbent {
                id: sig.id.clone(),
                role: sig.role,
                matched_by: format!("proc:{matched}"),
            });
            continue;
        }
        if let Some(matched) = find_first_prefix(&inputs.bpffs_pins, &sig.bpffs_markers) {
            found.push(DetectedIncumbent {
                id: sig.id.clone(),
                role: sig.role,
                matched_by: format!("bpffs:{matched}"),
            });
        }
    }
    found
}

fn find_first_prefix<'a>(observed: &'a [String], prefixes: &[String]) -> Option<&'a str> {
    for obs in observed {
        let obs_lower = obs.to_ascii_lowercase();
        for pref in prefixes {
            let p_lower = pref.to_ascii_lowercase();
            if !p_lower.is_empty() && obs_lower.starts_with(&p_lower) {
                return Some(obs.as_str());
            }
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::probe::{
        CiEnvironment, KernelSysctls, LandlockSupport, LockdownState, ProbeAttempt,
        RuntimeEnvironment, SeccompKernelState,
    };

    fn base_t1_host() -> HostProfile {
        HostProfile {
            active_lsms: vec!["capability".into(), "bpf".into(), "landlock".into()],
            bpf_lsm: BpfLsmSupport::Active,
            bpf_lsm_load_probe: ProbeAttempt::Executed,
            lockdown: LockdownState::None,
            btf: BtfSupport::Present { size_bytes: 1_024 },
            landlock: LandlockSupport::Supported { abi: 4 },
            fanotify: FanotifySupport::ContentPerm,
            cgroup: CgroupMode::UnifiedV2,
            seccomp: SeccompKernelState::Filter,
            sysctls: KernelSysctls {
                unprivileged_bpf_disabled: Some(1),
                perf_event_paranoid: Some(2),
                max_user_namespaces: Some(1024),
                config_bpf_lsm: Some(true),
            },
            runtime: RuntimeEnvironment::BareMetalOrVm,
            ci: CiEnvironment::None,
            tier: HostTier::T1FullEnforce,
        }
    }

    #[test]
    fn degrades_gracefully_on_exclusive_incumbent_and_saturated_trampolines() {
        let catalogue = IncumbentCatalogue::from_json_str(
            r#"{
                "signatures": [
                    {
                        "id": "sensor-alpha",
                        "role": "coexisting_telemetry",
                        "bpf_prog_prefixes": ["alpha_"],
                        "proc_comm_prefixes": ["alpha-daemon"]
                    },
                    {
                        "id": "sensor-beta",
                        "role": "exclusive_enforcer",
                        "proc_comm_prefixes": ["beta-agent"]
                    }
                ]
            }"#,
            "inline",
        )
        .unwrap();

        let coexist_plan = broker_linux_slots(
            &SlotBrokerInputs {
                host: base_t1_host(),
                active_bpf_progs: vec!["alpha_execve".into()],
                active_proc_comms: vec!["alpha-daemon".into()],
                bpffs_pins: Vec::new(),
                trampoline_slots_used: 8,
                trampoline_cap: 36,
                trampoline_slots_enforce: 10,
                audit_netlink_readable: true,
            },
            &catalogue,
        );
        assert_eq!(coexist_plan.selected_tier, HostTier::T1FullEnforce);
        assert_eq!(coexist_plan.primary_rung, SlotRung::BpfLsmEnforce);
        assert_eq!(coexist_plan.coexisting_sensors.len(), 1);

        let exclusive_plan = broker_linux_slots(
            &SlotBrokerInputs {
                host: base_t1_host(),
                active_bpf_progs: Vec::new(),
                active_proc_comms: vec!["beta-agent".into()],
                bpffs_pins: Vec::new(),
                trampoline_slots_used: 34,
                trampoline_cap: 36,
                trampoline_slots_enforce: 10,
                audit_netlink_readable: false,
            },
            &catalogue,
        );
        assert_eq!(exclusive_plan.selected_tier, HostTier::T3DegradedObserve);
        assert_eq!(exclusive_plan.primary_rung, SlotRung::CgroupAndFanotify);
        assert!(!exclusive_plan.enforcement_possible);
        assert!(exclusive_plan.degradation_reasons.len() >= 2);

        let mut gvisor_host = base_t1_host();
        gvisor_host.runtime = RuntimeEnvironment::GVisor;
        let gvisor_plan = broker_linux_slots(
            &SlotBrokerInputs {
                host: gvisor_host,
                active_bpf_progs: Vec::new(),
                active_proc_comms: Vec::new(),
                bpffs_pins: Vec::new(),
                trampoline_slots_used: 0,
                trampoline_cap: 36,
                trampoline_slots_enforce: 10,
                audit_netlink_readable: false,
            },
            &catalogue,
        );
        assert_eq!(gvisor_plan.selected_tier, HostTier::T4Sidecar);
        assert!(!gvisor_plan.enforcement_possible);
    }
}
