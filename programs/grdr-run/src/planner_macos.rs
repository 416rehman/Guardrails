// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use grdr_model::{ActionClass, AssuranceLevel, AssuranceRecord};
use grdr_sensor_macos::{
    AuthDeadlineBudget, DeadlineMissPolicy, DelegationPolicy, HarnessCatalogue,
    MacOsCapabilityFlags, MacOsContainmentMode, MacOsLimitsSnapshot, MacOsTier, SeatbeltLaunchPlan,
    SeatbeltProfileSpec, SlotRung, compute_macos_assurance, es_tree::EsClientStatus,
    generate_sbpl_profile_with_tmp, plan_macos_launch, probe_local_capabilities,
    scoped_session_tmp_dir,
};

use crate::RunError;
use crate::planner::{ContainmentStrategy, LaunchRequestSpec, PlatformContainmentPlan};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MacOsSuperviseMissMode {
    FailOpen,
    FailClosed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsSuperviseConfig {
    pub deadline_floor_ms: u64,
    pub miss_mode: MacOsSuperviseMissMode,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MacOsSupervisorPlan {
    pub descendants_mode: bool,
    pub deadline_floor_ms: u64,
    pub hold_cap_ms: u64,
    pub miss_policy: DeadlineMissPolicy,
    pub es_verified_live: bool,
}

pub(crate) fn resolve_macos_delegate_strategy(
    agent_name: &str,
    agent_has_native_sandbox: bool,
) -> ContainmentStrategy {
    if !agent_has_native_sandbox {
        return ContainmentStrategy::WrapAgent;
    }
    if let Some(entry) = HarnessCatalogue::embedded().find_by_kind(agent_name) {
        return match entry.delegation_mode {
            DelegationPolicy::Delegate => ContainmentStrategy::Delegate,
            DelegationPolicy::WrapTools => ContainmentStrategy::WrapTools,
            DelegationPolicy::WrapAgent => ContainmentStrategy::WrapAgent,
        };
    }
    ContainmentStrategy::WrapTools
}

pub(crate) fn build_macos_plan(
    req: &LaunchRequestSpec,
    strategy: ContainmentStrategy,
    proxy_env: &mut BTreeMap<String, String>,
) -> Result<PlatformContainmentPlan, RunError> {
    let scoped_tmp = if matches!(
        strategy,
        ContainmentStrategy::WrapTools | ContainmentStrategy::WrapAgent
    ) {
        Some(
            scoped_session_tmp_dir(&req.session_id)
                .map_err(|e| RunError::InvalidPlan(e.to_string()))?,
        )
    } else {
        None
    };

    let sb_spec = SeatbeltProfileSpec {
        session_id: req.session_id.clone(),
        workspace_root: req.workspace_root.clone(),
        state_dirs: req.state_dirs.clone(),
        protected_paths: req.protected_paths.clone(),
        decide_socket_path: req.decide_socket_path.clone(),
        proxy_port: req.proxy_port,
        deny_elevation_binaries: true,
    };

    let launch = match strategy {
        ContainmentStrategy::Delegate => {
            plan_macos_launch(&req.agent_name, req.agent_has_native_sandbox, &sb_spec)
                .map_err(|e| RunError::InvalidPlan(e.to_string()))?
        }
        ContainmentStrategy::WrapTools => {
            let tmp_dir = scoped_tmp
                .as_deref()
                .ok_or_else(|| RunError::InvalidPlan("missing scoped macOS tmp dir".into()))?;
            SeatbeltLaunchPlan {
                containment_mode: MacOsContainmentMode::WrapTools,
                visibility_is_claimed: true,
                on_failure_closed: true,
                profile_sbpl: Some(
                    generate_sbpl_profile_with_tmp(&sb_spec, tmp_dir)
                        .map_err(|e| RunError::InvalidPlan(e.to_string()))?,
                ),
                reason: "explicit WrapTools Seatbelt profile generated".into(),
            }
        }
        ContainmentStrategy::WrapAgent => {
            let tmp_dir = scoped_tmp
                .as_deref()
                .ok_or_else(|| RunError::InvalidPlan("missing scoped macOS tmp dir".into()))?;
            SeatbeltLaunchPlan {
                containment_mode: MacOsContainmentMode::WrapAgent,
                visibility_is_claimed: true,
                on_failure_closed: true,
                profile_sbpl: Some(
                    generate_sbpl_profile_with_tmp(&sb_spec, tmp_dir)
                        .map_err(|e| RunError::InvalidPlan(e.to_string()))?,
                ),
                reason: "explicit WrapAgent Seatbelt profile generated".into(),
            }
        }
        ContainmentStrategy::RequestOnly => SeatbeltLaunchPlan {
            containment_mode: MacOsContainmentMode::RequestOnly,
            visibility_is_claimed: true,
            on_failure_closed: false,
            profile_sbpl: None,
            reason: "request-only fallback configured explicitly".into(),
        },
    };

    if launch.profile_sbpl.is_some()
        && let Some(tmp_dir) = scoped_tmp
    {
        proxy_env.insert("TMPDIR".into(), tmp_dir);
    }

    let (supervisor, tier, es_status) = if let Some(sup) = &req.macos_supervise {
        let floor_ms = if sup.deadline_floor_ms > 0 {
            sup.deadline_floor_ms
        } else {
            MacOsLimitsSnapshot::try_embedded()
                .map_err(|e| RunError::InvalidPlan(e.to_string()))?
                .command_hold_max_ms
        };
        let budget = AuthDeadlineBudget::for_descendants_supervisor(
            floor_ms,
            sup.miss_mode == MacOsSuperviseMissMode::FailClosed,
        )
        .map_err(|e| RunError::InvalidPlan(e.to_string()))?;

        proxy_env.insert("GRDR_MAC_SUPERVISE".into(), "1".into());
        proxy_env.insert(
            "GRDR_MAC_SUPERVISE_DEADLINE_FLOOR_MS".into(),
            budget.kernel_deadline_ms.to_string(),
        );
        proxy_env.insert(
            "GRDR_MAC_SUPERVISE_HOLD_CAP_MS".into(),
            budget.engine_cutoff_ms.to_string(),
        );
        proxy_env.insert(
            "GRDR_MAC_SUPERVISE_FAIL_CLOSED".into(),
            if budget.policy == DeadlineMissPolicy::DescendantsFailClosed {
                "1".into()
            } else {
                "0".into()
            },
        );
        let live_caps =
            probe_local_capabilities(None).map_err(|e| RunError::InvalidPlan(e.to_string()))?;
        let es_verified_live =
            cfg!(target_os = "macos") && live_caps.es_status == EsClientStatus::Active;
        let (tier, es_status) = if es_verified_live {
            (MacOsTier::Tier3EndpointSecurity, EsClientStatus::Active)
        } else {
            (MacOsTier::Tier1HooksAndSeatbelt, live_caps.es_status)
        };
        (
            Some(MacOsSupervisorPlan {
                descendants_mode: true,
                deadline_floor_ms: budget.kernel_deadline_ms,
                hold_cap_ms: budget.engine_cutoff_ms,
                miss_policy: budget.policy,
                es_verified_live,
            }),
            tier,
            es_status,
        )
    } else {
        (
            None,
            MacOsTier::Tier1HooksAndSeatbelt,
            EsClientStatus::MissingEntitlement,
        )
    };

    let caps = MacOsCapabilityFlags {
        profile: req.profile,
        tier,
        containment: launch.containment_mode,
        content_filter_rung: SlotRung::Observe,
        es_status,
    };
    let exec_assurance: AssuranceRecord = compute_macos_assurance(&caps, ActionClass::Exec);
    let net_assurance: AssuranceRecord = compute_macos_assurance(&caps, ActionClass::NetConnect);
    let exec_level: AssuranceLevel = exec_assurance.level();
    Ok(PlatformContainmentPlan::MacOs {
        launch,
        supervisor,
        exec_assurance,
        net_assurance,
        exec_level,
    })
}
