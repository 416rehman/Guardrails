// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use serde::{Deserialize, Serialize};

use crate::WindowsSensorError;
use crate::wfp::WfpSublayerPlan;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum WfpEngineAccess {
    FullAdminWrite,
    ReadOnlyProbe,
    AccessDenied,
    UnsupportedPlatform,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpProviderInfo {
    pub key: String,
    pub name: String,
    pub persistent: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WfpCoexistenceReport {
    pub engine_access: WfpEngineAccess,
    pub provider_count: usize,
    pub providers: Vec<WfpProviderInfo>,
    pub grdr_sublayer_present: bool,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppliedWfpRules {
    pub applied: bool,
    pub filter_ids: Vec<u64>,
    pub detail: String,
}

pub fn probe_wfp_coexistence() -> Result<WfpCoexistenceReport, WindowsSensorError> {
    #[cfg(windows)]
    {
        crate::win_wfp_sys::probe_win_wfp_coexistence()
    }
    #[cfg(not(windows))]
    {
        Ok(WfpCoexistenceReport {
            engine_access: WfpEngineAccess::UnsupportedPlatform,
            provider_count: 0,
            providers: Vec::new(),
            grdr_sublayer_present: false,
            detail: "WFP probe unavailable on non-Windows host".to_string(),
        })
    }
}

pub fn apply_wfp_sublayer_plan(
    plan: &WfpSublayerPlan,
) -> Result<AppliedWfpRules, WindowsSensorError> {
    #[cfg(windows)]
    {
        crate::win_wfp_sys::apply_win_wfp_plan(plan)
    }
    #[cfg(not(windows))]
    {
        let _ = plan;
        Ok(AppliedWfpRules {
            applied: false,
            filter_ids: Vec::new(),
            detail: "WFP filter installation unavailable on non-Windows host".to_string(),
        })
    }
}

pub fn remove_applied_wfp_filters(applied: &AppliedWfpRules) -> Result<usize, WindowsSensorError> {
    #[cfg(windows)]
    {
        crate::win_wfp_sys::remove_win_wfp_filters(applied)
    }
    #[cfg(not(windows))]
    {
        let _ = applied;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wfp::{WfpPrincipalKey, plan_session_wfp_filters};

    #[test]
    fn coexistence_probe_returns_clean_report_or_graceful_denial() {
        let report = probe_wfp_coexistence().expect("probe must handle non-admin cleanly");
        assert!(matches!(
            report.engine_access,
            WfpEngineAccess::FullAdminWrite
                | WfpEngineAccess::ReadOnlyProbe
                | WfpEngineAccess::AccessDenied
                | WfpEngineAccess::UnsupportedPlatform
        ));
    }

    #[test]
    fn apply_plan_respects_privileges_or_platform() {
        let plan = plan_session_wfp_filters(
            WfpPrincipalKey::AppContainerPackageSid {
                package_sid: "S-1-15-2-1001".into(),
            },
            18080,
            Some(18081),
        )
        .expect("valid plan");
        let applied = apply_wfp_sublayer_plan(&plan).expect("graceful non-admin behavior");
        if applied.applied {
            let removed = remove_applied_wfp_filters(&applied).expect("cleanup");
            assert_eq!(removed, applied.filter_ids.len());
        } else {
            assert!(applied.filter_ids.is_empty());
        }
    }
}
