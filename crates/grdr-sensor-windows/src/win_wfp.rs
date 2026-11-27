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
        #[cfg(windows)]
        {
            let elevated = crate::win_wfp_sys::tests::current_process_is_elevated_admin()
                .expect("token elevation check must succeed");
            if elevated {
                assert_eq!(report.engine_access, WfpEngineAccess::ReadOnlyProbe);
                assert_eq!(report.provider_count, report.providers.len());
            } else {
                assert_eq!(report.engine_access, WfpEngineAccess::AccessDenied);
                assert_eq!(report.provider_count, 0);
                assert!(report.providers.is_empty());
            }
        }
        #[cfg(not(windows))]
        {
            assert_eq!(report.engine_access, WfpEngineAccess::UnsupportedPlatform);
            assert_eq!(report.provider_count, 0);
            assert!(report.providers.is_empty());
        }
    }

    #[test]
    fn apply_plan_respects_privileges_or_platform() {
        for principal in [
            WfpPrincipalKey::AppContainerPackageSid {
                package_sid: "S-1-15-2-1001".into(),
            },
            WfpPrincipalKey::AppContainerPackageSid {
                package_sid: "S-1-15-2-1-2-3-4-5-6-7-8".into(),
            },
            WfpPrincipalKey::SandboxSid {
                sid: "S-1-5-21-1000-2000-3000-1001".into(),
            },
            WfpPrincipalKey::ServiceSid {
                service_sid: "S-1-5-80-1234567890-1-2-3".into(),
            },
        ] {
            let plan = plan_session_wfp_filters(principal, 18080, Some(18081)).expect("valid plan");
            let applied = apply_wfp_sublayer_plan(&plan).expect("graceful non-admin behavior");
            #[cfg(windows)]
            {
                let elevated = crate::win_wfp_sys::tests::current_process_is_elevated_admin()
                    .expect("token elevation check must succeed");
                if elevated {
                    assert!(
                        applied.applied,
                        "elevated admin must apply WFP filters: {}",
                        applied.detail
                    );
                    assert_eq!(applied.filter_ids.len(), plan.rules.len());
                    let removed = remove_applied_wfp_filters(&applied).expect("cleanup");
                    assert_eq!(removed, plan.rules.len());
                } else {
                    assert!(!applied.applied);
                    assert!(applied.filter_ids.is_empty());
                }
            }
            #[cfg(not(windows))]
            {
                assert!(!applied.applied);
                assert!(applied.filter_ids.is_empty());
                let probe = probe_wfp_coexistence().expect("platform probe");
                assert_eq!(probe.engine_access, WfpEngineAccess::UnsupportedPlatform);
            }
        }
    }
}
