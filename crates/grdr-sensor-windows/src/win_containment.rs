// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use serde::{Deserialize, Serialize};

use crate::WindowsSensorError;
use crate::containment::{DenyAcePlan, JobObjectPlan, WriteRestrictedTokenPlan};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AppContainerProvisioned {
    pub profile_name: String,
    pub sid_string: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AclJournalEntry {
    pub target_path: String,
    pub prior_dacl_sddl: String,
    pub protected_dacl: bool,
}

#[derive(Debug)]
pub struct WinJobObjectHandle {
    #[cfg(windows)]
    inner: crate::win_containment_sys::WinJobHandle,
    job_name: String,
}

#[derive(Debug)]
pub struct WinRestrictedTokenHandle {
    #[cfg(windows)]
    inner: crate::win_containment_sys::WinRestrictedToken,
    sandbox_sid: String,
}

#[derive(Debug)]
pub struct WinSecurityCapabilitiesHandle {
    #[cfg(windows)]
    inner: crate::win_containment_sys::WinSecurityCapabilities,
    package_sid: String,
}

impl WinJobObjectHandle {
    pub fn from_plan(plan: &JobObjectPlan) -> Result<Self, WindowsSensorError> {
        #[cfg(windows)]
        {
            let inner = crate::win_containment_sys::WinJobHandle::from_plan(plan)?;
            Ok(Self {
                inner,
                job_name: plan.job_name.clone(),
            })
        }
        #[cfg(not(windows))]
        {
            Ok(Self {
                job_name: plan.job_name.clone(),
            })
        }
    }

    pub fn job_name(&self) -> &str {
        &self.job_name
    }

    pub fn assign_process(&self, pid: u32) -> Result<(), WindowsSensorError> {
        #[cfg(windows)]
        {
            self.inner.assign_process(pid)
        }
        #[cfg(not(windows))]
        {
            let _ = pid;
            Err(WindowsSensorError::Containment(
                "Win32 Job Object assignment unavailable on non-Windows host".to_string(),
            ))
        }
    }

    pub fn terminate(&self, exit_code: u32) -> Result<(), WindowsSensorError> {
        #[cfg(windows)]
        {
            self.inner.terminate(exit_code)
        }
        #[cfg(not(windows))]
        {
            let _ = exit_code;
            Ok(())
        }
    }
}

impl WinRestrictedTokenHandle {
    pub fn from_plan(plan: &WriteRestrictedTokenPlan) -> Result<Self, WindowsSensorError> {
        #[cfg(windows)]
        {
            let inner = crate::win_containment_sys::WinRestrictedToken::from_plan(plan)?;
            Ok(Self {
                inner,
                sandbox_sid: plan.sandbox_sid.clone(),
            })
        }
        #[cfg(not(windows))]
        {
            Err(WindowsSensorError::Containment(format!(
                "Win32 restricted token unavailable on non-Windows host for SID `{}`",
                plan.sandbox_sid
            )))
        }
    }

    pub fn sandbox_sid(&self) -> &str {
        &self.sandbox_sid
    }

    pub fn is_valid(&self) -> bool {
        #[cfg(windows)]
        {
            self.inner.is_valid()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

impl WinSecurityCapabilitiesHandle {
    pub fn from_package_sid(package_sid: &str) -> Result<Self, WindowsSensorError> {
        #[cfg(windows)]
        {
            let inner =
                crate::win_containment_sys::WinSecurityCapabilities::from_app_container_sid(
                    package_sid,
                )?;
            Ok(Self {
                inner,
                package_sid: package_sid.to_string(),
            })
        }
        #[cfg(not(windows))]
        {
            Err(WindowsSensorError::Containment(format!(
                "Win32 AppContainer SECURITY_CAPABILITIES unavailable on non-Windows host for `{package_sid}`"
            )))
        }
    }

    pub fn package_sid(&self) -> &str {
        &self.package_sid
    }

    pub fn is_valid(&self) -> bool {
        #[cfg(windows)]
        {
            !self.inner.app_container_sid_ptr().is_null()
        }
        #[cfg(not(windows))]
        {
            false
        }
    }
}

pub fn provision_app_container(
    profile_name: &str,
    display_name: &str,
    description: &str,
) -> Result<AppContainerProvisioned, WindowsSensorError> {
    if profile_name.trim().is_empty() || profile_name.len() > 64 {
        return Err(WindowsSensorError::Containment(
            "AppContainer profile_name must be 1..=64 chars".to_string(),
        ));
    }
    #[cfg(windows)]
    {
        crate::win_containment_sys::provision_win_app_container(
            profile_name,
            display_name,
            description,
        )
    }
    #[cfg(not(windows))]
    {
        let _ = (display_name, description);
        Err(WindowsSensorError::Containment(
            "AppContainer provisioning unavailable on non-Windows host".to_string(),
        ))
    }
}

pub fn remove_app_container(profile_name: &str) -> Result<(), WindowsSensorError> {
    #[cfg(windows)]
    {
        crate::win_containment_sys::delete_win_app_container(profile_name)
    }
    #[cfg(not(windows))]
    {
        let _ = profile_name;
        Ok(())
    }
}

pub fn apply_deny_aces(plans: &[DenyAcePlan]) -> Result<Vec<AclJournalEntry>, WindowsSensorError> {
    #[cfg(windows)]
    {
        crate::win_acl_sys::apply_win_deny_aces(plans)
    }
    #[cfg(not(windows))]
    {
        let _ = plans;
        Err(WindowsSensorError::Containment(
            "Win32 DACL Deny ACEs unavailable on non-Windows host".to_string(),
        ))
    }
}

pub fn restore_deny_aces(entries: &[AclJournalEntry]) -> Result<usize, WindowsSensorError> {
    #[cfg(windows)]
    {
        crate::win_acl_sys::restore_win_deny_aces(entries)
    }
    #[cfg(not(windows))]
    {
        let _ = entries;
        Ok(0)
    }
}

#[cfg(test)]
mod tests {
    #[cfg(windows)]
    use super::*;
    #[cfg(windows)]
    use crate::containment::{LaunchRoute, SandboxPrincipalKind, plan_tool_containment};

    #[cfg(windows)]
    #[test]
    fn creates_and_terminates_live_job_object_security_caps_and_restricted_token() {
        let plan_ac = plan_tool_containment(
            "unit-win-job-1",
            LaunchRoute::GrdrRun,
            SandboxPrincipalKind::AppContainer,
            "S-1-15-2-1001",
            r"C:\repo",
            &[],
            64 * 1024 * 1024,
        )
        .expect("plan ac");

        let job = WinJobObjectHandle::from_plan(&plan_ac.job).expect("create Job Object");
        assert_eq!(job.job_name(), "grdr-job-unit-win-job-1");
        assert!(WinJobObjectHandle::from_plan(&plan_ac.job).is_err());
        job.terminate(0)
            .expect("terminate empty Job Object cleanly");

        assert!(WinRestrictedTokenHandle::from_plan(&plan_ac.token).is_err());
        let sec_caps = WinSecurityCapabilitiesHandle::from_package_sid("S-1-15-2-1001")
            .expect("AppContainer SECURITY_CAPABILITIES");
        assert!(sec_caps.is_valid());
        assert_eq!(sec_caps.package_sid(), "S-1-15-2-1001");

        let plan_user = plan_tool_containment(
            "unit-win-job-2",
            LaunchRoute::GrdrRun,
            SandboxPrincipalKind::LocalSandboxUser,
            "S-1-5-21-1000-2000-3000-1001",
            r"C:\repo",
            &[],
            64 * 1024 * 1024,
        )
        .expect("plan user");
        let token =
            WinRestrictedTokenHandle::from_plan(&plan_user.token).expect("derive restricted token");
        assert!(token.is_valid());
        assert_eq!(token.sandbox_sid(), "S-1-5-21-1000-2000-3000-1001");
    }

    #[cfg(windows)]
    #[test]
    fn provisions_app_container_and_applies_reversible_deny_ace_journal() {
        let profile = format!("grdr.unit.ac.{}", std::process::id());
        let ac = provision_app_container(&profile, "Guardrails Unit", "Unit test profile")
            .expect("provision AppContainer");
        assert!(ac.sid_string.starts_with("S-1-15-2-"));

        let temp_dir = std::env::temp_dir().join(format!("grdr-acl-test-{}", std::process::id()));
        std::fs::create_dir_all(&temp_dir).expect("create temp test dir");
        let target = temp_dir.to_string_lossy().into_owned();
        let entries = apply_deny_aces(&[DenyAcePlan {
            target_path: target.clone(),
            sandbox_sid: ac.sid_string.clone(),
            deny_read_write: true,
            deny_execute: true,
        }])
        .expect("apply Deny ACE");
        assert_eq!(entries.len(), 1);
        assert!(
            entries
                .first()
                .is_some_and(|e| e.prior_dacl_sddl.starts_with("D:"))
        );

        let restored = restore_deny_aces(&entries).expect("restore prior DACL");
        assert_eq!(restored, 1);

        let _ = std::fs::remove_dir_all(&temp_dir);
        remove_app_container(&profile).expect("cleanup AppContainer profile");
    }
}
