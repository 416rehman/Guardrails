// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::ActionClass;

use crate::WindowsSensorError;
use crate::wfp::validate_sid_syntax;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SandboxPrincipalKind {
    AppContainer,
    MxcProcessContainer,
    LocalSandboxUser,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LaunchRoute {
    GrdrRun,
    ProcessWrapper,
    Delegate,
    HookRewrite,
    AdoptedAttributionOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobObjectPlan {
    pub job_name: String,
    pub no_breakaway: bool,
    pub kill_on_close: bool,
    pub active_process_limit: Option<u32>,
    pub memory_limit_bytes: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WriteRestrictedTokenPlan {
    pub principal_kind: SandboxPrincipalKind,
    pub sandbox_sid: String,
    pub granted_write_paths: Vec<String>,
    pub deny_elevate: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DenyAcePlan {
    pub target_path: String,
    pub sandbox_sid: String,
    pub deny_read_write: bool,
    pub deny_execute: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ToolContainmentPlan {
    pub route: LaunchRoute,
    pub job: JobObjectPlan,
    pub token: WriteRestrictedTokenPlan,
    pub deny_aces: Vec<DenyAcePlan>,
}

impl LaunchRoute {
    pub const fn provides_scoped_boundary_for(self, class: ActionClass) -> bool {
        match self {
            Self::GrdrRun | Self::ProcessWrapper | Self::Delegate => matches!(
                class,
                ActionClass::Exec
                    | ActionClass::FileRead
                    | ActionClass::FileWrite
                    | ActionClass::FileDelete
                    | ActionClass::NetConnect
                    | ActionClass::Elevate
            ),
            Self::HookRewrite => matches!(
                class,
                ActionClass::Exec | ActionClass::NetConnect | ActionClass::Elevate
            ),
            Self::AdoptedAttributionOnly => false,
        }
    }
}

pub fn plan_tool_containment(
    session_id: &str,
    route: LaunchRoute,
    principal_kind: SandboxPrincipalKind,
    sandbox_sid: &str,
    workspace_root: &str,
    protected_paths: &[String],
    memory_limit_bytes: u64,
) -> Result<ToolContainmentPlan, WindowsSensorError> {
    let clean_session = session_id.trim();
    if clean_session.is_empty()
        || clean_session.len() > 128
        || !clean_session
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '-' || c == '_')
    {
        return Err(WindowsSensorError::Containment(format!(
            "invalid containment session_id `{session_id}`"
        )));
    }
    let clean_ws = workspace_root.trim();
    if clean_ws.is_empty() || clean_ws.chars().any(|c| c == '\0' || c.is_control()) {
        return Err(WindowsSensorError::Containment(
            "workspace_root must be non-empty and control-char free".into(),
        ));
    }
    for path in protected_paths {
        if path.trim().is_empty() || path.chars().any(|c| c == '\0' || c.is_control()) {
            return Err(WindowsSensorError::Containment(format!(
                "invalid protected path `{path}`"
            )));
        }
    }
    if memory_limit_bytes == 0 {
        return Err(WindowsSensorError::Containment(
            "memory_limit_bytes must be non-zero".into(),
        ));
    }
    validate_sid_syntax(sandbox_sid).map_err(|e| WindowsSensorError::Containment(e.to_string()))?;

    let job = JobObjectPlan {
        job_name: format!("grdr-job-{clean_session}"),
        no_breakaway: true,
        kill_on_close: true,
        active_process_limit: None,
        memory_limit_bytes,
    };

    let token = WriteRestrictedTokenPlan {
        principal_kind,
        sandbox_sid: sandbox_sid.trim().to_string(),
        granted_write_paths: vec![workspace_root.trim().to_string()],
        deny_elevate: true,
    };

    let deny_aces = protected_paths
        .iter()
        .map(|path| DenyAcePlan {
            target_path: path.clone(),
            sandbox_sid: sandbox_sid.trim().to_string(),
            deny_read_write: true,
            deny_execute: true,
        })
        .collect();

    Ok(ToolContainmentPlan {
        route,
        job,
        token,
        deny_aces,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn route_boundaries_distinguish_hook_rewrite_and_adopted() {
        assert!(LaunchRoute::HookRewrite.provides_scoped_boundary_for(ActionClass::Exec));
        assert!(!LaunchRoute::HookRewrite.provides_scoped_boundary_for(ActionClass::FileWrite));
        assert!(LaunchRoute::GrdrRun.provides_scoped_boundary_for(ActionClass::FileWrite));
        assert!(
            !LaunchRoute::AdoptedAttributionOnly.provides_scoped_boundary_for(ActionClass::Exec)
        );
    }

    #[test]
    fn plans_job_token_and_execute_deny_aces_and_rejects_invalid_inputs() {
        assert!(
            plan_tool_containment(
                "s-1",
                LaunchRoute::GrdrRun,
                SandboxPrincipalKind::AppContainer,
                "not-a-sid",
                r"D:\repo",
                &[],
                1024,
            )
            .is_err()
        );
        assert!(
            plan_tool_containment(
                r"evil\..\job",
                LaunchRoute::GrdrRun,
                SandboxPrincipalKind::AppContainer,
                "S-1-15-2-42",
                r"D:\repo",
                &[],
                1024,
            )
            .is_err()
        );
        assert!(
            plan_tool_containment(
                "s-1",
                LaunchRoute::GrdrRun,
                SandboxPrincipalKind::AppContainer,
                "S-1-15-2-42",
                "",
                &[],
                1024,
            )
            .is_err()
        );
        assert!(
            plan_tool_containment(
                "s-1",
                LaunchRoute::GrdrRun,
                SandboxPrincipalKind::AppContainer,
                "S-1-15-2-42",
                r"D:\repo",
                &[],
                0,
            )
            .is_err()
        );

        let plan = plan_tool_containment(
            "s-win-1",
            LaunchRoute::GrdrRun,
            SandboxPrincipalKind::AppContainer,
            "S-1-15-2-42",
            r"D:\repo",
            &[r"C:\Users\dev\.ssh".into()],
            512 * 1024 * 1024,
        )
        .unwrap();
        assert!(plan.job.no_breakaway);
        assert!(plan.job.kill_on_close);
        assert_eq!(plan.deny_aces.len(), 1);
        assert!(plan.deny_aces[0].deny_execute);
    }
}
