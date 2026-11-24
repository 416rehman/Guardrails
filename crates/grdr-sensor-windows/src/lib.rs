// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod containment;
pub mod dev_drive;
pub mod driver_seam;
pub mod etw;
pub mod powershell;
pub mod wfp;

use grdr_model::error::CODE_STORE_IO;
use grdr_model::{
    ActionAttempt, ActionClass, AssuranceRecord, CodedError, ControlStrength, Finding,
    InstallProfile, OnFailure, TamperGrade, Visibility,
};
use grdr_ports::SensorPort;

pub use containment::{
    DenyAcePlan, JobObjectPlan, LaunchRoute, SandboxPrincipalKind, ToolContainmentPlan,
    WriteRestrictedTokenPlan, plan_tool_containment,
};
pub use dev_drive::{
    DevDriveCoverageProbe, DevDriveFilterPolicy, DevDriveTrust, DevDriveVolume,
    parse_fsutil_devdrv_output, probe_dev_drive_coverage,
};
pub use driver_seam::{
    DRIVER_PROTOCOL_MAGIC, DRIVER_PROTOCOL_VERSION, DRIVER_REPLY_DEADLINE_MS, DriverAttachmentKind,
    DriverBootGuard, DriverFloorVerdict, DriverProtocolHeader, WindowsDriverBackend,
};
pub use etw::{
    ETW_SESSION_NAME, EtwLossMetrics, EtwNormalizationOutcome, EtwProvenanceGrade, EtwProviderKind,
    EtwProviderSpec, EtwSessionDescriptor, EtwSource, NoopEtwSource, RawEtwRecord,
    default_etw_session_descriptor, evaluate_etw_loss, normalize_etw_record,
};
pub use powershell::{
    CaptureLevel, NormalizedScriptBlock, RawScriptBlockEvent, normalize_script_block_4104,
};
pub use wfp::{
    WfpFilterAction, WfpFilterRule, WfpLayer, WfpPrincipalKey, WfpSublayerPlan,
    plan_service_wfp_filters, plan_session_wfp_filters,
};

pub const CODE_WINSENS_ETW: &str = "GRDR-WINSENS-0001";
pub const CODE_WINSENS_WFP: &str = "GRDR-WINSENS-0002";
pub const CODE_WINSENS_CONTAINMENT: &str = "GRDR-WINSENS-0003";
pub const CODE_WINSENS_DEV_DRIVE: &str = "GRDR-WINSENS-0004";
pub const CODE_WINSENS_DRIVER: &str = "GRDR-WINSENS-0005";

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum WindowsSensorError {
    #[error("GRDR-WINSENS-0001: ETW collector fault: {0}")]
    Etw(String),
    #[error("GRDR-WINSENS-0002: WFP filter planner fault: {0}")]
    Wfp(String),
    #[error("GRDR-WINSENS-0003: Windows containment planner fault: {0}")]
    Containment(String),
    #[error("GRDR-WINSENS-0004: Dev Drive probe fault: {0}")]
    DevDrive(String),
    #[error("GRDR-WINSENS-0005: Windows kernel driver seam fault: {0}")]
    Driver(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum WindowsTier {
    W0Observe,
    W1Contain,
    W2Driver,
    W3HostPlatform,
}

#[derive(Debug)]
pub struct WindowsSensor<S> {
    source: S,
    device_id: String,
    device_name: String,
    tamper_findings: Vec<Finding>,
}

impl From<WindowsSensorError> for CodedError {
    fn from(err: WindowsSensorError) -> Self {
        let code = match &err {
            WindowsSensorError::Etw(_) => CODE_WINSENS_ETW,
            WindowsSensorError::Wfp(_) => CODE_WINSENS_WFP,
            WindowsSensorError::Containment(_) => CODE_WINSENS_CONTAINMENT,
            WindowsSensorError::DevDrive(_) => CODE_WINSENS_DEV_DRIVE,
            WindowsSensorError::Driver(_) => CODE_WINSENS_DRIVER,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Verify Windows sensor privileges and collector configuration.",
        )
    }
}

impl Default for WindowsSensor<NoopEtwSource> {
    fn default() -> Self {
        Self::new(NoopEtwSource, "local-windows", "windows-host")
    }
}

impl<S: EtwSource> WindowsSensor<S> {
    pub fn new(source: S, device_id: impl Into<String>, device_name: impl Into<String>) -> Self {
        Self {
            source,
            device_id: device_id.into(),
            device_name: device_name.into(),
            tamper_findings: Vec::new(),
        }
    }

    pub fn drain_tamper_findings(&mut self) -> Vec<Finding> {
        std::mem::take(&mut self.tamper_findings)
    }
}

impl<S: EtwSource> SensorPort for WindowsSensor<S> {
    fn sensor_name(&self) -> &'static str {
        "windows-etw"
    }

    fn poll_events(&mut self, max_events: usize) -> Result<Vec<ActionAttempt>, CodedError> {
        if max_events == 0 {
            return Ok(Vec::new());
        }
        let records = self.source.poll_records(max_events).map_err(|e| {
            CodedError::new(
                CODE_STORE_IO,
                format!("Windows ETW source failed: {e}"),
                "Verify Windows ETW session state and permissions.",
            )
        })?;
        let mut attempts = Vec::new();
        for record in records {
            if attempts.len() >= max_events {
                break;
            }
            match normalize_etw_record(&record, &self.device_id, &self.device_name) {
                EtwNormalizationOutcome::Attempt(attempt) => attempts.push(attempt),
                EtwNormalizationOutcome::TamperFinding(finding) => {
                    self.tamper_findings.push(finding);
                }
                EtwNormalizationOutcome::DroppedOutOfInterest => {}
            }
        }
        Ok(attempts)
    }
}

pub fn compute_windows_assurance(
    tier: WindowsTier,
    profile: InstallProfile,
    route: LaunchRoute,
    action_class: ActionClass,
    dev_drive_gap: bool,
) -> AssuranceRecord {
    if profile == InstallProfile::User {
        return AssuranceRecord {
            visibility: if action_class == ActionClass::Exec {
                Visibility::Observed
            } else {
                Visibility::Claimed
            },
            control: ControlStrength::Request,
            on_failure: OnFailure::Open,
            tamper: TamperGrade::User,
        };
    }

    let tamper = match tier {
        WindowsTier::W3HostPlatform => TamperGrade::Platform,
        _ => TamperGrade::Admin,
    };

    match tier {
        WindowsTier::W0Observe => AssuranceRecord {
            visibility: match action_class {
                ActionClass::Exec => Visibility::CrossChecked,
                ActionClass::NetConnect | ActionClass::FileWrite | ActionClass::FileDelete => {
                    Visibility::Observed
                }
                _ => Visibility::Claimed,
            },
            control: ControlStrength::Request,
            on_failure: OnFailure::Open,
            tamper,
        },
        WindowsTier::W1Contain => {
            let contained = route.provides_scoped_boundary_for(action_class);
            AssuranceRecord {
                visibility: if action_class == ActionClass::Exec {
                    Visibility::CrossChecked
                } else {
                    Visibility::Observed
                },
                control: if contained {
                    ControlStrength::ScopedBoundary
                } else {
                    ControlStrength::Request
                },
                on_failure: if contained {
                    OnFailure::Closed
                } else {
                    OnFailure::Open
                },
                tamper,
            }
        }
        WindowsTier::W2Driver => {
            let file_dev_drive_loss = dev_drive_gap
                && matches!(
                    action_class,
                    ActionClass::FileWrite | ActionClass::FileDelete
                );
            AssuranceRecord {
                visibility: Visibility::CrossChecked,
                control: if file_dev_drive_loss {
                    ControlStrength::ScopedBoundary
                } else {
                    ControlStrength::MandatoryBoundary
                },
                on_failure: OnFailure::Closed,
                tamper,
            }
        }
        WindowsTier::W3HostPlatform => AssuranceRecord {
            visibility: Visibility::CrossChecked,
            control: ControlStrength::MandatoryBoundary,
            on_failure: OnFailure::Closed,
            tamper,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use jiff::Timestamp;
    use std::collections::VecDeque;

    struct ScriptedEtwSource {
        queue: VecDeque<RawEtwRecord>,
    }

    impl EtwSource for ScriptedEtwSource {
        fn session_name(&self) -> &str {
            ETW_SESSION_NAME
        }

        fn poll_records(
            &mut self,
            max_records: usize,
        ) -> Result<Vec<RawEtwRecord>, WindowsSensorError> {
            let mut out = Vec::new();
            for _ in 0..max_records {
                let Some(item) = self.queue.pop_front() else {
                    break;
                };
                out.push(item);
            }
            Ok(out)
        }
    }

    #[test]
    fn windows_sensor_satisfies_port_contract_and_computes_honest_assurance() {
        let mut queue = VecDeque::new();
        queue.push_back(RawEtwRecord {
            provider: EtwProviderKind::KernelProcess,
            event_id: 1,
            kernel_header_pid: 4200,
            claimed_pid: 4200,
            parent_pid: 1000,
            process_image: "claude.exe".into(),
            in_agent_lineage: true,
            target: "git status".into(),
            session_id: "sess-win-1".into(),
            agent_name: "claude-code".into(),
            timestamp: Timestamp::from_second(1_700_000_000).unwrap(),
        });

        let mut sensor = WindowsSensor::new(
            ScriptedEtwSource { queue },
            "dev-win-1",
            "win11-workstation",
        );
        assert!(grdr_ports_testkit::assert_sensor_port_contract(&mut sensor).is_ok());

        let user_rec = compute_windows_assurance(
            WindowsTier::W1Contain,
            InstallProfile::User,
            LaunchRoute::GrdrRun,
            ActionClass::Exec,
            false,
        );
        assert_eq!(user_rec.control, ControlStrength::Request);
        assert_eq!(user_rec.level(), grdr_model::AssuranceLevel::Al2Guided);

        let w2_dev_drive = compute_windows_assurance(
            WindowsTier::W2Driver,
            InstallProfile::Protected,
            LaunchRoute::Delegate,
            ActionClass::FileWrite,
            true,
        );
        assert_eq!(w2_dev_drive.control, ControlStrength::ScopedBoundary);
        assert_eq!(
            w2_dev_drive.level(),
            grdr_model::AssuranceLevel::Al3Contained
        );
    }
}
