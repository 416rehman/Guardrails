// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_model::{
    ActionAttempt, ActionClass, ControlPoint, Finding, FindingClass, FindingLifecycle,
    FindingSeverity,
};

use crate::WindowsSensorError;

pub const ETW_SESSION_NAME: &str = "Grdr-Sensor-Trace";
pub const MAX_OS_ETW_SESSIONS: u32 = 64;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwProviderKind {
    KernelProcess,
    KernelNetwork,
    KernelFile,
    KernelRegistry,
    DnsClient,
    PowerShellScriptBlock,
    WfpDrop,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EtwProvenanceGrade {
    ObservedKernel,
    ObservedUser,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtwProviderSpec {
    pub kind: EtwProviderKind,
    pub provider_name: String,
    pub provider_guid: String,
    pub grade: EtwProvenanceGrade,
    pub agent_lineage_only: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EtwSessionDescriptor {
    pub session_name: String,
    pub max_os_sessions_limit: u32,
    pub providers: Vec<EtwProviderSpec>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RawEtwRecord {
    pub provider: EtwProviderKind,
    pub event_id: u16,
    pub kernel_header_pid: u32,
    pub claimed_pid: u32,
    pub parent_pid: u32,
    pub process_image: String,
    pub in_agent_lineage: bool,
    pub target: String,
    pub session_id: String,
    pub agent_name: String,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EtwNormalizationOutcome {
    Attempt(ActionAttempt),
    TamperFinding(Finding),
    DroppedOutOfInterest,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, Serialize, Deserialize)]
pub struct EtwLossMetrics {
    pub events_lost: u64,
    pub buffers_lost: u64,
    pub prior_rate_per_sec: u64,
    pub current_rate_per_sec: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "signal", rename_all = "snake_case")]
pub enum CoverageLossSignal {
    Healthy,
    LossReported { events_lost: u64, buffers_lost: u64 },
    SpikeThenSilenceDetected,
}

pub trait EtwSource: Send {
    fn session_name(&self) -> &str;
    fn poll_records(&mut self, max_records: usize)
    -> Result<Vec<RawEtwRecord>, WindowsSensorError>;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct NoopEtwSource;

impl EtwProviderKind {
    pub const fn grade(self) -> EtwProvenanceGrade {
        match self {
            Self::KernelProcess
            | Self::KernelNetwork
            | Self::KernelFile
            | Self::KernelRegistry
            | Self::WfpDrop => EtwProvenanceGrade::ObservedKernel,
            Self::DnsClient | Self::PowerShellScriptBlock => EtwProvenanceGrade::ObservedUser,
        }
    }

    pub const fn agent_lineage_only(self) -> bool {
        !matches!(self, Self::KernelProcess | Self::KernelRegistry)
    }

    pub const fn action_class(self) -> ActionClass {
        match self {
            Self::KernelProcess => ActionClass::Exec,
            Self::KernelNetwork | Self::DnsClient | Self::WfpDrop => ActionClass::NetConnect,
            Self::KernelFile => ActionClass::FileWrite,
            Self::KernelRegistry => ActionClass::ConfigChange,
            Self::PowerShellScriptBlock => ActionClass::Exec,
        }
    }
}

impl EtwSource for NoopEtwSource {
    fn session_name(&self) -> &str {
        ETW_SESSION_NAME
    }

    fn poll_records(
        &mut self,
        _max_records: usize,
    ) -> Result<Vec<RawEtwRecord>, WindowsSensorError> {
        Ok(Vec::new())
    }
}

pub fn default_etw_session_descriptor() -> EtwSessionDescriptor {
    EtwSessionDescriptor {
        session_name: ETW_SESSION_NAME.into(),
        max_os_sessions_limit: MAX_OS_ETW_SESSIONS,
        providers: vec![
            EtwProviderSpec {
                kind: EtwProviderKind::KernelProcess,
                provider_name: "Microsoft-Windows-Kernel-Process".into(),
                provider_guid: "22fb2cd6-0e7b-422b-a0c7-2fad1fd0e716".into(),
                grade: EtwProvenanceGrade::ObservedKernel,
                agent_lineage_only: false,
            },
            EtwProviderSpec {
                kind: EtwProviderKind::KernelNetwork,
                provider_name: "Microsoft-Windows-Kernel-Network".into(),
                provider_guid: "7dd42a49-5329-4832-8dfd-43d979153a88".into(),
                grade: EtwProvenanceGrade::ObservedKernel,
                agent_lineage_only: true,
            },
            EtwProviderSpec {
                kind: EtwProviderKind::KernelFile,
                provider_name: "Microsoft-Windows-Kernel-File".into(),
                provider_guid: "edd08927-9cc4-4e65-b970-c2560fb5c289".into(),
                grade: EtwProvenanceGrade::ObservedKernel,
                agent_lineage_only: true,
            },
            EtwProviderSpec {
                kind: EtwProviderKind::KernelRegistry,
                provider_name: "Microsoft-Windows-Kernel-Registry".into(),
                provider_guid: "70eb4f03-c1de-4f73-a051-33d13d5413bd".into(),
                grade: EtwProvenanceGrade::ObservedKernel,
                agent_lineage_only: false,
            },
            EtwProviderSpec {
                kind: EtwProviderKind::DnsClient,
                provider_name: "Microsoft-Windows-DNS-Client".into(),
                provider_guid: "1c95126e-7eea-49a9-a3fe-a378b03ddb4d".into(),
                grade: EtwProvenanceGrade::ObservedUser,
                agent_lineage_only: true,
            },
            EtwProviderSpec {
                kind: EtwProviderKind::PowerShellScriptBlock,
                provider_name: "Microsoft-Windows-PowerShell".into(),
                provider_guid: "a0c1853b-5c40-4b15-8766-3cf1c58f985a".into(),
                grade: EtwProvenanceGrade::ObservedUser,
                agent_lineage_only: true,
            },
            EtwProviderSpec {
                kind: EtwProviderKind::WfpDrop,
                provider_name: "Microsoft-Windows-WFP".into(),
                provider_guid: "0c478c5b-0351-41b1-8c58-4a6737da3203".into(),
                grade: EtwProvenanceGrade::ObservedKernel,
                agent_lineage_only: true,
            },
        ],
    }
}

pub fn normalize_etw_record(
    record: &RawEtwRecord,
    device_id: &str,
    device_name: &str,
) -> EtwNormalizationOutcome {
    // P3: user-mode provider events must match the expected host process and kernel header PID.
    if record.provider.grade() == EtwProvenanceGrade::ObservedUser {
        let pid_mismatch = record.kernel_header_pid != record.claimed_pid;
        let host_mismatch = record.provider == EtwProviderKind::PowerShellScriptBlock
            && !is_powershell_host(&record.process_image);
        if pid_mismatch || host_mismatch {
            return EtwNormalizationOutcome::TamperFinding(Finding {
                id: format!(
                    "fnd-etw-spoof-{}-{}",
                    record.kernel_header_pid,
                    record.timestamp.as_nanosecond()
                ),
                title: "ETW user-mode provider PID or host mismatch".into(),
                class: FindingClass::Tamper,
                finding_class_other: None,
                severity: FindingSeverity::High,
                lifecycle: FindingLifecycle::Open,
                device_id: device_id.into(),
                device_name: device_name.into(),
                session_id: record.session_id.clone(),
                agent_name: record.agent_name.clone(),
                rule_id: Some("windows.etw.pid_validation".into()),
                summary: format!(
                    "User-mode ETW event rejected: provider={:?} kernel_pid={} claimed_pid={} image={}",
                    record.provider,
                    record.kernel_header_pid,
                    record.claimed_pid,
                    record.process_image
                ),
                target: record.target.clone(),
                detected_at: record.timestamp,
            });
        }
    }

    if record.provider.agent_lineage_only() && !record.in_agent_lineage {
        return EtwNormalizationOutcome::DroppedOutOfInterest;
    }

    EtwNormalizationOutcome::Attempt(ActionAttempt {
        id: format!(
            "att-etw-{}-{}-{}",
            record.kernel_header_pid,
            record.event_id,
            record.timestamp.as_nanosecond()
        ),
        session_id: record.session_id.clone(),
        device_id: device_id.into(),
        device_name: device_name.into(),
        agent_name: record.agent_name.clone(),
        action_class: record.provider.action_class(),
        control_point: ControlPoint::Sensor,
        target: record.target.clone(),
        summary: format!(
            "ETW {:?} ({:?}) pid={} ppid={}",
            record.provider,
            record.provider.grade(),
            record.kernel_header_pid,
            record.parent_pid
        ),
        timestamp: record.timestamp,
        ..Default::default()
    })
}

pub fn evaluate_etw_loss(metrics: EtwLossMetrics) -> CoverageLossSignal {
    if metrics.prior_rate_per_sec >= 100 && metrics.current_rate_per_sec == 0 {
        return CoverageLossSignal::SpikeThenSilenceDetected;
    }
    if metrics.events_lost > 0 || metrics.buffers_lost > 0 {
        return CoverageLossSignal::LossReported {
            events_lost: metrics.events_lost,
            buffers_lost: metrics.buffers_lost,
        };
    }
    CoverageLossSignal::Healthy
}

pub fn is_powershell_host(image: &str) -> bool {
    let base = image
        .rsplit(['\\', '/'])
        .next()
        .unwrap_or(image)
        .to_ascii_lowercase();
    matches!(base.as_str(), "powershell.exe" | "pwsh.exe")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_spoofed_powershell_and_dns_client_etw_events_with_tamper_finding() {
        let ts = Timestamp::from_second(1_700_000_000).unwrap();
        let spoof_ps = RawEtwRecord {
            provider: EtwProviderKind::PowerShellScriptBlock,
            event_id: 4104,
            kernel_header_pid: 9999,
            claimed_pid: 4100,
            parent_pid: 100,
            process_image: "notepad.exe".into(),
            in_agent_lineage: true,
            target: "Invoke-Expression".into(),
            session_id: "sess-1".into(),
            agent_name: "claude-code".into(),
            timestamp: ts,
        };
        assert!(matches!(
            normalize_etw_record(&spoof_ps, "dev-1", "win"),
            EtwNormalizationOutcome::TamperFinding(f) if f.class == FindingClass::Tamper
        ));

        let spoof_dns = RawEtwRecord {
            provider: EtwProviderKind::DnsClient,
            event_id: 3008,
            kernel_header_pid: 9999,
            claimed_pid: 4100,
            parent_pid: 100,
            process_image: "node.exe".into(),
            in_agent_lineage: true,
            target: "exfil.example".into(),
            session_id: "sess-1".into(),
            agent_name: "claude-code".into(),
            timestamp: ts,
        };
        assert!(matches!(
            normalize_etw_record(&spoof_dns, "dev-1", "win"),
            EtwNormalizationOutcome::TamperFinding(f) if f.class == FindingClass::Tamper
        ));

        let reg_non_lineage = RawEtwRecord {
            provider: EtwProviderKind::KernelRegistry,
            event_id: 1,
            kernel_header_pid: 555,
            claimed_pid: 555,
            parent_pid: 100,
            process_image: "reg.exe".into(),
            in_agent_lineage: false,
            target: r"HKLM\SOFTWARE\Policies\ClaudeCode".into(),
            session_id: "sess-sys".into(),
            agent_name: "system".into(),
            timestamp: ts,
        };
        assert!(matches!(
            normalize_etw_record(&reg_non_lineage, "dev-1", "win"),
            EtwNormalizationOutcome::Attempt(_)
        ));
    }

    #[test]
    fn detects_etw_spike_then_silence_and_buffer_loss() {
        assert_eq!(
            evaluate_etw_loss(EtwLossMetrics {
                events_lost: 0,
                buffers_lost: 0,
                prior_rate_per_sec: 250,
                current_rate_per_sec: 0,
            }),
            CoverageLossSignal::SpikeThenSilenceDetected
        );
        assert_eq!(
            evaluate_etw_loss(EtwLossMetrics {
                events_lost: 4,
                buffers_lost: 1,
                prior_rate_per_sec: 10,
                current_rate_per_sec: 10,
            }),
            CoverageLossSignal::LossReported {
                events_lost: 4,
                buffers_lost: 1,
            }
        );
    }
}
