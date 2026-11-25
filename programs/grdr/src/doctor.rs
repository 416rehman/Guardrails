// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::process::ExitCode;

use jiff::Timestamp;
use serde::Serialize;

use grdr_agents::{
    DoctorSeverity, ObservedWindowsAgent, ProcessSnapshotSource, SystemWindowsProcessSource,
    WindowsDiscoveryTracker, WindowsOptionalTelemetryState, WindowsTelemetryAdvisory,
    WindowsTelemetryRegistryReader, WslBridgeProcess, detect_hostname, discover_local_agents,
    evaluate_windows_telemetry,
};
use grdr_model::InstallProfile;

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum WindowsProcessDoctorSection {
    NotApplicable,
    Observed {
        active_agents: Vec<ObservedWindowsAgent>,
        active_wsl_bridges: Vec<WslBridgeProcess>,
    },
    Unavailable {
        error_code: String,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DoctorReport {
    pub device_name: String,
    pub os: String,
    pub arch: String,
    pub install_profile: InstallProfile,
    pub worst_severity: DoctorSeverity,
    pub windows_telemetry: WindowsTelemetryAdvisory,
    pub windows_process_observation: WindowsProcessDoctorSection,
    pub discovered_agent_count: usize,
    pub discovered_mcp_count: usize,
    pub checked_at: Timestamp,
}

pub fn run_doctor(json: bool, profile: InstallProfile, strict: bool) -> ExitCode {
    let report = collect_doctor_report(profile);

    if json {
        match serde_json::to_string_pretty(&report) {
            Ok(out) => println!("{out}"),
            Err(err) => {
                eprintln!("GRDR-DOC-0002: failed serializing doctor report: {err}");
                return ExitCode::FAILURE;
            }
        }
    } else {
        print_human_report(&report);
    }

    exit_code_for_report(&report, strict)
}

pub fn collect_doctor_report(profile: InstallProfile) -> DoctorReport {
    let device_name = detect_hostname();
    let telemetry_reader = grdr_agents::windows_telemetry::SystemWindowsTelemetryReader;
    let process_source = SystemWindowsProcessSource;
    let discovery = discover_local_agents(profile);
    build_doctor_report_with(
        &device_name,
        profile,
        discovery.agents.len(),
        discovery.mcp_servers.len(),
        &telemetry_reader,
        &process_source,
        Timestamp::now(),
    )
}

pub fn build_doctor_report_with(
    device_name: &str,
    profile: InstallProfile,
    discovered_agent_count: usize,
    discovered_mcp_count: usize,
    telemetry_reader: &dyn WindowsTelemetryRegistryReader,
    process_source: &dyn ProcessSnapshotSource,
    now: Timestamp,
) -> DoctorReport {
    let windows_telemetry = evaluate_windows_telemetry(telemetry_reader);
    let windows_process_observation = if telemetry_reader.is_windows_host() {
        let mut tracker = WindowsDiscoveryTracker::new(process_source);
        match tracker.poll_delta(now) {
            Ok(_) => WindowsProcessDoctorSection::Observed {
                active_agents: tracker.active_agents().into_iter().cloned().collect(),
                active_wsl_bridges: tracker.active_wsl_bridges().into_iter().cloned().collect(),
            },
            Err(err) => WindowsProcessDoctorSection::Unavailable {
                error_code: err.code,
                reason: err.message,
            },
        }
    } else {
        WindowsProcessDoctorSection::NotApplicable
    };

    let worst_severity = windows_telemetry.severity;

    DoctorReport {
        device_name: device_name.into(),
        os: std::env::consts::OS.into(),
        arch: std::env::consts::ARCH.into(),
        install_profile: profile,
        worst_severity,
        windows_telemetry,
        windows_process_observation,
        discovered_agent_count,
        discovered_mcp_count,
        checked_at: now,
    }
}

pub fn exit_code_for_report(report: &DoctorReport, strict: bool) -> ExitCode {
    match report.worst_severity {
        DoctorSeverity::Error => ExitCode::FAILURE,
        DoctorSeverity::Advisory if strict => ExitCode::FAILURE,
        DoctorSeverity::Info | DoctorSeverity::Advisory => ExitCode::SUCCESS,
    }
}

fn print_human_report(report: &DoctorReport) {
    println!(
        "Guardrails ADR doctor ({}, {} / {}, profile: {:?}, severity: {:?})",
        report.device_name, report.os, report.arch, report.install_profile, report.worst_severity
    );
    println!(
        "Inventory: {} configured agent(s), {} MCP server(s)",
        report.discovered_agent_count, report.discovered_mcp_count
    );

    let state_label = match report.windows_telemetry.state {
        WindowsOptionalTelemetryState::NotApplicable => "not-applicable".to_string(),
        WindowsOptionalTelemetryState::Disabled => "disabled".to_string(),
        WindowsOptionalTelemetryState::EnabledExposure { feature_id } => {
            format!("enabled-exposure (feature {feature_id})")
        }
        WindowsOptionalTelemetryState::Unknown => "unknown".to_string(),
    };
    println!(
        "Windows telemetry ({}): {}",
        state_label, report.windows_telemetry.summary
    );
    println!("Guidance: {}", report.windows_telemetry.guidance);

    match &report.windows_process_observation {
        WindowsProcessDoctorSection::NotApplicable => {
            println!("Windows/WSL process observation: not applicable on this OS.");
        }
        WindowsProcessDoctorSection::Observed {
            active_agents,
            active_wsl_bridges,
        } => {
            println!(
                "Windows/WSL process observation: {} active coding-agent process(es), {} WSL bridge process(es)",
                active_agents.len(),
                active_wsl_bridges.len()
            );
            for agent in active_agents {
                println!(
                    "  - {} [{}] pid={} surface={:?}",
                    agent.agent_name, agent.agent_kind, agent.key.pid, agent.surface
                );
            }
        }
        WindowsProcessDoctorSection::Unavailable { error_code, reason } => {
            println!("Windows/WSL process observation unavailable ({error_code}): {reason}");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_agents::{
        CLI_CODING_AGENT_USAGE_FEATURE_ID, WindowsProcessEntry, WindowsTelemetryRegistrySnapshot,
    };
    use grdr_model::CodedError;

    struct MockTelemetry {
        windows: bool,
        snapshot: WindowsTelemetryRegistrySnapshot,
    }

    impl WindowsTelemetryRegistryReader for MockTelemetry {
        fn is_windows_host(&self) -> bool {
            self.windows
        }

        fn read_telemetry_snapshot(&self) -> WindowsTelemetryRegistrySnapshot {
            self.snapshot.clone()
        }
    }

    struct MockProcesses(Vec<WindowsProcessEntry>);

    impl ProcessSnapshotSource for MockProcesses {
        fn source_name(&self) -> &'static str {
            "mock"
        }

        fn snapshot_processes(&self) -> Result<Vec<WindowsProcessEntry>, CodedError> {
            Ok(self.0.clone())
        }
    }

    #[test]
    fn doctor_report_passes_on_non_windows_and_guides_on_windows_exposure() {
        let now = Timestamp::now();
        let linux_report = build_doctor_report_with(
            "linux-ci",
            InstallProfile::User,
            1,
            2,
            &MockTelemetry {
                windows: false,
                snapshot: WindowsTelemetryRegistrySnapshot::default(),
            },
            &MockProcesses(Vec::new()),
            now,
        );
        assert_eq!(
            linux_report.windows_telemetry.state,
            WindowsOptionalTelemetryState::NotApplicable
        );
        assert_eq!(linux_report.worst_severity, DoctorSeverity::Info);
        assert_eq!(exit_code_for_report(&linux_report, true), ExitCode::SUCCESS);

        let win_exposed = build_doctor_report_with(
            "win-endpoint",
            InstallProfile::Protected,
            2,
            1,
            &MockTelemetry {
                windows: true,
                snapshot: WindowsTelemetryRegistrySnapshot {
                    os_allow_telemetry: Some(3),
                    ..Default::default()
                },
            },
            &MockProcesses(vec![WindowsProcessEntry {
                pid: 700,
                parent_pid: 100,
                image_name: "claude.exe".into(),
                executable_path: None,
                command_line: Some("claude.exe".into()),
                session_id: Some(1),
            }]),
            now,
        );
        assert_eq!(
            win_exposed.windows_telemetry.state,
            WindowsOptionalTelemetryState::EnabledExposure {
                feature_id: CLI_CODING_AGENT_USAGE_FEATURE_ID
            }
        );
        assert_eq!(win_exposed.worst_severity, DoctorSeverity::Advisory);
        assert_eq!(exit_code_for_report(&win_exposed, false), ExitCode::SUCCESS);
        assert_eq!(exit_code_for_report(&win_exposed, true), ExitCode::FAILURE);
        assert!(matches!(
            win_exposed.windows_process_observation,
            WindowsProcessDoctorSection::Observed { ref active_agents, .. } if active_agents.len() == 1
        ));
    }
}
