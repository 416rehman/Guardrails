// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

pub const CODE_DOC_TELEMETRY_QUERY: &str = "GRDR-DOC-0001";
pub const CLI_CODING_AGENT_USAGE_FEATURE_ID: &str = "62580080";
pub const GPO_DATA_COLLECTION_KEY: &str =
    r"HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection";
pub const OS_DATA_COLLECTION_KEY: &str =
    r"HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\DataCollection";
pub const FEATURE_MANAGEMENT_OVERRIDES_KEY: &str =
    r"HKLM\SYSTEM\CurrentControlSet\Control\FeatureManagement\Overrides";
pub const ALLOW_TELEMETRY_VALUE_NAME: &str = "AllowTelemetry";
pub const MAX_TELEMETRY_VALUE_NAME: &str = "MaxTelemetryAllowed";
pub const RECOMMENDED_ALLOW_TELEMETRY_REQUIRED: u32 = 1;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum WindowsOptionalTelemetryState {
    NotApplicable,
    Disabled,
    EnabledExposure { feature_id: &'static str },
    Unknown,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TelemetryPolicySource {
    NonWindowsHost,
    GroupPolicyRegistry,
    LocalPolicyRegistry,
    FeatureManagementOverride,
    Unavailable,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DoctorSeverity {
    Info,
    Advisory,
    Error,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct WindowsTelemetryRegistrySnapshot {
    pub gpo_allow_telemetry: Option<u32>,
    pub os_allow_telemetry: Option<u32>,
    pub os_max_telemetry_allowed: Option<u32>,
    pub feature_62580080_enabled_state: Option<u32>,
    pub query_notes: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct WindowsTelemetryAdvisory {
    pub check_id: &'static str,
    pub feature_name: &'static str,
    pub state: WindowsOptionalTelemetryState,
    pub severity: DoctorSeverity,
    pub source: TelemetryPolicySource,
    pub snapshot: WindowsTelemetryRegistrySnapshot,
    pub gpo_registry_path: &'static str,
    pub policy_value_name: &'static str,
    pub recommended_allow_telemetry: u32,
    pub summary: String,
    pub guidance: String,
}

pub trait WindowsTelemetryRegistryReader {
    fn is_windows_host(&self) -> bool;
    fn read_telemetry_snapshot(&self) -> WindowsTelemetryRegistrySnapshot;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemWindowsTelemetryReader;

impl WindowsTelemetryRegistryReader for SystemWindowsTelemetryReader {
    fn is_windows_host(&self) -> bool {
        cfg!(windows)
    }

    fn read_telemetry_snapshot(&self) -> WindowsTelemetryRegistrySnapshot {
        read_system_telemetry_snapshot()
    }
}

pub fn inspect_windows_telemetry_advisory() -> WindowsTelemetryAdvisory {
    evaluate_windows_telemetry(&SystemWindowsTelemetryReader)
}

pub fn evaluate_windows_telemetry(
    reader: &dyn WindowsTelemetryRegistryReader,
) -> WindowsTelemetryAdvisory {
    if !reader.is_windows_host() {
        return build_advisory(
            WindowsOptionalTelemetryState::NotApplicable,
            DoctorSeverity::Info,
            TelemetryPolicySource::NonWindowsHost,
            WindowsTelemetryRegistrySnapshot::default(),
            "Windows Optional Diagnostic Data check is not applicable on this operating system.",
            "No Windows Group Policy hardening is needed on non-Windows hosts.",
        );
    }

    let snapshot = reader.read_telemetry_snapshot();
    let (effective_allow, source) =
        match (snapshot.gpo_allow_telemetry, snapshot.os_allow_telemetry) {
            (Some(val), _) => (Some(val), TelemetryPolicySource::GroupPolicyRegistry),
            (None, Some(val)) => (Some(val), TelemetryPolicySource::LocalPolicyRegistry),
            (None, None) => (None, TelemetryPolicySource::Unavailable),
        };

    if matches!(effective_allow, Some(0 | 1)) {
        return build_advisory(
            WindowsOptionalTelemetryState::Disabled,
            DoctorSeverity::Info,
            source,
            snapshot,
            "Windows Optional Diagnostic Data is restricted (AllowTelemetry <= 1); CLICodingAgentUsage (Feature 62580080) telemetry exposure is disabled.",
            "Diagnostic policy limits telemetry to Required or Off. Keep AllowTelemetry set to 1 (Required) or 0 (Security/Off on Enterprise) via GPO.",
        );
    }

    if snapshot.feature_62580080_enabled_state == Some(1) {
        return build_advisory(
            WindowsOptionalTelemetryState::Disabled,
            DoctorSeverity::Info,
            TelemetryPolicySource::FeatureManagementOverride,
            snapshot,
            "CLICodingAgentUsage (Feature 62580080) override is explicitly disabled in FeatureManagement.",
            "Confirm GPO HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry is also locked to 1 (Required) or 0 (Security/Off on Enterprise).",
        );
    }

    if matches!(effective_allow, Some(v) if v >= 2)
        || snapshot.feature_62580080_enabled_state == Some(2)
    {
        return build_advisory(
            WindowsOptionalTelemetryState::EnabledExposure {
                feature_id: CLI_CODING_AGENT_USAGE_FEATURE_ID,
            },
            DoctorSeverity::Advisory,
            if effective_allow.is_some() {
                source
            } else {
                TelemetryPolicySource::FeatureManagementOverride
            },
            snapshot,
            "Windows Optional Diagnostic Data is enabled; CLICodingAgentUsage (Feature 62580080) telemetry exposure may send coding-agent usage metadata to Microsoft.",
            "Set GPO HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry (REG_DWORD) to 1 (Required) or 0 (Security/Off on Enterprise) to disable Optional Diagnostic Data exposure.",
        );
    }

    build_advisory(
        WindowsOptionalTelemetryState::Unknown,
        DoctorSeverity::Advisory,
        TelemetryPolicySource::Unavailable,
        snapshot,
        "Windows Optional Diagnostic Data policy could not be determined from registry keys; CLICodingAgentUsage (Feature 62580080) exposure is unknown.",
        "Verify HKLM\\SOFTWARE\\Policies\\Microsoft\\Windows\\DataCollection\\AllowTelemetry via GPO or MDM and lock it to 1 (Required) or 0 (Security/Off on Enterprise).",
    )
}

fn build_advisory(
    state: WindowsOptionalTelemetryState,
    severity: DoctorSeverity,
    source: TelemetryPolicySource,
    snapshot: WindowsTelemetryRegistrySnapshot,
    summary: &str,
    guidance: &str,
) -> WindowsTelemetryAdvisory {
    WindowsTelemetryAdvisory {
        check_id: "windows.optional_diagnostic_data",
        feature_name: "CLICodingAgentUsage",
        state,
        severity,
        source,
        snapshot,
        gpo_registry_path: GPO_DATA_COLLECTION_KEY,
        policy_value_name: ALLOW_TELEMETRY_VALUE_NAME,
        recommended_allow_telemetry: RECOMMENDED_ALLOW_TELEMETRY_REQUIRED,
        summary: summary.into(),
        guidance: guidance.into(),
    }
}

pub fn parse_reg_dword_output(output: &str, value_name: &str) -> Option<u32> {
    for line in output.lines() {
        let mut parts = line.split_whitespace();
        let Some(name) = parts.next() else {
            continue;
        };
        if !name.eq_ignore_ascii_case(value_name) {
            continue;
        }
        let Some(reg_type) = parts.next() else {
            continue;
        };
        if !reg_type.eq_ignore_ascii_case("REG_DWORD") {
            continue;
        }
        let Some(raw_val) = parts.next() else {
            continue;
        };
        if let Some(hex) = raw_val
            .strip_prefix("0x")
            .or_else(|| raw_val.strip_prefix("0X"))
        {
            if let Ok(parsed) = u32::from_str_radix(hex, 16) {
                return Some(parsed);
            }
        } else if let Ok(parsed) = raw_val.parse::<u32>() {
            return Some(parsed);
        }
    }
    None
}

pub fn parse_feature_override_query(output: &str, feature_id: &str) -> Option<u32> {
    let mut in_matching_key = false;
    for line in output.lines() {
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with("HKEY_") {
            in_matching_key = trimmed.contains(feature_id);
            continue;
        }
        if in_matching_key && let Some(val) = parse_reg_dword_output(trimmed, "EnabledState") {
            return Some(val);
        }
    }
    None
}

#[cfg(windows)]
fn read_system_telemetry_snapshot() -> WindowsTelemetryRegistrySnapshot {
    let mut query_notes = Vec::new();
    let gpo_allow_telemetry = query_reg_dword(
        GPO_DATA_COLLECTION_KEY,
        ALLOW_TELEMETRY_VALUE_NAME,
        &mut query_notes,
    );
    let os_allow_telemetry = query_reg_dword(
        OS_DATA_COLLECTION_KEY,
        ALLOW_TELEMETRY_VALUE_NAME,
        &mut query_notes,
    );
    let os_max_telemetry_allowed = query_reg_dword(
        OS_DATA_COLLECTION_KEY,
        MAX_TELEMETRY_VALUE_NAME,
        &mut query_notes,
    );
    let feature_62580080_enabled_state =
        query_feature_override_state(CLI_CODING_AGENT_USAGE_FEATURE_ID, &mut query_notes);

    WindowsTelemetryRegistrySnapshot {
        gpo_allow_telemetry,
        os_allow_telemetry,
        os_max_telemetry_allowed,
        feature_62580080_enabled_state,
        query_notes,
    }
}

#[cfg(windows)]
fn query_reg_dword(key: &str, value_name: &str, notes: &mut Vec<String>) -> Option<u32> {
    use std::process::Command;

    match Command::new("reg.exe")
        .args(["query", key, "/v", value_name])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_reg_dword_output(&stdout, value_name)
        }
        Ok(_) => None,
        Err(err) => {
            notes.push(format!(
                "{CODE_DOC_TELEMETRY_QUERY}: reg query failed for {key}: {err}"
            ));
            None
        }
    }
}

#[cfg(windows)]
fn query_feature_override_state(feature_id: &str, notes: &mut Vec<String>) -> Option<u32> {
    use std::process::Command;

    match Command::new("reg.exe")
        .args([
            "query",
            FEATURE_MANAGEMENT_OVERRIDES_KEY,
            "/s",
            "/f",
            feature_id,
        ])
        .output()
    {
        Ok(output) if output.status.success() => {
            let stdout = String::from_utf8_lossy(&output.stdout);
            parse_feature_override_query(&stdout, feature_id)
        }
        Ok(_) => None,
        Err(err) => {
            notes.push(format!(
                "{CODE_DOC_TELEMETRY_QUERY}: feature override query failed: {err}"
            ));
            None
        }
    }
}

#[cfg(not(windows))]
fn read_system_telemetry_snapshot() -> WindowsTelemetryRegistrySnapshot {
    WindowsTelemetryRegistrySnapshot::default()
}

#[cfg(test)]
mod tests {
    use super::*;

    struct MockTelemetryReader {
        is_windows: bool,
        snapshot: WindowsTelemetryRegistrySnapshot,
    }

    impl WindowsTelemetryRegistryReader for MockTelemetryReader {
        fn is_windows_host(&self) -> bool {
            self.is_windows
        }

        fn read_telemetry_snapshot(&self) -> WindowsTelemetryRegistrySnapshot {
            self.snapshot.clone()
        }
    }

    #[test]
    fn non_windows_host_returns_not_applicable_without_error() {
        let reader = MockTelemetryReader {
            is_windows: false,
            snapshot: WindowsTelemetryRegistrySnapshot::default(),
        };
        let advisory = evaluate_windows_telemetry(&reader);
        assert_eq!(advisory.state, WindowsOptionalTelemetryState::NotApplicable);
        assert_eq!(advisory.severity, DoctorSeverity::Info);
        assert!(!advisory.summary.to_ascii_lowercase().contains("posture"));
    }

    #[test]
    fn detects_disabled_enabled_exposure_and_unknown_states() {
        let disabled = evaluate_windows_telemetry(&MockTelemetryReader {
            is_windows: true,
            snapshot: WindowsTelemetryRegistrySnapshot {
                gpo_allow_telemetry: Some(1),
                os_allow_telemetry: Some(3),
                ..Default::default()
            },
        });
        assert_eq!(disabled.state, WindowsOptionalTelemetryState::Disabled);
        assert_eq!(disabled.severity, DoctorSeverity::Info);
        assert_eq!(disabled.source, TelemetryPolicySource::GroupPolicyRegistry);

        let exposed = evaluate_windows_telemetry(&MockTelemetryReader {
            is_windows: true,
            snapshot: WindowsTelemetryRegistrySnapshot {
                os_allow_telemetry: Some(3),
                ..Default::default()
            },
        });
        assert_eq!(
            exposed.state,
            WindowsOptionalTelemetryState::EnabledExposure {
                feature_id: CLI_CODING_AGENT_USAGE_FEATURE_ID
            }
        );
        assert_eq!(exposed.severity, DoctorSeverity::Advisory);
        assert!(exposed.guidance.contains("AllowTelemetry"));
        assert!(!exposed.guidance.to_ascii_lowercase().contains("posture"));

        let unknown = evaluate_windows_telemetry(&MockTelemetryReader {
            is_windows: true,
            snapshot: WindowsTelemetryRegistrySnapshot::default(),
        });
        assert_eq!(unknown.state, WindowsOptionalTelemetryState::Unknown);
        assert_eq!(unknown.severity, DoctorSeverity::Advisory);
    }

    #[test]
    fn parses_reg_query_dword_and_feature_override_outputs() {
        let sample = "\r\nHKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\DataCollection\r\n    AllowTelemetry    REG_DWORD    0x1\r\n    MaxTelemetryAllowed    REG_DWORD    0x3\r\n";
        assert_eq!(parse_reg_dword_output(sample, "AllowTelemetry"), Some(1));
        assert_eq!(
            parse_reg_dword_output(sample, "MaxTelemetryAllowed"),
            Some(3)
        );
        assert_eq!(parse_reg_dword_output(sample, "MissingValue"), None);

        let feat = "\r\nHKEY_LOCAL_MACHINE\\SYSTEM\\CurrentControlSet\\Control\\FeatureManagement\\Overrides\\14\\62580080\r\n    EnabledState    REG_DWORD    0x2\r\n";
        assert_eq!(parse_feature_override_query(feat, "62580080"), Some(2));
        assert_eq!(parse_feature_override_query(feat, "99999999"), None);
    }
}
