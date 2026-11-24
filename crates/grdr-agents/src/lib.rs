// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

pub mod artifacts;
pub mod discover;
pub mod hook_codec;
pub mod install;
mod parse;
pub mod windows_discovery;
pub mod windows_process_parse;
pub mod windows_telemetry;

pub use artifacts::scan_artifacts_for_roots;
pub use discover::{
    detect_home_dir, detect_hostname, discover_from_roots, discover_from_roots_with_workspace,
    discover_local_agents,
};
pub use hook_codec::{HarnessKind, parse_claude_hook_stdin, parse_hook_stdin};
pub use install::{
    HookInstallReport, HookTargetKind, InstallOutcome, install_hook, uninstall_hook,
};
pub use windows_discovery::{
    CODE_WIN_SNAPSHOT_UNAVAILABLE, DiscoveryObserverState, ObservedWindowsAgent,
    ProcessInstanceKey, ProcessSnapshotSource, SystemWindowsProcessSource, WindowsDiscoveryEvent,
    WindowsDiscoveryTracker, WslBridgeProcess, discover_windows_processes_once,
};
pub use windows_process_parse::{
    AgentExecutionSurface, CODE_WIN_SNAPSHOT_PARSE, WindowsProcessEntry, WslInvocation,
    parse_cim_process_json, parse_tasklist_csv, parse_wsl_command_invocation,
};
pub use windows_telemetry::{
    CLI_CODING_AGENT_USAGE_FEATURE_ID, CODE_DOC_TELEMETRY_QUERY, DoctorSeverity,
    TelemetryPolicySource, WindowsOptionalTelemetryState, WindowsTelemetryAdvisory,
    WindowsTelemetryRegistryReader, WindowsTelemetryRegistrySnapshot, evaluate_windows_telemetry,
    inspect_windows_telemetry_advisory,
};
