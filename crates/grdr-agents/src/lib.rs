// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod abom;
pub mod artifacts;
mod artifacts_scan;
pub mod blocks_catalogue;
pub mod blocks_scan;
pub mod canary;
pub mod catalogue;
mod catalogue_parse;
pub mod discover;
mod discover_routes;
mod fs_safe;
pub mod hook_codec;
pub mod install;
mod install_entries;
mod install_journal;
mod json_edit;
pub mod mdm_render;
mod parse;
#[cfg(test)]
mod test_fs;
pub mod windows_discovery;
pub mod windows_process_parse;
pub mod windows_telemetry;

pub use abom::{
    AbomComponent, AgentBom, AgentDeclaration, DiffState, DriftKind, InventoryDiffRecord,
    ObservedAgentState, PresenceState, build_agent_bom, reconcile_inventory_diff,
};
pub use artifacts::{scan_artifacts_for_roots, scan_artifacts_for_roots_with_catalogue};
pub use blocks_scan::{
    BuildingBlockScanResult, DetectedBuildingBlock, scan_workspace_building_blocks,
};
pub use canary::{CanaryStatus, HookCanaryReport, HookHealthState, verify_hook_canary};
pub use catalogue::{
    AdminConfigPaths, AgentArtifactRoutes, AgentCatalogue, AgentFlagMode, AgentManifest,
    AgentRoutes, BuildingBlockCatalogue, BuildingBlockManifest, EcosystemPackages, HookEntryStyle,
    HookSpec, MdmIds, TimeoutUnit,
};
pub use discover::{
    FourPassDiscoveryInput, FourPassDiscoveryReport, Pass1CandidateSummary, detect_home_dir,
    detect_hostname, discover_four_pass, discover_from_roots, discover_from_roots_with_workspace,
    discover_local_agents,
};
pub use hook_codec::{parse_hook_stdin_with_catalogue, parse_hook_stdin_with_dialect};
pub use install::{
    HookDryRunDiff, HookInstallReport, HookInstallState, HookStatusReport, HookTargetKind,
    InstallOutcome, dry_run_hook_diff, hook_status, hook_status_with_catalogue, install_hook,
    install_hook_in_state_dir, install_hook_with_catalogue, recorded_hook_command, uninstall_hook,
    uninstall_hook_in_state_dir, uninstall_hook_with_catalogue,
};
pub use install_journal::detect_state_dir;
pub use mdm_render::{MdmTemplateFormat, render_mdm_snippet};
pub use windows_discovery::{
    CODE_WIN_SNAPSHOT_UNAVAILABLE, DiscoveryObserverState, ObservedWindowsAgent,
    ProcessInstanceKey, ProcessSnapshotSource, SYSTEM_SNAPSHOT_SOURCE_NAME, WindowsDiscoveryEvent,
    WindowsDiscoveryTracker, WslBridgeProcess,
};
pub use windows_process_parse::{
    AgentExecutionSurface, CODE_WIN_SNAPSHOT_PARSE, MatchedProcessSpec, WindowsProcessEntry,
    WslInvocation, classify_process_entry, classify_process_entry_with_catalogue,
    parse_cim_process_json, parse_tasklist_csv, parse_wsl_command_invocation,
};
pub use windows_telemetry::{
    CLI_CODING_AGENT_USAGE_FEATURE_ID, CODE_DOC_TELEMETRY_QUERY, DoctorSeverity,
    TelemetryPolicySource, WindowsOptionalTelemetryState, WindowsTelemetryAdvisory,
    WindowsTelemetryRegistryReader, WindowsTelemetryRegistrySnapshot, evaluate_windows_telemetry,
};
