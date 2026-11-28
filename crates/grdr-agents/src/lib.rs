// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod abom;
pub mod abom_formats;
pub mod artifacts;
mod artifacts_scan;
pub mod blocks_catalogue;
mod blocks_env_scan;
pub mod blocks_scan;
pub mod canary;
mod canary_exec;
pub mod catalogue;
mod catalogue_parse;
pub mod cred_inventory;
pub mod discover;
pub mod discover_routes;
pub mod endpoints_creds;
mod endpoints_pack;
mod fs_safe;
pub mod hook_codec;
pub mod importers;
pub mod install;
mod install_entries;
mod install_journal;
mod json_edit;
pub mod mdm_render;
mod parse;
#[cfg(test)]
mod test_fs;
pub mod triage;
pub mod triage_fleet;
pub mod windows_discovery;
pub mod windows_process_parse;
pub mod windows_telemetry;

pub use abom::{
    AbomComponent, AgentBom, AgentDeclaration, DiffState, DriftKind, InventoryDiffRecord,
    ObservedAgentState, PresenceState, build_agent_bom, reconcile_inventory_diff,
};
pub use abom_formats::{
    AbomChangeKind, AbomDiffEntry, AgentDeclarationToml, DeclaredToolSpec, IdentityProofLevel,
    diff_agent_boms, export_cyclonedx_1_7, export_ocsf_5020, parse_grdr_agent_toml,
};
pub use artifacts::{scan_artifacts_for_roots, scan_artifacts_for_roots_with_catalogue};
pub use blocks_scan::{
    BuildingBlockScanResult, DetectedBuildingBlock, ScanBudget, has_corroborated_mcp_sdk,
    scan_embedded_binary_markers, scan_workspace_building_blocks,
    scan_workspace_building_blocks_with_budget,
};
pub use canary::{
    CanaryStatus, ConfigLayerScope, HookCanaryReport, HookHealthState, HookLayerDisposition,
    HookLayerObservation, PassiveCanaryEvent, PassiveCanaryPhase, PassiveCanaryState,
    check_adapter_version_support, probe_hook_layer_precedence, verify_hook_canary,
    verify_hook_canary_exec, verify_hook_canary_with_passive,
};
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
pub use discover_routes::{ContainmentTier, evaluate_hook_assurance};
pub use endpoints_creds::{
    CredentialExposure, CredentialInventoryRecord, CredentialLocatorSpec, CredentialStoreKind,
    ModelEndpointBasis, ModelEndpointRecord, ModelEndpointRegistry, ModelEndpointState,
    build_credential_inventory_record, load_embedded_credential_locators,
};
pub use hook_codec::{parse_hook_stdin_with_catalogue, parse_hook_stdin_with_dialect};
pub use importers::{
    ImportSummary, QuarantineList, import_acp_registry, import_ai_detection_spec,
    import_uber_adr_signatures, lint_catalogue_pack_yaml, lint_cedar_block_on_advisory,
};
pub use install::{
    HookDryRunDiff, HookInstallReport, HookInstallState, HookStatusReport, HookTargetKind,
    InstallOutcome, dry_run_hook_diff, hook_status, hook_status_with_canary,
    hook_status_with_catalogue, install_hook, install_hook_in_state_dir,
    install_hook_with_catalogue, recorded_hook_command, uninstall_hook,
    uninstall_hook_in_state_dir, uninstall_hook_with_catalogue,
};
pub use install_journal::detect_state_dir;
pub use mdm_render::{MdmTemplateFormat, render_mdm_snippet};
pub use triage::{
    TriageDisposition, TriageItem, TriageObservationUpdate, TriageReopenTrigger,
    apply_triage_disposition, evaluate_triage_reopen, triage_finding_from_assessment,
};
pub use triage_fleet::{
    FleetDeclarationRecord, FleetInventoryState, FleetReconcileRow, OrgCatalogueEntry,
    OrgEntryAttributes, generate_org_catalogue_entry, reconcile_fleet_states,
    sanitize_upstream_proposal,
};
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
