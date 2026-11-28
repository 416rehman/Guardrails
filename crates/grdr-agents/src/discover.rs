// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Dynamic P14 4-pass agent discovery (`docs/design/05`).

use std::collections::{BTreeMap, BTreeSet};
use std::env;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use grdr_core::discover::{
    BehavioralAssessment, BehavioralObservation, Pass1MatchState, ProgramIdentity,
    classify_agentic_loop, evaluate_pass1_routes,
};
use grdr_model::{DiscoveredAgent, DiscoveryReport, InstallProfile};
use grdr_ports::LocalFsPort;

use crate::abom::{
    AgentBom, AgentDeclaration, InventoryDiffRecord, ObservedAgentState, PresenceState,
    build_agent_bom, reconcile_inventory_diff,
};
use crate::artifacts::scan_artifacts_for_roots_with_catalogue;
use crate::blocks_scan::{DetectedBuildingBlock, scan_workspace_building_blocks};
use crate::catalogue::{AgentCatalogue, BuildingBlockCatalogue};
use crate::discover_routes::{
    assurance_for_hook, build_program_identity, empty_report, find_matching_process,
    scan_manifest_filesystem_routes,
};
use crate::parse::display_path;
use crate::windows_process_parse::WindowsProcessEntry;

static EMBEDDED_DISCOVERY_CATALOGUE: OnceLock<Option<AgentCatalogue>> = OnceLock::new();
static EMBEDDED_DISCOVERY_BLOCKS: OnceLock<Option<BuildingBlockCatalogue>> = OnceLock::new();

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Pass1CandidateSummary {
    pub agent_id: String,
    pub agent_name: String,
    pub match_state: Pass1MatchState,
    pub matched_routes: Vec<String>,
    pub hook_installed: bool,
    pub program_identity: ProgramIdentity,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FourPassDiscoveryReport {
    pub report: DiscoveryReport,
    pub pass1: Vec<Pass1CandidateSummary>,
    pub building_blocks: Vec<DetectedBuildingBlock>,
    pub behavioral: Vec<BehavioralAssessment>,
    pub inventory_diff: Vec<InventoryDiffRecord>,
    pub abom: AgentBom,
}

pub struct FourPassDiscoveryInput<'a> {
    pub device_name: &'a str,
    pub home: Option<&'a Path>,
    pub appdata: Option<&'a Path>,
    pub workspace: Option<&'a Path>,
    pub profile: InstallProfile,
    pub hook_command: &'a str,
    pub fs: &'a dyn LocalFsPort,
    pub catalogue: &'a AgentCatalogue,
    pub blocks: &'a BuildingBlockCatalogue,
    pub processes: &'a [WindowsProcessEntry],
    pub observations: &'a [BehavioralObservation],
    pub declarations: &'a [AgentDeclaration],
}

#[must_use]
pub fn discover_local_agents(
    profile: InstallProfile,
    hook_command: &str,
    fs: &dyn LocalFsPort,
) -> DiscoveryReport {
    let home = detect_home_dir();
    let appdata = env::var_os("APPDATA").map(PathBuf::from);
    let cwd = env::current_dir().ok();
    let hostname = detect_hostname();
    discover_from_roots_with_workspace(
        &hostname,
        home.as_deref(),
        appdata.as_deref(),
        cwd.as_deref(),
        profile,
        hook_command,
        fs,
    )
}

#[must_use]
pub fn detect_hostname() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "local-workstation".into())
}

#[must_use]
pub fn detect_home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[must_use]
pub fn discover_from_roots(
    device_name: &str,
    home: Option<&Path>,
    appdata: Option<&Path>,
    profile: InstallProfile,
    hook_command: &str,
    fs: &dyn LocalFsPort,
) -> DiscoveryReport {
    discover_from_roots_with_workspace(device_name, home, appdata, None, profile, hook_command, fs)
}

#[must_use]
pub fn discover_from_roots_with_workspace(
    device_name: &str,
    home: Option<&Path>,
    appdata: Option<&Path>,
    workspace: Option<&Path>,
    profile: InstallProfile,
    hook_command: &str,
    fs: &dyn LocalFsPort,
) -> DiscoveryReport {
    let Some(catalogue) = EMBEDDED_DISCOVERY_CATALOGUE
        .get_or_init(|| AgentCatalogue::embedded().ok())
        .as_ref()
    else {
        return empty_report(device_name, profile);
    };
    let Some(blocks) = EMBEDDED_DISCOVERY_BLOCKS
        .get_or_init(|| BuildingBlockCatalogue::embedded().ok())
        .as_ref()
    else {
        return empty_report(device_name, profile);
    };
    discover_four_pass(&FourPassDiscoveryInput {
        device_name,
        home,
        appdata,
        workspace,
        profile,
        hook_command,
        fs,
        catalogue,
        blocks,
        processes: &[],
        observations: &[],
        declarations: &[],
    })
    .report
}

#[must_use]
pub fn discover_four_pass(input: &FourPassDiscoveryInput<'_>) -> FourPassDiscoveryReport {
    let FourPassDiscoveryInput {
        device_name,
        home,
        appdata,
        workspace,
        profile,
        hook_command,
        fs,
        catalogue,
        blocks,
        processes,
        observations,
        declarations,
    } = *input;
    let now = Timestamp::now();
    let mut agents = Vec::new();
    let mut mcp_servers = Vec::new();
    let mut scanned_paths = Vec::new();
    let mut warnings = Vec::new();
    let mut pass1 = Vec::new();
    let mut observed_states = Vec::new();

    if home.is_none() {
        warnings.push("Home directory environment variable was unavailable during scan.".into());
    }

    for manifest in catalogue.agents() {
        let mut matched_routes = Vec::new();
        let mut primary_path: Option<PathBuf> = None;
        let mut hook_installed = false;
        let mcp_before = mcp_servers.len();

        scan_manifest_filesystem_routes(
            manifest,
            home,
            appdata,
            workspace,
            hook_command,
            fs,
            &mut matched_routes,
            &mut primary_path,
            &mut hook_installed,
            &mut mcp_servers,
            &mut scanned_paths,
            &mut warnings,
        );

        let running_proc = find_matching_process(manifest, processes);
        if running_proc.is_some() {
            matched_routes.push("process:running".into());
        }

        let mcp_count = mcp_servers.len().saturating_sub(mcp_before);
        let match_state = evaluate_pass1_routes(matched_routes.len());
        if matched_routes.is_empty() {
            continue;
        }

        let exe_path = running_proc
            .and_then(|p| p.executable_path.clone())
            .or_else(|| primary_path.as_ref().map(|p| display_path(p)))
            .unwrap_or_default();
        let program_identity = build_program_identity(manifest, &exe_path);

        pass1.push(Pass1CandidateSummary {
            agent_id: manifest.id.clone(),
            agent_name: manifest.name.clone(),
            match_state,
            matched_routes,
            hook_installed,
            program_identity: program_identity.clone(),
        });

        let has_config_or_proc = primary_path
            .as_ref()
            .is_some_and(|p| fs.is_regular_file_nofollow(p))
            || running_proc.is_some();
        if match_state == Pass1MatchState::InstalledMatched || has_config_or_proc {
            let assurance = assurance_for_hook(hook_installed, profile);
            agents.push(DiscoveredAgent {
                id: format!("agent-{}", manifest.id),
                name: manifest.name.clone(),
                kind: manifest.id.clone(),
                config_path: exe_path,
                hook_installed,
                mcp_count,
                assurance,
                assurance_level: assurance.level(),
                sponsor: None,
                detected_at: now,
            });
        }

        let presence = if running_proc.is_some() {
            PresenceState::Running
        } else {
            PresenceState::InstalledOnly
        };
        observed_states.push(ObservedAgentState {
            agent_id: manifest.id.clone(),
            program_identity,
            presence,
            observed_signer: None,
            observed_hosts: BTreeSet::new(),
            observed_artifacts: BTreeMap::new(),
        });
    }

    let artifacts = scan_artifacts_for_roots_with_catalogue(
        catalogue,
        device_name,
        home,
        workspace,
        now,
        fs,
        &mut scanned_paths,
        &mut warnings,
    );
    let block_scan = scan_workspace_building_blocks(workspace, blocks, fs);
    if let Some(reason) = block_scan.blocked_reason {
        warnings.push(format!("Building-block scan incomplete: {reason:?}"));
    }

    let behavioral: Vec<BehavioralAssessment> = observations
        .iter()
        .map(|obs| classify_agentic_loop(obs, &blocks.classifier))
        .collect();

    let inventory_diff = reconcile_inventory_diff(declarations, &observed_states);
    let abom = build_agent_bom(device_name, &inventory_diff, &observed_states);

    let report = DiscoveryReport {
        device_name: device_name.into(),
        os: env::consts::OS.into(),
        arch: env::consts::ARCH.into(),
        install_profile: profile,
        agents,
        mcp_servers,
        artifacts,
        scanned_paths,
        warnings,
        scanned_at: now,
    };

    FourPassDiscoveryReport {
        report,
        pass1,
        building_blocks: block_scan.detected,
        behavioral,
        inventory_diff,
        abom,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::test_fs::TestLocalFs;
    use grdr_model::{AssuranceLevel, ControlStrength};
    use std::fs;

    #[test]
    fn discovers_agents_without_leaking_secrets() {
        let root = env::temp_dir().join(format!("grdr-disc-{}", uuid::Uuid::now_v7()));
        let claude_dir = root.join(".claude");
        let cursor_dir = root.join(".cursor");
        let codex_dir = root.join(".codex");
        fs::create_dir_all(&claude_dir).unwrap();
        fs::create_dir_all(&cursor_dir).unwrap();
        fs::create_dir_all(&codex_dir).unwrap();

        fs::write(
            claude_dir.join("settings.json"),
            r#"{
              "hooks": { "PreToolUse": [{ "command": "grdr-hook" }] },
              "mcpServers": {
                "github": {
                  "command": "/usr/local/bin/npx",
                  "env": { "GITHUB_TOKEN": "ghp_super_secret_token_do_not_leak" }
                }
              }
            }"#,
        )
        .unwrap();
        fs::write(
            cursor_dir.join("mcp.json"),
            r#"{"mcpServers":{"postgres":{"command":"uvx"}}}"#,
        )
        .unwrap();
        fs::write(codex_dir.join("config.toml"), "[mcp_servers.docs]\n").unwrap();

        let report = discover_from_roots(
            "test-box",
            Some(&root),
            None,
            InstallProfile::User,
            "grdr-hook",
            &TestLocalFs,
        );
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("ghp_super_secret_token_do_not_leak"));
        assert!(report.agents.iter().any(|a| a.kind == "claude-code"
            && a.hook_installed
            && a.assurance_level == AssuranceLevel::Al1Observed));
        assert!(report.agents.iter().any(|a| a.kind == "cursor"
            && !a.hook_installed
            && a.assurance_level == AssuranceLevel::Al1Observed));
        assert!(report.agents.iter().any(|a| a.kind == "codex"));
        assert!(
            report
                .mcp_servers
                .iter()
                .any(|m| m.name == "github" && m.command == "npx")
        );
        assert!(report.mcp_servers.iter().any(|m| m.name == "postgres"));
        assert!(report.mcp_servers.iter().any(|m| m.name == "docs"));

        let protected = assurance_for_hook(true, InstallProfile::Protected);
        assert_eq!(protected.control, ControlStrength::None);
        assert_eq!(protected.level(), AssuranceLevel::Al1Observed);

        let _ = fs::remove_dir_all(&root);
    }
}
