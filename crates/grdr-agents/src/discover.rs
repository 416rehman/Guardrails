// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::env;
use std::fs;
use std::path::{Path, PathBuf};

use jiff::Timestamp;

use grdr_model::{
    AssuranceRecord, ControlStrength, DiscoveredAgent, DiscoveryReport, InstallProfile,
    McpServerEntry, OnFailure, TamperGrade, Visibility,
};

use crate::artifacts::scan_artifacts_for_roots;
use crate::parse::{
    display_path, extract_mcp_servers, extract_toml_mcp_headers, json_contains_grdr_hook, read_json,
};

struct JsonAgentSpec<'a> {
    id: &'a str,
    name: &'a str,
    kind: &'a str,
    config_path: &'a Path,
    dir_exists: bool,
    display_root: &'a Path,
}

pub fn discover_local_agents(profile: InstallProfile) -> DiscoveryReport {
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
    )
}

pub fn detect_hostname() -> String {
    env::var("COMPUTERNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .ok()
        .filter(|s| !s.trim().is_empty())
        .unwrap_or_else(|| "local-workstation".into())
}

pub fn discover_from_roots(
    device_name: &str,
    home: Option<&Path>,
    appdata: Option<&Path>,
    profile: InstallProfile,
) -> DiscoveryReport {
    discover_from_roots_with_workspace(device_name, home, appdata, None, profile)
}

pub fn discover_from_roots_with_workspace(
    device_name: &str,
    home: Option<&Path>,
    appdata: Option<&Path>,
    workspace: Option<&Path>,
    profile: InstallProfile,
) -> DiscoveryReport {
    let now = Timestamp::now();
    let mut agents = Vec::new();
    let mut mcp_servers = Vec::new();
    let mut scanned_paths = Vec::new();
    let mut warnings = Vec::new();

    if let Some(home_dir) = home {
        scan_claude_code(
            home_dir,
            profile,
            now,
            &mut agents,
            &mut mcp_servers,
            &mut scanned_paths,
            &mut warnings,
        );
        scan_cursor(
            home_dir,
            appdata,
            profile,
            now,
            &mut agents,
            &mut mcp_servers,
            &mut scanned_paths,
        );
        scan_codex(
            home_dir,
            profile,
            now,
            &mut agents,
            &mut mcp_servers,
            &mut scanned_paths,
        );
        scan_gemini(
            home_dir,
            profile,
            now,
            &mut agents,
            &mut mcp_servers,
            &mut scanned_paths,
        );

        let windsurf_cfg = home_dir
            .join(".codeium")
            .join("windsurf")
            .join("mcp_config.json");
        scan_json_mcp_agent(
            JsonAgentSpec {
                id: "agent-windsurf",
                name: "Windsurf",
                kind: "windsurf",
                config_path: &windsurf_cfg,
                dir_exists: windsurf_cfg.is_file(),
                display_root: &windsurf_cfg,
            },
            profile,
            now,
            &mut agents,
            &mut mcp_servers,
            &mut scanned_paths,
        );

        let opencode_dir = home_dir.join(".config").join("opencode");
        let opencode_cfg = opencode_dir.join("opencode.json");
        scan_json_mcp_agent(
            JsonAgentSpec {
                id: "agent-opencode",
                name: "OpenCode",
                kind: "opencode",
                config_path: &opencode_cfg,
                dir_exists: opencode_dir.is_dir() || opencode_cfg.is_file(),
                display_root: &opencode_dir,
            },
            profile,
            now,
            &mut agents,
            &mut mcp_servers,
            &mut scanned_paths,
        );
    } else {
        warnings.push("Home directory environment variable was unavailable during scan.".into());
    }

    if let Some(vscode_cfg) = appdata
        .map(|d| d.join("Code").join("User").join("mcp.json"))
        .or_else(|| home.map(|h| h.join(".config").join("Code").join("User").join("mcp.json")))
    {
        scan_json_mcp_agent(
            JsonAgentSpec {
                id: "agent-vscode",
                name: "VS Code Copilot / MCP",
                kind: "vscode",
                config_path: &vscode_cfg,
                dir_exists: vscode_cfg.is_file(),
                display_root: &vscode_cfg,
            },
            profile,
            now,
            &mut agents,
            &mut mcp_servers,
            &mut scanned_paths,
        );
    }

    let artifacts = scan_artifacts_for_roots(
        device_name,
        home,
        workspace,
        now,
        &mut scanned_paths,
        &mut warnings,
    );

    DiscoveryReport {
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
    }
}

fn scan_claude_code(
    home: &Path,
    profile: InstallProfile,
    now: Timestamp,
    agents: &mut Vec<DiscoveredAgent>,
    mcp_servers: &mut Vec<McpServerEntry>,
    scanned_paths: &mut Vec<String>,
    warnings: &mut Vec<String>,
) {
    let claude_dir = home.join(".claude");
    let settings_path = claude_dir.join("settings.json");
    let claude_json = home.join(".claude.json");
    scanned_paths.push(display_path(&settings_path));
    scanned_paths.push(display_path(&claude_json));

    if !claude_dir.is_dir() && !settings_path.is_file() && !claude_json.is_file() {
        return;
    }

    let mut hook_installed = false;
    let mut local_mcps = Vec::new();
    for path in [&settings_path, &claude_json] {
        if path.is_file() {
            match read_json(path) {
                Ok(val) => {
                    if json_contains_grdr_hook(&val) {
                        hook_installed = true;
                    }
                    extract_mcp_servers(&val, "Claude Code", path, &mut local_mcps);
                }
                Err(err) => warnings.push(err),
            }
        }
    }

    let mcp_count = local_mcps.len();
    mcp_servers.extend(local_mcps);
    let assurance = assurance_for_hook(hook_installed, profile);

    agents.push(DiscoveredAgent {
        id: "agent-claude-code".into(),
        name: "Claude Code".into(),
        kind: "claude-code".into(),
        config_path: display_path(if settings_path.is_file() {
            &settings_path
        } else {
            &claude_dir
        }),
        hook_installed,
        mcp_count,
        assurance_level: assurance.level(),
        assurance,
        sponsor: None,
        detected_at: now,
    });
}

fn scan_cursor(
    home: &Path,
    appdata: Option<&Path>,
    profile: InstallProfile,
    now: Timestamp,
    agents: &mut Vec<DiscoveredAgent>,
    mcp_servers: &mut Vec<McpServerEntry>,
    scanned_paths: &mut Vec<String>,
) {
    let cursor_dir = home.join(".cursor");
    let mcp_path = cursor_dir.join("mcp.json");
    let appdata_cursor = appdata.map(|d| d.join("Cursor"));
    let exists = cursor_dir.is_dir()
        || mcp_path.is_file()
        || appdata_cursor.as_ref().is_some_and(|p| p.is_dir());

    scan_json_mcp_agent(
        JsonAgentSpec {
            id: "agent-cursor",
            name: "Cursor",
            kind: "cursor",
            config_path: &mcp_path,
            dir_exists: exists,
            display_root: &cursor_dir,
        },
        profile,
        now,
        agents,
        mcp_servers,
        scanned_paths,
    );
}

fn scan_codex(
    home: &Path,
    profile: InstallProfile,
    now: Timestamp,
    agents: &mut Vec<DiscoveredAgent>,
    mcp_servers: &mut Vec<McpServerEntry>,
    scanned_paths: &mut Vec<String>,
) {
    let codex_dir = home.join(".codex");
    let cfg_path = codex_dir.join("config.toml");
    scanned_paths.push(display_path(&cfg_path));
    if !codex_dir.is_dir() && !cfg_path.is_file() {
        return;
    }

    let mut local_mcps = Vec::new();
    if cfg_path.is_file()
        && let Ok(text) = fs::read_to_string(&cfg_path)
    {
        extract_toml_mcp_headers(&text, "Codex CLI", &cfg_path, &mut local_mcps);
    }

    let mcp_count = local_mcps.len();
    mcp_servers.extend(local_mcps);
    let assurance = assurance_for_hook(false, profile);

    agents.push(DiscoveredAgent {
        id: "agent-codex".into(),
        name: "Codex CLI".into(),
        kind: "codex".into(),
        config_path: display_path(if cfg_path.is_file() {
            &cfg_path
        } else {
            &codex_dir
        }),
        hook_installed: false,
        mcp_count,
        assurance_level: assurance.level(),
        assurance,
        sponsor: None,
        detected_at: now,
    });
}

fn scan_gemini(
    home: &Path,
    profile: InstallProfile,
    now: Timestamp,
    agents: &mut Vec<DiscoveredAgent>,
    mcp_servers: &mut Vec<McpServerEntry>,
    scanned_paths: &mut Vec<String>,
) {
    let gemini_dir = home.join(".gemini");
    let settings_path = gemini_dir.join("settings.json");
    let antigravity_mcp = gemini_dir.join("antigravity").join("mcp_config.json");
    scanned_paths.push(display_path(&settings_path));
    scanned_paths.push(display_path(&antigravity_mcp));

    if !gemini_dir.is_dir() {
        return;
    }

    let mut local_mcps = Vec::new();
    let mut hook_installed = false;
    for path in [&settings_path, &antigravity_mcp] {
        if path.is_file()
            && let Ok(val) = read_json(path)
        {
            if json_contains_grdr_hook(&val) {
                hook_installed = true;
            }
            extract_mcp_servers(&val, "Gemini CLI / Antigravity", path, &mut local_mcps);
        }
    }

    let mcp_count = local_mcps.len();
    mcp_servers.extend(local_mcps);
    let assurance = assurance_for_hook(hook_installed, profile);

    agents.push(DiscoveredAgent {
        id: "agent-gemini".into(),
        name: "Gemini CLI / Antigravity".into(),
        kind: "gemini".into(),
        config_path: display_path(&gemini_dir),
        hook_installed,
        mcp_count,
        assurance_level: assurance.level(),
        assurance,
        sponsor: None,
        detected_at: now,
    });
}

fn scan_json_mcp_agent(
    spec: JsonAgentSpec<'_>,
    profile: InstallProfile,
    now: Timestamp,
    agents: &mut Vec<DiscoveredAgent>,
    mcp_servers: &mut Vec<McpServerEntry>,
    scanned_paths: &mut Vec<String>,
) {
    scanned_paths.push(display_path(spec.config_path));
    if !spec.dir_exists {
        return;
    }

    let mut local_mcps = Vec::new();
    if spec.config_path.is_file()
        && let Ok(val) = read_json(spec.config_path)
    {
        extract_mcp_servers(&val, spec.name, spec.config_path, &mut local_mcps);
    }
    let mcp_count = local_mcps.len();
    mcp_servers.extend(local_mcps);
    let assurance = assurance_for_hook(false, profile);

    agents.push(DiscoveredAgent {
        id: spec.id.into(),
        name: spec.name.into(),
        kind: spec.kind.into(),
        config_path: display_path(spec.display_root),
        hook_installed: false,
        mcp_count,
        assurance_level: assurance.level(),
        assurance,
        sponsor: None,
        detected_at: now,
    });
}

fn assurance_for_hook(hook_installed: bool, profile: InstallProfile) -> AssuranceRecord {
    let (control, tamper) = match (hook_installed, profile) {
        (true, InstallProfile::Protected) => (ControlStrength::ScopedBoundary, TamperGrade::Admin),
        (true, InstallProfile::User) => (ControlStrength::Request, TamperGrade::User),
        (false, InstallProfile::Protected) => (ControlStrength::None, TamperGrade::Admin),
        (false, InstallProfile::User) => (ControlStrength::None, TamperGrade::User),
    };
    AssuranceRecord {
        visibility: Visibility::Claimed,
        control,
        on_failure: OnFailure::Open,
        tamper,
    }
}

pub fn detect_home_dir() -> Option<PathBuf> {
    env::var_os("HOME")
        .or_else(|| env::var_os("USERPROFILE"))
        .map(PathBuf::from)
}

#[cfg(test)]
mod tests {
    use super::*;
    use grdr_model::AssuranceLevel;

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

        let report = discover_from_roots("test-box", Some(&root), None, InstallProfile::User);
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("ghp_super_secret_token_do_not_leak"));
        assert!(report.agents.iter().any(|a| a.kind == "claude-code"
            && a.hook_installed
            && a.assurance_level == AssuranceLevel::Al2Guided));
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

        let _ = fs::remove_dir_all(&root);
    }
}
