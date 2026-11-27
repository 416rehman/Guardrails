// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use jiff::Timestamp;

use grdr_agents::{
    AgentCatalogue, AgentDeclaration, BuildingBlockCatalogue, CanaryStatus, DiffState, DriftKind,
    FourPassDiscoveryInput, HookHealthState, HookInstallState, HookTargetKind, InstallOutcome,
    MdmTemplateFormat, ObservedAgentState, PresenceState, WindowsProcessEntry, build_agent_bom,
    classify_process_entry_with_catalogue, discover_four_pass, discover_from_roots,
    dry_run_hook_diff, install_hook_in_state_dir, install_hook_with_catalogue,
    parse_hook_stdin_with_catalogue, parse_hook_stdin_with_dialect, reconcile_inventory_diff,
    recorded_hook_command, render_mdm_snippet, scan_artifacts_for_roots_with_catalogue,
    uninstall_hook_in_state_dir, uninstall_hook_with_catalogue, verify_hook_canary,
};
use grdr_core::discover::{
    BehaviorVerdict, BehavioralObservation, ExecutionEnvironmentSignal, IdentityHints,
    Pass1MatchState, ProgramIdentity,
};
use grdr_model::{AssuranceLevel, ControlStrength, InstallProfile};
use grdr_ports::{LocalFsPort, RegularEntryKind};

struct TestFs;

impl LocalFsPort for TestFs {
    fn check_no_ancestor_symlinks(&self, _path: &Path) -> Result<(), String> {
        Ok(())
    }

    fn inspect_nofollow(&self, path: &Path) -> Result<RegularEntryKind, String> {
        match fs::symlink_metadata(path) {
            Ok(meta) if meta.file_type().is_symlink() => Ok(RegularEntryKind::UnsafeOrOther),
            Ok(meta) if meta.is_file() => Ok(RegularEntryKind::File),
            Ok(meta) if meta.is_dir() => Ok(RegularEntryKind::Dir),
            Ok(_) => Ok(RegularEntryKind::UnsafeOrOther),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(RegularEntryKind::Missing),
            Err(e) => Err(e.to_string()),
        }
    }

    fn read_bounded_regular_bytes(&self, path: &Path, max_bytes: u64) -> Result<Vec<u8>, String> {
        if self.inspect_nofollow(path)? != RegularEntryKind::File {
            return Err("not a regular file".into());
        }
        let bytes = fs::read(path).map_err(|e| e.to_string())?;
        if u64::try_from(bytes.len()).unwrap_or(u64::MAX) > max_bytes {
            return Err("exceeded max_bytes".into());
        }
        Ok(bytes)
    }

    fn read_bounded_regular_string(&self, path: &Path, max_bytes: u64) -> Result<String, String> {
        let bytes = self.read_bounded_regular_bytes(path, max_bytes)?;
        String::from_utf8(bytes).map_err(|e| e.to_string())
    }

    fn read_dir_entries(&self, dir: &Path) -> Result<Vec<PathBuf>, String> {
        let rd = fs::read_dir(dir).map_err(|e| e.to_string())?;
        let mut out = Vec::new();
        for entry in rd {
            out.push(entry.map_err(|e| e.to_string())?.path());
        }
        out.sort();
        Ok(out)
    }

    fn ensure_dir_nofollow(&self, dir: &Path, _private_dir: bool) -> Result<(), String> {
        fs::create_dir_all(dir).map_err(|e| e.to_string())
    }

    fn atomic_write_nofollow(
        &self,
        path: &Path,
        bytes: &[u8],
        _private_file: bool,
    ) -> Result<(), String> {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).map_err(|e| e.to_string())?;
        }
        fs::write(path, bytes).map_err(|e| e.to_string())
    }

    fn remove_regular_file_nofollow(&self, path: &Path) -> Result<(), String> {
        fs::remove_file(path).map_err(|e| e.to_string())
    }
}

fn repo_root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .and_then(|p| p.parent())
        .map(std::path::Path::to_path_buf)
        .unwrap_or_else(|| PathBuf::from("."))
}

#[test]
fn embedded_catalogue_and_blocks_match_directory_manifests_with_17_plus_agents() {
    let embedded_cat = AgentCatalogue::embedded().expect("embedded catalogue loads");
    assert!(
        embedded_cat.agents().len() >= 16,
        "expected >=16 agents in catalogue, found {}",
        embedded_cat.agents().len()
    );

    let dir_cat = AgentCatalogue::load_from_dir(&repo_root().join("packs/catalogue"), &TestFs)
        .expect("load packs/catalogue directory");
    let mut emb_agents = embedded_cat.agents().to_vec();
    let mut dir_agents = dir_cat.agents().to_vec();
    emb_agents.sort_by(|a, b| a.id.cmp(&b.id));
    dir_agents.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(
        emb_agents, dir_agents,
        "catalogue.yaml drifted from packs/catalogue/agents/*.yaml"
    );

    let embedded_blocks = BuildingBlockCatalogue::embedded().expect("embedded blocks load");
    let dir_blocks =
        BuildingBlockCatalogue::load_from_dir(&repo_root().join("packs/building-blocks"), &TestFs)
            .expect("load packs/building-blocks directory");
    assert!(embedded_blocks.blocks().len() >= 8);
    let mut emb_blk = embedded_blocks.blocks().to_vec();
    let mut dir_blk = dir_blocks.blocks().to_vec();
    emb_blk.sort_by(|a, b| a.id.cmp(&b.id));
    dir_blk.sort_by(|a, b| a.id.cmp(&b.id));
    assert_eq!(
        emb_blk, dir_blk,
        "building-blocks.yaml drifted from packs/building-blocks/blocks/*.yaml"
    );
    assert_eq!(embedded_blocks.classifier, dir_blocks.classifier);

    let aider = dir_cat.resolve("aider").unwrap();
    let aider_mdm = render_mdm_snippet(aider, "grdr-hook", MdmTemplateFormat::Json).unwrap_err();
    assert_eq!(aider_mdm.code, "GRDR-AGENTS-0006");

    for id in [
        "claude-code",
        "cursor",
        "codex",
        "gemini-cli",
        "antigravity",
        "github-copilot",
        "windsurf",
        "cline",
        "roo-code",
        "aider",
        "opencode",
        "pi",
        "continue",
        "zed-ai",
        "junie",
        "amazon-q",
        "kiro",
    ] {
        assert!(
            dir_cat.resolve(id).is_some(),
            "missing agent `{id}` in packs/catalogue"
        );
    }
}

#[test]
fn p14_new_agent_manifest_enables_discovery_artifacts_hooks_canary_and_mdm_without_rust_changes() {
    let root = std::env::temp_dir().join(format!("grdr-p14-dyn-{}", uuid::Uuid::now_v7()));
    let pack_dir = root.join("packs-custom");
    let agents_dir = pack_dir.join("agents");
    let home = root.join("home");
    let ws = root.join("ws");
    let state_dir = home.join(".local/state/grdr");
    fs::create_dir_all(&agents_dir).unwrap();
    fs::create_dir_all(home.join(".novabot/skills/demo-skill")).unwrap();
    fs::create_dir_all(&ws).unwrap();

    fs::write(
        agents_dir.join("novabot.yaml"),
        r#"schema: grdr.catalogue/v1alpha1
id: novabot
aliases: [nova]
name: NovaBot
vendor: NovaWorks
kind: coding-agent
catalogue_tier: B
surfaces: [cli]
declared_action_classes: [exec, file.read, file.write]
containment_default: guided
adapter: hook-shim
routes:
  binaries: [novabot]
  windows_exes: [novabot.exe]
  wsl_harnesses: [novabot]
  cmdline_markers: [novabot-cli]
  npm: ['@novaworks/novabot']
  pypi: []
  vscode_extensions: []
  state_dirs: [.novabot]
  config_paths: [.novabot/config.json]
  admin_config_paths: {}
  mcp_config_paths: [.novabot/config.json]
  mcp_config_key: mcpServers
  env_markers: [NOVABOT_KEY]
  net: [api.novaworks.example]
  artifacts:
    skills: [.novabot/skills]
    plugins: []
    rules: [$WORKSPACE/NOVABOT.md]
    commands: []
    subagents: []
    transcripts: []
  autonomy_flags: [--yolo]
hook:
  supported: true
  dialect: novabot
  config_rel: .novabot/hooks.json
  config_format: json
  root_key: hooks
  entry_style: matcher-hooks
  events: [PreToolUse]
  all_events: [PreToolUse]
  timeout_ms: 200
  fail_mode: closed
  mdm_ids:
    plist_domain: dev.novaworks.novabot
    registry_subkey: 'Software\Policies\NovaWorks\NovaBot'
"#,
    )
    .unwrap();
    fs::write(
        home.join(".novabot/config.json"),
        r#"{"mcpServers":{"docs":{"command":"uvx"}}}"#,
    )
    .unwrap();
    fs::write(
        home.join(".novabot/skills/demo-skill/SKILL.md"),
        "---\nname: demo\n---\n",
    )
    .unwrap();
    fs::write(ws.join("NOVABOT.md"), "# rules\n").unwrap();
    fs::write(ws.join("requirements.txt"), "langgraph==0.2.0\nmcp>=1.0\n").unwrap();

    let custom_cat = AgentCatalogue::load_from_dir(&pack_dir, &TestFs).unwrap();
    let blocks = BuildingBlockCatalogue::embedded().unwrap();
    let procs = vec![WindowsProcessEntry {
        pid: 909,
        parent_pid: 1,
        image_name: "novabot.exe".into(),
        executable_path: Some(r"C:\Tools\novabot.exe".into()),
        command_line: None,
        session_id: Some(1),
    }];

    // Process matcher matches newly dropped manifest on Windows without Rust edits.
    let (matched, _) = classify_process_entry_with_catalogue(&procs[0], &custom_cat).unwrap();
    assert_eq!(matched.kind, "novabot");

    // Multi-harness hook install + dry-run diff + canary verify + MDM render all work dynamically.
    let target = HookTargetKind::from_name_with_catalogue("nova", &custom_cat).unwrap();
    let diff = dry_run_hook_diff(&target, &home, "grdr-hook", &custom_cat, &TestFs).unwrap();
    assert!(diff.changed);
    assert_eq!(diff.added_events, vec!["PreToolUse"]);

    let installed = install_hook_with_catalogue(
        &target,
        &home,
        &state_dir,
        "grdr-hook",
        false,
        &custom_cat,
        &TestFs,
    )
    .unwrap();
    assert_eq!(installed.outcome, InstallOutcome::Applied);

    let manifest = custom_cat.resolve("novabot").unwrap();
    let probe = r#"{"session_id":"s-nova","tool_name":"Bash","tool_input":{"command":"ls"}}"#;
    let canary = verify_hook_canary(manifest, &home, "grdr-hook", probe, &custom_cat, &TestFs);
    assert_eq!(canary.canary, CanaryStatus::Passed);
    assert_eq!(canary.health, HookHealthState::Effective);

    let plist = render_mdm_snippet(manifest, "grdr-hook", MdmTemplateFormat::Plist).unwrap();
    let reg = render_mdm_snippet(manifest, "grdr-hook", MdmTemplateFormat::Reg).unwrap();
    let intune = render_mdm_snippet(manifest, "grdr-hook", MdmTemplateFormat::Intune).unwrap();
    let jamf = render_mdm_snippet(manifest, "grdr-hook", MdmTemplateFormat::Jamf).unwrap();
    assert!(plist.contains("dev.novaworks.novabot"));
    assert!(reg.contains(r"Software\Policies\NovaWorks\NovaBot"));
    assert!(intune.contains("omaUri"));
    assert!(jamf.contains("PayloadContent"));

    // 4-Pass Discovery picks up novabot (AL2 Request), langgraph/mcp building blocks, and ABOM!
    let mut signals = std::collections::BTreeSet::new();
    signals.insert(ExecutionEnvironmentSignal::WorkspaceOrSandbox);
    let obs = vec![BehavioralObservation {
        process_name: "novabot.exe".into(),
        llm_request_timestamps_ms: vec![1_000, 3_000, 5_000],
        tool_effect_timestamps_ms: vec![1_200, 3_200, 5_200],
        environment_signals: signals,
        orchestrator_blocks: vec!["langgraph".into()],
        ..BehavioralObservation::default()
    }];
    let decl = vec![AgentDeclaration {
        agent_id: "absent-agent".into(),
        expected_program_id: None,
        expected_signer: None,
        allowed_hosts: Default::default(),
        approved_artifacts: Default::default(),
    }];
    let four_pass = discover_four_pass(&FourPassDiscoveryInput {
        device_name: "dev-win",
        home: Some(&home),
        appdata: None,
        workspace: Some(&ws),
        profile: InstallProfile::Protected,
        hook_command: "grdr-hook",
        fs: &TestFs,
        catalogue: &custom_cat,
        blocks: &blocks,
        processes: &procs,
        observations: &obs,
        declarations: &decl,
    });
    let agent = four_pass
        .report
        .agents
        .iter()
        .find(|a| a.kind == "novabot")
        .unwrap();
    assert!(agent.hook_installed);
    assert_eq!(agent.assurance.control, ControlStrength::Request);
    assert_eq!(agent.assurance_level, AssuranceLevel::Al2Guided);
    assert_eq!(
        four_pass.pass1[0].match_state,
        Pass1MatchState::InstalledMatched
    );
    assert!(
        four_pass
            .building_blocks
            .iter()
            .any(|b| b.block_id == "langgraph")
    );
    assert!(
        four_pass
            .building_blocks
            .iter()
            .any(|b| b.block_id == "mcp-sdks")
    );
    assert_eq!(
        four_pass.behavioral[0].verdict,
        BehaviorVerdict::AgentClassified
    );
    assert!(
        four_pass
            .inventory_diff
            .iter()
            .any(|d| d.agent_id == "novabot" && d.diff_state == DiffState::ObservedUndeclared)
    );
    assert!(
        four_pass
            .inventory_diff
            .iter()
            .any(|d| d.agent_id == "absent-agent" && d.diff_state == DiffState::DeclaredAbsent)
    );

    let mut scanned = Vec::new();
    let mut warnings = Vec::new();
    let arts = scan_artifacts_for_roots_with_catalogue(
        &custom_cat,
        "dev-win",
        Some(&home),
        Some(&ws),
        Timestamp::now(),
        &TestFs,
        &mut scanned,
        &mut warnings,
    );
    assert!(arts.iter().any(|a| a.name == "demo-skill"));
    assert!(arts.iter().any(|a| a.name == "NOVABOT.md"));

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn multi_harness_hook_install_supports_codex_copilot_and_windsurf() {
    let root = std::env::temp_dir().join(format!("grdr-multi-hook-{}", uuid::Uuid::now_v7()));
    let state_dir = root.join(".local/state/grdr");
    for agent_name in [
        "codex",
        "copilot",
        "windsurf",
        "cline",
        "roo-code",
        "opencode",
        "pi",
        "amazon-q",
        "kiro",
        "antigravity",
    ] {
        let target = HookTargetKind::from_name(agent_name).unwrap();
        let res = install_hook_in_state_dir(
            target.clone(),
            &root,
            &state_dir,
            "grdr-hook",
            false,
            &TestFs,
        )
        .unwrap();
        assert_eq!(res.outcome, InstallOutcome::Applied);
        assert!(res.config_path.is_file());
        let st = grdr_agents::hook_status(target.clone(), &root, "grdr-hook", &TestFs).unwrap();
        assert_eq!(st.state, HookInstallState::Effective);
        let un = uninstall_hook_in_state_dir(target, &root, &state_dir, None, &TestFs).unwrap();
        assert_eq!(un.outcome, InstallOutcome::Applied);
    }

    let cat = AgentCatalogue::embedded().unwrap();
    let claude = cat.resolve("claude-code").unwrap();
    let missed = verify_hook_canary(claude, &root, "grdr-hook", "{}", &cat, &TestFs);
    assert_eq!(missed.canary, CanaryStatus::Missed);
    assert_eq!(missed.health, HookHealthState::NotConfigured);

    install_hook_in_state_dir(
        HookTargetKind::ClaudeCode,
        &root,
        &state_dir,
        "grdr-hook",
        false,
        &TestFs,
    )
    .unwrap();
    let malformed = verify_hook_canary(claude, &root, "grdr-hook", "{not-json", &cat, &TestFs);
    assert_eq!(malformed.canary, CanaryStatus::ProbeRejected);
    assert_eq!(malformed.health, HookHealthState::CanaryFailed);

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn abom_drift_triage_and_digest_reconciles_declared_vs_observed() {
    let signed = ProgramIdentity::from_hints(&IdentityHints {
        code_signer: Some("Anthropic, Inc.".into()),
        binary_digest: Some("abc123".into()),
        executable_path: "/usr/local/bin/claude".into(),
        ..IdentityHints::default()
    });
    let pkg = ProgramIdentity::from_hints(&IdentityHints {
        ecosystem: Some("npm".into()),
        package_name: Some("@openai/codex".into()),
        package_version: Some("1.2.0".into()),
        executable_path: "/usr/bin/codex".into(),
        ..IdentityHints::default()
    });
    let decl = AgentDeclaration {
        agent_id: "claude-code".into(),
        expected_program_id: Some(signed.canonical_id()),
        expected_signer: Some("Anthropic, Inc.".into()),
        allowed_hosts: ["api.anthropic.com".to_owned()].into_iter().collect(),
        approved_artifacts: [("CLAUDE.md".to_owned(), "sha-old".to_owned())]
            .into_iter()
            .collect(),
    };
    let obs_drift = ObservedAgentState {
        agent_id: "claude-code".into(),
        program_identity: signed,
        presence: PresenceState::Running,
        observed_signer: Some("Untrusted-Signer".into()),
        observed_hosts: ["api.anthropic.com".into(), "evil.example".into()]
            .into_iter()
            .collect(),
        observed_artifacts: [("CLAUDE.md".to_owned(), "sha-new".to_owned())]
            .into_iter()
            .collect(),
    };
    let obs_undeclared = ObservedAgentState {
        agent_id: "custom-runner".into(),
        program_identity: pkg,
        presence: PresenceState::Running,
        observed_signer: None,
        observed_hosts: BTreeSet::new(),
        observed_artifacts: BTreeMap::new(),
    };
    let diff = reconcile_inventory_diff(&[decl], &[obs_drift.clone(), obs_undeclared.clone()]);
    assert_eq!(diff.len(), 2);
    let claude_rec = diff.iter().find(|r| r.agent_id == "claude-code").unwrap();
    assert_eq!(claude_rec.diff_state, DiffState::ShadowOrDrift);
    assert!(claude_rec.drift_kinds.contains(&DriftKind::SignerChanged));
    assert!(
        claude_rec
            .drift_kinds
            .contains(&DriftKind::RemoteEndpointAdded)
    );
    assert!(
        claude_rec
            .drift_kinds
            .contains(&DriftKind::ArtifactDigestChanged)
    );
    let undecl = diff.iter().find(|r| r.agent_id == "custom-runner").unwrap();
    assert_eq!(undecl.diff_state, DiffState::ObservedUndeclared);

    let abom = build_agent_bom("host-1", &diff, &[obs_drift, obs_undeclared]);
    assert_eq!(abom.components.len(), 2);
    assert_eq!(abom.bom_digest.len(), 64);
}

#[test]
fn manifest_rejects_path_traversal_unsafe_routes_and_mdm_injection() {
    let bad_rel = r#"schema: grdr.catalogue/v1alpha1
id: bad-agent
name: BadAgent
routes:
  state_dirs: [.bad]
  config_paths: ["../../etc/passwd"]
hook:
  supported: true
  config_rel: .bad/hooks.json
  root_key: hooks
  entry_style: matcher-hooks
  events: [PreToolUse]
"#;
    assert_eq!(
        AgentCatalogue::from_catalogue_yaml(bad_rel)
            .unwrap_err()
            .code,
        "GRDR-AGENTS-0004"
    );

    let bad_hook_rel = bad_rel
        .replace(r#""../../etc/passwd""#, ".bad/cfg.json")
        .replace(".bad/hooks.json", "/etc/evil.json");
    assert_eq!(
        AgentCatalogue::from_catalogue_yaml(&bad_hook_rel)
            .unwrap_err()
            .code,
        "GRDR-AGENTS-0004"
    );

    let bad_id = bad_rel
        .replace(r#""../../etc/passwd""#, ".bad/cfg.json")
        .replace("id: bad-agent", "id: ../escape");
    assert_eq!(
        AgentCatalogue::from_catalogue_yaml(&bad_id)
            .unwrap_err()
            .code,
        "GRDR-AGENTS-0004"
    );

    let cat = AgentCatalogue::embedded().unwrap();
    let claude = cat.resolve("claude-code").unwrap();
    let cmd_inj = render_mdm_snippet(
        claude,
        "grdr-hook\"\r\n[HKEY_LOCAL_MACHINE\\Evil]",
        MdmTemplateFormat::Reg,
    )
    .unwrap_err();
    assert_eq!(cmd_inj.code, "GRDR-AGENTS-0006");

    let mut evil_manifest = claude.clone();
    evil_manifest.hook.mdm_ids.registry_subkey =
        Some("Software\\Policies\\X]\r\n[HKEY_LOCAL_MACHINE\\Y".into());
    assert_eq!(
        render_mdm_snippet(&evil_manifest, "grdr-hook", MdmTemplateFormat::Reg)
            .unwrap_err()
            .code,
        "GRDR-AGENTS-0006"
    );
}

#[test]
fn journal_sha_mismatch_preserves_user_edits_and_custom_root_key_installs() {
    let root = std::env::temp_dir().join(format!("grdr-sec-inst-{}", uuid::Uuid::now_v7()));
    let state_dir = root.join("state");
    fs::create_dir_all(root.join(".claude")).unwrap();
    let cfg_path = root.join(".claude/settings.json");
    fs::write(&cfg_path, "{\n  \"model\": \"keep-me\"\n}\n").unwrap();

    install_hook_in_state_dir(
        HookTargetKind::ClaudeCode,
        &root,
        &state_dir,
        "grdr-hook",
        false,
        &TestFs,
    )
    .unwrap();
    let installed_text = fs::read_to_string(&cfg_path).unwrap();
    let edited = installed_text.replace(
        "\"model\": \"keep-me\"",
        "\"model\": \"keep-me\",\n  \"userAdded\": true",
    );
    fs::write(&cfg_path, edited).unwrap();

    let un =
        uninstall_hook_in_state_dir(HookTargetKind::ClaudeCode, &root, &state_dir, None, &TestFs)
            .unwrap();
    assert_eq!(un.outcome, InstallOutcome::Applied);
    let after = fs::read_to_string(&cfg_path).unwrap();
    assert!(after.contains("\"userAdded\": true"));
    assert!(after.contains("\"model\": \"keep-me\""));
    assert!(!after.contains("grdr-hook"));

    // Custom root_key preserves surrounding fields cleanly.
    let custom_yaml = r#"schema: grdr.catalogue/v1alpha1
id: custom-hook-agent
name: Custom Hook Agent
routes:
  state_dirs: [.customhook]
  config_paths: [.customhook/config.json]
hook:
  supported: true
  dialect: custom-hook-agent
  config_rel: .customhook/config.json
  root_key: lifecycleHooks
  entry_style: matcher-hooks
  events: [BeforeCustomTool]
"#;
    let custom_cat = AgentCatalogue::from_catalogue_yaml(custom_yaml).unwrap();
    let target =
        HookTargetKind::from_name_with_catalogue("custom-hook-agent", &custom_cat).unwrap();
    fs::create_dir_all(root.join(".customhook")).unwrap();
    fs::write(
        root.join(".customhook/config.json"),
        "{\n  \"theme\": \"obsidian\"\n}\n",
    )
    .unwrap();
    install_hook_with_catalogue(
        &target,
        &root,
        &state_dir,
        "grdr-hook",
        false,
        &custom_cat,
        &TestFs,
    )
    .unwrap();
    let custom_after = fs::read_to_string(root.join(".customhook/config.json")).unwrap();
    assert!(custom_after.contains("\"lifecycleHooks\""));
    assert!(custom_after.contains("\"theme\": \"obsidian\""));
    uninstall_hook_with_catalogue(&target, &root, &state_dir, None, &custom_cat, &TestFs).unwrap();

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn hook_codec_caps_oversized_stdin_and_discover_scrubs_urls_and_appdata() {
    let oversized = format!("{{\"session_id\":\"{}\"}}", "a".repeat(1_048_600));
    let err = parse_hook_stdin_with_dialect("auto", &oversized, "host").unwrap_err();
    assert!(err.contains("GRDR-AGENTS-0002"));

    let custom_cat = AgentCatalogue::from_catalogue_yaml(
        r#"schema: grdr.catalogue/v1alpha1
id: event-bot
name: EventBot
routes:
  state_dirs: [.eventbot]
hook:
  supported: true
  dialect: event-bot
  config_rel: .eventbot/hooks.json
  root_key: hooks
  entry_style: matcher-hooks
  events: [BeforeEventBotTool]
"#,
    )
    .unwrap();
    let attempt = parse_hook_stdin_with_catalogue(
        "auto",
        r#"{"session_id":"eb-1","hook_event_name":"BeforeEventBotTool","tool_name":"Bash","tool_input":{"command":"id"}}"#,
        "host",
        &custom_cat,
    )
    .unwrap();
    assert_eq!(attempt.agent_name, "event-bot");
    assert_eq!(attempt.session_id, "eb-1");

    let root = std::env::temp_dir().join(format!("grdr-sec-disc-{}", uuid::Uuid::now_v7()));
    let appdata = root.join("appdata");
    fs::create_dir_all(root.join(".claude")).unwrap();
    fs::create_dir_all(appdata.join("Code/User")).unwrap();
    fs::write(
        root.join(".claude/settings.json"),
        r#"{
  "mcpServers": {
    "remote": { "url": "https://user:secret_pass@mcp.example.com/sse?token=secret#frag" },
    "local": { "command": "\"/opt/bin/uvx\" --from mcp-pkg" }
  }
}"#,
    )
    .unwrap();
    fs::write(
        appdata.join("Code/User/mcp.json"),
        r#"{"servers":{"vscode-mcp":{"command":"node server.js"}}}"#,
    )
    .unwrap();

    let report = discover_from_roots(
        "box",
        Some(&root),
        Some(&appdata),
        InstallProfile::User,
        "grdr-hook",
        &TestFs,
    );
    let report_json = serde_json::to_string(&report).unwrap();
    assert!(!report_json.contains("secret_pass"));
    assert!(!report_json.contains("token=secret"));
    assert!(
        report
            .mcp_servers
            .iter()
            .any(|m| m.name == "remote" && m.command == "https://mcp.example.com/sse")
    );
    assert!(
        report
            .mcp_servers
            .iter()
            .any(|m| m.name == "local" && m.command == "uvx")
    );
    assert!(
        report
            .mcp_servers
            .iter()
            .any(|m| m.name == "vscode-mcp" && m.command == "node")
    );

    let _ = fs::remove_dir_all(&root);
}

#[cfg(unix)]
#[test]
fn symlink_config_or_catalogue_file_is_rejected_without_following() {
    use std::os::unix::fs::symlink;

    let root = std::env::temp_dir().join(format!("grdr-sec-sym-{}", uuid::Uuid::now_v7()));
    let state_dir = root.join("state");
    fs::create_dir_all(root.join(".claude")).unwrap();
    let victim = root.join("victim.txt");
    fs::write(&victim, "DO_NOT_OVERWRITE").unwrap();
    symlink(&victim, root.join(".claude/settings.json")).unwrap();

    let err = install_hook_in_state_dir(
        HookTargetKind::ClaudeCode,
        &root,
        &state_dir,
        "grdr-hook",
        false,
        &TestFs,
    )
    .unwrap_err();
    assert!(err.contains("GRDR-AGENTS-0002") || err.contains("symlink"));
    assert_eq!(fs::read_to_string(&victim).unwrap(), "DO_NOT_OVERWRITE");

    let _ = fs::remove_dir_all(&root);
}

#[test]
fn hardening_rejects_duplicate_ids_false_hook_matches_mdm_drift_and_custom_commands() {
    // Single-file catalogues reject duplicate agent / block IDs.
    let dup_agents = AgentCatalogue::from_catalogue_yaml(
        r#"schema: grdr.catalogue/v1alpha1
agents:
  - id: dup-one
    name: DupOne
    routes:
      state_dirs: [.dup1]
    hook:
      supported: false
  - id: dup-one
    name: DupTwo
    routes:
      state_dirs: [.dup2]
    hook:
      supported: false
"#,
    );
    assert_eq!(dup_agents.unwrap_err().code, "GRDR-AGENTS-0004");

    let dup_blocks = BuildingBlockCatalogue::from_yaml(
        r#"schema: grdr.building-blocks/v1alpha1
blocks:
  - id: blk-dup
    name: One
    role: orchestrator
    agentic: yes
  - id: blk-dup
    name: Two
    role: llm-sdk
    agentic: no
"#,
    );
    assert_eq!(dup_blocks.unwrap_err().code, "GRDR-AGENTS-0005");

    // False command matches in name/matcher/comment/description or arg[1] must fail;
    // TOML MCP sections extract real scrubbed command/url and fallback to stdio-toml.
    let root = std::env::temp_dir().join(format!("grdr-h-b3-{}", uuid::Uuid::now_v7()));
    let state_dir = root.join("state");
    fs::create_dir_all(root.join(".claude")).unwrap();
    fs::create_dir_all(root.join(".codex")).unwrap();
    fs::write(
        root.join(".claude/settings.json"),
        r#"{
  "hooks": {
    "PreToolUse": [{
      "matcher": "grdr-hook",
      "name": "grdr-hook",
      "description": "grdr-hook",
      "comment": "grdr-hook",
      "hooks": [
        { "type": "command", "command": "/opt/other/wrapper" },
        { "type": "command", "command": ["echo", "grdr-hook"] }
      ]
    }]
  }
}"#,
    )
    .unwrap();
    fs::write(
        root.join(".codex/config.toml"),
        r#"[mcp_servers.local_stdio]
command = "/usr/local/bin/uvx"

[mcp_servers.remote_http]
url = "https://user:secret_pass@mcp.example.com/sse?token=secret#frag"

[mcp_servers.bare_server]
"#,
    )
    .unwrap();
    let dec_report = discover_from_roots(
        "box",
        Some(&root),
        None,
        InstallProfile::User,
        "grdr-hook",
        &TestFs,
    );
    let claude = dec_report
        .agents
        .iter()
        .find(|a| a.kind == "claude-code")
        .unwrap();
    assert!(
        !claude.hook_installed,
        "name/matcher/comment/description or arg[1] must not count as installed"
    );
    assert!(
        dec_report
            .mcp_servers
            .iter()
            .any(|m| m.name == "local_stdio" && m.transport == "stdio" && m.command == "uvx")
    );
    assert!(dec_report.mcp_servers.iter().any(|m| {
        m.name == "remote_http"
            && m.transport == "http"
            && m.command == "https://mcp.example.com/sse"
    }));
    assert!(dec_report.mcp_servers.iter().any(|m| {
        m.name == "bare_server" && m.transport == "stdio" && m.command == "stdio-toml"
    }));
    assert!(
        !dec_report
            .mcp_servers
            .iter()
            .any(|m| m.command == "codex-mcp")
    );

    // Custom hook_command is persisted in journal, detected, and stripped even post-edit.
    let custom_cmd = "/opt/custom/acme-hook";
    install_hook_in_state_dir(
        HookTargetKind::Cursor,
        &root,
        &state_dir,
        custom_cmd,
        false,
        &TestFs,
    )
    .unwrap();
    assert_eq!(
        recorded_hook_command(&HookTargetKind::Cursor, &state_dir, &TestFs)
            .unwrap()
            .as_deref(),
        Some(custom_cmd)
    );
    assert!(
        grdr_agents::hook_status(HookTargetKind::Cursor, &root, custom_cmd, &TestFs)
            .unwrap()
            .installed
    );
    let cursor_cfg = root.join(".cursor/hooks.json");
    let modified_cursor =
        fs::read_to_string(&cursor_cfg)
            .unwrap()
            .replacen('{', "{\"userFlag\": true,", 1);
    fs::write(&cursor_cfg, modified_cursor).unwrap();
    let removed_custom =
        uninstall_hook_in_state_dir(HookTargetKind::Cursor, &root, &state_dir, None, &TestFs)
            .unwrap();
    assert_eq!(removed_custom.outcome, InstallOutcome::Applied);
    let post_uninstall = fs::read_to_string(&cursor_cfg).unwrap();
    assert!(post_uninstall.contains("userFlag"));
    assert!(!post_uninstall.contains("acme-hook"));

    // Dynamic payload_session_keys matching without hardcoded harness checks.
    let key_cat = AgentCatalogue::from_catalogue_yaml(
        r#"schema: grdr.catalogue/v1alpha1
id: key-driven-agent
name: KeyDrivenAgent
routes:
  state_dirs: [.keydriven]
hook:
  supported: true
  dialect: key-driven-dialect
  config_rel: .keydriven/hooks.json
  events: [CustomPreTool]
  payload_session_keys: [custom_session_token]
"#,
    )
    .unwrap();
    let dyn_attempt = parse_hook_stdin_with_catalogue(
        "auto",
        r#"{"custom_session_token":"tok-99","tool_name":"Bash","tool_input":{"command":"pwd"}}"#,
        "host",
        &key_cat,
    )
    .unwrap();
    assert_eq!(dyn_attempt.agent_name, "key-driven-dialect");
    assert_eq!(dyn_attempt.session_id, "tok-99");

    // MDM snippet respects agent_flag/timeout_unit_secs/entry_name and rejects bad plist_domain.
    let mdm_cat = AgentCatalogue::from_catalogue_yaml(
        r#"schema: grdr.catalogue/v1alpha1
id: mdm-flags-agent
name: MdmFlagsAgent
routes:
  state_dirs: [.mdmflags]
hook:
  supported: true
  dialect: mdm-flags-agent
  config_rel: .mdmflags/hooks.json
  root_key: lifecycle
  entry_style: matcher-hooks
  entry_name: guardrails-check
  events: [PreTool]
  timeout_ms: 1500
  timeout_unit_secs: true
  append_agent_flag: false
  mdm_ids:
    plist_domain: com.example.mdmflags
"#,
    )
    .unwrap();
    let mut mdm_manifest = mdm_cat.resolve("mdm-flags-agent").unwrap().clone();
    let mdm_json = render_mdm_snippet(&mdm_manifest, "/opt/grdr", MdmTemplateFormat::Json).unwrap();
    assert!(!mdm_json.contains("--agent"));
    assert!(mdm_json.contains("\"timeout\": 2"));
    assert!(mdm_json.contains("\"name\": \"guardrails-check\""));
    mdm_manifest.hook.mdm_ids.plist_domain = Some("..evil.domain".into());
    assert_eq!(
        render_mdm_snippet(&mdm_manifest, "/opt/grdr", MdmTemplateFormat::Plist)
            .unwrap_err()
            .code,
        "GRDR-AGENTS-0006"
    );

    // Signed->unsigned and unapproved/missing artifacts both report ABOM drift.
    let h2_decl = AgentDeclaration {
        agent_id: "claude-code".into(),
        expected_program_id: None,
        expected_signer: Some("Anthropic, Inc.".into()),
        allowed_hosts: BTreeSet::new(),
        approved_artifacts: [("CLAUDE.md".into(), "sha-approved".into())]
            .into_iter()
            .collect(),
    };
    let h2_obs = ObservedAgentState {
        agent_id: "claude-code".into(),
        program_identity: ProgramIdentity::from_hints(&IdentityHints::default()),
        presence: PresenceState::Running,
        observed_signer: None,
        observed_hosts: BTreeSet::new(),
        observed_artifacts: [
            ("CLAUDE.md".into(), "sha-approved".into()),
            ("ROGUE.md".into(), "sha-rogue".into()),
        ]
        .into_iter()
        .collect(),
    };
    let h2_diff = reconcile_inventory_diff(&[h2_decl], &[h2_obs]);
    assert!(h2_diff[0].drift_kinds.contains(&DriftKind::SignerChanged));
    assert!(
        h2_diff[0]
            .drift_kinds
            .contains(&DriftKind::ArtifactDigestChanged)
    );

    let _ = fs::remove_dir_all(&root);
}
