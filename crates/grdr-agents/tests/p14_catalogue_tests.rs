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
    let static_canary =
        verify_hook_canary(manifest, &home, "grdr-hook", probe, &custom_cat, &TestFs);
    assert_eq!(static_canary.canary, CanaryStatus::Missed);
    assert_eq!(static_canary.health, HookHealthState::Configured);
    let mut passive_ok = grdr_agents::PassiveCanaryState::new();
    passive_ok.apply(grdr_agents::PassiveCanaryEvent::SessionStart {
        pid: 99,
        session_key: "s-nova".into(),
        at_ms: 100,
    });
    passive_ok.apply(grdr_agents::PassiveCanaryEvent::HookPreTool {
        session_key: "s-nova".into(),
        at_ms: 110,
    });
    passive_ok.apply(grdr_agents::PassiveCanaryEvent::OsSensorToolEffect {
        pid: 99,
        at_ms: 120,
    });
    let canary = grdr_agents::verify_hook_canary_with_passive(
        manifest,
        &home,
        "grdr-hook",
        probe,
        &passive_ok,
        &custom_cat,
        &TestFs,
    );
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
    assert_eq!(agent.assurance.control, ControlStrength::None);
    assert_eq!(agent.assurance_level, AssuranceLevel::Al1Observed);
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

#[test]
fn passive_canary_al2_cap_layer_precedence_and_containment_tiers() {
    use grdr_agents::{
        ConfigLayerScope, ContainmentTier, HookLayerDisposition, HookLayerObservation,
        PassiveCanaryEvent, PassiveCanaryPhase, PassiveCanaryState, check_adapter_version_support,
        evaluate_hook_assurance, hook_status_with_canary, probe_hook_layer_precedence,
    };

    // Pending passive canary holds Protected hooks at AL1 Observed, then verified -> AL2 Guided, never AL3.
    let pending = evaluate_hook_assurance(
        InstallProfile::Protected,
        true,
        HookHealthState::Configured,
        true,
        ContainmentTier::HookOnly,
    );
    assert_eq!(pending.control, ControlStrength::None);
    assert_eq!(pending.level(), AssuranceLevel::Al1Observed);

    let verified_hook = evaluate_hook_assurance(
        InstallProfile::Protected,
        true,
        HookHealthState::Effective,
        true,
        ContainmentTier::HookOnly,
    );
    assert_eq!(verified_hook.control, ControlStrength::Request);
    assert_eq!(verified_hook.level(), AssuranceLevel::Al2Guided);

    let scoped = evaluate_hook_assurance(
        InstallProfile::Protected,
        true,
        HookHealthState::Effective,
        true,
        ContainmentTier::ScopedSandbox,
    );
    assert_eq!(scoped.level(), AssuranceLevel::Al3Contained);

    let enforced = evaluate_hook_assurance(
        InstallProfile::Protected,
        true,
        HookHealthState::Effective,
        true,
        ContainmentTier::MandatoryKernelFailClosed,
    );
    assert_eq!(enforced.level(), AssuranceLevel::Al4Enforced);

    // Passive SessionStart + PreToolUse verification & macOS transcript fallback canary-missed.
    let mut canary = PassiveCanaryState::new();
    canary.apply(PassiveCanaryEvent::SessionStart {
        pid: 4200,
        session_key: "sess-a".into(),
        at_ms: 1000,
    });
    canary.apply(PassiveCanaryEvent::HookPreTool {
        session_key: "sess-a".into(),
        at_ms: 1020,
    });
    assert_eq!(
        canary.apply(PassiveCanaryEvent::OsSensorToolEffect {
            pid: 4200,
            at_ms: 1040,
        }),
        HookHealthState::Effective
    );
    assert_eq!(canary.phase, PassiveCanaryPhase::Verified);

    let mut missed = PassiveCanaryState::new();
    missed.apply(PassiveCanaryEvent::SessionStart {
        pid: 4201,
        session_key: "sess-b".into(),
        at_ms: 2000,
    });
    missed.apply(PassiveCanaryEvent::TranscriptToolFallback {
        session_key: "sess-b".into(),
        at_ms: 2100,
    });
    assert_eq!(
        missed.advance_clock(2200),
        HookHealthState::ConfiguredNotEffective
    );
    assert_eq!(missed.finding_rule.as_deref(), Some("canary-missed"));

    assert_eq!(
        probe_hook_layer_precedence(
            &[
                HookLayerObservation {
                    scope: ConfigLayerScope::ManagedPolicy,
                    disposition: HookLayerDisposition::DisabledAllHooks,
                },
                HookLayerObservation {
                    scope: ConfigLayerScope::UserConfig,
                    disposition: HookLayerDisposition::HasGrdrHook,
                },
            ],
            false,
        ),
        HookHealthState::Shadowed
    );
    assert_eq!(
        check_adapter_version_support(Some("99.0.0"), (1, 0), Some((3, 9))),
        HookHealthState::UnknownVersion
    );

    let root = std::env::temp_dir().join(format!("grdr-pcanary-{}", uuid::Uuid::now_v7()));
    let state_dir = root.join("state");
    fs::create_dir_all(root.join(".claude")).unwrap();
    install_hook_in_state_dir(
        HookTargetKind::ClaudeCode,
        &root,
        &state_dir,
        "grdr-hook",
        false,
        &TestFs,
    )
    .unwrap();
    let cat = AgentCatalogue::embedded().unwrap();
    let unverified = hook_status_with_canary(
        &HookTargetKind::ClaudeCode,
        &root,
        "grdr-hook",
        None,
        &cat,
        &TestFs,
    )
    .unwrap();
    assert_eq!(unverified.health, HookHealthState::Configured);
    let passed = hook_status_with_canary(
        &HookTargetKind::ClaudeCode,
        &root,
        "grdr-hook",
        Some(true),
        &cat,
        &TestFs,
    )
    .unwrap();
    assert_eq!(passed.health, HookHealthState::Effective);
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn multi_language_pass2_scanners_and_budget_enforcement() {
    use grdr_agents::{
        ScanBudget, has_corroborated_mcp_sdk, scan_embedded_binary_markers,
        scan_workspace_building_blocks_with_budget,
    };
    use grdr_core::discover::ScanBlockedReason;

    let root = std::env::temp_dir().join(format!("grdr-pass2-lang-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(root.join(".venv/lib/python3.12/site-packages/langgraph.dist-info"))
        .unwrap();
    fs::write(
        root.join(".venv/lib/python3.12/site-packages/langgraph.dist-info/METADATA"),
        "Metadata-Version: 2.1\nName: langgraph\nVersion: 0.2.0\n",
    )
    .unwrap();
    fs::create_dir_all(root.join("node_modules/@modelcontextprotocol/sdk")).unwrap();
    fs::write(
        root.join("node_modules/@modelcontextprotocol/sdk/package.json"),
        r#"{"name":"@modelcontextprotocol/sdk","version":"1.2.0"}"#,
    )
    .unwrap();
    fs::write(
        root.join("go.mod"),
        "module acme/bot\nrequire (\n  github.com/cloudwego/eino v0.3.0\n)\n",
    )
    .unwrap();
    fs::write(
        root.join("Cargo.lock"),
        "[[package]]\nname = \"rig-core\"\nversion = \"0.6.0\"\n",
    )
    .unwrap();
    fs::write(
        root.join("pom.xml"),
        "<project><dependencies><dependency><groupId>dev.langchain4j</groupId><artifactId>langchain4j</artifactId></dependency></dependencies></project>",
    )
    .unwrap();
    fs::create_dir_all(root.join("bin")).unwrap();
    fs::write(
        root.join("bin/Agent.deps.json"),
        r#"{"libraries":{"Microsoft.SemanticKernel/1.0.0":{"type":"package"}}}"#,
    )
    .unwrap();

    let blocks = BuildingBlockCatalogue::embedded().unwrap();
    let res = scan_workspace_building_blocks_with_budget(
        Some(&root),
        &blocks,
        ScanBudget::default(),
        &TestFs,
    );
    assert_eq!(res.blocked_reason, None);
    let ids: BTreeSet<&str> = res.detected.iter().map(|d| d.block_id.as_str()).collect();
    for expected in [
        "langgraph",
        "mcp-sdks",
        "eino-adk",
        "rig",
        "langchain4j",
        "semantic-kernel",
    ] {
        assert!(
            ids.contains(expected),
            "missing block {expected} in {ids:?}"
        );
    }
    assert!(!has_corroborated_mcp_sdk(&res.detected, false));
    assert!(has_corroborated_mcp_sdk(&res.detected, true));

    let tight = scan_workspace_building_blocks_with_budget(
        Some(&root),
        &blocks,
        ScanBudget {
            max_ms: 200,
            max_stats: 2,
            max_manifests: 100,
            max_bytes: 1024 * 1024,
        },
        &TestFs,
    );
    assert_eq!(
        tight.blocked_reason,
        Some(ScanBlockedReason::BudgetExceeded)
    );

    let embedded = scan_embedded_binary_markers(
        b"go.buildinfo github.com/cloudwego/eino",
        "custom-agent-bin",
        &blocks,
    );
    assert!(embedded.iter().any(|b| b.block_id == "eino-adk"));
    let _ = fs::remove_dir_all(&root);
}

#[test]
fn pass4_fleet_triage_org_fingerprint_endpoints_creds_importers_and_abom() {
    use grdr_agents::{
        CredentialExposure, FleetDeclarationRecord, FleetInventoryState, ModelEndpointRegistry,
        ModelEndpointState, OrgEntryAttributes, QuarantineList, TriageDisposition, TriageItem,
        TriageObservationUpdate, TriageReopenTrigger, apply_triage_disposition,
        build_credential_inventory_record, diff_agent_boms, evaluate_triage_reopen,
        export_cyclonedx_1_7, export_ocsf_5020, generate_org_catalogue_entry, import_acp_registry,
        import_ai_detection_spec, import_uber_adr_signatures, lint_catalogue_pack_yaml,
        lint_cedar_block_on_advisory, parse_grdr_agent_toml, reconcile_fleet_states,
        sanitize_upstream_proposal,
    };

    // Fleet 6-state matrix: separated declared-unseen vs declared-blind.
    let mut incumbent = BTreeSet::new();
    incumbent.insert("defender-only-bot".to_owned());
    let decls = vec![FleetDeclarationRecord {
        agent_id: "absent-bot".into(),
        declared_at_epoch_secs: 100,
        expected_signer: None,
        allowed_hosts: BTreeSet::new(),
        approved_artifacts: BTreeMap::new(),
    }];
    let blind_rows = reconcile_fleet_states(&decls, &[], true, &incumbent, 100 + 8 * 86_400);
    assert!(
        blind_rows.iter().any(|r| {
            r.agent_id == "absent-bot" && r.state == FleetInventoryState::DeclaredBlind
        })
    );
    assert!(blind_rows.iter().any(|r| {
        r.agent_id == "defender-only-bot" && r.state == FleetInventoryState::IncumbentOnly
    }));
    let unseen_rows =
        reconcile_fleet_states(&decls, &[], false, &BTreeSet::new(), 100 + 8 * 86_400);
    assert_eq!(unseen_rows[0].state, FleetInventoryState::DeclaredUnseen);
    assert_eq!(
        unseen_rows[0].finding_rule.as_deref(),
        Some("discovery.declaration-stale")
    );

    // Triage widening discipline, reopen triggers & P8 HMAC org fingerprint.
    let mut item = TriageItem {
        org_id: "org-1".into(),
        program_id: "src:private-repo:hash".into(),
        device_ids: BTreeSet::new(),
        verdict: BehaviorVerdict::LlmClient,
        observed_signer: Some("Vendor A".into()),
        observed_hosts: ["api.anthropic.com".into()].into_iter().collect(),
        observed_package: Some("acme-bot".into()),
        building_blocks: BTreeSet::new(),
        disposition: None,
        decided_at_epoch_secs: None,
        expires_at_epoch_secs: None,
        reopened_by: None,
    };
    let same_approver_err = apply_triage_disposition(
        &mut item,
        TriageDisposition::Snooze {
            owner: "alice".into(),
            approver: Some("alice".into()),
            justification: "bench".into(),
            ttl_days: 10,
        },
        true,
        1_000,
    )
    .unwrap_err();
    assert_eq!(same_approver_err.code, "GRDR-AGENTS-0005");
    apply_triage_disposition(
        &mut item,
        TriageDisposition::LlmClientNotAgent {
            owner: "alice".into(),
            approver: Some("bob".into()),
            justification: "etl job".into(),
            ttl_days: 180,
        },
        true,
        1_000,
    )
    .unwrap();
    let reopen = evaluate_triage_reopen(
        &mut item,
        &TriageObservationUpdate {
            verdict: BehaviorVerdict::AgentSuspected,
            observed_signer: Some("Vendor B".into()),
            observed_hosts: ["api.anthropic.com".into()].into_iter().collect(),
            observed_package: Some("acme-bot".into()),
            building_blocks: BTreeSet::new(),
            now_epoch_secs: 2_000,
        },
    );
    assert_eq!(reopen, Some(TriageReopenTrigger::SignerChanged));

    let priv_id = ProgramIdentity::from_hints(&IdentityHints {
        workspace_id: Some("corp/secret-bot".into()),
        tree_digest: Some("sha1".into()),
        executable_path: "/home/alice/secret/run".into(),
        ..IdentityHints::default()
    });
    let tenant_salt = b"0123456789abcdef0123456789abcdef";
    let org_entry = generate_org_catalogue_entry(
        &priv_id,
        tenant_salt,
        &["github.com".into()],
        OrgEntryAttributes {
            agent_kind: "coding-agent".into(),
            sponsor_team: "platform-sec".into(),
            building_blocks: vec!["langgraph".into()],
            inference_hosts: vec!["llm-gw.internal".into()],
            env_markers: vec![],
        },
    )
    .unwrap();
    assert!(org_entry.id.starts_with("agt_x_"));
    assert!(org_entry.primary_route.starts_with("src:hmac_"));
    assert!(sanitize_upstream_proposal(&org_entry).is_none());

    // Model endpoint learn / declare / reject & secret-free credential inventory.
    let mut reg = ModelEndpointRegistry::new(tenant_salt).unwrap();
    let gw = reg.declare_endpoint("openai", "gw.corp.internal", Some("corp"), Some("spki123"));
    assert_eq!(gw.state, ModelEndpointState::Declared);
    let learned = reg
        .learn_from_http_shape("127.0.0.1:8080", "/v1/messages", &[])
        .unwrap()
        .unwrap();
    assert_eq!(learned.state, ModelEndpointState::Learned);
    assert!(
        reg.learn_from_env_base_url("OPENAI_BASE_URL", "https://user:pw@llm.local/v1")
            .unwrap()
            .is_some()
    );
    assert!(reg.in_inference_set("llm.local"));
    assert_eq!(reg.reject_endpoint("llm.local").unwrap(), "audit.admin");
    assert!(!reg.in_inference_set("llm.local"));

    let secret_raw = ["sk", "-", "ant", "-api03-secretvalue123456"].concat();
    let cred = build_credential_inventory_record(
        tenant_salt,
        "mcp.github.env.ANTHROPIC_API_KEY",
        Some("user"),
        Some(&secret_raw),
        Some(500),
    )
    .unwrap();
    assert!(cred.id.starts_with("crd_"));
    assert_eq!(cred.exposure, CredentialExposure::Plaintext);
    assert!(cred.policy_violation_finding);
    let cred_json = serde_json::to_string(&cred).unwrap();
    assert!(!cred_json.contains(&secret_raw));

    // P7 linter, importers w/ quarantine.json, grdr-agent.toml, CycloneDX 1.7 / OCSF 5020 + diff.
    let bad_p7 = "id: evil\ncommands: [\"rm -rf /\"]\n";
    assert_eq!(
        lint_catalogue_pack_yaml(bad_p7).unwrap_err().code,
        "GRDR-AGENTS-0004"
    );
    assert_eq!(
        lint_cedar_block_on_advisory(
            "forbid(principal, action, resource) when { context.agent_suspected == true };"
        )
        .unwrap_err()
        .code,
        "GRDR-AGENTS-0004"
    );

    let quar = QuarantineList::from_json(r#"{"quarantined":["bad-agent"]}"#).unwrap();
    let ai_imp = import_ai_detection_spec(
        "agents:\n  - id: bad-agent\n    name: Bad\n  - id: good-agent\n    name: Good\n    binaries: [good]\n",
        &quar,
    )
    .unwrap();
    assert_eq!(ai_imp.skipped_quarantined, 1);
    assert_eq!(ai_imp.imported[0].catalogue_tier, "B");
    assert_eq!(
        import_uber_adr_signatures(
            r#"{"agents":[{"id":"u-agent","process_names":["uagent"]}]}"#,
            &quar
        )
        .unwrap()
        .imported
        .len(),
        1
    );
    assert_eq!(
        import_acp_registry(
            r#"{"agents":[{"id":"acp-agent","command":"acp-bin"}]}"#,
            &quar
        )
        .unwrap()
        .imported[0]
            .adapter,
        "acp"
    );

    let toml_decl = parse_grdr_agent_toml(
        r#"
schema = "grdr.agent/v1alpha1"
slug = "invoice-bot"
sponsor_team = "finance-platform"
identity = { pkg = "pypi:acme-invoice" }
session_exclusive = true
tools = [ { name = "run_sql", action_class = "net.request" } ]
model_endpoints = [ "https://llm.acme.internal" ]
expected_children = [ "psql" ]
"#,
    )
    .unwrap();
    assert!(toml_decl.expected_children_inert);
    let bom_before = build_agent_bom("dev-1", &[], &[]);
    let obs_one = ObservedAgentState {
        agent_id: "invoice-bot".into(),
        program_identity: toml_decl.identity.clone(),
        presence: PresenceState::Running,
        observed_signer: None,
        observed_hosts: BTreeSet::new(),
        observed_artifacts: BTreeMap::new(),
    };
    let diff_one = reconcile_inventory_diff(
        &[toml_decl.to_agent_declaration()],
        std::slice::from_ref(&obs_one),
    );
    let bom_after = build_agent_bom("dev-1", &diff_one, &[obs_one]);
    let cdx = export_cyclonedx_1_7(&bom_after, tenant_salt).unwrap();
    assert_eq!(cdx["specVersion"], "1.7");
    let ocsf = export_ocsf_5020(&bom_after, tenant_salt).unwrap();
    assert_eq!(ocsf["class_uid"], 5020);
    assert_eq!(diff_agent_boms(&bom_before, &bom_after).len(), 1);
}

#[test]
fn section5_adversarial_canary_p8_secret_triage_abom_and_importer_checks() {
    use grdr_agents::{
        AgentDeclaration, CredentialExposure, ModelEndpointRegistry, ObservedAgentState,
        OrgEntryAttributes, PassiveCanaryEvent, PassiveCanaryPhase, PassiveCanaryState,
        PresenceState, QuarantineList, TriageDisposition, TriageItem, TriageObservationUpdate,
        TriageReopenTrigger, apply_triage_disposition, build_agent_bom,
        build_credential_inventory_record, check_adapter_version_support, evaluate_triage_reopen,
        export_cyclonedx_1_7, export_ocsf_5020, generate_org_catalogue_entry,
        lint_catalogue_pack_yaml, lint_cedar_block_on_advisory, parse_grdr_agent_toml,
        reconcile_inventory_diff, sanitize_upstream_proposal, scan_workspace_building_blocks,
        verify_hook_canary_exec,
    };
    use grdr_core::discover::{BehaviorVerdict, IdentityHints, ProgramIdentity};
    use std::collections::{BTreeMap, BTreeSet};

    // 1. Passive canary rejects pre-SessionStart, session rebind, HookPreTool-only self-verify,
    //    TranscriptToolFallback without OS effect, and expired HookPreTool timestamps.
    assert_eq!(
        check_adapter_version_support(None, (1, 0), Some((3, 9))),
        HookHealthState::UnknownVersion
    );
    let mut passive = PassiveCanaryState::new();
    passive.apply(PassiveCanaryEvent::HookPreTool {
        session_key: "s1".into(),
        at_ms: 100,
    });
    assert_eq!(passive.phase, PassiveCanaryPhase::Idle);
    passive.apply(PassiveCanaryEvent::SessionStart {
        pid: 10,
        session_key: "s1".into(),
        at_ms: 200,
    });
    passive.apply(PassiveCanaryEvent::SessionStart {
        pid: 99,
        session_key: "hijack".into(),
        at_ms: 210,
    });
    assert_eq!(passive.pid, Some(10));
    assert_eq!(passive.session_key.as_deref(), Some("s1"));
    assert_eq!(
        passive.apply(PassiveCanaryEvent::HookPreTool {
            session_key: "s1".into(),
            at_ms: 220,
        }),
        HookHealthState::Configured
    );
    assert_eq!(passive.phase, PassiveCanaryPhase::AwaitingFirstTool);
    passive.advance_clock(400);
    assert!(passive.first_hook_pre_ms.is_none());
    passive.apply(PassiveCanaryEvent::HookPreTool {
        session_key: "s1".into(),
        at_ms: 450,
    });
    assert_eq!(
        passive.apply(PassiveCanaryEvent::TranscriptToolFallback {
            session_key: "s1".into(),
            at_ms: 460,
        }),
        HookHealthState::Configured
    );
    assert_ne!(passive.phase, PassiveCanaryPhase::Verified);

    let root = std::env::temp_dir().join(format!("grdr-sec5-{}", uuid::Uuid::now_v7()));
    let _ = fs::create_dir_all(&root);
    let cat = AgentCatalogue::embedded().unwrap();
    let claude = cat.resolve("claude-code").unwrap();
    let exec_fail = verify_hook_canary_exec(
        claude,
        &root,
        "/nonexistent/grdr-hook-missing",
        r#"{"session_id":"s1","tool_name":"Bash","tool_input":{"command":"ls"}}"#,
        &cat,
        &TestFs,
    );
    assert_ne!(exec_fail.health, HookHealthState::Effective);
    let _ = fs::remove_dir_all(&root);

    // 2. Weak HMAC salts are rejected; plaintext secrets are never masked by keystore/vault field names;
    //    benign hyphenated tokens don't trigger locators; query/userinfo stripped cleanly.
    let strong_salt = [0x5Au8; 32];
    assert!(ModelEndpointRegistry::new(b"too-short").is_err());
    assert!(build_credential_inventory_record(b"short", "a", None, Some("val"), None).is_err());
    let mut reg = ModelEndpointRegistry::new(&strong_salt).unwrap();
    let rec = reg
        .learn_from_env_base_url("OPENAI_BASE_URL", "https://user:pw@llm.local?api=1#frag")
        .unwrap()
        .unwrap();
    assert_eq!(rec.origin, "llm.local");
    let raw_secret = ["sk", "-", "ant", "-api03-leakunderkeychain123"].concat();
    let leaked_in_keychain = build_credential_inventory_record(
        &strong_salt,
        "mcp.keychain.token",
        None,
        Some(&raw_secret),
        None,
    )
    .unwrap();
    assert_eq!(leaked_in_keychain.exposure, CredentialExposure::Plaintext);
    assert!(leaked_in_keychain.policy_violation_finding);
    let benign_disk = build_credential_inventory_record(
        &strong_salt,
        "notes.disk_label",
        None,
        Some("${DISK_USAGE_REF}"),
        None,
    )
    .unwrap();
    assert_eq!(benign_disk.exposure, CredentialExposure::SafeReference);

    // 3. Sanitize upstream proposal scrubs private fields; SignerChanged suppressed when expected_signer None.
    let pkg_id = ProgramIdentity::from_hints(&IdentityHints {
        ecosystem: Some("npm".into()),
        package_name: Some("public-agent".into()),
        package_version: Some("1.0.0".into()),
        ..IdentityHints::default()
    });
    let org_entry = generate_org_catalogue_entry(
        &pkg_id,
        &strong_salt,
        &[],
        OrgEntryAttributes {
            agent_kind: "coding-agent".into(),
            sponsor_team: "sec-team".into(),
            building_blocks: vec!["private-sdk".into()],
            inference_hosts: vec!["internal-gw.corp".into()],
            env_markers: vec!["PRIVATE_ENV_TOKEN".into()],
        },
    )
    .unwrap();
    let prop = sanitize_upstream_proposal(&org_entry).unwrap();
    assert!(prop.building_blocks.is_empty());
    assert!(prop.env_markers.is_empty());
    assert!(prop.inference_hosts.is_empty());

    let no_signer_diff = reconcile_inventory_diff(
        &[AgentDeclaration {
            agent_id: "public-agent".into(),
            expected_program_id: Some(pkg_id.canonical_id()),
            expected_signer: None,
            allowed_hosts: BTreeSet::new(),
            approved_artifacts: BTreeMap::new(),
        }],
        &[ObservedAgentState {
            agent_id: "public-agent".into(),
            program_identity: pkg_id.clone(),
            presence: PresenceState::Running,
            observed_signer: Some("Vendor".into()),
            observed_hosts: BTreeSet::new(),
            observed_artifacts: BTreeMap::new(),
        }],
    );
    assert!(
        !no_signer_diff[0]
            .drift_kinds
            .contains(&grdr_agents::DriftKind::SignerChanged)
    );

    // 4. Triage reopen from empty observed_hosts + escalation across Snooze -> AgentSuspected.
    let mut item = TriageItem {
        org_id: "org".into(),
        program_id: pkg_id.canonical_id(),
        device_ids: BTreeSet::new(),
        verdict: BehaviorVerdict::LlmClient,
        observed_signer: None,
        observed_hosts: BTreeSet::new(),
        observed_package: Some("public-agent".into()),
        building_blocks: BTreeSet::new(),
        disposition: None,
        decided_at_epoch_secs: None,
        expires_at_epoch_secs: None,
        reopened_by: None,
    };
    apply_triage_disposition(
        &mut item,
        TriageDisposition::Snooze {
            owner: "alice".into(),
            approver: Some("bob".into()),
            justification: "watch".into(),
            ttl_days: 7,
        },
        true,
        1_000,
    )
    .unwrap();
    assert_eq!(
        evaluate_triage_reopen(
            &mut item,
            &TriageObservationUpdate {
                verdict: BehaviorVerdict::LlmClient,
                observed_signer: None,
                observed_hosts: ["new.egress.test".into()].into_iter().collect(),
                observed_package: Some("public-agent".into()),
                building_blocks: BTreeSet::new(),
                now_epoch_secs: 1_100,
            }
        ),
        Some(TriageReopenTrigger::RemoteEndpointAdded)
    );
    apply_triage_disposition(
        &mut item,
        TriageDisposition::NotAi {
            owner: "alice".into(),
            approver: Some("bob".into()),
            justification: "utility".into(),
            ttl_days: 7,
        },
        true,
        1_200,
    )
    .unwrap();
    assert_eq!(
        evaluate_triage_reopen(
            &mut item,
            &TriageObservationUpdate {
                verdict: BehaviorVerdict::AgentSuspected,
                observed_signer: None,
                observed_hosts: ["new.egress.test".into()].into_iter().collect(),
                observed_package: Some("public-agent".into()),
                building_blocks: BTreeSet::new(),
                now_epoch_secs: 1_300,
            }
        ),
        Some(TriageReopenTrigger::OutcomeEscalatedToSuspected)
    );

    // 5. TOML sections/empty identity rejection + P8 pseudonymized CycloneDX/OCSF + Importers hardening.
    assert!(
        parse_grdr_agent_toml(
            r#"
schema = "grdr.agent/v1alpha1"
slug = "empty-id"
sponsor_team = "sec"
identity = {}
"#
        )
        .is_err()
    );
    let sec_toml = parse_grdr_agent_toml(
        r#"
schema = "grdr.agent/v1alpha1"
slug = "clean-bot"
sponsor_team = "sec"
identity = { src = 'org/private-bot' }
model_endpoints = [ "https://tok:pw@gw.local?secret=1#h" ]

[other]
slug = "overwritten-if-buggy"
"#,
    )
    .unwrap();
    assert_eq!(sec_toml.slug, "clean-bot");
    let decl_hosts = sec_toml.to_agent_declaration().allowed_hosts;
    assert!(decl_hosts.contains("gw.local"));

    let priv_bom = build_agent_bom(
        "alice-macbook-secret",
        &[],
        &[ObservedAgentState {
            agent_id: "clean-bot".into(),
            program_identity: ProgramIdentity::RawPath {
                path: "/Users/alice/secret-agent".into(),
            },
            presence: PresenceState::Running,
            observed_signer: None,
            observed_hosts: BTreeSet::new(),
            observed_artifacts: BTreeMap::new(),
        }],
    );
    let cdx_json =
        serde_json::to_string(&export_cyclonedx_1_7(&priv_bom, &strong_salt).unwrap()).unwrap();
    assert!(!cdx_json.contains("alice-macbook-secret"));
    assert!(!cdx_json.contains("/Users/alice/secret-agent"));
    let ocsf_json =
        serde_json::to_string(&export_ocsf_5020(&priv_bom, &strong_salt).unwrap()).unwrap();
    assert!(!ocsf_json.contains("alice-macbook-secret"));
    assert!(!ocsf_json.contains("/Users/alice/secret-agent"));

    assert!(QuarantineList::from_json(r#"{"wrong":[]}"#).is_err());
    assert!(lint_catalogue_pack_yaml("id: bad\ncommand: bash\n").is_err());
    assert!(
        lint_cedar_block_on_advisory(
            "// allow; comment\nforbid(principal, action, resource) when { context.kind == \"agent-suspected\" };"
        )
        .is_err()
    );
    assert!(
        lint_cedar_block_on_advisory(
            "permit(principal, action, resource) unless { context.basis == \"traffic\" };"
        )
        .is_err()
    );

    // 6. POM <groupId> scoping does not leak <project><groupId> into dependencies without <groupId>.
    let pom_ws = std::env::temp_dir().join(format!("grdr-pom-{}", uuid::Uuid::now_v7()));
    fs::create_dir_all(&pom_ws).unwrap();
    fs::write(
        pom_ws.join("pom.xml"),
        "<project><groupId>com.openai</groupId><dependencies><dependency><artifactId>openai-java</artifactId></dependency></dependencies></project>",
    )
    .unwrap();
    let block_cat = grdr_agents::BuildingBlockCatalogue::embedded().unwrap();
    let pom_scan = scan_workspace_building_blocks(Some(&pom_ws), &block_cat, &TestFs);
    assert!(pom_scan.blocked_reason.is_none());
    let _ = fs::remove_dir_all(&pom_ws);

    // 7. Private container registry ImageDigest is stripped on sanitize_upstream_proposal.
    let priv_img = ProgramIdentity::from_hints(&IdentityHints {
        image_repository: Some("registry.corp.internal/team/bot@sha256:abcdef".into()),
        executable_path: "/usr/local/bin/bot".into(),
        ..IdentityHints::default()
    });
    let priv_img_entry = generate_org_catalogue_entry(
        &priv_img,
        &strong_salt,
        &[],
        OrgEntryAttributes {
            agent_kind: "coding-agent".into(),
            sponsor_team: "platform".into(),
            building_blocks: vec![],
            inference_hosts: vec![],
            env_markers: vec![],
        },
    )
    .unwrap();
    assert!(sanitize_upstream_proposal(&priv_img_entry).is_none());
    let mut mixed_img = org_entry.clone();
    mixed_img.image_repository = Some("registry.corp.internal/team/bot@sha256:abcdef".into());
    let san_mixed = sanitize_upstream_proposal(&mixed_img).unwrap();
    assert!(san_mixed.image_repository.is_none());

    // BehaviorVerdict::AgentClassified creates triage findings and reopens Snooze/NotAi.
    let classified_assessment = grdr_core::discover::BehavioralAssessment {
        process_name: "agent".into(),
        verdict: BehaviorVerdict::AgentClassified,
        disposition: grdr_core::discover::ClassifierDisposition::AdvisoryOnly,
        cycle_count: 3,
        coincidence_ratio_bp: 9000,
        noisy_or_score_bp: 9000,
        reason: "classified loop".into(),
    };
    let mut classified_item =
        grdr_agents::triage_finding_from_assessment("org", "dev", &pkg_id, &classified_assessment)
            .expect("AgentClassified must open triage finding");
    classified_item.verdict = BehaviorVerdict::LlmClient;
    apply_triage_disposition(
        &mut classified_item,
        TriageDisposition::Snooze {
            owner: "alice".into(),
            approver: Some("bob".into()),
            justification: "checking".into(),
            ttl_days: 7,
        },
        true,
        2_000,
    )
    .unwrap();
    assert_eq!(
        evaluate_triage_reopen(
            &mut classified_item,
            &TriageObservationUpdate {
                verdict: BehaviorVerdict::AgentClassified,
                observed_signer: None,
                observed_hosts: BTreeSet::new(),
                observed_package: None,
                building_blocks: BTreeSet::new(),
                now_epoch_secs: 2_100,
            }
        ),
        Some(TriageReopenTrigger::OutcomeEscalatedToSuspected)
    );

    // unquote_toml preserves trailing escaped backslashes; control/bidi chars fail closed.
    let esc_toml = parse_grdr_agent_toml(
        r#"
schema = "grdr.agent/v1alpha1"
slug = "esc-bot"
sponsor_team = "sec-team"
identity = { pkg = "npm:esc-bot" }
credential_mode = "foo\\"
"#,
    )
    .unwrap();
    assert_eq!(esc_toml.credential_mode, r"foo\");
    assert!(
        parse_grdr_agent_toml(
            "schema = \"grdr.agent/v1alpha1\"\nslug = \"bidi-bot\"\nsponsor_team = \"sec\u{202E}bad\"\nidentity = { pkg = \"npm:b\" }\n"
        )
        .is_err()
    );
}
