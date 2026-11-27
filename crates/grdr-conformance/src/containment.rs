// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Sandbox containment invariants (D-21) and compile-down soundness checks (D-12).

use std::path::PathBuf;

use grdr_agents::{
    HookTargetKind, InstallOutcome, install_hook_in_state_dir, uninstall_hook_in_state_dir,
};
use grdr_core::policy::{essentials_pack, evaluate};
use grdr_crypto::{fill_random, sha256_hex};
use grdr_model::{
    ActionAttempt, ActionClass, ApprovalGrade, AssuranceLevel, ControlPoint, KillSwitchState, Mode,
    PolicyPack, PolicyRule, RuleMatch, Verdict,
};
use grdr_sandbox_engine::{ContainmentMode, SandboxSpec, prepare_contained_command};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::{ConformanceError, ScenarioCategory, ScenarioOutcome, ScenarioResult};

const UNSUPPORTED_CEDAR_TOKENS: &[&str] = &[
    "unless",
    "context.",
    "||",
    " has ",
    "principal.",
    "Grdr::User",
    "!=",
    "resource.in_workspace",
    "!",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NativeTargetKind {
    ClaudeCodeManagedSettings,
    CodexRequirements,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledNativeRule {
    pub rule_id: String,
    pub target_kind: NativeTargetKind,
    pub action_classes: Vec<ActionClass>,
    pub deny_patterns: Vec<String>,
}

pub fn compile_down_sound_rules(
    packs: &[PolicyPack],
    target_kind: NativeTargetKind,
) -> Vec<CompiledNativeRule> {
    let mut compiled = Vec::new();
    for pack in packs {
        for rule in &pack.rules {
            if !is_compile_down_eligible(rule) {
                continue;
            }
            let mut patterns = Vec::new();
            patterns.extend(rule.matcher.target_prefixes.clone());
            patterns.extend(rule.matcher.target_contains.clone());
            compiled.push(CompiledNativeRule {
                rule_id: rule.id.clone(),
                target_kind,
                action_classes: rule.matcher.action_classes.clone(),
                deny_patterns: patterns,
            });
        }
    }
    compiled
}

pub fn is_compile_down_eligible(rule: &PolicyRule) -> bool {
    if !rule.enabled || rule.mode != Mode::Block || !rule.locked || !rule.matcher.agents.is_empty()
    {
        return false;
    }
    let all_path_or_mcp_actions = !rule.matcher.action_classes.is_empty()
        && rule.matcher.action_classes.iter().all(|c| {
            matches!(
                c,
                ActionClass::FileRead
                    | ActionClass::FileWrite
                    | ActionClass::FileDelete
                    | ActionClass::ConfigChange
                    | ActionClass::NetConnect
                    | ActionClass::NetRequest
                    | ActionClass::McpConnect
            )
        });
    if !all_path_or_mcp_actions {
        return false;
    }
    if let Some(cedar) = rule.cedar.as_deref()
        && UNSUPPORTED_CEDAR_TOKENS
            .iter()
            .any(|tok| cedar.contains(tok))
    {
        return false;
    }
    !rule.matcher.target_prefixes.is_empty() || !rule.matcher.target_contains.is_empty()
}

pub fn run_containment_and_compile_down_checks() -> Result<Vec<ScenarioResult>, ConformanceError> {
    let now = Timestamp::from_second(1_700_000_000).unwrap_or(Timestamp::UNIX_EPOCH);
    verify_sandbox_containment_d21()?;
    verify_compile_down_soundness_d12(now)?;
    verify_hook_install_preservation_d49()?;

    Ok(vec![
        ScenarioResult {
            id: "D21-CONTAINMENT".into(),
            category: ScenarioCategory::Containment,
            title: "Sandbox strips sensitive env secrets and bounds assurance".into(),
            outcome: ScenarioOutcome::Pass,
            detail: "verified".into(),
        },
        ScenarioResult {
            id: "D12-COMPILE-DOWN".into(),
            category: ScenarioCategory::CompileDown,
            title: "Native compile-down rules are a strict subset of Cedar Block denies".into(),
            outcome: ScenarioOutcome::Pass,
            detail: "verified".into(),
        },
        ScenarioResult {
            id: "D49-HOOK-COEXIST".into(),
            category: ScenarioCategory::CompileDown,
            title: "Hook install preserves foreign hooks and restores byte-for-byte".into(),
            outcome: ScenarioOutcome::Pass,
            detail: "verified".into(),
        },
    ])
}

fn verify_sandbox_containment_d21() -> Result<(), ConformanceError> {
    let env = vec![
        ("PATH".into(), "/usr/bin".into()),
        ("GITHUB_TOKEN".into(), "ghp_topsecret_value".into()),
        ("CUSTOM_API_KEY".into(), "key_topsecret_value".into()),
    ];

    let obs_spec = SandboxSpec {
        session_id: "ses_obs".into(),
        agent_name: "claude-code".into(),
        mode: ContainmentMode::ObserveOnly,
        workdir: None,
        extra_allow_env: vec![],
        strip_secret_env: true,
    };
    let (_cmd, obs_report) = prepare_contained_command("git", &["status".into()], &obs_spec, &env)
        .map_err(|e| ConformanceError::ScenarioFailed {
            scenario_id: "D21-CONTAINMENT".into(),
            detail: e.to_string(),
        })?;
    if obs_report.effective_assurance != AssuranceLevel::Al1Observed {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D21-CONTAINMENT".into(),
            detail: "ObserveOnly should yield AL1 Observed".into(),
        });
    }

    let contained_spec = SandboxSpec {
        session_id: "ses_cont".into(),
        agent_name: "claude-code".into(),
        mode: ContainmentMode::WorkspaceContained,
        workdir: None,
        extra_allow_env: vec![],
        strip_secret_env: true,
    };
    let (cmd, cont_report) =
        prepare_contained_command("git", &["status".into()], &contained_spec, &env).map_err(
            |e| ConformanceError::ScenarioFailed {
                scenario_id: "D21-CONTAINMENT".into(),
                detail: e.to_string(),
            },
        )?;
    if cont_report.effective_assurance != AssuranceLevel::Al2Guided {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D21-CONTAINMENT".into(),
            detail: "user-mode sandbox without kernel namespace must stay AL2".into(),
        });
    }
    let exposed_secret = cmd.get_envs().any(|(k, _)| {
        let name = k.to_string_lossy();
        name == "GITHUB_TOKEN" || name == "CUSTOM_API_KEY"
    });
    let preserved_path = cmd.get_envs().any(|(k, _)| k.to_string_lossy() == "PATH");
    if exposed_secret || !preserved_path {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D21-CONTAINMENT".into(),
            detail: "Command environment leaked secret or dropped PATH".into(),
        });
    }
    let serialized = serde_json::to_string(&cont_report).unwrap_or_default();
    if serialized.contains("ghp_topsecret_value") || serialized.contains("key_topsecret_value") {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D21-CONTAINMENT".into(),
            detail: "sandbox report leaked raw secret value".into(),
        });
    }
    Ok(())
}

fn verify_compile_down_soundness_d12(now: Timestamp) -> Result<(), ConformanceError> {
    let base_rule = PolicyRule {
        id: "neg.base".into(),
        title: "Neg".into(),
        description: "Neg".into(),
        mode: Mode::Block,
        min_grade: ApprovalGrade::G2,
        enabled: true,
        locked: true,
        matcher: RuleMatch {
            action_classes: vec![ActionClass::FileWrite],
            target_prefixes: vec![".secret/".into()],
            target_contains: vec![],
            agents: vec![],
        },
        hits: 0,
        would_ask_hits: 0,
        would_block_hits: 0,
        reason_template: "neg".into(),
        cedar: None,
    };
    let negative_rules = [
        PolicyRule {
            id: "neg.unlocked".into(),
            locked: false,
            ..base_rule.clone()
        },
        PolicyRule {
            id: "neg.ask".into(),
            mode: Mode::Ask,
            ..base_rule.clone()
        },
        PolicyRule {
            id: "neg.agent-scoped".into(),
            matcher: RuleMatch {
                agents: vec!["cursor".into()],
                ..base_rule.matcher.clone()
            },
            ..base_rule.clone()
        },
        PolicyRule {
            id: "neg.unless".into(),
            cedar: Some("forbid (principal, action, resource) unless { false };".into()),
            ..base_rule.clone()
        },
        PolicyRule {
            id: "neg.context".into(),
            cedar: Some(
                "forbid (principal, action, resource) when { context.taint_labels.contains(\"x\") };"
                    .into(),
            ),
            ..base_rule.clone()
        },
        PolicyRule {
            id: "neg.in-workspace".into(),
            cedar: Some("forbid (principal, action, resource) when { !resource.in_workspace };".into()),
            ..base_rule.clone()
        },
        PolicyRule {
            id: "neg.exec-mixed".into(),
            matcher: RuleMatch {
                action_classes: vec![ActionClass::FileWrite, ActionClass::Exec],
                ..base_rule.matcher
            },
            ..base_rule
        },
    ];
    for neg in &negative_rules {
        if is_compile_down_eligible(neg) {
            return Err(ConformanceError::UnsoundCompileDown {
                rule_id: neg.id.clone(),
                detail: "ineligible rule unexpectedly passed compile-down eligibility".into(),
            });
        }
    }

    let packs = vec![essentials_pack()];
    let compiled = compile_down_sound_rules(&packs, NativeTargetKind::ClaudeCodeManagedSettings);
    if compiled.is_empty() {
        return Err(ConformanceError::UnsoundCompileDown {
            rule_id: "essentials".into(),
            detail: "expected at least one eligible locked Block rule".into(),
        });
    }
    if compiled.iter().any(|c| {
        c.rule_id == "essentials.credential-stores" || c.rule_id == "essentials.hook-bypass"
    }) {
        return Err(ConformanceError::UnsoundCompileDown {
            rule_id: "essentials".into(),
            detail: "Ask or command-string rules must never compile down".into(),
        });
    }

    for native in &compiled {
        for class in &native.action_classes {
            if !matches!(
                class,
                ActionClass::FileRead
                    | ActionClass::FileWrite
                    | ActionClass::FileDelete
                    | ActionClass::ConfigChange
            ) {
                continue;
            }
            for pattern in &native.deny_patterns {
                let probe = ActionAttempt {
                    id: "probe-d12".into(),
                    session_id: "ses_d12".into(),
                    device_id: "dev_d12".into(),
                    device_name: "host".into(),
                    agent_name: "claude-code".into(),
                    action_class: *class,
                    control_point: ControlPoint::Hook,
                    target: format!("{pattern}settings.json"),
                    summary: "compile-down soundness probe".into(),
                    timestamp: now,
                    ..Default::default()
                };
                let receipt = evaluate(&probe, &packs, &[], &KillSwitchState::Inactive, now);
                if receipt.verdict != Verdict::Deny {
                    return Err(ConformanceError::UnsoundCompileDown {
                        rule_id: native.rule_id.clone(),
                        detail: format!(
                            "native probe `{}` did not evaluate to Deny in Cedar",
                            probe.target
                        ),
                    });
                }
            }
        }
    }
    Ok(())
}

fn exclusive_temp_dir() -> Result<PathBuf, ConformanceError> {
    let mut entropy = [0u8; 16];
    fill_random(&mut entropy).map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D49-HOOK-COEXIST".into(),
        detail: e.to_string(),
    })?;
    let hex = sha256_hex(&entropy);
    let prefix = hex.get(0..16).unwrap_or("rand");
    let temp = std::env::temp_dir().join(format!("grdr-conf-d49-{}-{prefix}", std::process::id()));
    std::fs::create_dir(&temp).map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D49-HOOK-COEXIST".into(),
        detail: e.to_string(),
    })?;
    Ok(temp)
}

fn verify_hook_install_preservation_d49() -> Result<(), ConformanceError> {
    let temp = exclusive_temp_dir()?;
    let state_dir = temp.join("state");
    let claude_dir = temp.join(".claude");
    std::fs::create_dir_all(&claude_dir).map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D49-HOOK-COEXIST".into(),
        detail: e.to_string(),
    })?;
    let settings_path = claude_dir.join("settings.json");
    let original = "{\n  \"hooks\": {\n    \"PreToolUse\": [\n      {\n        \"matcher\": \"Bash\",\n        \"hooks\": [{\"type\": \"command\", \"command\": \"/opt/other/hook\"}]\n      }\n    ]\n  }\n}\n";
    std::fs::write(&settings_path, original).map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D49-HOOK-COEXIST".into(),
        detail: e.to_string(),
    })?;

    let fs = grdr_peer_os::OsLocalFs;
    let installed = install_hook_in_state_dir(
        HookTargetKind::ClaudeCode,
        &temp,
        &state_dir,
        "grdr-hook",
        false,
        &fs,
    )
    .map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D49-HOOK-COEXIST".into(),
        detail: e,
    })?;
    if installed.outcome != InstallOutcome::Applied
        || !installed.preview_json.contains("/opt/other/hook")
    {
        let _ = std::fs::remove_dir_all(&temp);
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D49-HOOK-COEXIST".into(),
            detail: "hook install did not preserve foreign entry".into(),
        });
    }
    let _ = uninstall_hook_in_state_dir(HookTargetKind::ClaudeCode, &temp, &state_dir, None, &fs)
        .map_err(|e| ConformanceError::ScenarioFailed {
        scenario_id: "D49-HOOK-COEXIST".into(),
        detail: e,
    })?;
    let restored = std::fs::read_to_string(&settings_path).unwrap_or_default();
    let _ = std::fs::remove_dir_all(&temp);
    if restored != original {
        return Err(ConformanceError::ScenarioFailed {
            scenario_id: "D49-HOOK-COEXIST".into(),
            detail: "uninstall did not restore original config byte for byte".into(),
        });
    }
    Ok(())
}
