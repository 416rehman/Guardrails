// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Declarative YAML-driven CM-13 native compile-down targets (`OpenShell`, `DefenseClaw`, `Numbat`, `Claude Code`, `Codex`).

use std::collections::BTreeSet;
use std::path::Path;

use grdr_model::{Mode, PolicyPack, PolicyRule};

use super::PolicyError;
use super::compile_down::{
    CompileDownSkip, compile_down_claude_code_with_profile, compile_down_codex_with_profile,
    eligibility_gap_for_target, resolve_meta,
};
use super::compile_down_render::{parse_compile_targets_yaml, render_generic_target};
use super::compile_down_verify::{render_claude_settings_json, render_codex_requirements_toml};
use super::compiler::CompiledRuleMeta;
use crate::analyze::pack_io::{pack_list_max_bytes, read_pack_child_text};

const EMBEDDED_COMPILE_TARGETS_YAML: &str =
    include_str!("../../../../packs/lists/compile-targets.yaml");

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TargetRenderFormat {
    Json,
    Toml,
    Yaml,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileTargetProfile {
    pub id: String,
    pub format: TargetRenderFormat,
    pub schema: String,
    pub verdict_token: String,
    pub supports_allow_overrides: bool,
    pub supports_exec_rules: bool,
    pub read_tool: Option<String>,
    pub write_tool: Option<String>,
    pub exec_tool: Option<String>,
    pub net_tool: Option<String>,
    pub exec_pattern_suffix: Option<String>,
    pub approval_policy: Option<String>,
    pub sandbox_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TargetRuleSpec {
    pub rule_id: String,
    pub actions: Vec<String>,
    pub protect_patterns: Vec<String>,
    pub allow_patterns: Vec<String>,
    pub verdict: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledTargetBundle {
    pub target_id: String,
    pub schema: String,
    pub format: TargetRenderFormat,
    pub rules: Vec<TargetRuleSpec>,
    pub skipped: Vec<CompileDownSkip>,
    pub rendered: String,
}

/// Loads CM-13 compile-down target profiles from `<packs_dir>/lists/compile-targets.yaml`.
pub fn load_compile_targets_from_dir(
    packs_dir: &Path,
) -> Result<Vec<CompileTargetProfile>, PolicyError> {
    let max_bytes = pack_list_max_bytes().map_err(|detail| PolicyError::ValidationFailed {
        rule_id: "compile-targets".into(),
        detail,
    })?;
    let raw = read_pack_child_text(packs_dir, "lists/compile-targets.yaml", max_bytes).map_err(
        |detail| PolicyError::ValidationFailed {
            rule_id: "compile-targets".into(),
            detail,
        },
    )?;
    parse_compile_targets_yaml(&raw)
}

/// Returns built-in CM-13 compile-down target profiles loaded from shipped `packs/lists/compile-targets.yaml`.
pub fn default_compile_targets() -> Result<Vec<CompileTargetProfile>, PolicyError> {
    parse_compile_targets_yaml(EMBEDDED_COMPILE_TARGETS_YAML)
}

/// Compiles `packs` and `metas` into any YAML-declared CM-13 target (`claude-code`, `codex`, `openshell`, `defenseclaw`, `numbat`).
pub fn compile_down_for_target(
    target_id: &str,
    packs: &[PolicyPack],
    metas: &[CompiledRuleMeta],
) -> Result<CompiledTargetBundle, PolicyError> {
    let targets = default_compile_targets()?;
    let profile = targets
        .into_iter()
        .find(|t| t.id == target_id)
        .ok_or_else(|| PolicyError::ValidationFailed {
            rule_id: "compile-targets".into(),
            detail: format!("unknown compile-down target `{target_id}`"),
        })?;
    compile_down_with_profile(&profile, packs, metas)
}

/// Compiles `packs` and `metas` using an explicit `CompileTargetProfile`.
pub fn compile_down_with_profile(
    profile: &CompileTargetProfile,
    packs: &[PolicyPack],
    metas: &[CompiledRuleMeta],
) -> Result<CompiledTargetBundle, PolicyError> {
    if profile.id == "claude-code" {
        let settings = compile_down_claude_code_with_profile(profile, packs, metas);
        let rendered = render_claude_settings_json(&settings);
        let rules = settings
            .compiled_rule_ids
            .into_iter()
            .map(|id| TargetRuleSpec {
                rule_id: id,
                actions: Vec::new(),
                protect_patterns: settings.deny_rules.clone(),
                allow_patterns: Vec::new(),
                verdict: profile.verdict_token.clone(),
            })
            .collect();
        return Ok(CompiledTargetBundle {
            target_id: profile.id.clone(),
            schema: profile.schema.clone(),
            format: profile.format,
            rules,
            skipped: settings.skipped,
            rendered,
        });
    }
    if profile.id == "codex" {
        let req = compile_down_codex_with_profile(profile, packs, metas);
        let rendered = render_codex_requirements_toml(&req);
        let rules = req
            .compiled_rule_ids
            .into_iter()
            .map(|id| TargetRuleSpec {
                rule_id: id,
                actions: Vec::new(),
                protect_patterns: req.prefix_rules.clone(),
                allow_patterns: Vec::new(),
                verdict: profile.verdict_token.clone(),
            })
            .collect();
        return Ok(CompiledTargetBundle {
            target_id: profile.id.clone(),
            schema: profile.schema.clone(),
            format: profile.format,
            rules,
            skipped: req.skipped,
            rendered,
        });
    }

    let mut rules = Vec::new();
    let mut skipped = Vec::new();
    let meta_map: std::collections::BTreeMap<&str, &CompiledRuleMeta> =
        metas.iter().map(|m| (m.rule_id.as_str(), m)).collect();

    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            if let Some(reason) = eligibility_gap_for_target(
                rule,
                &meta_map,
                profile.supports_allow_overrides,
                profile.supports_exec_rules,
            ) {
                skipped.push(CompileDownSkip {
                    rule_id: rule.id.clone(),
                    reason,
                });
                continue;
            }
            let meta_opt = resolve_meta(rule, &meta_map);
            let protect_patterns = collect_rule_protect_patterns(rule, meta_opt);
            if protect_patterns.is_empty() {
                continue;
            }
            let allow_patterns: Vec<String> = meta_opt
                .map(|m| m.allow_list.iter().cloned().collect())
                .unwrap_or_default();
            let actions: Vec<String> = rule
                .matcher
                .action_classes
                .iter()
                .map(|a| a.as_str().to_owned())
                .collect();
            rules.push(TargetRuleSpec {
                rule_id: rule.id.clone(),
                actions,
                protect_patterns,
                allow_patterns,
                verdict: profile.verdict_token.clone(),
            });
        }
    }

    let rendered = render_generic_target(profile, &rules);
    Ok(CompiledTargetBundle {
        target_id: profile.id.clone(),
        schema: profile.schema.clone(),
        format: profile.format,
        rules,
        skipped,
        rendered,
    })
}

fn collect_rule_protect_patterns(
    rule: &PolicyRule,
    meta: Option<&CompiledRuleMeta>,
) -> Vec<String> {
    let mut out = BTreeSet::new();
    for p in rule
        .matcher
        .target_prefixes
        .iter()
        .chain(&rule.matcher.target_contains)
    {
        let trimmed = p.trim();
        if !trimmed.is_empty() {
            out.insert(trimmed.to_owned());
        }
    }
    if let Some(m) = meta {
        for p in &m.protect_list {
            let trimmed = p.trim();
            if !trimmed.is_empty() {
                out.insert(trimmed.to_owned());
            }
        }
    }
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use super::*;
    use crate::policy::{
        CompileDownSkipReason, CompileOptions, KillSwitchState, compile_down_claude_code,
        compile_down_codex, compile_packs_with_options, verify_compile_down_subset,
    };
    use grdr_model::{
        ActionAttempt, ActionClass, ApprovalGrade, ControlPoint, IdentityMode, RuleMatch,
    };
    use jiff::Timestamp;

    fn static_rule(id: &str, actions: Vec<ActionClass>, prefixes: Vec<&str>) -> PolicyRule {
        PolicyRule {
            id: id.into(),
            title: id.into(),
            description: id.into(),
            mode: Mode::Block,
            min_grade: ApprovalGrade::G2,
            enabled: true,
            locked: true,
            matcher: RuleMatch {
                action_classes: actions,
                target_prefixes: prefixes.into_iter().map(str::to_owned).collect(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template: "Blocked".into(),
            cedar: None,
        }
    }

    fn single_pack(id: &str, rule: PolicyRule) -> PolicyPack {
        PolicyPack {
            id: id.into(),
            name: id.into(),
            description: String::new(),
            version: "1.0.0".into(),
            channel: "custom".into(),
            rules: vec![rule],
            key_id: None,
            signature: None,
        }
    }

    #[test]
    fn compiles_exec_protect_allow_rules_across_cm13_targets_soundly() {
        let now = Timestamp::from_second(1_700_000_000).expect("ts");
        let pack = single_pack(
            "custom.cd-exec",
            static_rule(
                "custom.block-curl-pipe",
                vec![ActionClass::Exec],
                vec!["rm -rf /"],
            ),
        );

        let claude = compile_down_claude_code(std::slice::from_ref(&pack), &[]);
        assert!(claude.deny_rules.contains(&"Bash(rm -rf /:*)".to_owned()));
        let codex = compile_down_codex(std::slice::from_ref(&pack), &[]);
        assert!(codex.prefix_rules.contains(&"rm -rf /".to_owned()));

        let probe = ActionAttempt {
            id: "p1".into(),
            session_id: "s1".into(),
            device_id: "d1".into(),
            device_name: "host-1".into(),
            agent_name: "claude".into(),
            action_class: ActionClass::Exec,
            control_point: ControlPoint::Hook,
            target: "rm -rf /etc".into(),
            summary: "rm -rf /etc".into(),
            timestamp: now,
            ..Default::default()
        };
        assert!(verify_compile_down_subset(
            std::slice::from_ref(&pack),
            &[probe],
            &claude,
            now
        ));

        let view_rule = PolicyRule {
            cedar: Some(
                "@id(\"custom.vault-allow\")\n@final(\"true\")\n@message(\"Protected vault\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource) when { resource.classes.contains(\"match:custom.vault-allow\") } unless { resource.classes.contains(\"allow:custom.vault-allow\") };".into(),
            ),
            ..static_rule("custom.vault-allow", vec![ActionClass::FileRead], vec!["/vault/"])
        };
        let vault_pack = single_pack("custom.vault", view_rule);
        let mut layer_overrides = BTreeMap::new();
        layer_overrides.insert(
            "custom.vault-allow".to_owned(),
            crate::policy::EffectiveLayerRule {
                rule_id: "custom.vault-allow".into(),
                source_layer: grdr_model::LayerKind::User,
                mode: Mode::Block,
                lock: grdr_model::LayerLock::Default,
                protect_list: ["/vault/**".to_owned()].into_iter().collect(),
                allow_list: ["/vault/public/**".to_owned()].into_iter().collect(),
                user_timelock_seconds: None,
                polarity_vs_parent: grdr_model::ChangePolarity::Unchanged,
            },
        );
        let compiled = compile_packs_with_options(
            std::slice::from_ref(&vault_pack),
            &KillSwitchState::Inactive,
            "s1",
            "d1",
            &CompileOptions {
                identity_mode: IdentityMode::Pseudonymous,
                layer_overrides,
                ..CompileOptions::default()
            },
            now,
        )
        .expect("compile");

        let claude_vault =
            compile_down_claude_code(std::slice::from_ref(&vault_pack), &compiled.active_rules);
        assert!(claude_vault.deny_rules.is_empty());
        assert_eq!(
            claude_vault.skipped[0].reason,
            CompileDownSkipReason::HasUnlessClause
        );

        for target_id in ["openshell", "defenseclaw", "numbat"] {
            let bundle = compile_down_for_target(
                target_id,
                std::slice::from_ref(&vault_pack),
                &compiled.active_rules,
            )
            .expect("cm13 target");
            assert_eq!(bundle.rules.len(), 1);
            assert!(
                bundle.rules[0]
                    .protect_patterns
                    .iter()
                    .any(|p| p == "/vault/**")
            );
            assert!(
                bundle.rules[0]
                    .allow_patterns
                    .iter()
                    .any(|a| a == "/vault/public/**")
            );
            assert!(bundle.rendered.contains("/vault/public/**"));
        }

        assert!(compile_down_for_target("unknown-target", &[vault_pack], &[]).is_err());
    }

    #[test]
    fn rejects_uncovered_multi_action_arbitrary_unless_paren_injection_and_toml_escaping() {
        let now = Timestamp::from_second(1_700_000_000).expect("ts");

        let partial_claude = single_pack(
            "p.partial",
            static_rule(
                "r.read-write",
                vec![ActionClass::FileRead, ActionClass::FileWrite],
                vec!["/etc/"],
            ),
        );
        let c_res = compile_down_claude_code(&[partial_claude], &[]);
        assert!(c_res.deny_rules.is_empty());
        assert_eq!(c_res.skipped.len(), 1);

        let partial_codex = single_pack(
            "p.codex",
            static_rule(
                "r.exec-read",
                vec![ActionClass::Exec, ActionClass::FileRead],
                vec!["curl "],
            ),
        );
        let x_res = compile_down_codex(&[partial_codex], &[]);
        assert!(x_res.prefix_rules.is_empty());
        assert_eq!(x_res.skipped.len(), 1);

        let paren_inject = single_pack(
            "p.inject",
            static_rule("r.inj", vec![ActionClass::FileRead], vec!["/a), Allow(*"]),
        );
        let inj_res = compile_down_claude_code(&[paren_inject], &[]);
        assert!(inj_res.deny_rules.is_empty());

        let mut no_exec = default_compile_targets()
            .expect("targets")
            .into_iter()
            .find(|t| t.id == "claude-code")
            .expect("claude profile");
        no_exec.supports_exec_rules = false;
        let exec_pack = single_pack(
            "p.exec",
            static_rule("r.exec", vec![ActionClass::Exec], vec!["id"]),
        );
        let no_exec_bundle =
            compile_down_with_profile(&no_exec, &[exec_pack], &[]).expect("compile with no exec");
        assert!(no_exec_bundle.rules.is_empty());
        assert_eq!(no_exec_bundle.skipped.len(), 1);

        let arb_unless = PolicyRule {
            cedar: Some(
                "@id(\"r.arb\")\n@final(\"true\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource) when { resource.classes.contains(\"match:r.arb\") } unless { true };".into(),
            ),
            ..static_rule("r.arb", vec![ActionClass::FileRead], vec!["/vault/"])
        };
        let mut arb_profile = default_compile_targets()
            .expect("targets")
            .into_iter()
            .find(|t| t.id == "numbat")
            .expect("numbat");
        arb_profile.format = TargetRenderFormat::Toml;
        let mut overrides = BTreeMap::new();
        overrides.insert(
            "r.arb".to_owned(),
            crate::policy::EffectiveLayerRule {
                rule_id: "r.arb".into(),
                source_layer: grdr_model::LayerKind::User,
                mode: Mode::Block,
                lock: grdr_model::LayerLock::Default,
                protect_list: ["/vault/**".to_owned()].into_iter().collect(),
                allow_list: ["/vault/ok".to_owned()].into_iter().collect(),
                user_timelock_seconds: None,
                polarity_vs_parent: grdr_model::ChangePolarity::Unchanged,
            },
        );
        let arb_pack = single_pack("p.arb", arb_unless);
        let compiled_arb = compile_packs_with_options(
            std::slice::from_ref(&arb_pack),
            &KillSwitchState::Inactive,
            "s",
            "d",
            &CompileOptions {
                identity_mode: IdentityMode::Pseudonymous,
                layer_overrides: overrides,
                ..CompileOptions::default()
            },
            now,
        )
        .expect("compile arb");
        let arb_bundle =
            compile_down_with_profile(&arb_profile, &[arb_pack], &compiled_arb.active_rules)
                .expect("bundle");
        assert!(arb_bundle.rules.is_empty());
        assert_eq!(
            arb_bundle.skipped[0].reason,
            CompileDownSkipReason::HasUnlessClause
        );

        let read_prefix_pack = single_pack(
            "p.pref",
            static_rule("r.etc", vec![ActionClass::FileRead], vec!["/etc/"]),
        );
        let pref_settings = compile_down_claude_code(std::slice::from_ref(&read_prefix_pack), &[]);
        assert!(
            pref_settings
                .deny_rules
                .contains(&"Read(/etc/*)".to_owned())
        );
        let wrong_probe = ActionAttempt {
            id: "wrong".into(),
            session_id: "s1".into(),
            device_id: "d1".into(),
            device_name: "host-1".into(),
            agent_name: "claude".into(),
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: "/tmp/etc/passwd".into(),
            summary: "/tmp/etc/passwd".into(),
            timestamp: now,
            ..Default::default()
        };
        assert!(verify_compile_down_subset(
            &[read_prefix_pack],
            &[wrong_probe],
            &pref_settings,
            now
        ));

        let newline_rule = static_rule("r.nl", vec![ActionClass::FileRead], vec!["/foo\nbar"]);
        let nl_pack = single_pack("p.nl", newline_rule);
        let yaml_bundle = compile_down_for_target("openshell", std::slice::from_ref(&nl_pack), &[])
            .expect("yaml escape");
        assert!(yaml_bundle.rendered.contains("/foo\\nbar"));
        let toml_bundle =
            compile_down_with_profile(&arb_profile, &[nl_pack], &[]).expect("toml escape");
        assert!(toml_bundle.rendered.contains("protect = [\"/foo\\nbar\"]"));
    }

    #[test]
    fn verify_subset_handles_double_star_globs_scoped_headers_and_blank_patterns() {
        let now = Timestamp::from_second(1_700_000_000).expect("ts");

        let etc_pack = single_pack(
            "p.etc",
            static_rule("r.etc", vec![ActionClass::FileRead], vec!["/etc/"]),
        );
        let mut vault_settings = compile_down_claude_code(std::slice::from_ref(&etc_pack), &[]);
        vault_settings.deny_rules = vec!["Read(/vault/**)".to_owned()];
        let vault_probe = ActionAttempt {
            id: "vault-secret".into(),
            session_id: "s1".into(),
            device_id: "d1".into(),
            device_name: "host-1".into(),
            agent_name: "claude".into(),
            action_class: ActionClass::FileRead,
            control_point: ControlPoint::Hook,
            target: "/vault/secret".into(),
            summary: "/vault/secret".into(),
            timestamp: now,
            ..Default::default()
        };
        assert!(!verify_compile_down_subset(
            &[etc_pack],
            std::slice::from_ref(&vault_probe),
            &vault_settings,
            now
        ));

        let vault_pack = single_pack(
            "p.vault",
            static_rule("r.vault", vec![ActionClass::FileRead], vec!["/vault/"]),
        );
        let sibling_probe = ActionAttempt {
            id: "vaulted".into(),
            target: "/vaulted/secret".into(),
            summary: "/vaulted/secret".into(),
            ..vault_probe.clone()
        };
        assert!(verify_compile_down_subset(
            &[vault_pack],
            &[vault_probe, sibling_probe],
            &vault_settings,
            now
        ));

        let scoped_headers = [
            "forbid (principal == Grdr::Agent::\"claude\", action == Grdr::Action::\"file.read\", resource);",
            "forbid (principal is Grdr::Agent, action == Grdr::Action::\"file.read\", resource);",
            "forbid (principal, action == Grdr::Action::\"file.read\", resource == Grdr::Path::\"/vault/x\");",
            "forbid (principal, action == Grdr::Action::\"file.read\", resource in [Grdr::Path::\"/vault\"]);",
            "forbid ( /* ) */ principal == Grdr::Agent::\"claude\", action == Grdr::Action::\"file.read\", resource );",
        ];
        for (idx, header) in scoped_headers.iter().enumerate() {
            let rule_id = format!("custom.scoped.{idx}");
            let cedar =
                format!("@id(\"{rule_id}\")\n@final(\"true\")\n@message(\"Scoped\")\n{header}");
            let rule = PolicyRule {
                cedar: Some(cedar),
                ..static_rule(&rule_id, vec![ActionClass::FileRead], vec!["/vault/"])
            };
            let pack = single_pack("p.scoped", rule);
            let settings = compile_down_claude_code(&[pack], &[]);
            assert!(
                settings.deny_rules.is_empty(),
                "header {idx} must not compile down"
            );
            assert_eq!(
                settings.skipped,
                vec![crate::policy::CompileDownSkip {
                    rule_id,
                    reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
                }]
            );
        }

        let blank_rule = static_rule("r.blank", vec![ActionClass::FileRead], vec!["   ", "\t"]);
        let blank_pack = single_pack("p.blank", blank_rule);
        let blank_claude = compile_down_claude_code(std::slice::from_ref(&blank_pack), &[]);
        assert!(blank_claude.deny_rules.is_empty());
        assert_eq!(
            blank_claude.skipped,
            vec![crate::policy::CompileDownSkip {
                rule_id: "r.blank".into(),
                reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
            }]
        );
        let blank_openshell =
            compile_down_for_target("openshell", &[blank_pack], &[]).expect("openshell compile");
        assert!(blank_openshell.rules.is_empty());
        assert_eq!(
            blank_openshell.skipped,
            vec![crate::policy::CompileDownSkip {
                rule_id: "r.blank".into(),
                reason: CompileDownSkipReason::UnsupportedDynamicPredicate,
            }]
        );
    }
}
