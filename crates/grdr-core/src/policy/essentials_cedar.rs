// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Authoritative YAML/Cedar Essentials pack compiler and signed pack merger (`D-12`, `D-53`, `P14`, `P17`).

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::PolicySet;
use grdr_crypto::sha256_hex;
use grdr_model::{ApprovalGrade, IdentityMode, Mode, PolicyPack, PolicyRule, RuleMatch};

use super::PolicyError;
use super::compiler::runtime_schema;
use super::lint::{extract_policy_actions, lint_cedar_source_extended};
use super::pack_meta::parse_pack_toml_meta;
use super::render::{
    check_reserved_rule_prefix, parse_optional_grade, parse_optional_mode, parse_rule_annotations,
    validate_policy_set,
};
use crate::detect::pack_sig::verify_pack_signature_json;

const MAX_CEDAR_RULES_PER_PACK: usize = 512;

/// Canonical parity Cedar rules loaded directly from `packs/rules/essentials-parity.cedar`.
pub const ESSENTIALS_PARITY_CEDAR: &str =
    include_str!("../../../../packs/rules/essentials-parity.cedar");
const ESSENTIALS_PARITY_PACK_TOML: &str = include_str!("../../../../packs/rules/pack.toml");

/// Signed disk Essentials Cedar rules loaded directly from `packs/essentials/rules/essentials.cedar`.
pub const ESSENTIALS_DISK_CEDAR: &str =
    include_str!("../../../../packs/essentials/rules/essentials.cedar");

const ESSENTIALS_DISK_PACK_TOML: &str = include_str!("../../../../packs/essentials/pack.toml");
const ESSENTIALS_DISK_SIG_JSON: &str = include_str!("../../../../packs/essentials/signature.json");
const ESSENTIALS_DISK_LISTS_YAML: &str =
    include_str!("../../../../packs/essentials/lists/protected-paths.yaml");
const ESSENTIALS_DISK_SESSION_YAML: &str =
    include_str!("../../../../packs/essentials/session-rules.yaml");
const ESSENTIALS_DISK_VECTORS_YAML: &str =
    include_str!("../../../../packs/essentials/tests/essentials-vectors.yaml");
const EMBEDDED_TRUST_ROOTS_TOML: &str = include_str!("../../../../packs/trust-roots.toml");

#[derive(Debug, Clone)]
pub struct PackTomlMeta {
    pub id: String,
    pub version: String,
    pub kind: String,
    pub declared_reads: BTreeSet<String>,
}

/// Verifies embedded `packs/essentials/` and compiles the authoritative merged `grdr.essentials` `PolicyPack`.
pub fn canonical_essentials_pack() -> Result<PolicyPack, PolicyError> {
    verify_embedded_essentials_signature()?;
    let disk = compile_cedar_pack_from_sources(ESSENTIALS_DISK_PACK_TOML, ESSENTIALS_DISK_CEDAR)?;
    let parity =
        compile_cedar_pack_from_sources(ESSENTIALS_PARITY_PACK_TOML, ESSENTIALS_PARITY_CEDAR)?;
    Ok(merge_essentials_rules(disk, parity))
}

fn verify_embedded_essentials_signature() -> Result<(), PolicyError> {
    let verified = verify_pack_signature_json(
        ESSENTIALS_DISK_SIG_JSON,
        EMBEDDED_TRUST_ROOTS_TOML,
        "grdr.essentials",
    )
    .map_err(|e| PolicyError::ValidationFailed {
        rule_id: "packs/essentials".into(),
        detail: e.to_string(),
    })?;
    let embedded_files: &[(&str, &[u8])] = &[
        (
            "lists/protected-paths.yaml",
            ESSENTIALS_DISK_LISTS_YAML.as_bytes(),
        ),
        ("pack.toml", ESSENTIALS_DISK_PACK_TOML.as_bytes()),
        ("rules/essentials.cedar", ESSENTIALS_DISK_CEDAR.as_bytes()),
        (
            "session-rules.yaml",
            ESSENTIALS_DISK_SESSION_YAML.as_bytes(),
        ),
        (
            "tests/essentials-vectors.yaml",
            ESSENTIALS_DISK_VECTORS_YAML.as_bytes(),
        ),
    ];
    if verified.verified_file_sha256s.len() != embedded_files.len() {
        return Err(PolicyError::ValidationFailed {
            rule_id: "packs/essentials".into(),
            detail: "embedded essentials manifest file count mismatch".into(),
        });
    }
    for &(rel_path, bytes) in embedded_files {
        let Some((expected_sha, expected_len)) = verified.verified_file_sha256s.get(rel_path)
        else {
            return Err(PolicyError::ValidationFailed {
                rule_id: "packs/essentials".into(),
                detail: format!("missing embedded essentials manifest entry `{rel_path}`"),
            });
        };
        let actual_len = u64::try_from(bytes.len()).unwrap_or(u64::MAX);
        if actual_len != *expected_len || sha256_hex(bytes) != *expected_sha {
            return Err(PolicyError::ValidationFailed {
                rule_id: "packs/essentials".into(),
                detail: format!("embedded essentials SHA-256 mismatch on `{rel_path}`"),
            });
        }
    }
    Ok(())
}

fn merge_essentials_rules(mut base_pack: PolicyPack, parity_pack: PolicyPack) -> PolicyPack {
    let mut by_id: BTreeMap<String, PolicyRule> = BTreeMap::new();
    for rule in parity_pack.rules {
        by_id.insert(rule.id.clone(), rule);
    }
    let mut merged = Vec::new();
    for disk_rule in base_pack.rules {
        if let Some(strict_rule) = by_id.remove(&disk_rule.id) {
            merged.push(strict_rule);
        } else {
            merged.push(disk_rule);
        }
    }
    for (_, extra_rule) in by_id {
        merged.push(extra_rule);
    }
    base_pack.rules = merged;
    base_pack
}

/// Compiles `pack.toml` + Cedar source into a validated `PolicyPack` using Cedar 4.x schema & P7 lint.
pub fn compile_cedar_pack_from_sources(
    pack_toml: &str,
    cedar_src: &str,
) -> Result<PolicyPack, PolicyError> {
    let mut meta = parse_pack_toml_meta(pack_toml)?;
    if meta.id == "grdr.essentials"
        && (meta.declared_reads.contains("path.classes")
            || meta.declared_reads.contains("credential.classes"))
    {
        meta.declared_reads.insert("resource.classes".into());
    }
    let _ = lint_cedar_source_extended(
        &meta.id,
        &meta.id,
        cedar_src,
        Some(&meta.declared_reads),
        IdentityMode::Pseudonymous,
    )?;

    let schema = runtime_schema()?;
    let statements = split_cedar_statements(cedar_src)?;
    if statements.len() > MAX_CEDAR_RULES_PER_PACK {
        return Err(PolicyError::ValidationFailed {
            rule_id: meta.id,
            detail: "Cedar policy rule count exceeds per-pack cap".into(),
        });
    }

    let is_base_pack = meta.id == "grdr.base";
    let is_essentials_pack = meta.id == "grdr.essentials";
    let mut seen_rule_ids = BTreeSet::new();
    let mut rules = Vec::with_capacity(statements.len());

    for (idx, stmt) in statements.into_iter().enumerate() {
        let parsed_set = PolicySet::from_str(&stmt).map_err(|e| PolicyError::CompileFailed {
            rule_id: format!("{}.rule-{idx}", meta.id),
            detail: e.to_string(),
        })?;
        let mut policies = parsed_set.policies();
        let (Some(policy), None) = (policies.next(), policies.next()) else {
            return Err(PolicyError::CompileFailed {
                rule_id: format!("{}.rule-{idx}", meta.id),
                detail: "statement did not parse to a single Cedar policy".into(),
            });
        };
        let rule_id = policy
            .annotation("id")
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .ok_or_else(|| PolicyError::ValidationFailed {
                rule_id: format!("{}.rule-{idx}", meta.id),
                detail: "policy statement missing required `@id` annotation".into(),
            })?;
        check_reserved_rule_prefix(&meta.id, &rule_id, is_base_pack, is_essentials_pack)?;
        if !seen_rule_ids.insert(rule_id.clone()) {
            return Err(PolicyError::ValidationFailed {
                rule_id,
                detail: "duplicate `@id` within Cedar policy pack".into(),
            });
        }
        validate_policy_set(schema, &parsed_set, &rule_id)?;

        let anns = parse_rule_annotations(&rule_id, policy)?;
        let default_mode = if anns.is_final {
            Mode::Block
        } else {
            Mode::Ask
        };
        let max_mode = parse_optional_mode(&rule_id, policy.annotation("max_mode"), Mode::Block)?;
        let mut mode = default_mode.min(max_mode);
        if anns.is_final && mode >= Mode::Ask {
            mode = Mode::Block;
        }
        let min_grade = parse_optional_grade(&rule_id, policy.annotation("min_grade"))?
            .or(anns.min_grade)
            .unwrap_or(ApprovalGrade::G1);
        let reason_template = policy
            .annotation("message")
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| format!("Blocked or held by `{rule_id}`."));
        let title = policy
            .annotation("steer")
            .filter(|s| !s.trim().is_empty())
            .map(str::to_owned)
            .unwrap_or_else(|| rule_id.clone());
        let action_classes = extract_policy_actions(&stmt);

        rules.push(PolicyRule {
            id: rule_id,
            title,
            description: reason_template.clone(),
            mode,
            min_grade,
            enabled: true,
            locked: anns.is_final || mode == Mode::Block,
            matcher: RuleMatch {
                action_classes,
                target_prefixes: Vec::new(),
                target_contains: Vec::new(),
                agents: Vec::new(),
            },
            hits: 0,
            would_ask_hits: 0,
            would_block_hits: 0,
            reason_template,
            cedar: Some(stmt),
        });
    }

    Ok(PolicyPack {
        id: meta.id.clone(),
        name: format!("Guardrails Pack ({})", meta.id),
        description: format!(
            "Compiled from signed Cedar/YAML pack `{}` ({})",
            meta.id, meta.kind
        ),
        version: meta.version,
        channel: "signed-pack".into(),
        rules,
        key_id: None,
        signature: None,
    })
}

fn split_cedar_statements(src: &str) -> Result<Vec<String>, PolicyError> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_str = false;
    let mut escaped = false;
    let mut in_line_comment = false;
    let mut in_block_comment = false;
    let mut chars = src.chars().peekable();
    while let Some(ch) = chars.next() {
        if in_line_comment {
            if ch == '\n' {
                in_line_comment = false;
                cur.push(ch);
            }
            continue;
        }
        if in_block_comment {
            if ch == '*' && chars.peek() == Some(&'/') {
                let _ = chars.next();
                in_block_comment = false;
                cur.push(' ');
            } else if ch == '\n' {
                cur.push(ch);
            }
            continue;
        }
        if in_str {
            cur.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_str = false;
            }
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'/') {
            in_line_comment = true;
            let _ = chars.next();
            continue;
        }
        if ch == '/' && chars.peek() == Some(&'*') {
            in_block_comment = true;
            let _ = chars.next();
            continue;
        }
        if ch == '"' {
            in_str = true;
            cur.push(ch);
            continue;
        }
        cur.push(ch);
        if ch == ';' {
            let trimmed = cur.trim().to_owned();
            cur.clear();
            if !trimmed.is_empty() {
                out.push(trimmed);
            }
        }
    }
    if in_str {
        return Err(PolicyError::CompileFailed {
            rule_id: "cedar-pack".into(),
            detail: "unterminated string literal in Cedar pack source".into(),
        });
    }
    if in_block_comment {
        return Err(PolicyError::CompileFailed {
            rule_id: "cedar-pack".into(),
            detail: "unterminated block comment in Cedar pack source".into(),
        });
    }
    if !cur.trim().is_empty() {
        return Err(PolicyError::CompileFailed {
            rule_id: "cedar-pack".into(),
            detail: "trailing incomplete Cedar statement without `;`".into(),
        });
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use std::path::Path;

    use super::*;
    use crate::policy::caps::{DeterministicEntropy, default_control_point_caps};
    use crate::policy::compiler::{CompileOptions, compile_packs_with_options};
    use crate::policy::{
        ActorKind, KillSwitchState, RequestBuildOptions, VerdictEvalConfig,
        build_cedar_request_with_options, evaluate, load_cedar_policy_pack_from_dir,
        resolve_verdict,
    };
    use grdr_model::{
        ActionAttempt, ActionClass, ApprovalGrade, ControlPoint, InstallProfile, Verdict,
    };
    use jiff::Timestamp;

    #[test]
    fn canonical_essentials_compiles_from_disk_and_rejects_p7_violations() {
        let pack = canonical_essentials_pack().expect("canonical essentials pack");
        assert_eq!(pack.id, "grdr.essentials");
        assert_eq!(pack.rules.len(), 9);

        let now = Timestamp::from_second(1_700_000_000).expect("ts");
        let packs = vec![pack];
        let attempt = |id: &str, action_class: ActionClass, target: &str| ActionAttempt {
            id: id.into(),
            session_id: "sess-ess".into(),
            device_id: "dev-ess".into(),
            device_name: "host-ess".into(),
            agent_name: "claude".into(),
            action_class,
            control_point: ControlPoint::Hook,
            target: target.into(),
            summary: target.into(),
            timestamp: now,
            ..Default::default()
        };

        let write_ctrl = evaluate(
            &attempt("v1", ActionClass::FileWrite, ".claude/settings.json"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(write_ctrl.verdict, Verdict::Deny);
        assert_eq!(
            write_ctrl.rule_id.as_deref(),
            Some("essentials.control-files.write")
        );

        let no_sandbox_subshell = evaluate(
            &attempt("v1b", ActionClass::Exec, "claude --no-sandbox $(id)"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(no_sandbox_subshell.verdict, Verdict::Deny);

        let read_key = evaluate(
            &attempt("v2", ActionClass::FileRead, "~/.ssh/id_rsa"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(read_key.verdict, Verdict::StepUp);
        assert_eq!(
            read_key.rule_id.as_deref(),
            Some("essentials.cred-store.read")
        );

        let cred_use_ssh = evaluate(
            &attempt("v2b", ActionClass::CredUse, "~/.ssh/id_rsa"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(cred_use_ssh.verdict, Verdict::StepUp);
        assert_eq!(
            cred_use_ssh.rule_id.as_deref(),
            Some("essentials.cred-store.read")
        );

        let workspace_del = evaluate(
            &attempt("v3", ActionClass::FileDelete, "tmp/scratch -rf"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(workspace_del.verdict, Verdict::Allow);

        let outside_del = evaluate(
            &attempt("v4", ActionClass::FileDelete, "/var/tmp/outside -rf"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(outside_del.verdict, Verdict::StepUp);
        assert_eq!(
            outside_del.rule_id.as_deref(),
            Some("essentials.delete-outside-workspace")
        );

        let exec_elev = evaluate(
            &attempt("v5", ActionClass::Exec, "sudo id"),
            &packs,
            &[],
            &KillSwitchState::Inactive,
            now,
        );
        assert_eq!(exec_elev.verdict, Verdict::StepUp);

        let undet_attempt = attempt("v6", ActionClass::FileWrite, ".claude/settings.json");
        let opts = RequestBuildOptions {
            actor_kind: ActorKind::Undetermined,
            agent_capable_host: true,
            ..RequestBuildOptions::default()
        };
        let bundle = compile_packs_with_options(
            &packs,
            &KillSwitchState::Inactive,
            &undet_attempt.session_id,
            &undet_attempt.device_id,
            &CompileOptions::default(),
            now,
        )
        .expect("compile bundle");
        let built = build_cedar_request_with_options(
            &undet_attempt,
            &packs,
            &bundle.active_rules,
            &[],
            None,
            &opts,
            now,
        )
        .expect("build request");
        let cfg = VerdictEvalConfig {
            host_profile: InstallProfile::User,
            device_max_grade: ApprovalGrade::G3,
            timelock_enabled: false,
            observer: opts.observer,
            caps: default_control_point_caps(undet_attempt.control_point, None),
            modify_attempts: 0,
        };
        let mut entropy = DeterministicEntropy::from_seed_bytes(undet_attempt.id.as_bytes());
        let resolved =
            resolve_verdict(&undet_attempt, &bundle, &built, &cfg, &mut entropy).expect("resolve");
        assert_eq!(resolved.verdict, Verdict::StepUp);
        assert_eq!(
            resolved.top_rule_id.as_deref(),
            Some("essentials.undetermined.control-files")
        );

        let repo_root = Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
        let signed_disk = load_cedar_policy_pack_from_dir(&repo_root.join("packs/essentials"))
            .expect("load signed packs/essentials");
        assert_eq!(signed_disk.id, "grdr.essentials");
    }

    #[test]
    fn rejects_pack_toml_p7_bypasses_block_comment_splits_and_unsigned_dirs() {
        let base_cedar = "@id(\"custom.read\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource is Grdr::Path) when { resource.classes.contains(\"cred-store\") };";

        let wildcard_toml = "id = \"custom.pack\"\nversion = \"1.0.0\"\nper_person_scoring = false\n[[reads]]\npath = \"*\"\ndata_class = \"structural\"\n";
        assert!(compile_cedar_pack_from_sources(wildcard_toml, base_cedar).is_err());

        let singular_cap = "id = \"custom.pack\"\nversion = \"1.0.0\"\nper_person_scoring = false\ncommand = \"sh\"\n[[reads]]\npath = \"resource.classes\"\ndata_class = \"structural\"\n";
        assert!(compile_cedar_pack_from_sources(singular_cap, base_cedar).is_err());

        let unknown_sec = "id = \"custom.pack\"\nversion = \"1.0.0\"\nper_person_scoring = false\n[extra]\nx = \"y\"\n[[reads]]\npath = \"resource.classes\"\ndata_class = \"structural\"\n";
        assert!(compile_cedar_pack_from_sources(unknown_sec, base_cedar).is_err());

        let reserved_prefix = "id = \"custom.pack\"\nversion = \"1.0.0\"\nper_person_scoring = false\n[[reads]]\npath = \"resource.classes\"\ndata_class = \"structural\"\n";
        let spoof_ess_cedar = "@id(\"essentials.spoof\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource is Grdr::Path) when { resource.classes.contains(\"cred-store\") };";
        assert!(compile_cedar_pack_from_sources(reserved_prefix, spoof_ess_cedar).is_err());

        let stmts =
            split_cedar_statements(&format!("/* comment ; with ; semicolons */\n{base_cedar}"))
                .expect("split with block comment");
        assert_eq!(stmts.len(), 1);
        assert!(split_cedar_statements("/* unterminated").is_err());

        let bad_schema = "@id(\"custom.badschema\")\nforbid (principal is Grdr::Session, action == Grdr::Action::\"file.read\", resource is Grdr::Path) when { resource.nonexistent_attr == \"x\" };";
        assert!(compile_cedar_pack_from_sources(reserved_prefix, bad_schema).is_err());

        let tmp =
            std::env::temp_dir().join(format!("grdr-w1-2-unsigned-cedar-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&tmp);
        std::fs::create_dir_all(tmp.join("rules")).expect("mkdir");
        std::fs::write(tmp.join("pack.toml"), reserved_prefix).expect("write toml");
        std::fs::write(tmp.join("rules/r.cedar"), base_cedar).expect("write cedar");
        assert!(load_cedar_policy_pack_from_dir(&tmp).is_err());
        let _ = std::fs::remove_dir_all(&tmp);
    }
}
