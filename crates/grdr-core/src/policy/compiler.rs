// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compiles PolicyPack rules into validated Cedar 4.x PolicySets.

use std::collections::BTreeMap;
use std::str::FromStr;
use std::sync::LazyLock;

use cedar_policy::{Effect, Policy, PolicyId, PolicySet, Schema, ValidationMode, Validator, pst};
use grdr_model::{ApprovalGrade, KillSwitchState, Mode, PolicyPack, PolicyRule};
use grdr_schema::cedar::{CedarPlane, parse_schema};
use jiff::Timestamp;

use super::PolicyError;

const PARSER_DEPTH_LIMIT: usize = 64;
const BASE_PERMIT_ID: &str = "grdr.base.permit";
const BASE_PERMIT_CEDAR: &str = r#"@id("grdr.base.permit")
permit (principal, action, resource);"#;
const KILL_SWITCH_ID: &str = "system.kill-switch";
const KILL_SWITCH_CEDAR: &str = r#"@id("system.kill-switch")
@mode("Block")
@final("true")
forbid (principal, action, resource);"#;

static RUNTIME_SCHEMA: LazyLock<Result<Schema, String>> =
    LazyLock::new(|| parse_schema(CedarPlane::Runtime).map_err(|e| e.to_string()));

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct CompiledRuleMeta {
    pub(crate) policy_id: String,
    pub(crate) rule_id: String,
    pub(crate) pack_id: String,
    pub(crate) mode: Mode,
    pub(crate) min_grade: ApprovalGrade,
    pub(crate) locked: bool,
    pub(crate) is_final: bool,
    pub(crate) reason_template: String,
}

#[derive(Debug)]
pub(crate) struct CompiledPolicyBundle {
    pub(crate) enforced: PolicySet,
    pub(crate) shadow: PolicySet,
    pub(crate) meta_by_policy_id: BTreeMap<String, CompiledRuleMeta>,
    pub(crate) active_rules: Vec<CompiledRuleMeta>,
}

pub(crate) fn runtime_schema() -> Result<&'static Schema, PolicyError> {
    match &*RUNTIME_SCHEMA {
        Ok(schema) => Ok(schema),
        Err(detail) => Err(PolicyError::SchemaUnavailable {
            detail: detail.clone(),
        }),
    }
}

pub(crate) fn compile_packs(
    packs: &[PolicyPack],
    kill_switch: &KillSwitchState,
    session_id: &str,
    device_id: &str,
    now: Timestamp,
) -> Result<CompiledPolicyBundle, PolicyError> {
    let schema = runtime_schema()?;
    let mut enforced = PolicySet::new();
    let mut shadow = PolicySet::new();
    let mut meta_by_policy_id = BTreeMap::new();
    let mut active_rules = Vec::new();

    add_base_permit(&mut enforced)?;

    if kill_switch.is_active_for(session_id, device_id, now) {
        let ks_policy = Policy::parse_with_depth_limit(
            Some(parse_policy_id(KILL_SWITCH_ID)?),
            KILL_SWITCH_CEDAR,
            PARSER_DEPTH_LIMIT,
        )
        .map_err(|e| PolicyError::CompileFailed {
            rule_id: KILL_SWITCH_ID.into(),
            detail: e.to_string(),
        })?;
        add_policy_to_set(&mut enforced, ks_policy, KILL_SWITCH_ID)?;
        meta_by_policy_id.insert(
            KILL_SWITCH_ID.into(),
            CompiledRuleMeta {
                policy_id: KILL_SWITCH_ID.into(),
                rule_id: KILL_SWITCH_ID.into(),
                pack_id: "system".into(),
                mode: Mode::Block,
                min_grade: ApprovalGrade::G3,
                locked: true,
                is_final: true,
                reason_template: kill_switch_reason(kill_switch),
            },
        );
    }

    for (pack_idx, pack) in packs.iter().enumerate() {
        for (rule_idx, rule) in pack.rules.iter().enumerate() {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            let policy_id = unique_policy_id(&rule.id, pack_idx, rule_idx, &meta_by_policy_id);
            let source = rule
                .cedar
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| render_rule_cedar(rule));
            let (compiled, is_final) =
                compile_rule_policy(rule, &source, &policy_id, rule.mode, true)?;

            let meta = CompiledRuleMeta {
                policy_id: policy_id.clone(),
                rule_id: rule.id.clone(),
                pack_id: pack.id.clone(),
                mode: rule.mode,
                min_grade: rule.min_grade,
                locked: rule.locked,
                is_final,
                reason_template: rule.reason_template.clone(),
            };
            meta_by_policy_id.insert(policy_id, meta.clone());
            active_rules.push(meta);

            match rule.mode {
                Mode::Watch => add_policy_to_set(&mut shadow, compiled, &rule.id)?,
                Mode::Ask | Mode::Block => add_policy_to_set(&mut enforced, compiled, &rule.id)?,
                Mode::Off => {}
            }
        }
    }

    validate_policy_set(schema, &enforced, "enforced")?;
    validate_policy_set(schema, &shadow, "shadow")?;

    Ok(CompiledPolicyBundle {
        enforced,
        shadow,
        meta_by_policy_id,
        active_rules,
    })
}

pub(crate) fn compile_single_rule_for_replay(
    rule: &PolicyRule,
    mode: Mode,
) -> Result<Option<PolicySet>, PolicyError> {
    if mode == Mode::Off {
        return Ok(None);
    }
    let schema = runtime_schema()?;
    let mut set = PolicySet::new();
    add_base_permit(&mut set)?;

    let source = rule
        .cedar
        .as_deref()
        .filter(|s| !s.trim().is_empty())
        .map(str::to_string)
        .unwrap_or_else(|| render_rule_cedar(rule));
    let (compiled, _) = compile_rule_policy(rule, &source, &rule.id, mode, false)?;
    add_policy_to_set(&mut set, compiled, &rule.id)?;
    validate_policy_set(schema, &set, &rule.id)?;
    Ok(Some(set))
}

pub fn validate_cedar_rule(source: &str) -> Result<Policy, PolicyError> {
    let schema = runtime_schema()?;
    let policy = Policy::parse_with_depth_limit(None, source, PARSER_DEPTH_LIMIT).map_err(|e| {
        PolicyError::CompileFailed {
            rule_id: "custom".into(),
            detail: e.to_string(),
        }
    })?;
    if policy.effect() != Effect::Forbid {
        return Err(PolicyError::PermitNotAllowed {
            rule_id: policy.id().to_string(),
        });
    }
    let mut set = PolicySet::new();
    let pid = policy.id().to_string();
    add_policy_to_set(&mut set, policy.clone(), &pid)?;
    validate_policy_set(schema, &set, &pid)?;
    Ok(policy)
}

pub fn render_rule_cedar(rule: &PolicyRule) -> String {
    let id_esc = escape_cedar_string(&rule.id);
    let reason_esc = escape_cedar_string(&rule.reason_template);
    let mode_label = rule.mode.label();
    let min_grade = format!("{:?}", rule.min_grade);
    let final_attr = if rule.locked { " @final(\"true\")" } else { "" };

    let action_clause = if rule.matcher.action_classes.is_empty() {
        "action in Grdr::Action::\"any\"".to_string()
    } else if rule.matcher.action_classes.len() == 1 {
        let act = rule
            .matcher
            .action_classes
            .first()
            .map(|a| a.as_str())
            .unwrap_or("exec");
        format!("action == Grdr::Action::\"{act}\"")
    } else {
        let items: Vec<String> = rule
            .matcher
            .action_classes
            .iter()
            .map(|a| format!("Grdr::Action::\"{}\"", a.as_str()))
            .collect();
        format!("action in [{}]", items.join(", "))
    };

    let mut conditions = Vec::new();
    if !rule.matcher.agents.is_empty() {
        let checks: Vec<String> = rule
            .matcher
            .agents
            .iter()
            .map(|agent| {
                let norm = escape_cedar_string(&agent.trim().to_ascii_lowercase());
                format!("principal in Grdr::Agent::\"{norm}\"")
            })
            .collect();
        if checks.len() == 1 {
            if let Some(single) = checks.into_iter().next() {
                conditions.push(single);
            }
        } else {
            conditions.push(format!("({})", checks.join(" || ")));
        }
    }

    if !rule.matcher.target_prefixes.is_empty() || !rule.matcher.target_contains.is_empty() {
        conditions.push(format!("resource.classes.contains(\"match:{id_esc}\")"));
    }

    let when_block = if conditions.is_empty() {
        String::new()
    } else {
        format!("\nwhen {{ {} }}", conditions.join(" && "))
    };

    format!(
        "@id(\"{id_esc}\")\n@class(\"out-of-boundary\")\n@mode(\"{mode_label}\")\n@min_grade(\"{min_grade}\"){final_attr}\n@message(\"{reason_esc}\")\nforbid (\n  principal is Grdr::Session,\n  {action_clause},\n  resource\n){when_block};"
    )
}

fn compile_rule_policy(
    rule: &PolicyRule,
    source: &str,
    policy_id: &str,
    mode: Mode,
    attach_grant_unless: bool,
) -> Result<(Policy, bool), PolicyError> {
    let parsed_id = parse_policy_id(policy_id)?;
    let policy = Policy::parse_with_depth_limit(Some(parsed_id), source, PARSER_DEPTH_LIMIT)
        .map_err(|e| PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: e.to_string(),
        })?;

    if policy.effect() != Effect::Forbid {
        return Err(PolicyError::PermitNotAllowed {
            rule_id: rule.id.clone(),
        });
    }

    let is_final = rule.locked || policy.annotation("final").is_some_and(|val| val == "true");
    let pst_policy = policy
        .try_into_pst()
        .map_err(|e| PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: e.to_string(),
        })?;
    let pst::Policy::Static(static_policy) = pst_policy else {
        return Err(PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: "linked template policies are not permitted in rule definitions".into(),
        });
    };

    let mut template = static_policy.body().clone();
    template
        .annotations
        .insert("mode".into(), mode.label().into());
    if is_final {
        template.annotations.insert("final".into(), "true".into());
    }

    let needs_grant_clause =
        attach_grant_unless && (mode == Mode::Ask || (mode == Mode::Block && !is_final));
    if needs_grant_clause {
        let grant_clause = build_grant_unless_clause(&rule.id)?;
        template
            .try_add_clause(grant_clause)
            .map_err(|e| PolicyError::CompileFailed {
                rule_id: rule.id.clone(),
                detail: e.to_string(),
            })?;
    }

    let updated =
        pst::StaticPolicy::try_from(template).map_err(|e| PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: e.to_string(),
        })?;
    let rebuilt =
        Policy::from_pst(pst::Policy::Static(updated)).map_err(|e| PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: e.to_string(),
        })?;
    Ok((rebuilt, is_final))
}

fn build_grant_unless_clause(rule_id: &str) -> Result<pst::Clause, PolicyError> {
    let escaped = escape_cedar_string(rule_id);
    let helper_src = format!(
        "forbid (principal, action, resource) unless {{ context.grants.contains(\"{escaped}\") }};"
    );
    let helper =
        Policy::parse_with_depth_limit(None, &helper_src, PARSER_DEPTH_LIMIT).map_err(|e| {
            PolicyError::CompileFailed {
                rule_id: rule_id.into(),
                detail: e.to_string(),
            }
        })?;
    let pst_helper = helper
        .try_into_pst()
        .map_err(|e| PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: e.to_string(),
        })?;
    let pst::Policy::Static(sp) = pst_helper else {
        return Err(PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: "unexpected linked policy while building grant clause".into(),
        });
    };
    sp.body()
        .clauses()
        .first()
        .cloned()
        .ok_or_else(|| PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: "missing unless clause in grant helper".into(),
        })
}

fn validate_policy_set(schema: &Schema, set: &PolicySet, label: &str) -> Result<(), PolicyError> {
    let validator = Validator::new(schema.clone());
    let result = validator.validate(set, ValidationMode::Strict);
    if !result.validation_passed() {
        let errs: Vec<String> = result
            .validation_errors()
            .map(ToString::to_string)
            .collect();
        return Err(PolicyError::ValidationFailed {
            rule_id: label.into(),
            detail: errs.join("; "),
        });
    }
    Ok(())
}

fn add_base_permit(set: &mut PolicySet) -> Result<(), PolicyError> {
    let base_policy = Policy::parse_with_depth_limit(
        Some(parse_policy_id(BASE_PERMIT_ID)?),
        BASE_PERMIT_CEDAR,
        PARSER_DEPTH_LIMIT,
    )
    .map_err(|e| PolicyError::CompileFailed {
        rule_id: BASE_PERMIT_ID.into(),
        detail: e.to_string(),
    })?;
    add_policy_to_set(set, base_policy, BASE_PERMIT_ID)
}

fn add_policy_to_set(
    set: &mut PolicySet,
    policy: Policy,
    rule_id: &str,
) -> Result<(), PolicyError> {
    set.add(policy).map_err(|e| PolicyError::CompileFailed {
        rule_id: rule_id.into(),
        detail: e.to_string(),
    })
}

fn parse_policy_id(raw: &str) -> Result<PolicyId, PolicyError> {
    PolicyId::from_str(raw).map_err(|e| PolicyError::CompileFailed {
        rule_id: raw.into(),
        detail: e.to_string(),
    })
}

fn unique_policy_id(
    rule_id: &str,
    pack_idx: usize,
    rule_idx: usize,
    existing: &BTreeMap<String, CompiledRuleMeta>,
) -> String {
    if !existing.contains_key(rule_id) {
        rule_id.into()
    } else {
        format!("{pack_idx}/{rule_idx}/{rule_id}")
    }
}

fn kill_switch_reason(ks: &KillSwitchState) -> String {
    match ks {
        KillSwitchState::Frozen { reason, .. } => format!("Session frozen: {reason}"),
        KillSwitchState::Killed { reason, .. } => format!("Kill switch active: {reason}"),
        KillSwitchState::Inactive => String::new(),
    }
}

pub(crate) fn escape_cedar_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}
