// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Compiles PolicyPack rules into validated Cedar 4.x PolicySets with metadata extraction.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;
use std::sync::LazyLock;

use cedar_policy::{Effect, Policy, PolicySet, Schema};
use grdr_model::{
    ActionClass, ApprovalGrade, IdentityMode, KillSwitchState, LayerKind, LayerLock, LossBehaviour,
    Mode, PolicyPack, PolicyRule, RemedyCapability, RuleMutability,
};
use grdr_schema::cedar::{CedarPlane, parse_schema};
use jiff::Timestamp;

use super::PolicyError;
use super::layers::{EffectiveLayerRule, append_effective_hash_entry};
use super::lint::{
    body_has_unless_clause, check_cedar_nesting_depth, extract_policy_actions,
    reads_session_label_epoch,
};
use super::render::{
    PARSER_DEPTH_LIMIT, ParsedRuleAnns, add_base_permit, add_policy_to_set,
    check_reserved_rule_prefix, compile_parsed_policy, parse_optional_mode, parse_policy_id,
    parse_rule_annotations, render_rule_cedar, validate_policy_set,
};
use super::request::ContextField;
use super::views::{compute_cedar_reads, lint_cedar_source_extended};

const KILL_SWITCH_ID: &str = "system.kill-switch";
const KILL_SWITCH_CEDAR: &str = r#"@id("system.kill-switch")
@mode("Block")
@final("true")
forbid (principal, action, resource);"#;

static RUNTIME_SCHEMA: LazyLock<Result<Schema, String>> =
    LazyLock::new(|| parse_schema(CedarPlane::Runtime).map_err(|e| e.to_string()));

// grdr:allow-s4 compiled rule metadata flags reflect independent Cedar static attributes
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompiledRuleMeta {
    pub policy_id: String,
    pub rule_id: String,
    pub pack_id: String,
    pub layer: LayerKind,
    pub mode: Mode,
    pub min_grade: ApprovalGrade,
    pub mutability: RuleMutability,
    pub remedy: RemedyCapability,
    pub remedy_transform: Option<String>,
    pub on_loss: LossBehaviour,
    pub locked: bool,
    pub is_final: bool,
    pub requires_snapshot: bool,
    pub has_unless: bool,
    pub stateless: bool,
    pub floor_eligible: bool,
    pub actions: Vec<ActionClass>,
    pub reads: BTreeSet<ContextField>,
    pub approver: String,
    pub reason_template: String,
    pub steer: String,
    pub protect_list: BTreeSet<String>,
    pub allow_list: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompileOptions {
    pub identity_mode: IdentityMode,
    pub pack_layer: LayerKind,
    pub layer_overrides: BTreeMap<String, EffectiveLayerRule>,
}

#[derive(Debug)]
pub struct CompiledPolicyBundle {
    pub enforced: PolicySet,
    pub shadow: PolicySet,
    pub meta_by_policy_id: BTreeMap<String, CompiledRuleMeta>,
    pub active_rules: Vec<CompiledRuleMeta>,
    pub effective_hash: String,
    pub reads_label_epoch: bool,
}

impl Default for CompileOptions {
    fn default() -> Self {
        Self {
            identity_mode: IdentityMode::Named,
            pack_layer: LayerKind::User,
            layer_overrides: BTreeMap::new(),
        }
    }
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
    compile_packs_with_options(
        packs,
        kill_switch,
        session_id,
        device_id,
        &CompileOptions::default(),
        now,
    )
}

pub fn compile_packs_with_options(
    packs: &[PolicyPack],
    kill_switch: &KillSwitchState,
    session_id: &str,
    device_id: &str,
    opts: &CompileOptions,
    now: Timestamp,
) -> Result<CompiledPolicyBundle, PolicyError> {
    let schema = runtime_schema()?;
    let mut enforced = PolicySet::new();
    let mut shadow = PolicySet::new();
    let mut meta_by_policy_id = BTreeMap::new();
    let mut active_rules = Vec::new();
    let mut reads_label_epoch = false;
    let mut hash_input = format!("id_mode={:?}|", opts.identity_mode);

    let has_explicit_base = packs
        .iter()
        .any(|p| p.id == "grdr.base" && p.rules.iter().any(|r| r.enabled));
    if !has_explicit_base {
        add_base_permit(&mut enforced)?;
    }
    let mut seen_rule_ids = BTreeSet::new();

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
                layer: LayerKind::Provider,
                mode: Mode::Block,
                min_grade: ApprovalGrade::G3,
                mutability: RuleMutability::Final,
                remedy: RemedyCapability::Plain,
                remedy_transform: None,
                on_loss: LossBehaviour::Block,
                locked: true,
                is_final: true,
                requires_snapshot: false,
                has_unless: false,
                stateless: true,
                floor_eligible: true,
                actions: Vec::new(),
                reads: BTreeSet::new(),
                approver: "admin".into(),
                reason_template: kill_switch_reason(kill_switch),
                steer: "Release the active freeze or kill switch on Respond.".into(),
                protect_list: BTreeSet::new(),
                allow_list: BTreeSet::new(),
            },
        );
    }

    for (pack_idx, pack) in packs.iter().enumerate() {
        let is_base_pack = pack.id == "grdr.base";
        let is_essentials_pack = matches!(
            pack.id.as_str(),
            "pack-essentials-slice0" | "grdr.essentials" | "essentials"
        );
        for (rule_idx, rule) in pack.rules.iter().enumerate() {
            if !rule.enabled {
                continue;
            }
            let has_cedar = rule.cedar.as_deref().is_some_and(|s| !s.trim().is_empty());
            if rule.mode == Mode::Off && !opts.layer_overrides.contains_key(&rule.id) && !has_cedar
            {
                continue;
            }
            let source = rule
                .cedar
                .as_deref()
                .filter(|s| !s.trim().is_empty())
                .map(str::to_string)
                .unwrap_or_else(|| render_rule_cedar(rule));

            let _ =
                lint_cedar_source_extended(&pack.id, &rule.id, &source, None, opts.identity_mode)?;
            check_cedar_nesting_depth(&rule.id, &source)?;
            let parsed_set =
                PolicySet::from_str(&source).map_err(|e| PolicyError::CompileFailed {
                    rule_id: rule.id.clone(),
                    detail: e.to_string(),
                })?;

            let is_multi_policy = parsed_set.policies().count() > 1;
            for (sub_idx, parsed_policy) in parsed_set.policies().enumerate() {
                let effective_id = parsed_policy
                    .annotation("id")
                    .map(str::to_owned)
                    .unwrap_or_else(|| rule.id.clone());
                check_reserved_rule_prefix(
                    &pack.id,
                    &effective_id,
                    is_base_pack,
                    is_essentials_pack,
                )?;
                if !seen_rule_ids.insert(effective_id.clone()) {
                    return Err(PolicyError::ValidationFailed {
                        rule_id: effective_id,
                        detail: "duplicate rule id across loaded packs".into(),
                    });
                }

                let policy_id = unique_policy_id(
                    &effective_id,
                    pack_idx,
                    rule_idx.saturating_mul(100).saturating_add(sub_idx),
                    &meta_by_policy_id,
                );
                let mut rule_view = rule.clone();
                rule_view.id = effective_id.clone();
                let layer_override = opts.layer_overrides.get(&effective_id);
                let max_mode = parse_optional_mode(
                    &effective_id,
                    parsed_policy.annotation("max_mode"),
                    Mode::Block,
                )?;
                let base_mode = layer_override.map_or(rule.mode, |eff| eff.mode);
                rule_view.mode = base_mode.min(max_mode);
                if let Some(eff) = layer_override
                    && eff.lock == LayerLock::Locked
                {
                    rule_view.locked = true;
                }
                if rule_view.mode == Mode::Off {
                    continue;
                }
                let anns = parse_rule_annotations(&effective_id, parsed_policy)?;
                if let Some(g) = anns.min_grade {
                    rule_view.min_grade = if is_multi_policy {
                        g
                    } else {
                        rule_view.min_grade.max(g)
                    };
                }
                if let Some(msg) = parsed_policy.annotation("message") {
                    rule_view.reason_template = msg.to_owned();
                }

                let policy_text = parsed_policy.to_string();
                reads_label_epoch |= reads_session_label_epoch(&policy_text);
                let policy_reads = compute_cedar_reads(&policy_text);
                let raw_has_unless = body_has_unless_clause(&policy_text);
                let is_final = anns.is_final
                    || (rule.cedar.is_none() && rule_view.mode == Mode::Block && rule_view.locked);
                if is_final && rule_view.mode >= Mode::Ask {
                    rule_view.mode = Mode::Block;
                }

                let compiled = compile_parsed_policy(
                    &rule_view,
                    parsed_policy.clone(),
                    &policy_id,
                    rule_view.mode,
                    is_final,
                    true,
                    is_base_pack,
                )?;

                if compiled.effect() == Effect::Permit {
                    hash_input.push_str("permit:");
                    hash_input.push_str(&policy_id);
                    hash_input.push(':');
                    hash_input.push_str(&compiled.to_string());
                    hash_input.push(';');
                    add_policy_to_set(&mut enforced, compiled, &rule_view.id)?;
                    continue;
                }

                let rule_layer = layer_override.map_or(opts.pack_layer, |eff| eff.source_layer);
                let (protect_list, allow_list) = layer_override.map_or_else(
                    || (BTreeSet::new(), BTreeSet::new()),
                    |eff| (eff.protect_list.clone(), eff.allow_list.clone()),
                );
                let meta = build_rule_meta(
                    pack,
                    &rule_view,
                    &policy_id,
                    &compiled,
                    policy_reads,
                    raw_has_unless,
                    is_final,
                    &anns,
                    protect_list,
                    allow_list,
                    is_essentials_pack,
                    rule_layer,
                );
                append_effective_hash_entry(
                    &mut hash_input,
                    &meta,
                    &rule_view,
                    &compiled.to_string(),
                );
                meta_by_policy_id.insert(policy_id, meta.clone());
                active_rules.push(meta);

                match rule_view.mode {
                    Mode::Watch => add_policy_to_set(&mut shadow, compiled, &rule_view.id)?,
                    Mode::Ask | Mode::Block => {
                        add_policy_to_set(&mut enforced, compiled, &rule_view.id)?
                    }
                    Mode::Off => {}
                }
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
        reads_label_epoch,
        effective_hash: grdr_crypto::domain_sha256_hex(
            "grdr.bundle.effective.v1",
            hash_input.as_bytes(),
        ),
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
    let _ = lint_cedar_source_extended("replay", &rule.id, &source, None, IdentityMode::Named)?;
    check_cedar_nesting_depth(&rule.id, &source)?;
    let parsed_set = PolicySet::from_str(&source).map_err(|e| PolicyError::CompileFailed {
        rule_id: rule.id.clone(),
        detail: e.to_string(),
    })?;
    for (idx, parsed_policy) in parsed_set.policies().enumerate() {
        let effective_id = parsed_policy
            .annotation("id")
            .map(str::to_owned)
            .unwrap_or_else(|| rule.id.clone());
        let max_mode = parse_optional_mode(
            &effective_id,
            parsed_policy.annotation("max_mode"),
            Mode::Block,
        )?;
        let mut eff_mode = mode.min(max_mode);
        if eff_mode == Mode::Off {
            continue;
        }
        let anns = parse_rule_annotations(&effective_id, parsed_policy)?;
        let ann_final = anns.is_final;
        let is_final =
            ann_final || (rule.cedar.is_none() && eff_mode == Mode::Block && rule.locked);
        if is_final && eff_mode >= Mode::Ask {
            eff_mode = Mode::Block;
        }
        let pid = if idx == 0 {
            effective_id.clone()
        } else {
            format!("replay/{idx}/{effective_id}")
        };
        let compiled = compile_parsed_policy(
            rule,
            parsed_policy.clone(),
            &pid,
            eff_mode,
            is_final,
            false,
            false,
        )?;
        add_policy_to_set(&mut set, compiled, &effective_id)?;
    }
    validate_policy_set(schema, &set, &rule.id)?;
    Ok(Some(set))
}

#[allow(
    clippy::too_many_arguments,
    reason = "compiled rule metadata builder binds independent Cedar policy annotations and layer lists"
)]
fn build_rule_meta(
    pack: &PolicyPack,
    rule: &PolicyRule,
    policy_id: &str,
    compiled: &Policy,
    reads: BTreeSet<ContextField>,
    has_unless: bool,
    is_final: bool,
    anns: &ParsedRuleAnns,
    protect_list: BTreeSet<String>,
    allow_list: BTreeSet<String>,
    is_essentials_pack: bool,
    default_layer: LayerKind,
) -> CompiledRuleMeta {
    let remedy = if anns.remedy_transform.is_some() {
        RemedyCapability::ModifyTransform
    } else {
        RemedyCapability::Plain
    };
    let stateless = !reads.contains(&ContextField::SessionLabels);
    let floor_eligible =
        compiled.effect() == Effect::Forbid && is_final && !has_unless && stateless;
    let layer = if is_essentials_pack && rule.id.starts_with("essentials.") {
        LayerKind::Provider
    } else {
        default_layer
    };
    let actions = extract_policy_actions(&compiled.to_string());

    CompiledRuleMeta {
        policy_id: policy_id.into(),
        rule_id: rule.id.clone(),
        pack_id: pack.id.clone(),
        layer,
        mode: rule.mode,
        min_grade: rule.min_grade,
        mutability: if is_final {
            RuleMutability::Final
        } else {
            RuleMutability::Liftable
        },
        remedy,
        remedy_transform: anns.remedy_transform.clone(),
        on_loss: anns.on_loss,
        locked: rule.locked,
        is_final,
        requires_snapshot: anns.requires_snapshot,
        has_unless,
        stateless,
        floor_eligible,
        actions,
        reads,
        approver: anns.approver.clone(),
        reason_template: rule.reason_template.clone(),
        steer: compiled
            .annotation("steer")
            .unwrap_or("Follow policy guidance.")
            .to_owned(),
        protect_list,
        allow_list,
    }
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
