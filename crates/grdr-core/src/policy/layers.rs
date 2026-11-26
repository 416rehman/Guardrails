// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Multi-layer policy settings hierarchy, locked ceilings, list containment, and effective hashes.

use std::collections::{BTreeMap, BTreeSet};

use grdr_crypto::domain_sha256_hex;
use grdr_model::eval::is_essentials_rule_id;
use grdr_model::{ChangePolarity, LayerKind, LayerLock, LayerModeSetting, Mode, PolicyRule};

use super::PolicyError;
use super::compiler::CompiledRuleMeta;

const EFFECTIVE_HASH_DOMAIN: &str = "grdr.policy-layers.effective.v1";

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LayerRuleEntry {
    pub rule_id: String,
    pub mode: Mode,
    pub lock: LayerLock,
    pub protect_list: BTreeSet<String>,
    pub allow_list: BTreeSet<String>,
    pub timelock_seconds: Option<u32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PolicyLayerSpec {
    pub layer: LayerKind,
    pub entries: Vec<LayerRuleEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EffectiveLayerRule {
    pub rule_id: String,
    pub source_layer: LayerKind,
    pub mode: Mode,
    pub lock: LayerLock,
    pub protect_list: BTreeSet<String>,
    pub allow_list: BTreeSet<String>,
    pub user_timelock_seconds: Option<u32>,
    pub polarity_vs_parent: ChangePolarity,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MergedPolicyLayers {
    pub rules: BTreeMap<String, EffectiveLayerRule>,
    pub effective_hash: String,
}

pub fn merge_policy_layers(layers: &[PolicyLayerSpec]) -> Result<MergedPolicyLayers, PolicyError> {
    let mut ordered: Vec<&PolicyLayerSpec> = layers.iter().collect();
    ordered.sort_by_key(|spec| spec.layer);

    let mut resolved: BTreeMap<String, EffectiveLayerRule> = BTreeMap::new();

    for spec in ordered {
        let layer_name = layer_kind_label(spec.layer);
        for entry in &spec.entries {
            if entry.timelock_seconds == Some(0) {
                return Err(PolicyError::LayerViolation {
                    layer: layer_name.into(),
                    rule_id: entry.rule_id.clone(),
                    detail: "disclosed timelock must be greater than zero seconds".into(),
                });
            }
            if entry.timelock_seconds.is_some()
                && (spec.layer != LayerKind::User || is_essentials_rule_id(&entry.rule_id))
            {
                return Err(PolicyError::LayerViolation {
                    layer: layer_name.into(),
                    rule_id: entry.rule_id.clone(),
                    detail: "disclosed timelock is allowed only on user-local custom rules".into(),
                });
            }

            if let Some(parent) = resolved.get(&entry.rule_id).cloned() {
                let parent_setting = LayerModeSetting {
                    mode: parent.mode,
                    lock: parent.lock,
                };
                let child_setting = LayerModeSetting {
                    mode: entry.mode,
                    lock: entry.lock,
                };
                let (merged_mode, mode_polarity) =
                    resolve_layer_setting(parent_setting, child_setting).ok_or_else(|| {
                        PolicyError::LayerViolation {
                            layer: layer_name.into(),
                            rule_id: entry.rule_id.clone(),
                            detail: format!(
                                "policy.layer-violation: cannot weaken locked mode {:?} to {:?}",
                                parent.mode, entry.mode
                            ),
                        }
                    })?;

                let protect_polarity = check_glob_list_containment(
                    layer_name,
                    &entry.rule_id,
                    false,
                    parent.lock == LayerLock::Locked,
                    &parent.protect_list,
                    &entry.protect_list,
                )?;
                let allow_polarity = check_glob_list_containment(
                    layer_name,
                    &entry.rule_id,
                    true,
                    parent.lock == LayerLock::Locked,
                    &parent.allow_list,
                    &entry.allow_list,
                )?;

                let combined_polarity =
                    combine_polarity([mode_polarity, protect_polarity, allow_polarity]);
                resolved.insert(
                    entry.rule_id.clone(),
                    EffectiveLayerRule {
                        rule_id: entry.rule_id.clone(),
                        source_layer: spec.layer,
                        mode: merged_mode.mode,
                        lock: merged_mode.lock,
                        protect_list: entry.protect_list.clone(),
                        allow_list: entry.allow_list.clone(),
                        user_timelock_seconds: entry.timelock_seconds,
                        polarity_vs_parent: combined_polarity,
                    },
                );
            } else {
                resolved.insert(
                    entry.rule_id.clone(),
                    EffectiveLayerRule {
                        rule_id: entry.rule_id.clone(),
                        source_layer: spec.layer,
                        mode: entry.mode,
                        lock: entry.lock,
                        protect_list: entry.protect_list.clone(),
                        allow_list: entry.allow_list.clone(),
                        user_timelock_seconds: entry.timelock_seconds,
                        polarity_vs_parent: ChangePolarity::Unchanged,
                    },
                );
            }
        }
    }

    let effective_hash = compute_effective_layers_hash(&resolved);
    Ok(MergedPolicyLayers {
        rules: resolved,
        effective_hash,
    })
}

pub fn check_glob_list_containment(
    layer_name: &str,
    rule_id: &str,
    is_allow_list: bool,
    locked: bool,
    parent: &BTreeSet<String>,
    child: &BTreeSet<String>,
) -> Result<ChangePolarity, PolicyError> {
    if let Some(exact) = exact_list_containment(is_allow_list, parent, child) {
        return Ok(exact);
    }
    if is_allow_list {
        let subsumed = child
            .iter()
            .all(|c| parent.iter().any(|p| glob_pattern_subsumes(p, c)));
        if subsumed {
            return Ok(ChangePolarity::Narrowing);
        }
        if locked {
            return Err(PolicyError::LayerViolation {
                layer: layer_name.into(),
                rule_id: rule_id.into(),
                detail: "policy.layer-violation: allow-list widens locked ancestor".into(),
            });
        }
        return Ok(ChangePolarity::Widening);
    }

    let preserved = parent
        .iter()
        .all(|p| child.iter().any(|c| glob_pattern_subsumes(c, p)));
    if preserved {
        return Ok(ChangePolarity::Narrowing);
    }
    if locked {
        return Err(PolicyError::LayerViolation {
            layer: layer_name.into(),
            rule_id: rule_id.into(),
            detail: "policy.layer-violation: protect-list removes locked ancestor guard".into(),
        });
    }
    Ok(ChangePolarity::Widening)
}

pub fn glob_pattern_subsumes(broader: &str, narrower: &str) -> bool {
    let b_norm = broader.trim().replace('\\', "/");
    let n_norm = narrower.trim().replace('\\', "/");
    let b = b_norm.as_str();
    let n = n_norm.as_str();
    if b.is_empty() || n.is_empty() || pattern_has_dotdot(b) || pattern_has_dotdot(n) {
        return false;
    }
    if b == "**" {
        return true;
    }
    if b == "*" {
        return !n.contains('/') && !n.contains("**");
    }
    if b == n {
        return true;
    }
    if let Some(prefix) = b.strip_suffix("**") {
        if prefix.ends_with('/') {
            return n.starts_with(prefix);
        }
        return !prefix.contains('*')
            && !n.trim_end_matches('*').contains('/')
            && n.starts_with(prefix);
    }
    if let Some(prefix) = b.strip_suffix('*')
        && !prefix.contains('*')
        && let Some(rest) = n.strip_prefix(prefix)
    {
        return !rest.contains('/') && !n.contains("**");
    }
    if let Some(suffix) = b.strip_prefix("**/")
        && !suffix.contains('*')
    {
        let seg_suffix = format!("/{suffix}");
        return n == suffix || n.ends_with(&seg_suffix);
    }
    if let Some(suffix) = b.strip_prefix('*')
        && !suffix.contains('*')
        && let Some(rest) = n.strip_suffix(suffix)
    {
        return !rest.contains('/') && !n.contains("**");
    }
    false
}

pub fn compute_effective_layers_hash(rules: &BTreeMap<String, EffectiveLayerRule>) -> String {
    let mut canonical = String::new();
    for rule in rules.values() {
        push_len_field(&mut canonical, &rule.rule_id);
        push_len_field(&mut canonical, layer_kind_label(rule.source_layer));
        push_len_field(&mut canonical, rule.mode.label());
        push_len_field(
            &mut canonical,
            if rule.lock == LayerLock::Locked {
                "locked"
            } else {
                "default"
            },
        );
        let tl = rule
            .user_timelock_seconds
            .map(|s| s.to_string())
            .unwrap_or_else(|| "none".into());
        push_len_field(&mut canonical, &tl);
        canonical.push_str(&format!("P{}:", rule.protect_list.len()));
        for item in &rule.protect_list {
            push_len_field(&mut canonical, item);
        }
        canonical.push_str(&format!("A{}:", rule.allow_list.len()));
        for item in &rule.allow_list {
            push_len_field(&mut canonical, item);
        }
        canonical.push('\n');
    }
    domain_sha256_hex(EFFECTIVE_HASH_DOMAIN, canonical.as_bytes())
}

fn push_len_field(buf: &mut String, field: &str) {
    buf.push_str(&field.len().to_string());
    buf.push(':');
    buf.push_str(field);
    buf.push(';');
}

fn pattern_has_dotdot(pattern: &str) -> bool {
    pattern.replace('\\', "/").split('/').any(|seg| seg == "..")
}

pub(crate) fn glob_matches_target(pattern: &str, target: &str) -> bool {
    let p_norm = pattern.trim().replace('\\', "/").to_ascii_lowercase();
    let t_norm = target.trim().replace('\\', "/").to_ascii_lowercase();
    let p = p_norm.as_str();
    let t = t_norm.as_str();
    // Never reject `..` segments in targets here: protect_list must still catch normalized
    // or relative traversal paths, while rule_matches_allow_list gates on !has_dotdot separately.
    if p.is_empty() || t.is_empty() || pattern_has_dotdot(p) {
        return false;
    }
    let p_segs: Vec<&str> = p.split('/').filter(|s| !s.is_empty()).collect();
    let t_segs: Vec<&str> = t.split('/').filter(|s| !s.is_empty()).collect();
    if p_segs.is_empty() || t_segs.is_empty() {
        return false;
    }
    if p.starts_with('/') != t.starts_with('/') && p_segs.first() != Some(&"**") {
        return false;
    }
    glob_segs_match(&p_segs, &t_segs)
}

fn glob_segs_match(pat: &[&str], tgt: &[&str]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;
    while ti < tgt.len() {
        if let (Some(&p_seg), Some(&t_seg)) = (pat.get(pi), tgt.get(ti))
            && p_seg != "**"
            && wildcard_seg_match(p_seg.as_bytes(), t_seg.as_bytes())
        {
            pi = pi.saturating_add(1);
            ti = ti.saturating_add(1);
        } else if pat.get(pi) == Some(&"**") {
            while pat.get(pi.saturating_add(1)) == Some(&"**") {
                pi = pi.saturating_add(1);
            }
            star_pi = Some(pi);
            pi = pi.saturating_add(1);
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp.saturating_add(1);
            star_ti = star_ti.saturating_add(1);
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pat.get(pi) == Some(&"**") {
        pi = pi.saturating_add(1);
    }
    pi == pat.len()
}

fn wildcard_seg_match(pat: &[u8], tgt: &[u8]) -> bool {
    let mut pi = 0usize;
    let mut ti = 0usize;
    let mut star_pi: Option<usize> = None;
    let mut star_ti = 0usize;
    while ti < tgt.len() {
        if let (Some(&pc), Some(&tc)) = (pat.get(pi), tgt.get(ti))
            && (pc == b'?' || pc == tc)
        {
            pi = pi.saturating_add(1);
            ti = ti.saturating_add(1);
        } else if pat.get(pi) == Some(&b'*') {
            star_pi = Some(pi);
            pi = pi.saturating_add(1);
            star_ti = ti;
        } else if let Some(sp) = star_pi {
            pi = sp.saturating_add(1);
            star_ti = star_ti.saturating_add(1);
            ti = star_ti;
        } else {
            return false;
        }
    }
    while pat.get(pi) == Some(&b'*') {
        pi = pi.saturating_add(1);
    }
    pi == pat.len()
}

fn resolve_layer_setting(
    parent: LayerModeSetting,
    child: LayerModeSetting,
) -> Option<(LayerModeSetting, ChangePolarity)> {
    if parent.lock == LayerLock::Locked && child.mode < parent.mode {
        return None;
    }
    let polarity = if child.mode > parent.mode {
        ChangePolarity::Narrowing
    } else if child.mode < parent.mode {
        ChangePolarity::Widening
    } else {
        ChangePolarity::Unchanged
    };
    let lock = if parent.lock == LayerLock::Locked || child.lock == LayerLock::Locked {
        LayerLock::Locked
    } else {
        LayerLock::Default
    };
    Some((
        LayerModeSetting {
            mode: child.mode,
            lock,
        },
        polarity,
    ))
}

fn exact_list_containment(
    is_allow_list: bool,
    parent: &BTreeSet<String>,
    child: &BTreeSet<String>,
) -> Option<ChangePolarity> {
    if is_allow_list {
        return child
            .is_subset(parent)
            .then_some(if child.len() < parent.len() {
                ChangePolarity::Narrowing
            } else {
                ChangePolarity::Unchanged
            });
    }
    parent
        .is_subset(child)
        .then_some(if child.len() > parent.len() {
            ChangePolarity::Narrowing
        } else {
            ChangePolarity::Unchanged
        })
}

fn combine_polarity<const N: usize>(items: [ChangePolarity; N]) -> ChangePolarity {
    if items.contains(&ChangePolarity::Widening) {
        ChangePolarity::Widening
    } else if items.contains(&ChangePolarity::Narrowing) {
        ChangePolarity::Narrowing
    } else {
        ChangePolarity::Unchanged
    }
}

fn layer_kind_label(layer: LayerKind) -> &'static str {
    match layer {
        LayerKind::Provider => "provider",
        LayerKind::Org => "org",
        LayerKind::Group => "group",
        LayerKind::Device => "device",
        LayerKind::User => "user",
    }
}

pub(crate) fn append_effective_hash_entry(
    out: &mut String,
    meta: &CompiledRuleMeta,
    rule: &PolicyRule,
    cedar_txt: &str,
) {
    out.push_str(&format!(
        "|id={}:{}|pack={}:{}|mode={}|layer={:?}|grade={:?}|final={}|locked={}|loss={:?}|snap={}|app={}:{}|act={:?}|pfx={:?}|cnt={:?}|agt={:?}|pl={:?}|al={:?}|rsn={}:{}|str={}:{}|cedar={}:{}|",
        meta.policy_id.len(),
        meta.policy_id,
        meta.pack_id.len(),
        meta.pack_id,
        meta.mode.label(),
        meta.layer,
        meta.min_grade,
        meta.is_final,
        meta.locked,
        meta.on_loss,
        meta.requires_snapshot,
        meta.approver.len(),
        meta.approver,
        rule.matcher.action_classes,
        rule.matcher.target_prefixes,
        rule.matcher.target_contains,
        rule.matcher.agents,
        meta.protect_list,
        meta.allow_list,
        meta.reason_template.len(),
        meta.reason_template,
        meta.steer.len(),
        meta.steer,
        cedar_txt.len(),
        cedar_txt,
    ));
}
