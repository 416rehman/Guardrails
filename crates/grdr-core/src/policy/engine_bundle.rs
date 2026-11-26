// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Verified bundle integrity checks, hierarchical layer compilation, and Engine interest derivation.

use std::collections::{BTreeMap, BTreeSet};
use std::str::FromStr;

use cedar_policy::PolicySet;
use grdr_crypto::domain_sha256_hex;
use grdr_model::eval::is_essentials_rule_id;
use grdr_model::{
    ActionClass, ApprovalGrade, Grant, IdentityMode, InstallProfile, KillSwitchState, LayerKind,
    LayerLock, Mode, PolicyPack, PolicyRule, SignatureStatus, TrustedKeyInfo, verify_grant,
    verify_pack,
};
use jiff::Timestamp;

use super::PolicyError;
use super::caps::cached_limits;
use super::compiler::{CompileOptions, CompiledPolicyBundle, compile_packs_with_options};
use super::engine_types::{InterestSet, VerifiedBundle, push_len};
use super::layers::{EffectiveLayerRule, LayerRuleEntry, PolicyLayerSpec, merge_policy_layers};
use super::lint::extract_policy_actions;
use super::render::{parse_optional_final, parse_optional_mode};

pub(crate) type CompiledBundleParts = (
    Vec<PolicyPack>,
    CompiledPolicyBundle,
    InterestSet,
    BTreeMap<String, EffectiveLayerRule>,
);

pub(crate) fn compute_bundle_hash_parts(
    packs: &[PolicyPack],
    layers: &[PolicyLayerSpec],
    identity_mode: IdentityMode,
    host_profile: InstallProfile,
    user_timelock_enabled: bool,
    device_max_grade: ApprovalGrade,
) -> String {
    let mut buf = format!(
        "{:?}:{:?}:{}:{:?};P{};",
        identity_mode,
        host_profile,
        user_timelock_enabled,
        device_max_grade,
        packs.len()
    );
    for pack in packs {
        push_len(&mut buf, &pack.id);
        push_len(&mut buf, &pack.version);
        push_len(&mut buf, &format!("{:?}", pack.channel));
        buf.push_str(&format!("R{};", pack.rules.len()));
        for r in &pack.rules {
            push_len(&mut buf, &r.id);
            push_len(&mut buf, r.mode.label());
            buf.push_str(&format!("{}:{}:{:?};", r.enabled, r.locked, r.min_grade));
            push_len(&mut buf, r.cedar.as_deref().unwrap_or(""));
            for p in &r.matcher.target_prefixes {
                push_len(&mut buf, p);
            }
            for c in &r.matcher.target_contains {
                push_len(&mut buf, c);
            }
        }
    }
    buf.push_str(&format!("L{};", layers.len()));
    for spec in layers {
        buf.push_str(&format!("{:?}:E{};", spec.layer, spec.entries.len()));
        for e in &spec.entries {
            push_len(&mut buf, &e.rule_id);
            push_len(&mut buf, e.mode.label());
            buf.push_str(&format!("{:?}:{:?};", e.lock, e.timelock_seconds));
            for p in &e.protect_list {
                push_len(&mut buf, p);
            }
            for a in &e.allow_list {
                push_len(&mut buf, a);
            }
        }
    }
    domain_sha256_hex("grdr.verified-bundle.v1", buf.as_bytes())
}

pub(crate) fn verify_bundle_contents(bundle: &VerifiedBundle) -> Result<(), PolicyError> {
    if bundle.bundle_id.trim().is_empty() || bundle.bundle_hash.trim().is_empty() {
        return Err(PolicyError::ValidationFailed {
            rule_id: bundle.bundle_id.clone(),
            detail: "bundle_id and bundle_hash must not be empty".into(),
        });
    }
    let expected = compute_bundle_hash_parts(
        &bundle.packs,
        &bundle.layers,
        bundle.identity_mode,
        bundle.host_profile,
        bundle.user_timelock_enabled,
        bundle.device_max_grade,
    );
    if bundle.bundle_hash != expected {
        return Err(PolicyError::ValidationFailed {
            rule_id: bundle.bundle_id.clone(),
            detail: "bundle_hash does not match verified packs and layers".into(),
        });
    }
    let max_mb = cached_limits().map_or(32usize, |l| {
        usize::try_from(l.packs.max_pack_bundle_mb).unwrap_or(32)
    });
    let max_bytes = max_mb.saturating_mul(1024 * 1024);
    let mut bundle_bytes: usize = 0;
    for pack in &bundle.packs {
        bundle_bytes = bundle_bytes
            .saturating_add(pack.id.len())
            .saturating_add(pack.name.len())
            .saturating_add(pack.description.len())
            .saturating_add(pack.version.len())
            .saturating_add(pack.channel.len());
        for rule in &pack.rules {
            bundle_bytes = bundle_bytes
                .saturating_add(rule.id.len())
                .saturating_add(rule.title.len())
                .saturating_add(rule.description.len())
                .saturating_add(rule.reason_template.len())
                .saturating_add(rule.cedar.as_deref().map_or(0, str::len));
            for item in rule
                .matcher
                .target_prefixes
                .iter()
                .chain(rule.matcher.target_contains.iter())
                .chain(rule.matcher.agents.iter())
            {
                bundle_bytes = bundle_bytes.saturating_add(item.len());
            }
        }
    }
    for layer in &bundle.layers {
        for entry in &layer.entries {
            bundle_bytes = bundle_bytes.saturating_add(entry.rule_id.len());
            for item in entry.protect_list.iter().chain(entry.allow_list.iter()) {
                bundle_bytes = bundle_bytes.saturating_add(item.len());
            }
        }
    }
    if bundle_bytes > max_bytes {
        return Err(PolicyError::ValidationFailed {
            rule_id: bundle.bundle_id.clone(),
            detail: format!("pack bundle exceeds {max_mb} MiB limit"),
        });
    }
    for pack in &bundle.packs {
        if (!bundle.trusted_keys.is_empty() || pack.key_id.is_some() || pack.signature.is_some())
            && verify_pack(pack, &bundle.trusted_keys) != SignatureStatus::Verified
        {
            return Err(PolicyError::ValidationFailed {
                rule_id: pack.id.clone(),
                detail: "pack cryptographic signature invalid or key untrusted".into(),
            });
        }
    }
    Ok(())
}

pub(crate) fn verify_grant_signature_for_bundle(
    grant: &Grant,
    trusted_keys: &[TrustedKeyInfo],
) -> Result<(), PolicyError> {
    if (!trusted_keys.is_empty() || grant.key_id.is_some() || grant.signature.is_some())
        && verify_grant(grant, trusted_keys) != SignatureStatus::Verified
    {
        return Err(PolicyError::SnapshotCorrupt {
            detail: format!(
                "grant `{}` signature invalid or key untrusted",
                grant.grant_id
            ),
        });
    }
    Ok(())
}

fn extract_rule_layer_seeds(
    rule: &PolicyRule,
) -> Result<Vec<(String, Mode, LayerLock)>, PolicyError> {
    let cedar_src = rule
        .cedar
        .as_deref()
        .map(str::trim)
        .filter(|s| !s.is_empty());
    let Some(src) = cedar_src else {
        let lock = if rule.locked {
            LayerLock::Locked
        } else {
            LayerLock::Default
        };
        return Ok(vec![(rule.id.clone(), rule.mode, lock)]);
    };
    let parsed_set = PolicySet::from_str(src).map_err(|e| PolicyError::CompileFailed {
        rule_id: rule.id.clone(),
        detail: e.to_string(),
    })?;
    let mut seeds = Vec::new();
    for policy in parsed_set.policies() {
        let eff_id = policy.annotation("id").unwrap_or(&rule.id).to_owned();
        let max_mode = parse_optional_mode(&eff_id, policy.annotation("max_mode"), Mode::Block)?;
        let ann_final = parse_optional_final(&eff_id, policy.annotation("final"))?;
        let mut seeded_mode = rule.mode.min(max_mode);
        if let Some(m) = policy.annotation("mode") {
            seeded_mode = seeded_mode.min(parse_optional_mode(&eff_id, Some(m), Mode::Block)?);
        }
        if ann_final && seeded_mode >= Mode::Ask {
            seeded_mode = Mode::Block;
        }
        let lock = if rule.locked || ann_final {
            LayerLock::Locked
        } else {
            LayerLock::Default
        };
        seeds.push((eff_id, seeded_mode, lock));
    }
    Ok(seeds)
}

pub(crate) fn compile_verified_bundle(
    bundle: &VerifiedBundle,
    now: Timestamp,
) -> Result<CompiledBundleParts, PolicyError> {
    verify_bundle_contents(bundle)?;
    let base_layer = profile_layer(bundle.host_profile);
    let mut provider_entries = Vec::new();
    let mut base_entries = Vec::new();
    for pack in &bundle.packs {
        for rule in &pack.rules {
            if !rule.enabled {
                continue;
            }
            for (eff_id, seeded_mode, seeded_lock) in extract_rule_layer_seeds(rule)? {
                if is_essentials_rule_id(&eff_id) {
                    provider_entries.push(LayerRuleEntry {
                        rule_id: eff_id,
                        mode: seeded_mode,
                        lock: seeded_lock,
                        protect_list: BTreeSet::new(),
                        allow_list: BTreeSet::new(),
                        timelock_seconds: None,
                    });
                    continue;
                }
                let defined_above = bundle.layers.iter().any(|spec| {
                    spec.layer < base_layer && spec.entries.iter().any(|e| e.rule_id == eff_id)
                });
                if !defined_above {
                    base_entries.push(LayerRuleEntry {
                        rule_id: eff_id,
                        mode: seeded_mode,
                        lock: seeded_lock,
                        protect_list: BTreeSet::new(),
                        allow_list: BTreeSet::new(),
                        timelock_seconds: None,
                    });
                }
            }
        }
    }
    let mut all_layers = Vec::new();
    if !provider_entries.is_empty() {
        all_layers.push(PolicyLayerSpec {
            layer: LayerKind::Provider,
            entries: provider_entries,
        });
    }
    if !base_entries.is_empty() {
        all_layers.push(PolicyLayerSpec {
            layer: base_layer,
            entries: base_entries,
        });
    }
    all_layers.extend(bundle.layers.iter().cloned());

    let merged_layers = if all_layers.is_empty() {
        None
    } else {
        Some(merge_policy_layers(&all_layers)?)
    };
    let layer_overrides = merged_layers
        .as_ref()
        .map_or_else(BTreeMap::new, |m| m.rules.clone());
    let mut effective_packs = bundle.packs.clone();
    for pack in &mut effective_packs {
        for rule in &mut pack.rules {
            if rule.cedar.as_deref().is_none_or(|s| s.trim().is_empty())
                && let Some(eff) = layer_overrides.get(&rule.id)
            {
                rule.mode = eff.mode;
                rule.locked = eff.lock == LayerLock::Locked;
            }
        }
    }
    let mut compiled = compile_packs_with_options(
        &effective_packs,
        &KillSwitchState::Inactive,
        "",
        "",
        &CompileOptions {
            identity_mode: bundle.identity_mode,
            pack_layer: base_layer,
            layer_overrides: layer_overrides.clone(),
        },
        now,
    )?;
    let layers_hash = merged_layers
        .as_ref()
        .map_or("none", |l| l.effective_hash.as_str());
    let combined = format!(
        "{}:{}:{:?}:{:?}:{}:{:?}",
        compiled.effective_hash,
        layers_hash,
        bundle.identity_mode,
        bundle.host_profile,
        bundle.user_timelock_enabled,
        bundle.device_max_grade,
    );
    compiled.effective_hash = domain_sha256_hex("grdr.bundle.effective.v1", combined.as_bytes());
    let interest = derive_interest_set(&effective_packs);
    Ok((effective_packs, compiled, interest, layer_overrides))
}

pub(crate) fn profile_layer(profile: InstallProfile) -> LayerKind {
    match profile {
        InstallProfile::User => LayerKind::User,
        InstallProfile::Protected => LayerKind::Device,
    }
}

pub(crate) fn derive_interest_set(packs: &[PolicyPack]) -> InterestSet {
    let mut set = InterestSet {
        process_scoped: true,
        ..Default::default()
    };
    for pack in packs {
        for rule in &pack.rules {
            if !rule.enabled || rule.mode == Mode::Off {
                continue;
            }
            let mut actions = rule.matcher.action_classes.clone();
            let mut has_any_action = false;
            if let Some(ref cedar) = rule.cedar {
                has_any_action = cedar.contains("Grdr::Action::\"any\"");
                for ac in extract_policy_actions(cedar) {
                    if !actions.contains(&ac) {
                        actions.push(ac);
                    }
                }
                extract_hosts_and_ports(cedar, &mut set.hosts, &mut set.ports);
            }
            if has_any_action || actions.is_empty() {
                for ac in [
                    ActionClass::Exec,
                    ActionClass::FileRead,
                    ActionClass::FileWrite,
                    ActionClass::FileDelete,
                    ActionClass::NetConnect,
                    ActionClass::NetRequest,
                    ActionClass::LlmRequest,
                    ActionClass::McpConnect,
                    ActionClass::McpCall,
                    ActionClass::CredUse,
                    ActionClass::AgentSpawn,
                    ActionClass::ConfigChange,
                    ActionClass::Elevate,
                    ActionClass::UiAct,
                    ActionClass::DataFlow,
                ] {
                    if !set.action_classes.contains(&ac) {
                        set.action_classes.push(ac);
                    }
                }
            }
            for ac in actions {
                if !set.action_classes.contains(&ac) {
                    set.action_classes.push(ac);
                }
                if matches!(ac, ActionClass::NetConnect | ActionClass::NetRequest) {
                    set.ports.insert(443);
                    set.ports.insert(80);
                }
            }
            for a in &rule.matcher.agents {
                set.agents.insert(a.to_ascii_lowercase());
            }
            for p in &rule.matcher.target_prefixes {
                set.path_prefixes.insert(p.clone());
                extract_hosts_and_ports(p, &mut set.hosts, &mut set.ports);
            }
            for c in &rule.matcher.target_contains {
                extract_hosts_and_ports(c, &mut set.hosts, &mut set.ports);
                if is_domain_like_host(c) {
                    set.hosts.insert(c.to_ascii_lowercase());
                } else {
                    set.path_contains.insert(c.clone());
                }
            }
        }
    }
    set
}

fn is_domain_like_host(raw: &str) -> bool {
    let s = raw.trim();
    if s.is_empty()
        || s.starts_with('.')
        || s.ends_with('.')
        || !s.contains('.')
        || s.contains('/')
        || s.contains('\\')
        || s.contains(' ')
    {
        return false;
    }
    s.split('.')
        .all(|seg| !seg.is_empty() && seg.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-'))
}

fn extract_hosts_and_ports(text: &str, hosts: &mut BTreeSet<String>, ports: &mut BTreeSet<u16>) {
    let mut pos = 0usize;
    while let Some(rel) = text.get(pos..).and_then(|s| s.find("://")) {
        let start = pos.saturating_add(rel).saturating_add(3);
        let tail = text.get(start..).unwrap_or("");
        let end = tail
            .find(|c: char| c.is_ascii_whitespace() || matches!(c, '/' | '?' | '#' | '"' | '\''))
            .unwrap_or(tail.len());
        let auth = tail.get(..end).unwrap_or("");
        let host_port = auth.rsplit('@').next().unwrap_or(auth);
        if let Some((h, p)) = host_port.rsplit_once(':')
            && let Ok(port) = p.parse::<u16>()
        {
            ports.insert(port);
            if !h.is_empty() {
                hosts.insert(h.trim_matches(['[', ']']).to_ascii_lowercase());
            }
        } else if !host_port.is_empty() {
            hosts.insert(host_port.trim_matches(['[', ']']).to_ascii_lowercase());
        }
        pos = start;
    }
    let mut search = text;
    while let Some(idx) = search.find(".port") {
        let after = search
            .get(idx.saturating_add(5)..)
            .unwrap_or("")
            .trim_start();
        let rest = after
            .strip_prefix("==")
            .or_else(|| after.strip_prefix("!="))
            .map(str::trim_start)
            .unwrap_or("");
        let digits: String = rest.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(port) = digits.parse::<u16>()
            && port > 0
        {
            ports.insert(port);
        }
        search = search.get(idx.saturating_add(5)..).unwrap_or("");
    }
}
