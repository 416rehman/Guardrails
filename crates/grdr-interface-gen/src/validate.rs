// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use crate::loader_extra::ensure_not_symlink;
use crate::model::{GenError, InterfaceBundle};
use crate::validate_extra::{
    validate_contrast, validate_css_safety, validate_messages_and_translations,
    validate_registry_uniqueness,
};

pub fn validate_bundle(bundle: &InterfaceBundle, repo_root: &Path) -> Result<(), GenError> {
    validate_css_safety(bundle)?;
    validate_brand_alignment(bundle)?;
    validate_contrast(bundle)?;
    validate_messages_and_translations(bundle)?;
    validate_registry_uniqueness(bundle)?;

    let icon_keys: BTreeSet<&str> = bundle.icons.iter().map(|i| i.key.as_str()).collect();
    let msg_keys: BTreeSet<&str> = bundle.messages.iter().map(|m| m.id.as_str()).collect();

    for icon in &bundle.icons {
        if let Some(same_as) = &icon.same_as
            && !icon_keys.contains(same_as.as_str())
        {
            return Err(GenError::Validation {
                file: "contracts/interface/icons.toml".to_owned(),
                detail: format!("icon '{}' references missing same_as '{same_as}'", icon.key),
            });
        }
    }

    for entry in &bundle.presentations {
        if !icon_keys.contains(entry.icon.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/presentation.toml".to_owned(),
                detail: format!(
                    "entry '{}::{}' references missing icon '{}'",
                    entry.enum_name, entry.value, entry.icon
                ),
            });
        }
        if !msg_keys.contains(entry.label.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/presentation.toml".to_owned(),
                detail: format!(
                    "entry '{}::{}' references missing label token '{}'",
                    entry.enum_name, entry.value, entry.label
                ),
            });
        }
        if let Some(desc_key) = &entry.description
            && !msg_keys.contains(desc_key.as_str())
        {
            return Err(GenError::Validation {
                file: "contracts/interface/presentation.toml".to_owned(),
                detail: format!(
                    "entry '{}::{}' references missing description token '{}'",
                    entry.enum_name, entry.value, desc_key
                ),
            });
        }
    }

    let mut seen_route_ids = BTreeSet::new();
    for route in &bundle.routes {
        if !seen_route_ids.insert(route.id.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/routes.toml".to_owned(),
                detail: format!("duplicate route id '{}'", route.id),
            });
        }
        if !icon_keys.contains(route.icon.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/routes.toml".to_owned(),
                detail: format!(
                    "route '{}' references missing icon '{}'",
                    route.id, route.icon
                ),
            });
        }
        if !msg_keys.contains(route.title.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/routes.toml".to_owned(),
                detail: format!(
                    "route '{}' references missing title token '{}'",
                    route.id, route.title
                ),
            });
        }
    }

    let mut seen_shortcuts = BTreeSet::new();
    for sc in &bundle.shortcuts {
        let key_pair = (sc.scope.as_str(), sc.keys.to_ascii_lowercase());
        if !seen_shortcuts.insert(key_pair) {
            return Err(GenError::Validation {
                file: "contracts/interface/shortcuts.toml".to_owned(),
                detail: format!("duplicate shortcut '{}' in scope '{}'", sc.keys, sc.scope),
            });
        }
    }

    for notif in &bundle.notifications {
        if !icon_keys.contains(notif.icon.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/notifications.toml".to_owned(),
                detail: format!(
                    "notification '{}' references missing icon '{}'",
                    notif.class, notif.icon
                ),
            });
        }
        if !msg_keys.contains(notif.title_token.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/notifications.toml".to_owned(),
                detail: format!(
                    "notification '{}' references missing title token '{}'",
                    notif.class, notif.title_token
                ),
            });
        }
    }

    for msg in &bundle.messages {
        for bad in &bundle.vocabulary.forbidden {
            if contains_word_ci(&msg.msg, &bad.word) {
                return Err(GenError::Validation {
                    file: format!("contracts/interface/strings/src/{}.mf2.toml", msg.namespace),
                    detail: format!(
                        "token '{}' uses forbidden term '{}' (use '{}' instead)",
                        msg.id, bad.word, bad.replacement
                    ),
                });
            }
        }
    }

    for tr in &bundle.translations {
        for (id, text) in &tr.entries {
            for bad in &bundle.vocabulary.forbidden {
                if contains_word_ci(text, &bad.word) {
                    return Err(GenError::Validation {
                        file: format!(
                            "contracts/interface/strings/tr/{}/messages.mf2.toml",
                            tr.locale_tag
                        ),
                        detail: format!(
                            "translation '{}' uses forbidden term '{}' (use '{}' instead)",
                            id, bad.word, bad.replacement
                        ),
                    });
                }
            }
        }
    }

    validate_p14_catalogue_parity(bundle, repo_root)?;
    Ok(())
}

fn validate_brand_alignment(bundle: &InterfaceBundle) -> Result<(), GenError> {
    if bundle.brand.product_name != bundle.vocabulary.brand_name {
        return Err(GenError::Validation {
            file: "contracts/interface/brand/brand.toml".to_owned(),
            detail: format!(
                "brand product_name '{}' mismatches vocabulary '{}'",
                bundle.brand.product_name, bundle.vocabulary.brand_name
            ),
        });
    }
    if bundle.brand.font_sans != bundle.tokens.base.typography.sans
        || bundle.brand.font_mono != bundle.tokens.base.typography.mono
    {
        return Err(GenError::Validation {
            file: "contracts/interface/brand/brand.toml".to_owned(),
            detail: "brand typography tokens drift from contracts/interface/tokens.json".to_owned(),
        });
    }
    let checks = [
        (
            "accent",
            bundle.brand.accent.as_str(),
            bundle.tokens.base.light.get("accentSignal"),
        ),
        (
            "accent_dark",
            bundle.brand.accent_dark.as_str(),
            bundle.tokens.base.dark.get("accentSignal"),
        ),
        (
            "surface_light",
            bundle.brand.surface_light.as_str(),
            bundle.tokens.base.light.get("bgCanvas"),
        ),
        (
            "surface_dark",
            bundle.brand.surface_dark.as_str(),
            bundle.tokens.base.dark.get("bgCanvas"),
        ),
    ];
    for (field, actual, expected_opt) in checks {
        if let Some(expected) = expected_opt
            && !actual.eq_ignore_ascii_case(expected)
        {
            return Err(GenError::Validation {
                file: "contracts/interface/brand/brand.toml".to_owned(),
                detail: format!("brand.{field} '{actual}' drifts from tokens.json '{expected}'"),
            });
        }
    }
    Ok(())
}

fn validate_p14_catalogue_parity(
    bundle: &InterfaceBundle,
    repo_root: &Path,
) -> Result<(), GenError> {
    let agents_dir = repo_root.join("packs").join("catalogue").join("agents");
    ensure_not_symlink(&agents_dir, "packs/catalogue/agents")?;
    if !agents_dir.is_dir() {
        return Ok(());
    }
    let mut keys = BTreeSet::new();
    for entry in &bundle.harness_icons {
        keys.insert(entry.id.to_ascii_lowercase());
        for alias in &entry.aliases {
            keys.insert(alias.to_ascii_lowercase());
        }
    }
    let read_dir = fs::read_dir(&agents_dir).map_err(|source| GenError::Io {
        path: agents_dir.clone(),
        source,
    })?;
    for item in read_dir {
        let item = item.map_err(|source| GenError::Io {
            path: agents_dir.clone(),
            source,
        })?;
        let path = item.path();
        ensure_not_symlink(&path, "packs/catalogue/agents")?;
        if path.extension().and_then(|e| e.to_str()) != Some("yaml") {
            continue;
        }
        let text = fs::read_to_string(&path).map_err(|source| GenError::Io {
            path: path.clone(),
            source,
        })?;
        if let Some(id) = extract_yaml_scalar(&text, "id:")
            && !keys.contains(&id.to_ascii_lowercase())
        {
            return Err(GenError::Validation {
                file: "contracts/interface/icons.toml".to_owned(),
                detail: format!("missing P14 [[harness_icon]] entry for catalogue agent '{id}'"),
            });
        }
    }
    Ok(())
}

fn extract_yaml_scalar(text: &str, prefix: &str) -> Option<String> {
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(rest) = trimmed.strip_prefix(prefix) {
            return Some(rest.trim().trim_matches('"').trim_matches('\'').to_owned());
        }
    }
    None
}

fn contains_word_ci(haystack: &str, needle: &str) -> bool {
    let lower_hay = haystack.to_ascii_lowercase();
    let lower_needle = needle.to_ascii_lowercase();
    lower_hay
        .split(|c: char| !c.is_ascii_alphanumeric() && c != '_')
        .any(|tok| tok == lower_needle)
}
