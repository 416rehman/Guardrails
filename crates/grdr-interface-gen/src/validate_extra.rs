// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use crate::model::{GenError, InterfaceBundle, MessageSpec};

const WCAG_AA_TEXT_RATIO: f64 = 4.5;

const REQUIRED_TEXT_PAIRS: &[(&str, &str, &str)] = &[
    ("inkPrimary/bgCanvas", "inkPrimary", "bgCanvas"),
    ("inkSecondary/bgCanvas", "inkSecondary", "bgCanvas"),
    ("inkMuted/bgCanvas", "inkMuted", "bgCanvas"),
    ("inkMuted/bgRail", "inkMuted", "bgRail"),
    ("accentSignal/bgCanvas", "accentSignal", "bgCanvas"),
    ("allow/bgCanvas", "allow", "bgCanvas"),
    ("watch/bgCanvas", "watch", "bgCanvas"),
    ("ask/bgCanvas", "ask", "bgCanvas"),
    ("block/bgCanvas", "block", "bgCanvas"),
    (
        "actionPrimaryInk/actionPrimaryBg",
        "actionPrimaryInk",
        "actionPrimaryBg",
    ),
    ("attentionInk/attentionBg", "attentionInk", "attentionBg"),
    ("allow/allowBg", "allow", "allowBg"),
    ("watch/watchBg", "watch", "watchBg"),
    ("ask/askBg", "ask", "askBg"),
    ("block/blockBg", "block", "blockBg"),
    ("neutral/neutralBg", "neutral", "neutralBg"),
];

pub fn validate_contrast(bundle: &InterfaceBundle) -> Result<(), GenError> {
    check_palette_contrast("light", &bundle.tokens.light_resolved)?;
    check_palette_contrast("dark", &bundle.tokens.dark_resolved)?;
    Ok(())
}

fn check_palette_contrast(
    mode_name: &str,
    palette: &BTreeMap<String, String>,
) -> Result<(), GenError> {
    let canvas_hex = palette
        .get("bgCanvas")
        .ok_or_else(|| GenError::Validation {
            file: "contracts/interface/tokens.json".to_owned(),
            detail: format!("missing '{mode_name}.bgCanvas' token"),
        })?;
    let canvas_rgb = parse_hex_rgb(canvas_hex)?;

    for &(pair_name, fg_key, bg_key) in REQUIRED_TEXT_PAIRS {
        let Some(fg_val) = palette.get(fg_key) else {
            return Err(GenError::Validation {
                file: "contracts/interface/tokens.json".to_owned(),
                detail: format!("missing '{mode_name}.{fg_key}' token"),
            });
        };
        let Some(bg_val) = palette.get(bg_key) else {
            return Err(GenError::Validation {
                file: "contracts/interface/tokens.json".to_owned(),
                detail: format!("missing '{mode_name}.{bg_key}' token"),
            });
        };
        let fg_rgb = composite_over_canvas(fg_val, canvas_rgb)?;
        let bg_rgb = composite_over_canvas(bg_val, canvas_rgb)?;
        let ratio = contrast_ratio_rgb(fg_rgb, bg_rgb);
        if ratio < WCAG_AA_TEXT_RATIO {
            return Err(GenError::Validation {
                file: "contracts/interface/tokens.json".to_owned(),
                detail: format!(
                    "'{mode_name}' pair '{pair_name}' contrast {ratio:.2}:1 below WCAG AA {WCAG_AA_TEXT_RATIO:.1}:1"
                ),
            });
        }
    }
    Ok(())
}

fn contrast_ratio_rgb(fg: [f64; 3], bg: [f64; 3]) -> f64 {
    let l1 = rgb_luminance(fg);
    let l2 = rgb_luminance(bg);
    let bright = l1.max(l2);
    let dark = l1.min(l2);
    (bright + 0.05) / (dark + 0.05)
}

fn rgb_luminance(rgb: [f64; 3]) -> f64 {
    let [r, g, b] = rgb;
    0.2126 * linearize(r) + 0.7152 * linearize(g) + 0.0722 * linearize(b)
}

fn composite_over_canvas(raw: &str, canvas: [f64; 3]) -> Result<[f64; 3], GenError> {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed
        .strip_prefix("rgba(")
        .and_then(|s| s.strip_suffix(')'))
    {
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        if parts.len() != 4 {
            return Err(GenError::Validation {
                file: "contracts/interface/tokens.json".to_owned(),
                detail: format!("expected rgba(r, g, b, a), found '{raw}'"),
            });
        }
        let r = parse_u8_channel(parts.first().copied(), raw)?;
        let g = parse_u8_channel(parts.get(1).copied(), raw)?;
        let b = parse_u8_channel(parts.get(2).copied(), raw)?;
        let alpha_raw = parts.get(3).copied().unwrap_or("1");
        let alpha = alpha_raw.parse::<f64>().map_err(|_| GenError::Validation {
            file: "contracts/interface/tokens.json".to_owned(),
            detail: format!("invalid alpha '{alpha_raw}' in '{raw}'"),
        })?;
        let a = alpha.clamp(0.0, 1.0);
        let inv = 1.0 - a;
        let [cr, cg, cb] = canvas;
        return Ok([r * a + cr * inv, g * a + cg * inv, b * a + cb * inv]);
    }
    parse_hex_rgb(trimmed)
}

fn parse_hex_rgb(hex: &str) -> Result<[f64; 3], GenError> {
    let clean = hex.trim().strip_prefix('#').unwrap_or("");
    if clean.len() != 6 || !clean.bytes().all(|b| b.is_ascii_hexdigit()) {
        return Err(GenError::Validation {
            file: "contracts/interface/tokens.json".to_owned(),
            detail: format!("expected hex color '#rrggbb', found '{hex}'"),
        });
    }
    let r = parse_hex_channel(clean.get(0..2), hex)?;
    let g = parse_hex_channel(clean.get(2..4), hex)?;
    let b = parse_hex_channel(clean.get(4..6), hex)?;
    Ok([r, g, b])
}

fn parse_u8_channel(slice: Option<&str>, full: &str) -> Result<f64, GenError> {
    let raw = slice.ok_or_else(|| GenError::Validation {
        file: "contracts/interface/tokens.json".to_owned(),
        detail: format!("invalid rgba channel in '{full}'"),
    })?;
    let val = raw.parse::<u8>().map_err(|_| GenError::Validation {
        file: "contracts/interface/tokens.json".to_owned(),
        detail: format!("invalid rgba byte '{raw}' in '{full}'"),
    })?;
    Ok(f64::from(val) / 255.0)
}

fn parse_hex_channel(slice: Option<&str>, full: &str) -> Result<f64, GenError> {
    let raw = slice.ok_or_else(|| GenError::Validation {
        file: "contracts/interface/tokens.json".to_owned(),
        detail: format!("invalid hex color '{full}'"),
    })?;
    let val = u8::from_str_radix(raw, 16).map_err(|_| GenError::Validation {
        file: "contracts/interface/tokens.json".to_owned(),
        detail: format!("invalid hex byte '{raw}' in '{full}'"),
    })?;
    Ok(f64::from(val) / 255.0)
}

fn linearize(channel: f64) -> f64 {
    if channel <= 0.04045 {
        channel / 12.92
    } else {
        ((channel + 0.055) / 1.055).powf(2.4)
    }
}

pub fn validate_messages_and_translations(bundle: &InterfaceBundle) -> Result<(), GenError> {
    let mut base_by_id: BTreeMap<&str, &MessageSpec> = BTreeMap::new();
    for msg in &bundle.messages {
        if base_by_id.insert(msg.id.as_str(), msg).is_some() {
            return Err(GenError::Validation {
                file: format!("contracts/interface/strings/src/{}.mf2.toml", msg.namespace),
                detail: format!("duplicate language token id '{}'", msg.id),
            });
        }
    }

    for tr in &bundle.translations {
        let tr_file = format!(
            "contracts/interface/strings/tr/{}/messages.mf2.toml",
            tr.locale_tag
        );
        for (id, tr_text) in &tr.entries {
            let Some(base) = base_by_id.get(id.as_str()) else {
                return Err(GenError::Validation {
                    file: tr_file,
                    detail: format!(
                        "orphan translation key '{id}' is not declared in contracts/interface/strings/src/"
                    ),
                });
            };
            let base_vars = extract_mf2_placeholders(&base.msg);
            let tr_vars = extract_mf2_placeholders(tr_text);
            if base_vars != tr_vars {
                return Err(GenError::Validation {
                    file: tr_file,
                    detail: format!(
                        "placeholder mismatch for '{id}': expected {base_vars:?}, got {tr_vars:?}"
                    ),
                });
            }
        }
    }
    Ok(())
}

pub fn validate_registry_uniqueness(bundle: &InterfaceBundle) -> Result<(), GenError> {
    let mut seen_icon_keys = BTreeSet::new();
    for icon in &bundle.icons {
        if !seen_icon_keys.insert(icon.key.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/icons.toml".to_owned(),
                detail: format!("duplicate icon key '{}'", icon.key),
            });
        }
    }

    let mut seen_notif_classes = BTreeSet::new();
    for notif in &bundle.notifications {
        if !seen_notif_classes.insert(notif.class.as_str()) {
            return Err(GenError::Validation {
                file: "contracts/interface/notifications.toml".to_owned(),
                detail: format!("duplicate notification class '{}'", notif.class),
            });
        }
    }

    let mut seen_locale_tags = BTreeSet::new();
    for loc in &bundle.locales {
        if !seen_locale_tags.insert(loc.tag.to_ascii_lowercase()) {
            return Err(GenError::Validation {
                file: "contracts/interface/strings/locales.toml".to_owned(),
                detail: format!("duplicate locale tag '{}'", loc.tag),
            });
        }
    }

    let mut seen_pres = BTreeSet::new();
    for entry in &bundle.presentations {
        let key = format!("{}::{}", entry.enum_name, entry.value);
        if !seen_pres.insert(key.clone()) {
            return Err(GenError::Validation {
                file: "contracts/interface/presentation.toml".to_owned(),
                detail: format!("duplicate presentation entry '{key}'"),
            });
        }
    }

    let mut seen_harness_ids = BTreeSet::new();
    let mut seen_kind_tokens: BTreeMap<&str, BTreeSet<String>> = BTreeMap::new();
    for entry in &bundle.harness_icons {
        let id_norm = entry.id.to_ascii_lowercase();
        if !seen_harness_ids.insert(id_norm.clone()) {
            return Err(GenError::Validation {
                file: "contracts/interface/icons.toml".to_owned(),
                detail: format!("duplicate harness_icon id '{}'", entry.id),
            });
        }
        let kind_set = seen_kind_tokens.entry(entry.kind.as_str()).or_default();
        if !kind_set.insert(id_norm) {
            return Err(GenError::Validation {
                file: "contracts/interface/icons.toml".to_owned(),
                detail: format!(
                    "colliding harness_icon id '{}' in kind '{}'",
                    entry.id, entry.kind
                ),
            });
        }
        let mut local_aliases = BTreeSet::new();
        for alias in &entry.aliases {
            let norm = alias.to_ascii_lowercase();
            if !local_aliases.insert(norm.clone()) || !kind_set.insert(norm) {
                return Err(GenError::Validation {
                    file: "contracts/interface/icons.toml".to_owned(),
                    detail: format!(
                        "duplicate or colliding alias '{}' on harness_icon '{}'",
                        alias, entry.id
                    ),
                });
            }
        }
    }

    let mut seen_os_tokens = BTreeSet::new();
    for os in &bundle.os_icons {
        if !seen_os_tokens.insert(os.id.to_ascii_lowercase()) {
            return Err(GenError::Validation {
                file: "contracts/interface/icons.toml".to_owned(),
                detail: format!("duplicate os_icon id '{}'", os.id),
            });
        }
        for alias in &os.aliases {
            if !seen_os_tokens.insert(alias.to_ascii_lowercase()) {
                return Err(GenError::Validation {
                    file: "contracts/interface/icons.toml".to_owned(),
                    detail: format!("colliding os_icon alias '{}' on '{}'", alias, os.id),
                });
            }
        }
    }

    let mut seen_mac_shortcuts = BTreeSet::new();
    for sc in &bundle.shortcuts {
        let pair = (sc.scope.as_str(), sc.macos_keys.to_ascii_lowercase());
        if !seen_mac_shortcuts.insert(pair) {
            return Err(GenError::Validation {
                file: "contracts/interface/shortcuts.toml".to_owned(),
                detail: format!(
                    "duplicate shortcut macos_keys '{}' in scope '{}'",
                    sc.macos_keys, sc.scope
                ),
            });
        }
    }

    if let Some(cli) = &bundle.cli {
        let mut codes = BTreeSet::new();
        let mut exit_names = BTreeSet::new();
        for ec in &cli.exit_codes {
            if !codes.insert(ec.code) {
                return Err(GenError::Validation {
                    file: "contracts/interface/cli.toml".to_owned(),
                    detail: format!("duplicate cli exit_code {}", ec.code),
                });
            }
            if !exit_names.insert(ec.name.as_str()) {
                return Err(GenError::Validation {
                    file: "contracts/interface/cli.toml".to_owned(),
                    detail: format!("duplicate cli exit_code name '{}'", ec.name),
                });
            }
        }
        let mut cmds = BTreeSet::new();
        for cmd in &cli.commands {
            if !cmds.insert(cmd.name.as_str()) {
                return Err(GenError::Validation {
                    file: "contracts/interface/cli.toml".to_owned(),
                    detail: format!("duplicate cli command '{}'", cmd.name),
                });
            }
        }
    }
    Ok(())
}

pub fn validate_css_safety(bundle: &InterfaceBundle) -> Result<(), GenError> {
    let ext_file = "contracts/interface/tokens/studio-extended.json";
    for imp in &bundle.tokens.extended.font_imports {
        check_safe_css_scalar(imp, ext_file, "font_imports", false)?;
        if imp.contains("..")
            || imp.contains('\\')
            || !imp.starts_with("@fontsource/")
            || !imp.ends_with(".css")
        {
            return Err(GenError::Validation {
                file: ext_file.to_owned(),
                detail: format!("unsafe font import path '{imp}'"),
            });
        }
    }
    for (k, v) in &bundle.tokens.extended.spacing {
        check_safe_css_scalar(k, ext_file, "spacing key", false)?;
        check_safe_css_scalar(v, ext_file, &format!("spacing.{k}"), false)?;
    }
    for (script, spec) in &bundle.tokens.extended.scripts {
        check_safe_css_scalar(script, ext_file, "script key", false)?;
        check_safe_css_scalar(
            &spec.font_sans,
            ext_file,
            &format!("scripts.{script}.font_sans"),
            true,
        )?;
    }

    let brand_file = "contracts/interface/brand/brand.toml";
    check_safe_css_scalar(
        &bundle.brand.font_sans,
        brand_file,
        "tokens.font_sans",
        true,
    )?;
    check_safe_css_scalar(
        &bundle.brand.font_mono,
        brand_file,
        "tokens.font_mono",
        true,
    )?;
    let tok_file = "contracts/interface/tokens.json";
    check_safe_css_scalar(
        &bundle.tokens.base.typography.sans,
        tok_file,
        "typography.sans",
        true,
    )?;
    check_safe_css_scalar(
        &bundle.tokens.base.typography.mono,
        tok_file,
        "typography.mono",
        true,
    )?;
    check_safe_css_scalar(&bundle.tokens.base.radius.sm, tok_file, "radius.sm", false)?;
    check_safe_css_scalar(&bundle.tokens.base.radius.md, tok_file, "radius.md", false)?;
    check_safe_css_scalar(&bundle.tokens.base.radius.lg, tok_file, "radius.lg", false)?;
    check_safe_css_scalar(
        &bundle.tokens.base.radius.pill,
        tok_file,
        "radius.pill",
        false,
    )?;

    for (k, v) in &bundle.tokens.light_resolved {
        check_safe_css_scalar(v, tok_file, &format!("light.{k}"), false)?;
    }
    for (k, v) in &bundle.tokens.dark_resolved {
        check_safe_css_scalar(v, tok_file, &format!("dark.{k}"), false)?;
    }
    Ok(())
}

fn check_safe_css_scalar(
    val: &str,
    file: &str,
    field: &str,
    allow_quotes: bool,
) -> Result<(), GenError> {
    let lower = val.to_ascii_lowercase();
    let has_forbidden_quote = !allow_quotes && (val.contains('"') || val.contains('\''));
    let unbalanced_quote = allow_quotes && (val.matches('"').count() & 1) != 0;
    if has_forbidden_quote
        || unbalanced_quote
        || val.contains(';')
        || val.contains('{')
        || val.contains('}')
        || val.contains('\\')
        || val.contains('\r')
        || val.contains('\n')
        || val.contains("/*")
        || val.contains("*/")
        || lower.contains("</style")
        || lower.contains("url(")
        || lower.contains("expression(")
    {
        return Err(GenError::Validation {
            file: file.to_owned(),
            detail: format!("unsafe CSS token content in '{field}': '{val}'"),
        });
    }
    Ok(())
}

fn extract_mf2_placeholders(raw: &str) -> BTreeSet<String> {
    let mut vars = BTreeSet::new();
    let bytes = raw.as_bytes();
    let mut i: usize = 0;
    while i.saturating_add(1) < bytes.len() {
        if bytes.get(i) == Some(&b'{') && bytes.get(i.saturating_add(1)) == Some(&b'$') {
            let mut j = i.saturating_add(2);
            while let Some(&b) = bytes.get(j) {
                if b.is_ascii_alphanumeric() || b == b'_' {
                    j = j.saturating_add(1);
                } else {
                    break;
                }
            }
            if j > i.saturating_add(2)
                && let Some(slice) = raw.get(i.saturating_add(2)..j)
            {
                vars.insert(slice.to_owned());
            }
            i = j;
        } else {
            i = i.saturating_add(1);
        }
    }
    vars
}
