// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::PathBuf;

use serde::Serialize;

use crate::model::{GenError, InterfaceBundle};

const RUNE_LOCKED_TOKENS: &[&str] = &[
    "allow",
    "allow_bg",
    "watch",
    "watch_bg",
    "ask",
    "ask_bg",
    "block",
    "block_bg",
    "attention_bg",
    "attention_ink",
    "operator_bg",
    "operator_ink",
    "operator_badge",
];

#[derive(Serialize)]
struct RuneThemeBlend {
    strategy: &'static str,
    opacity: f32,
}

#[derive(Serialize)]
struct RuneThemeDocument<'a> {
    #[serde(rename = "$schema")]
    schema: &'static str,
    name: &'a str,
    blend: RuneThemeBlend,
    palette: BTreeMap<String, String>,
    light: BTreeMap<String, String>,
    dark: BTreeMap<String, String>,
    numbers: BTreeMap<String, f32>,
    locked_tokens: &'static [&'static str],
}

#[derive(Serialize)]
struct RouteManifestEntry<'a> {
    id: &'a str,
    title_token: &'a str,
    icon_key: &'a str,
    area: &'a str,
    scopes: &'a [String],
    requires: &'a str,
    path: &'a str,
    shell_nav: bool,
}

#[derive(Serialize)]
struct ShortcutEntry<'a> {
    action: &'a str,
    scope: &'a str,
    keys: &'a str,
    macos_keys: &'a str,
    desc: &'a str,
}

#[derive(Serialize)]
struct NotificationEntry<'a> {
    class: &'a str,
    channels: &'a [String],
    dedup_window_secs: i64,
    quiet_hours: bool,
    tone: &'a str,
    icon: &'a str,
    title_token: &'a str,
}

#[derive(Serialize)]
struct CliExitEntry<'a> {
    code: i64,
    name: &'a str,
    desc: &'a str,
}

#[derive(Serialize)]
struct CliCommandEntry<'a> {
    name: &'a str,
    kind: &'a str,
    verbs: &'a [String],
    desc: &'a str,
    flags: &'a [String],
    agent_callable: bool,
}

#[derive(Serialize)]
struct CliManifest<'a> {
    schema: &'a str,
    exit_codes: Vec<CliExitEntry<'a>>,
    commands: Vec<CliCommandEntry<'a>>,
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct AnsiPaletteRole<'a> {
    ansi16: &'a str,
    dark_hex: String,
    light_hex: String,
}

fn serialize_pretty<T: Serialize>(value: &T, artifact_path: &str) -> Result<String, GenError> {
    let mut json = serde_json::to_string_pretty(value).map_err(|source| GenError::Json {
        path: PathBuf::from(artifact_path),
        source,
    })?;
    json.push('\n');
    Ok(json)
}

pub fn render_rune_theme_json(bundle: &InterfaceBundle) -> Result<String, GenError> {
    let mut light = BTreeMap::new();
    for (k, v) in &bundle.tokens.light_resolved {
        if let Some(hex8) = css_color_to_rrggbbaa(v) {
            light.insert(camel_to_snake(k), hex8);
        }
    }
    let mut dark = BTreeMap::new();
    for (k, v) in &bundle.tokens.dark_resolved {
        if let Some(hex8) = css_color_to_rrggbbaa(v) {
            dark.insert(camel_to_snake(k), hex8);
        }
    }

    let mut palette = BTreeMap::new();
    insert_palette_hex(&mut palette, "brand_accent", &bundle.brand.accent);
    insert_palette_hex(&mut palette, "brand_accent_dark", &bundle.brand.accent_dark);
    insert_palette_hex(
        &mut palette,
        "porcelain_canvas",
        &bundle.brand.surface_light,
    );
    insert_palette_hex(&mut palette, "obsidian_canvas", &bundle.brand.surface_dark);
    if let Some(v) = bundle.tokens.base.light.get("allow") {
        insert_palette_hex(&mut palette, "locked_allow", v);
    }
    if let Some(v) = bundle.tokens.base.light.get("watch") {
        insert_palette_hex(&mut palette, "locked_watch", v);
    }
    if let Some(v) = bundle.tokens.base.light.get("ask") {
        insert_palette_hex(&mut palette, "locked_ask", v);
    }
    if let Some(v) = bundle.tokens.base.light.get("block") {
        insert_palette_hex(&mut palette, "locked_block", v);
    }

    let mut numbers = BTreeMap::new();
    for (k, v) in &bundle.tokens.extended.spacing {
        if let Some(px) = parse_px_f32(v) {
            numbers.insert(k.replace('-', "_"), px);
        }
    }
    if let Some(px) = parse_px_f32(&bundle.tokens.base.radius.sm) {
        numbers.insert("radius_sm".to_owned(), px);
    }
    if let Some(px) = parse_px_f32(&bundle.tokens.base.radius.md) {
        numbers.insert("radius_md".to_owned(), px);
    }
    if let Some(px) = parse_px_f32(&bundle.tokens.base.radius.lg) {
        numbers.insert("radius_lg".to_owned(), px);
    }
    if let Some(px) = parse_px_f32(&bundle.tokens.base.radius.pill) {
        numbers.insert("radius_pill".to_owned(), px);
    }
    let m = &bundle.tokens.extended.motion;
    numbers.insert("motion_quick_ms".to_owned(), m.quick_ms as f32);
    numbers.insert("motion_standard_ms".to_owned(), m.standard_ms as f32);
    numbers.insert("motion_emphasis_ms".to_owned(), m.emphasis_ms as f32);
    numbers.insert(
        "approval_arm_default_ms".to_owned(),
        m.approval_arm_default_ms as f32,
    );
    numbers.insert(
        "approval_arm_irreversible_ms".to_owned(),
        m.approval_arm_irreversible_ms as f32,
    );

    let doc = RuneThemeDocument {
        schema: "grdr.rune-theme.v1alpha1",
        name: &bundle.tokens.base.meta.name,
        blend: RuneThemeBlend {
            strategy: "srgb",
            opacity: 1.0,
        },
        palette,
        light,
        dark,
        numbers,
        locked_tokens: RUNE_LOCKED_TOKENS,
    };
    serialize_pretty(&doc, "contracts/interface/generated/rune-theme.json")
}

pub fn render_routes_json(bundle: &InterfaceBundle) -> Result<String, GenError> {
    let list: Vec<RouteManifestEntry<'_>> = bundle
        .routes
        .iter()
        .map(|r| RouteManifestEntry {
            id: &r.id,
            title_token: &r.title,
            icon_key: &r.icon,
            area: &r.area,
            scopes: &r.scopes,
            requires: &r.requires,
            path: &r.path,
            shell_nav: r.shell_nav,
        })
        .collect();
    serialize_pretty(&list, "contracts/interface/generated/routes.json")
}

pub fn render_shortcuts_json(bundle: &InterfaceBundle) -> Result<String, GenError> {
    let list: Vec<ShortcutEntry<'_>> = bundle
        .shortcuts
        .iter()
        .map(|s| ShortcutEntry {
            action: &s.action,
            scope: &s.scope,
            keys: &s.keys,
            macos_keys: &s.macos_keys,
            desc: &s.desc,
        })
        .collect();
    serialize_pretty(&list, "contracts/interface/generated/shortcuts.json")
}

pub fn render_notifications_json(bundle: &InterfaceBundle) -> Result<String, GenError> {
    let list: Vec<NotificationEntry<'_>> = bundle
        .notifications
        .iter()
        .map(|n| NotificationEntry {
            class: &n.class,
            channels: &n.channels,
            dedup_window_secs: n.dedup_window_secs,
            quiet_hours: n.quiet_hours,
            tone: &n.tone,
            icon: &n.icon,
            title_token: &n.title_token,
        })
        .collect();
    serialize_pretty(&list, "contracts/interface/generated/notifications.json")
}

pub fn render_cli_json(bundle: &InterfaceBundle) -> Result<String, GenError> {
    let Some(cli) = &bundle.cli else {
        return Ok("{}\n".to_owned());
    };
    let manifest = CliManifest {
        schema: &cli.schema,
        exit_codes: cli
            .exit_codes
            .iter()
            .map(|c| CliExitEntry {
                code: c.code,
                name: &c.name,
                desc: &c.desc,
            })
            .collect(),
        commands: cli
            .commands
            .iter()
            .map(|c| CliCommandEntry {
                name: &c.name,
                kind: &c.kind,
                verbs: &c.verbs,
                desc: &c.desc,
                flags: &c.flags,
                agent_callable: c.agent_callable,
            })
            .collect(),
    };
    serialize_pretty(&manifest, "contracts/interface/generated/cli-contract.json")
}

pub fn render_ansi_palette_json(bundle: &InterfaceBundle) -> Result<String, GenError> {
    let mut roles = BTreeMap::new();
    let pairs = [
        ("allow", "green", "allow"),
        ("watch", "blue", "watch"),
        ("ask", "yellow", "ask"),
        ("block", "red", "block"),
        ("neutral", "gray", "neutral"),
        ("accent", "brightBlue", "accentSignal"),
        ("ink", "white", "inkPrimary"),
        ("muted", "brightBlack", "inkMuted"),
    ];
    for (role, ansi_name, token_key) in pairs {
        let light_hex = bundle
            .tokens
            .base
            .light
            .get(token_key)
            .cloned()
            .unwrap_or_default();
        let dark_hex = bundle
            .tokens
            .base
            .dark
            .get(token_key)
            .cloned()
            .unwrap_or_default();
        roles.insert(
            role,
            AnsiPaletteRole {
                ansi16: ansi_name,
                dark_hex,
                light_hex,
            },
        );
    }
    serialize_pretty(&roles, "contracts/interface/generated/ansi-palette.json")
}

pub fn render_email_tokens_css(bundle: &InterfaceBundle) -> String {
    let mut out = String::new();
    out.push_str("/* @generated by grdr-interface-gen from contracts/interface/tokens/. Do not edit by hand. */\n");
    out.push_str(":root {\n");
    let _ = writeln!(
        out,
        "  --grdr-email-font-sans: {};",
        bundle.tokens.base.typography.sans
    );
    let _ = writeln!(
        out,
        "  --grdr-email-font-mono: {};",
        bundle.tokens.base.typography.mono
    );
    for key in [
        "bgCanvas",
        "bgRail",
        "borderSubtle",
        "inkPrimary",
        "inkSecondary",
        "accentSignal",
        "allow",
        "watch",
        "ask",
        "block",
    ] {
        if let Some(val) = bundle.tokens.base.light.get(key) {
            let _ = writeln!(out, "  --grdr-email-{}: {val};", camel_to_kebab(key));
        }
    }
    out.push_str("}\n");
    out
}

fn insert_palette_hex(map: &mut BTreeMap<String, String>, key: &str, raw: &str) {
    if let Some(hex8) = css_color_to_rrggbbaa(raw) {
        map.insert(key.to_owned(), hex8);
    }
}

fn css_color_to_rrggbbaa(raw: &str) -> Option<String> {
    let s = raw.trim();
    if let Some(hex) = s.strip_prefix('#') {
        if hex.len() == 6 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(format!("#{}ff", hex.to_ascii_lowercase()));
        }
        if hex.len() == 8 && hex.bytes().all(|b| b.is_ascii_hexdigit()) {
            return Some(format!("#{}", hex.to_ascii_lowercase()));
        }
        return None;
    }
    if let Some(inner) = s.strip_prefix("rgba(").and_then(|v| v.strip_suffix(')')) {
        let parts: Vec<&str> = inner.split(',').map(str::trim).collect();
        if parts.len() != 4 {
            return None;
        }
        let r: u8 = parts.first()?.parse().ok()?;
        let g: u8 = parts.get(1)?.parse().ok()?;
        let b: u8 = parts.get(2)?.parse().ok()?;
        let a_f: f32 = parts.get(3)?.parse().ok()?;
        let a_clamped = a_f.clamp(0.0, 1.0);
        let a = (a_clamped * 255.0).round() as u8;
        return Some(format!("#{r:02x}{g:02x}{b:02x}{a:02x}"));
    }
    None
}

fn parse_px_f32(raw: &str) -> Option<f32> {
    raw.trim().strip_suffix("px")?.trim().parse::<f32>().ok()
}

fn camel_to_snake(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for (idx, ch) in raw.char_indices() {
        if ch.is_ascii_uppercase() {
            if idx > 0 {
                out.push('_');
            }
            out.push(ch.to_ascii_lowercase());
        } else {
            out.push(ch);
        }
    }
    out
}

fn camel_to_kebab(raw: &str) -> String {
    camel_to_snake(raw).replace('_', "-")
}
