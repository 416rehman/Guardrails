use std::collections::BTreeMap;
use std::fmt::Write as _;

use crate::model::InterfaceBundle;

struct CssTokenKey {
    json_key: &'static str,
    css_name: &'static str,
}

const THEME_CSS_KEYS: &[CssTokenKey] = &[
    CssTokenKey {
        json_key: "bgCanvas",
        css_name: "--bg-canvas",
    },
    CssTokenKey {
        json_key: "bgRail",
        css_name: "--bg-rail",
    },
    CssTokenKey {
        json_key: "bgSurface",
        css_name: "--bg-surface",
    },
    CssTokenKey {
        json_key: "bgElevated",
        css_name: "--bg-elevated",
    },
    CssTokenKey {
        json_key: "bgRecessed",
        css_name: "--bg-recessed",
    },
    CssTokenKey {
        json_key: "bgHover",
        css_name: "--bg-hover",
    },
    CssTokenKey {
        json_key: "borderSubtle",
        css_name: "--border-subtle",
    },
    CssTokenKey {
        json_key: "borderStrong",
        css_name: "--border-strong",
    },
    CssTokenKey {
        json_key: "inkPrimary",
        css_name: "--ink-primary",
    },
    CssTokenKey {
        json_key: "inkSecondary",
        css_name: "--ink-secondary",
    },
    CssTokenKey {
        json_key: "inkMuted",
        css_name: "--ink-muted",
    },
    CssTokenKey {
        json_key: "actionPrimaryBg",
        css_name: "--action-primary-bg",
    },
    CssTokenKey {
        json_key: "actionPrimaryInk",
        css_name: "--action-primary-ink",
    },
    CssTokenKey {
        json_key: "accentSignal",
        css_name: "--accent-primary",
    },
    CssTokenKey {
        json_key: "accentSoft",
        css_name: "--accent-soft",
    },
    CssTokenKey {
        json_key: "backdropScrim",
        css_name: "--backdrop-scrim",
    },
    CssTokenKey {
        json_key: "shadowOverlay",
        css_name: "--shadow-overlay",
    },
    CssTokenKey {
        json_key: "pressTint",
        css_name: "--press-tint",
    },
    CssTokenKey {
        json_key: "allow",
        css_name: "--tone-allow",
    },
    CssTokenKey {
        json_key: "allowBg",
        css_name: "--tone-allow-bg",
    },
    CssTokenKey {
        json_key: "toneAllowBorder",
        css_name: "--tone-allow-border",
    },
    CssTokenKey {
        json_key: "watch",
        css_name: "--tone-watch",
    },
    CssTokenKey {
        json_key: "watchBg",
        css_name: "--tone-watch-bg",
    },
    CssTokenKey {
        json_key: "toneWatchBorder",
        css_name: "--tone-watch-border",
    },
    CssTokenKey {
        json_key: "ask",
        css_name: "--tone-ask",
    },
    CssTokenKey {
        json_key: "askBg",
        css_name: "--tone-ask-bg",
    },
    CssTokenKey {
        json_key: "toneAskBorder",
        css_name: "--tone-ask-border",
    },
    CssTokenKey {
        json_key: "attentionSurfaceGradient",
        css_name: "--attention-surface-gradient",
    },
    CssTokenKey {
        json_key: "attentionSurfaceBorder",
        css_name: "--attention-surface-border",
    },
    CssTokenKey {
        json_key: "attentionBg",
        css_name: "--attention-pill-bg",
    },
    CssTokenKey {
        json_key: "attentionInk",
        css_name: "--attention-pill-ink",
    },
    CssTokenKey {
        json_key: "block",
        css_name: "--tone-block",
    },
    CssTokenKey {
        json_key: "blockBg",
        css_name: "--tone-block-bg",
    },
    CssTokenKey {
        json_key: "toneBlockBorder",
        css_name: "--tone-block-border",
    },
    CssTokenKey {
        json_key: "neutral",
        css_name: "--tone-neutral",
    },
    CssTokenKey {
        json_key: "neutralBg",
        css_name: "--tone-neutral-bg",
    },
    CssTokenKey {
        json_key: "toneNeutralBorder",
        css_name: "--tone-neutral-border",
    },
    CssTokenKey {
        json_key: "vizAllowStart",
        css_name: "--viz-allow-start",
    },
    CssTokenKey {
        json_key: "vizAllowEnd",
        css_name: "--viz-allow-end",
    },
    CssTokenKey {
        json_key: "vizAllowEdge",
        css_name: "--viz-allow-edge",
    },
    CssTokenKey {
        json_key: "vizAllowGlow",
        css_name: "--viz-allow-glow",
    },
    CssTokenKey {
        json_key: "vizWatchStart",
        css_name: "--viz-watch-start",
    },
    CssTokenKey {
        json_key: "vizWatchEnd",
        css_name: "--viz-watch-end",
    },
    CssTokenKey {
        json_key: "vizWatchEdge",
        css_name: "--viz-watch-edge",
    },
    CssTokenKey {
        json_key: "vizWatchGlow",
        css_name: "--viz-watch-glow",
    },
    CssTokenKey {
        json_key: "vizAskStart",
        css_name: "--viz-ask-start",
    },
    CssTokenKey {
        json_key: "vizAskEnd",
        css_name: "--viz-ask-end",
    },
    CssTokenKey {
        json_key: "vizAskEdge",
        css_name: "--viz-ask-edge",
    },
    CssTokenKey {
        json_key: "vizAskGlow",
        css_name: "--viz-ask-glow",
    },
    CssTokenKey {
        json_key: "vizBlockStart",
        css_name: "--viz-block-start",
    },
    CssTokenKey {
        json_key: "vizBlockEnd",
        css_name: "--viz-block-end",
    },
    CssTokenKey {
        json_key: "vizBlockEdge",
        css_name: "--viz-block-edge",
    },
    CssTokenKey {
        json_key: "vizBlockGlow",
        css_name: "--viz-block-glow",
    },
    CssTokenKey {
        json_key: "vizGridLine",
        css_name: "--viz-grid-line",
    },
    CssTokenKey {
        json_key: "vizRailTrack",
        css_name: "--viz-rail-track",
    },
    CssTokenKey {
        json_key: "vizDialTrack",
        css_name: "--viz-dial-track",
    },
    CssTokenKey {
        json_key: "vizDialTick",
        css_name: "--viz-dial-tick",
    },
    CssTokenKey {
        json_key: "vizHexEmpty",
        css_name: "--viz-hex-empty",
    },
    CssTokenKey {
        json_key: "vizHexEmptyStroke",
        css_name: "--viz-hex-empty-stroke",
    },
    CssTokenKey {
        json_key: "surfaceSpecular",
        css_name: "--surface-specular",
    },
    CssTokenKey {
        json_key: "surfaceElevatedShadow",
        css_name: "--surface-elevated-shadow",
    },
    CssTokenKey {
        json_key: "heroGlassBg",
        css_name: "--hero-glass-bg",
    },
    CssTokenKey {
        json_key: "heroGlassBorder",
        css_name: "--hero-glass-border",
    },
    CssTokenKey {
        json_key: "heroCardBg",
        css_name: "--hero-card-bg",
    },
    CssTokenKey {
        json_key: "heroCardShadow",
        css_name: "--hero-card-shadow",
    },
    CssTokenKey {
        json_key: "operatorBg",
        css_name: "--operator-bar-bg",
    },
    CssTokenKey {
        json_key: "operatorInk",
        css_name: "--operator-bar-ink",
    },
    CssTokenKey {
        json_key: "operatorBadge",
        css_name: "--operator-badge-bg",
    },
    CssTokenKey {
        json_key: "operatorBadgeInk",
        css_name: "--operator-badge-ink",
    },
    CssTokenKey {
        json_key: "focusRing",
        css_name: "--focus-ring",
    },
];

pub fn render_tokens_css(bundle: &InterfaceBundle) -> String {
    let mut out = String::new();
    out.push_str(
        "/* @generated by grdr-interface-gen from interface/tokens/. Do not edit by hand. */\n",
    );
    for imp in &bundle.tokens.extended.font_imports {
        let _ = writeln!(out, "@import \"{}\";", imp);
    }
    out.push('\n');
    out.push_str(":root,\nhtml[data-theme=\"light\"] {\n");
    for (k, v) in &bundle.tokens.extended.spacing {
        let _ = writeln!(out, "  --{k}: {v};");
    }
    let _ = writeln!(
        out,
        "  --font-sans: {};",
        bundle.tokens.base.typography.sans
    );
    let _ = writeln!(
        out,
        "  --font-mono: {};",
        bundle.tokens.base.typography.mono
    );
    let _ = writeln!(out, "  --radius-sm: {};", bundle.tokens.base.radius.sm);
    let _ = writeln!(out, "  --radius-md: {};", bundle.tokens.base.radius.md);
    let _ = writeln!(out, "  --radius-lg: {};", bundle.tokens.base.radius.lg);
    let _ = writeln!(out, "  --radius-pill: {};", bundle.tokens.base.radius.pill);
    let motion = &bundle.tokens.extended.motion;
    let _ = writeln!(out, "  --motion-quick: {}ms;", motion.quick_ms);
    let _ = writeln!(out, "  --motion-standard: {}ms;", motion.standard_ms);
    let _ = writeln!(out, "  --motion-emphasis: {}ms;", motion.emphasis_ms);
    let _ = writeln!(
        out,
        "  --approval-arm-default: {}ms;",
        motion.approval_arm_default_ms
    );
    let _ = writeln!(
        out,
        "  --approval-arm-irreversible: {}ms;",
        motion.approval_arm_irreversible_ms
    );
    write_theme_vars(&mut out, &bundle.tokens.light_resolved);
    out.push_str("}\n\n");

    out.push_str("html[data-theme=\"dark\"] {\n");
    write_theme_vars(&mut out, &bundle.tokens.dark_resolved);
    out.push_str("}\n\n");

    out.push_str("@media (prefers-reduced-motion: reduce) {\n");
    out.push_str("  :root {\n");
    out.push_str("    --motion-quick: 0ms;\n");
    out.push_str("    --motion-standard: 0ms;\n");
    out.push_str("    --motion-emphasis: 0ms;\n");
    out.push_str("  }\n");
    out.push_str("}\n");

    out
}

fn write_theme_vars(out: &mut String, map: &BTreeMap<String, String>) {
    for entry in THEME_CSS_KEYS {
        if let Some(val) = map.get(entry.json_key) {
            let _ = writeln!(out, "  {}: {val};", entry.css_name);
        }
    }
}

pub fn render_tokens_ts(bundle: &InterfaceBundle) -> String {
    let mut out = String::new();
    out.push_str(
        "// @generated by grdr-interface-gen from interface/tokens/. Do not edit by hand.\n\n",
    );
    out.push_str("export const SPACING_TOKENS = {\n");
    for (k, v) in &bundle.tokens.extended.spacing {
        let _ = writeln!(out, "  {}: {},", ts_str(k), ts_str(v));
    }
    out.push_str("} as const;\n\n");

    out.push_str("export const RADIUS_TOKENS = {\n");
    let _ = writeln!(out, "  sm: {},", ts_str(&bundle.tokens.base.radius.sm));
    let _ = writeln!(out, "  md: {},", ts_str(&bundle.tokens.base.radius.md));
    let _ = writeln!(out, "  lg: {},", ts_str(&bundle.tokens.base.radius.lg));
    let _ = writeln!(out, "  pill: {},", ts_str(&bundle.tokens.base.radius.pill));
    out.push_str("} as const;\n\n");

    out.push_str("export const LOCKED_SEMANTIC_TONES = {\n");
    out.push_str("  allow: \"var(--tone-allow)\",\n");
    out.push_str("  watch: \"var(--tone-watch)\",\n");
    out.push_str("  ask: \"var(--tone-ask)\",\n");
    out.push_str("  block: \"var(--tone-block)\",\n");
    out.push_str("  neutral: \"var(--tone-neutral)\",\n");
    out.push_str("  accent: \"var(--accent-primary)\",\n");
    out.push_str("} as const;\n\n");

    out.push_str("export const LIGHT_PALETTE = {\n");
    for (k, v) in &bundle.tokens.base.light {
        let _ = writeln!(out, "  {}: {},", ts_str(k), ts_str(v));
    }
    out.push_str("} as const;\n\n");

    out.push_str("export const DARK_PALETTE = {\n");
    for (k, v) in &bundle.tokens.base.dark {
        let _ = writeln!(out, "  {}: {},", ts_str(k), ts_str(v));
    }
    out.push_str("} as const;\n");
    out
}

pub fn render_i18n_generated_ts(bundle: &InterfaceBundle) -> String {
    let mut out = String::new();
    out.push_str("// @generated by grdr-interface-gen from interface/. Do not edit by hand.\n\n");

    out.push_str("export type LocaleCode = ");
    let locale_union: Vec<String> = bundle.locales.iter().map(|l| ts_str(&l.tag)).collect();
    out.push_str(&locale_union.join(" | "));
    out.push_str(";\n\n");

    out.push_str("export const SUPPORTED_LOCALES = [\n");
    for loc in &bundle.locales {
        let _ = writeln!(
            out,
            "  {{ tag: {}, tier: {}, script: {}, direction: {} }},",
            ts_str(&loc.tag),
            ts_str(&loc.tier),
            ts_str(&loc.script),
            ts_str(&loc.direction),
        );
    }
    out.push_str("] as const;\n\n");

    let _ = writeln!(
        out,
        "export const BRAND_NAME = {};",
        ts_str(&bundle.vocabulary.brand_name)
    );
    let _ = writeln!(
        out,
        "export const BRAND_SHORT_NAME = {};\n",
        ts_str(&bundle.vocabulary.brand_short_name)
    );

    out.push_str("export const VOCABULARY_TERMS = {\n");
    for term in &bundle.vocabulary.terms {
        let _ = writeln!(
            out,
            "  {}: {{ term: {}, translate: {} }},",
            ts_str(&term.key),
            ts_str(&term.term),
            term.translate,
        );
    }
    out.push_str("} as const;\n\n");

    out.push_str("export const ICON_REGISTRY = {\n");
    for icon in &bundle.icons {
        let _ = writeln!(
            out,
            "  {}: {{ lucide: {}, mirror: {} }},",
            ts_str(&icon.key),
            ts_str(&icon.lucide),
            icon.mirror,
        );
    }
    out.push_str("} as const;\n\n");

    out.push_str("export const PRESENTATION_REGISTRY = [\n");
    for entry in &bundle.presentations {
        let desc = match &entry.description {
            Some(d) => ts_str(d),
            None => "null".to_owned(),
        };
        let _ = writeln!(
            out,
            "  {{ enumName: {}, value: {}, labelKey: {}, descriptionKey: {desc}, iconKey: {}, tone: {} }},",
            ts_str(&entry.enum_name),
            ts_str(&entry.value),
            ts_str(&entry.label),
            ts_str(&entry.icon),
            ts_str(&entry.tone),
        );
    }
    out.push_str("] as const;\n\n");

    out.push_str("export const INTERFACE_ROUTES = [\n");
    for route in &bundle.routes {
        let scopes: Vec<String> = route.scopes.iter().map(|s| ts_str(s)).collect();
        let _ = writeln!(
            out,
            "  {{ id: {}, titleKey: {}, iconKey: {}, area: {}, scopes: [{}], requires: {} }},",
            ts_str(&route.id),
            ts_str(&route.title),
            ts_str(&route.icon),
            ts_str(&route.area),
            scopes.join(", "),
            ts_str(&route.requires),
        );
    }
    out.push_str("] as const;\n\n");

    out.push_str("export const MESSAGES = {\n");
    for msg in &bundle.messages {
        let _ = writeln!(out, "  {}: {},", ts_str(&msg.id), ts_str(&msg.msg));
    }
    out.push_str("} as const;\n\n");

    out.push_str("export type MessageKey = keyof typeof MESSAGES;\n\n");
    out.push_str("export function t(key: MessageKey): string {\n");
    out.push_str("  return MESSAGES[key];\n");
    out.push_str("}\n\n");
    out.push_str("export function lookupMessage(locale: LocaleCode, key: MessageKey): string {\n");
    out.push_str("  const base = MESSAGES[key];\n");
    out.push_str("  switch (locale) {\n");
    out.push_str("    case \"en-US\":\n");
    out.push_str("      return base;\n");
    out.push_str("    case \"en-XA\":\n");
    out.push_str("      return `[${base} ~~~]`;\n");
    out.push_str("    case \"ar-XB\":\n");
    out.push_str("      return `\\u2066${base}\\u2069`;\n");
    out.push_str("    case \"ja-XC\":\n");
    out.push_str("      return `「${base}」`;\n");
    out.push_str("  }\n");
    out.push_str("}\n");

    out
}

fn ts_str(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}
