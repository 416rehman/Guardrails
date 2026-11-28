// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

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
        "/* @generated by grdr-interface-gen from contracts/interface/tokens/. Do not edit by hand. */\n",
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
    out.push_str("  --font-family-body: var(--font-sans);\n");
    out.push_str("  --font-family-heading: var(--font-sans);\n");
    out.push_str("  --font-family-code: var(--font-mono);\n");
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

    out.push_str("[data-astryx-theme=\"neutral\"] {\n");
    out.push_str("  --font-family-body: var(--font-sans);\n");
    out.push_str("  --font-family-heading: var(--font-sans);\n");
    out.push_str("  --font-family-code: var(--font-mono);\n");
    out.push_str("}\n\n");

    for (script, spec) in &bundle.tokens.extended.scripts {
        if script == "latn" {
            continue;
        }
        let selector = if script == "arab" {
            "html[data-script=\"arab\"],\nhtml[dir=\"rtl\"]".to_owned()
        } else {
            format!("html[data-script=\"{script}\"]")
        };
        let _ = writeln!(out, "{selector} {{");
        let _ = writeln!(out, "  --font-sans: {};", spec.font_sans);
        out.push_str("  --font-family-body: var(--font-sans);\n");
        out.push_str("  --font-family-heading: var(--font-sans);\n");
        let _ = writeln!(out, "  --script-line-height: {};", spec.line_height_step);
        let _ = writeln!(
            out,
            "  --script-min-font-size: {}px;",
            spec.min_font_size_px
        );
        out.push_str("}\n\n");
        if !spec.allow_italic {
            let _ = writeln!(
                out,
                "html[data-script=\"{script}\"] em,\nhtml[data-script=\"{script}\"] i {{\n  font-style: normal;\n}}\n"
            );
            if bundle
                .locales
                .iter()
                .any(|loc| loc.script == *script && loc.direction == "rtl")
            {
                let _ = writeln!(
                    out,
                    "html[dir=\"rtl\"] em,\nhtml[dir=\"rtl\"] i {{\n  font-style: normal;\n}}\n"
                );
            }
        }
    }

    out.push_str("@media (prefers-reduced-motion: reduce) {\n");
    out.push_str("  :root {\n");
    out.push_str("    --motion-quick: 0ms;\n");
    out.push_str("    --motion-standard: 0ms;\n");
    out.push_str("    --motion-emphasis: 0ms;\n");
    out.push_str("  }\n");
    out.push_str("}\n");
    out
}

pub fn render_tokens_ts(bundle: &InterfaceBundle) -> String {
    let mut out = String::new();
    out.push_str(concat!(
        "// SPDX-",
        "License-Identifier: Apache-2.0\n",
        "// SPDX-FileCopyrightText: The Guardrails ADR Authors\n",
        "// @generated by grdr-interface-gen from contracts/interface/tokens/. Do not edit by hand.\n\n",
    ));
    out.push_str("export const SPACING_TOKENS = {\n");
    for (k, v) in &bundle.tokens.extended.spacing {
        let _ = writeln!(out, "  {}: {},", ts_str(k), ts_str(v));
    }
    out.push_str("} as const;\n\n");

    out.push_str("export const TYPOGRAPHY_TOKENS = {\n");
    let _ = writeln!(
        out,
        "  sans: {},",
        ts_str(&bundle.tokens.base.typography.sans)
    );
    let _ = writeln!(
        out,
        "  mono: {},",
        ts_str(&bundle.tokens.base.typography.mono)
    );
    out.push_str("} as const;\n\n");

    out.push_str("export const SCRIPT_TYPOGRAPHY = {\n");
    for (script, spec) in &bundle.tokens.extended.scripts {
        let _ = writeln!(
            out,
            "  {}: {{ fontSans: {}, minFontSizePx: {}, lineHeightStep: {}, allowItalic: {} }},",
            ts_str(script),
            ts_str(&spec.font_sans),
            spec.min_font_size_px,
            spec.line_height_step,
            spec.allow_italic,
        );
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

pub fn ts_str(value: &str) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "\"\"".to_owned())
}

fn write_theme_vars(out: &mut String, map: &BTreeMap<String, String>) {
    for entry in THEME_CSS_KEYS {
        if let Some(val) = map.get(entry.json_key) {
            let _ = writeln!(out, "  {}: {val};", entry.css_name);
        }
    }
}
