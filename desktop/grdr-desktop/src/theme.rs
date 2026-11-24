use grdr_ui_model::ThemeChoice;
use rune::{Color, TextStyle};
use rune_kit::{Kit, PaletteSeed, StateColors};

fn hex_color(raw: &str) -> Color {
    rune::color::hex(raw).unwrap_or(Color::BLACK)
}

#[derive(Clone, Copy, Debug)]
pub struct StudioColors {
    pub canvas: Color,
    pub rail: Color,
    pub recessed: Color,
    pub hover: Color,
    pub border_subtle: Color,
    pub border_strong: Color,
    pub ink_primary: Color,
    pub ink_secondary: Color,
    pub ink_muted: Color,
    pub action_bg: Color,
    pub action_ink: Color,
    pub brand_tile: Color,
    pub accent: Color,
    pub accent_soft: Color,
    pub allow: Color,
    pub allow_bg: Color,
    pub watch: Color,
    pub watch_bg: Color,
    pub ask: Color,
    pub ask_bg: Color,
    pub attention_bg: Color,
    pub attention_ink: Color,
    pub attention_wash_start: Color,
    pub attention_wash_mid: Color,
    pub attention_border: Color,
    pub block: Color,
    pub block_bg: Color,
    pub panel_top: Color,
    pub panel_bottom: Color,
    pub rail_top: Color,
    pub rim_top: Color,
    pub specular_rim: Color,
    pub drop_shadow: Color,
    pub inset_well: Color,
    pub dial_track: Color,
    pub grid_line: Color,
    pub viz_allow_end: Color,
    pub viz_ask_start: Color,
    pub viz_block_start: Color,
}

#[derive(Clone, Debug)]
pub struct StudioTheme {
    pub kit: Kit,
    pub c: StudioColors,
    pub display_headline: TextStyle,
    pub section_title: TextStyle,
    pub body: TextStyle,
    pub body_strong: TextStyle,
    pub caption: TextStyle,
    pub mono: TextStyle,
    pub metric_num: TextStyle,
}

#[must_use]
pub fn build_theme(choice: ThemeChoice) -> StudioTheme {
    let dark = matches!(choice, ThemeChoice::Dark);
    let c = if dark {
        StudioColors {
            canvas: hex_color("#0B0D10"),
            rail: hex_color("#0F1216"),
            recessed: hex_color("#13171D"),
            hover: hex_color("#1C2129"),
            border_subtle: hex_color("#1F242D"),
            border_strong: hex_color("#2E3542"),
            ink_primary: hex_color("#F1F5F9"),
            ink_secondary: hex_color("#94A3B8"),
            ink_muted: hex_color("#7C8798"),
            action_bg: hex_color("#F1F5F9"),
            action_ink: hex_color("#0B0D10"),
            brand_tile: hex_color("#FFFFFF"),
            accent: hex_color("#3B82F6"),
            accent_soft: hex_color("#3B82F6").alpha(0.14),
            allow: hex_color("#34D399"),
            allow_bg: hex_color("#34D399").alpha(0.10),
            watch: hex_color("#60A5FA"),
            watch_bg: hex_color("#60A5FA").alpha(0.10),
            ask: hex_color("#FACC15"),
            ask_bg: hex_color("#FACC15").alpha(0.14),
            attention_bg: hex_color("#FACC15"),
            attention_ink: hex_color("#0B0D10"),
            attention_wash_start: hex_color("#EF4444").alpha(0.17),
            attention_wash_mid: hex_color("#EF4444").alpha(0.055),
            attention_border: hex_color("#F87171").alpha(0.28),
            block: hex_color("#F87171"),
            block_bg: hex_color("#F87171").alpha(0.10),
            panel_top: hex_color("#161B22"),
            panel_bottom: hex_color("#12161C"),
            rail_top: hex_color("#11151B"),
            rim_top: Color::WHITE.alpha(0.08),
            specular_rim: Color::WHITE.alpha(0.05),
            drop_shadow: Color::BLACK.alpha(0.32),
            inset_well: Color::BLACK.alpha(0.24),
            dial_track: hex_color("#1F242D"),
            grid_line: hex_color("#F1F5F9").alpha(0.06),
            viz_allow_end: hex_color("#3B82F6"),
            viz_ask_start: hex_color("#FACC15"),
            viz_block_start: hex_color("#EF4444"),
        }
    } else {
        StudioColors {
            canvas: hex_color("#FFFFFF"),
            rail: hex_color("#F8F9FB"),
            recessed: hex_color("#F4F5F7"),
            hover: hex_color("#EEF0F4"),
            border_subtle: hex_color("#E5E7EB"),
            border_strong: hex_color("#D1D5DB"),
            ink_primary: hex_color("#0F172A"),
            ink_secondary: hex_color("#475569"),
            ink_muted: hex_color("#64748B"),
            action_bg: hex_color("#0F172A"),
            action_ink: hex_color("#FFFFFF"),
            brand_tile: hex_color("#111827"),
            accent: hex_color("#2563EB"),
            accent_soft: hex_color("#2563EB").alpha(0.08),
            allow: hex_color("#15803D"),
            allow_bg: hex_color("#15803D").alpha(0.08),
            watch: hex_color("#1D4ED8"),
            watch_bg: hex_color("#1D4ED8").alpha(0.08),
            ask: hex_color("#A16207"),
            ask_bg: hex_color("#FACC15").alpha(0.18),
            attention_bg: hex_color("#FACC15"),
            attention_ink: hex_color("#111827"),
            attention_wash_start: hex_color("#EF4444").alpha(0.11),
            attention_wash_mid: hex_color("#EF4444").alpha(0.038),
            attention_border: hex_color("#EF4444").alpha(0.24),
            block: hex_color("#B91C1C"),
            block_bg: hex_color("#B91C1C").alpha(0.08),
            panel_top: hex_color("#FFFFFF"),
            panel_bottom: hex_color("#FAFBFD"),
            rail_top: hex_color("#F8F9FB"),
            rim_top: Color::WHITE,
            specular_rim: Color::WHITE.alpha(0.85),
            drop_shadow: hex_color("#0F172A").alpha(0.05),
            inset_well: hex_color("#0F172A").alpha(0.04),
            dial_track: hex_color("#E5E7EB"),
            grid_line: hex_color("#0F172A").alpha(0.06),
            viz_allow_end: hex_color("#3B82F6"),
            viz_ask_start: hex_color("#EAB308"),
            viz_block_start: hex_color("#EF4444"),
        }
    };

    let mut kit = Kit::from_palette(PaletteSeed {
        bg: c.canvas,
        fg: c.ink_primary,
        accent: c.accent,
    });
    kit.c.page = c.canvas;
    kit.c.bg_base = c.canvas;
    kit.c.bg_deep = c.rail;
    kit.c.layer_01 = c.recessed;
    kit.c.layer_02 = c.hover;
    kit.c.border_muted = c.border_subtle;
    kit.c.border_base = c.border_subtle;
    kit.c.border_strong = c.border_strong;
    kit.c.text_base = c.ink_primary;
    kit.c.text_muted = c.ink_secondary;
    kit.c.text_faint = c.ink_muted;
    kit.c.hover = c.hover;
    kit.c.success = StateColors {
        bg: c.allow_bg,
        fg: c.allow,
        border: c.allow.alpha(0.35),
        icon: c.allow,
    };
    kit.c.info = StateColors {
        bg: c.watch_bg,
        fg: c.watch,
        border: c.watch.alpha(0.35),
        icon: c.watch,
    };
    kit.c.warning = StateColors {
        bg: c.ask_bg,
        fg: c.ask,
        border: c.ask.alpha(0.35),
        icon: c.ask,
    };
    kit.c.danger = StateColors {
        bg: c.block_bg,
        fg: c.block,
        border: c.block.alpha(0.35),
        icon: c.block,
    };

    let display_headline = TextStyle {
        size: 30.0,
        weight: 700.0,
        line_height: 36.0,
        tracking: -0.6,
        ..kit.ty.ui_medium
    };
    let section_title = TextStyle {
        size: 17.0,
        weight: 700.0,
        line_height: 22.0,
        tracking: -0.2,
        ..kit.ty.ui_medium
    };
    let body = kit.ty.body;
    let body_strong = kit.ty.body_medium;
    let caption = TextStyle {
        size: 12.0,
        line_height: 17.0,
        ..kit.ty.ui
    };
    let mono = kit.ty.mono;
    let metric_num = TextStyle {
        size: 24.0,
        weight: 700.0,
        line_height: 28.0,
        tracking: -0.4,
        features: "'tnum' 1",
        ..kit.ty.ui_medium
    };

    StudioTheme {
        kit,
        c,
        display_headline,
        section_title,
        body,
        body_strong,
        caption,
        mono,
        metric_num,
    }
}
