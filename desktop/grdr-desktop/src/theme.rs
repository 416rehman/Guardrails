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
    pub accent: Color,
    pub accent_soft: Color,
    pub allow: Color,
    pub allow_bg: Color,
    pub watch: Color,
    pub watch_bg: Color,
    pub ask: Color,
    pub ask_bg: Color,
    pub block: Color,
    pub block_bg: Color,
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
            canvas: hex_color("#121211"),
            rail: hex_color("#181816"),
            recessed: hex_color("#1F1F1C"),
            hover: hex_color("#272723"),
            border_subtle: hex_color("#2A2A26"),
            border_strong: hex_color("#3D3D37"),
            ink_primary: hex_color("#F4F4F0"),
            ink_secondary: hex_color("#A6A69E"),
            ink_muted: hex_color("#787871"),
            action_bg: hex_color("#F4F4F0"),
            action_ink: hex_color("#111111"),
            accent: hex_color("#5B9BFF"),
            accent_soft: hex_color("#5B9BFF").alpha(0.14),
            allow: hex_color("#4ADE80"),
            allow_bg: hex_color("#4ADE80").alpha(0.13),
            watch: hex_color("#60A5FA"),
            watch_bg: hex_color("#60A5FA").alpha(0.14),
            ask: hex_color("#FBBF24"),
            ask_bg: hex_color("#FBBF24").alpha(0.14),
            block: hex_color("#F87171"),
            block_bg: hex_color("#F87171").alpha(0.14),
        }
    } else {
        StudioColors {
            canvas: hex_color("#FFFFFF"),
            rail: hex_color("#F7F7F5"),
            recessed: hex_color("#F3F3F0"),
            hover: hex_color("#ECECE7"),
            border_subtle: hex_color("#E6E6E0"),
            border_strong: hex_color("#CFCFC8"),
            ink_primary: hex_color("#111111"),
            ink_secondary: hex_color("#52524E"),
            ink_muted: hex_color("#767670"),
            action_bg: hex_color("#111111"),
            action_ink: hex_color("#FFFFFF"),
            accent: hex_color("#0F52BA"),
            accent_soft: hex_color("#0F52BA").alpha(0.08),
            allow: hex_color("#166534"),
            allow_bg: hex_color("#166534").alpha(0.09),
            watch: hex_color("#0F52BA"),
            watch_bg: hex_color("#0F52BA").alpha(0.09),
            ask: hex_color("#B45309"),
            ask_bg: hex_color("#B45309").alpha(0.10),
            block: hex_color("#B91C1C"),
            block_bg: hex_color("#B91C1C").alpha(0.09),
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
