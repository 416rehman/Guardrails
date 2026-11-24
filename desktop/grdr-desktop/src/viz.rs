use std::sync::Arc;

use rune::{
    Color, El, Image, ImageCache, LineCap, Shadow, Shape, SurfaceFit, TextStyle, canvas, col, el,
    icon, row, spacer, text,
};

use grdr_ui_model::ThemeChoice;

use crate::icons;
use crate::kit::{DesktopApp, status_pill_with_icon};
use crate::theme::{StudioColors, StudioTheme, build_theme};

const PANEL_DITHER_W: u32 = 960;
const PANEL_DITHER_H: u32 = 180;
const DIAL_DITHER_W: u32 = 220;
const DIAL_DITHER_H: u32 = 190;
const FLOOR_STRIPE_W: u32 = 960;
const FLOOR_STRIPE_H: u32 = 4;
const BAR_STRIPE_W: u32 = 36;
const BAR_STRIPE_H: u32 = 18;
const HATCH_W: u32 = 256;
const HATCH_H: u32 = 96;

pub struct DesktopTextures {
    pub panel_dither_light: Image,
    pub panel_dither_dark: Image,
    pub dial_dither_light: Image,
    pub dial_dither_dark: Image,
    pub stripe_floor: Image,
    pub stripe_bar_block: Image,
    pub stripe_bar_ask: Image,
    pub hatch_light: Image,
    pub hatch_dark: Image,
}

impl DesktopTextures {
    #[must_use]
    pub fn new(cache: &ImageCache) -> Self {
        let light = build_theme(ThemeChoice::Light).c;
        let dark = build_theme(ThemeChoice::Dark).c;

        let panel_dither_light =
            build_dither_plate(cache, PANEL_DITHER_W, PANEL_DITHER_H, &light, 15, true);
        let panel_dither_dark =
            build_dither_plate(cache, PANEL_DITHER_W, PANEL_DITHER_H, &dark, 22, true);
        let dial_dither_light =
            build_dither_plate(cache, DIAL_DITHER_W, DIAL_DITHER_H, &light, 18, false);
        let dial_dither_dark =
            build_dither_plate(cache, DIAL_DITHER_W, DIAL_DITHER_H, &dark, 24, false);
        let stripe_floor =
            build_diagonal_stripe_plate(cache, FLOOR_STRIPE_W, FLOOR_STRIPE_H, light.block, 54, 10);
        let stripe_bar_block = build_diagonal_stripe_plate(
            cache,
            BAR_STRIPE_W,
            BAR_STRIPE_H,
            light.ink_primary,
            36,
            8,
        );
        let stripe_bar_ask = build_diagonal_stripe_plate(
            cache,
            BAR_STRIPE_W,
            BAR_STRIPE_H,
            light.ink_primary,
            32,
            8,
        );
        let hatch_light = build_hatch_plate(cache, light.ink_primary, 22, 8);
        let hatch_dark = build_hatch_plate(cache, dark.ink_primary, 24, 8);

        let _ = panel_dither_light.wait();
        let _ = panel_dither_dark.wait();
        let _ = dial_dither_light.wait();
        let _ = dial_dither_dark.wait();
        let _ = stripe_floor.wait();
        let _ = stripe_bar_block.wait();
        let _ = stripe_bar_ask.wait();
        let _ = hatch_light.wait();
        let _ = hatch_dark.wait();

        Self {
            panel_dither_light,
            panel_dither_dark,
            dial_dither_light,
            dial_dither_dark,
            stripe_floor,
            stripe_bar_block,
            stripe_bar_ask,
            hatch_light,
            hatch_dark,
        }
    }

    #[must_use]
    pub fn dither(&self, dark_mode: bool) -> &Image {
        if dark_mode {
            &self.panel_dither_dark
        } else {
            &self.panel_dither_light
        }
    }

    #[must_use]
    pub fn dial_dither(&self, dark_mode: bool) -> &Image {
        if dark_mode {
            &self.dial_dither_dark
        } else {
            &self.dial_dither_light
        }
    }

    #[must_use]
    pub fn hatch(&self, dark_mode: bool) -> &Image {
        if dark_mode {
            &self.hatch_dark
        } else {
            &self.hatch_light
        }
    }
}

fn srgb_u8(linear: f32) -> u8 {
    let clamped = linear.clamp(0.0, 1.0);
    let encoded = if clamped <= 0.003_130_8 {
        clamped * 12.92
    } else {
        1.055 * clamped.powf(1.0 / 2.4) - 0.055
    };
    (encoded * 255.0).round().clamp(0.0, 255.0) as u8
}

fn rgb_u8(color: Color) -> [u8; 3] {
    [srgb_u8(color.r), srgb_u8(color.g), srgb_u8(color.b)]
}

const fn bayer4_threshold(x: u32, y: u32) -> f32 {
    let slot = match (x % 4, y % 4) {
        (0, 0) => 0,
        (2, 0) => 8,
        (0, 2) => 12,
        (2, 2) => 4,
        (1, 0) => 2,
        (3, 0) => 10,
        (1, 2) => 14,
        (3, 2) => 6,
        (0, 1) => 3,
        (2, 1) => 11,
        (0, 3) => 15,
        (2, 3) => 7,
        (1, 1) => 1,
        (3, 1) => 9,
        (1, 3) => 13,
        _ => 5,
    };
    (slot as f32 + 0.5) / 16.0
}

fn build_dither_plate(
    cache: &ImageCache,
    width: u32,
    height: u32,
    c: &StudioColors,
    max_alpha: u8,
    wide_vignette: bool,
) -> Image {
    let [ar, ag, ab] = rgb_u8(c.accent);
    let [ir, ig, ib] = rgb_u8(c.ink_primary);
    let cap = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(4);
    let mut bytes = Vec::with_capacity(cap);
    let w_f = width as f32;
    let h_f = height as f32;

    for y in 0..height {
        let ny = y as f32 / h_f;
        for x in 0..width {
            let nx = x as f32 / w_f;
            let (radial, intensity) = if wide_vignette {
                let dx = (nx - 0.86) * 1.45;
                let dy = (ny - 0.16) * 1.15;
                let r = (1.0 - (dx * dx + dy * dy).sqrt()).clamp(0.0, 1.0);
                let top_right = (nx.powf(1.8) * (1.0 - ny * 0.55)).clamp(0.0, 1.0);
                (r, (r * 0.65 + top_right * 0.28).clamp(0.0, 1.0))
            } else {
                let dx = (nx - 0.72) * 1.15;
                let dy = ny - 0.24;
                let r = (1.0 - (dx * dx + dy * dy).sqrt()).clamp(0.0, 1.0);
                (r, (0.08 + r * 0.62).clamp(0.0, 1.0))
            };

            if intensity > bayer4_threshold(x, y) && radial > 0.04 {
                let mix_accent = (radial * 1.15).clamp(0.0, 1.0);
                let r = ((ir as f32) * (1.0 - mix_accent) + (ar as f32) * mix_accent)
                    .round()
                    .clamp(0.0, 255.0) as u8;
                let g = ((ig as f32) * (1.0 - mix_accent) + (ag as f32) * mix_accent)
                    .round()
                    .clamp(0.0, 255.0) as u8;
                let b = ((ib as f32) * (1.0 - mix_accent) + (ab as f32) * mix_accent)
                    .round()
                    .clamp(0.0, 255.0) as u8;
                let a = (f32::from(max_alpha) * (0.35 + 0.65 * radial))
                    .round()
                    .clamp(0.0, 255.0) as u8;
                bytes.extend_from_slice(&[r, g, b, a]);
            } else {
                bytes.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    cache.rgba(width, height, Arc::<[u8]>::from(bytes))
}

fn build_diagonal_stripe_plate(
    cache: &ImageCache,
    width: u32,
    height: u32,
    tint: Color,
    alpha: u8,
    period: u32,
) -> Image {
    let [r, g, b] = rgb_u8(tint);
    let half = (period / 2).max(1);
    let cap = (width as usize)
        .saturating_mul(height as usize)
        .saturating_mul(4);
    let mut bytes = Vec::with_capacity(cap);

    for y in 0..height {
        for x in 0..width {
            let phase = (x.saturating_add(y)) % period.max(2);
            if phase < half {
                bytes.extend_from_slice(&[r, g, b, alpha]);
            } else {
                bytes.extend_from_slice(&[r, g, b, 6]);
            }
        }
    }
    cache.rgba(width, height, Arc::<[u8]>::from(bytes))
}

fn build_hatch_plate(cache: &ImageCache, tint: Color, alpha: u8, spacing: u32) -> Image {
    let [r, g, b] = rgb_u8(tint);
    let stride = spacing.max(4);
    let cap = (HATCH_W as usize)
        .saturating_mul(HATCH_H as usize)
        .saturating_mul(4);
    let mut bytes = Vec::with_capacity(cap);

    for y in 0..HATCH_H {
        for x in 0..HATCH_W {
            let phase = (x.saturating_add(y)) % stride;
            if phase <= 1 {
                bytes.extend_from_slice(&[r, g, b, alpha]);
            } else {
                bytes.extend_from_slice(&[0, 0, 0, 0]);
            }
        }
    }
    cache.rgba(HATCH_W, HATCH_H, Arc::<[u8]>::from(bytes))
}

#[must_use]
pub fn is_dark_theme(t: &StudioTheme) -> bool {
    t.c.canvas.luminance() < 0.2
}

#[must_use]
pub fn texture_overlay(img: &Image) -> El {
    el().pin(Some(0.0), Some(0.0), Some(0.0), Some(0.0))
        .pixels_fit(img.pixels(), SurfaceFit::Fill)
}

#[must_use]
pub fn top_stripe_ribbon(img: &Image, height: f32) -> El {
    el().w_full()
        .h(height)
        .pixels_fit(img.pixels(), SurfaceFit::Fill)
}

#[must_use]
pub fn hardware_panel(
    key: &'static str,
    radius: f32,
    dither: &Image,
    t: &StudioTheme,
    body: El,
) -> El {
    el().key(key)
        .continuous_corners()
        .radius(radius)
        .clip_rounded(radius)
        .gradient(t.c.panel_top, t.c.panel_bottom)
        .border_gradient(1.0, t.c.rim_top, t.c.border_subtle)
        .box_shadow(Shadow {
            x: 0.0,
            y: 1.0,
            blur: 0.0,
            spread: 0.0,
            color: t.c.specular_rim,
            inset: true,
        })
        .shadow(6.0, 16.0, t.c.drop_shadow)
        .child(texture_overlay(dither))
        .child(body)
}

fn arc_points(
    cx: f32,
    cy: f32,
    r: f32,
    start_deg: f32,
    sweep_deg: f32,
    steps: usize,
) -> Vec<[f32; 2]> {
    let mut pts = Vec::with_capacity(steps.saturating_add(1));
    let count = steps.max(2);
    for idx in 0..=count {
        let frac = idx as f32 / count as f32;
        let rad = (start_deg + sweep_deg * frac).to_radians();
        pts.push([cx + r * rad.cos(), cy + r * rad.sin()]);
    }
    pts
}

#[must_use]
pub fn coverage_visual(
    pct: u8,
    boundary_count: usize,
    total: usize,
    app: &DesktopApp,
    t: &StudioTheme,
) -> El {
    let clamped = f32::from(pct.min(100)) / 100.0;
    let dark = is_dark_theme(t);
    let accent = if pct >= 50 {
        t.c.viz_allow_start
    } else {
        t.c.viz_watch_start
    };
    let accent_end = if pct >= 50 {
        t.c.viz_allow_end
    } else {
        t.c.viz_watch_end
    };
    let accent_edge = if pct >= 50 {
        t.c.viz_allow_edge
    } else {
        t.c.viz_watch_edge
    };

    let start_deg = -210.0_f32;
    let full_sweep = 240.0_f32;
    let cx = 64.0_f32;
    let cy = 58.0_f32;
    let radius = 43.0_f32;

    let mut dial = Shape::new();
    for step in 0..=24 {
        let frac = step as f32 / 24.0;
        let angle = (start_deg + full_sweep * frac).to_radians();
        let major = step % 6 == 0;
        let r_in = if major { radius + 7.5 } else { radius + 9.0 };
        let r_out = if major { radius + 12.5 } else { radius + 11.0 };
        let tick_w = if major { 1.4 } else { 0.9 };
        let tick_color = if major {
            t.c.ink_muted.alpha(0.75)
        } else {
            t.c.dial_tick
        };
        dial = dial.line(
            [cx + r_in * angle.cos(), cy + r_in * angle.sin()],
            [cx + r_out * angle.cos(), cy + r_out * angle.sin()],
            tick_w,
            LineCap::Round,
            tick_color,
        );
    }

    dial = dial.stroke_with(
        arc_points(cx, cy, radius, start_deg, full_sweep, 48),
        false,
        9.0,
        LineCap::Round,
        t.c.dial_track,
    );

    if clamped > 0.01 {
        let active_sweep = (full_sweep * clamped).max(6.0);
        let active_pts = arc_points(cx, cy, radius, start_deg, active_sweep, 48);
        dial = dial
            .stroke_with(
                active_pts.clone(),
                false,
                14.0,
                LineCap::Round,
                accent.alpha(0.20),
            )
            .stroke_with(active_pts, false, 9.0, LineCap::Round, accent)
            .stroke_with(
                arc_points(cx, cy, radius - 2.2, start_deg, active_sweep, 40),
                false,
                2.0,
                LineCap::Round,
                accent_edge.alpha(0.75),
            );
        let end_rad = (start_deg + active_sweep).to_radians();
        let px = cx + radius * end_rad.cos();
        let py = cy + radius * end_rad.sin();
        dial = dial
            .line([px, py], [px, py], 12.0, LineCap::Round, accent.alpha(0.32))
            .line([px, py], [px, py], 6.0, LineCap::Round, accent_edge);
    }

    let pct_style = TextStyle {
        size: 24.0,
        weight: 600.0,
        line_height: 26.0,
        ..t.display_headline
    };

    let dial_stage = el()
        .size(128.0, 96.0)
        .center()
        .child(canvas(dial).size(128.0, 96.0))
        .child(
            col()
                .pin(Some(0.0), Some(30.0), Some(0.0), None)
                .items_center()
                .gap(1.0)
                .child(
                    text(format!("{pct}%"))
                        .font(pct_style)
                        .color(t.c.ink_primary),
                )
                .child(text("Boundary").font(t.caption).color(t.c.ink_muted)),
        );

    let inner = col()
        .w_full()
        .padding(14.0)
        .gap(4.0)
        .items_center()
        .child(
            row()
                .w_full()
                .center_y()
                .gap(8.0)
                .child(icon(&icons::SHIELD_CHECK, 15.0).color(accent))
                .child(
                    text("Boundary coverage")
                        .font(t.caption)
                        .color(t.c.ink_secondary),
                ),
        )
        .child(dial_stage)
        .child(
            text(format!("{boundary_count} of {total} sandboxed"))
                .font(t.caption)
                .color(t.c.ink_muted),
        );

    el().w(220.0)
        .continuous_corners()
        .radius(14.0)
        .clip_rounded(14.0)
        .gradient(t.c.panel_top, t.c.panel_bottom)
        .radial_gradient(
            [0.65, 0.25],
            145.0,
            [
                (0.0, accent.alpha(0.15)),
                (0.65, accent_end.alpha(0.05)),
                (1.0, Color::TRANSPARENT),
            ],
        )
        .border_gradient(1.0, t.c.rim_top, t.c.border_subtle)
        .box_shadow(Shadow {
            x: 0.0,
            y: 1.0,
            blur: 0.0,
            spread: 0.0,
            color: t.c.specular_rim,
            inset: true,
        })
        .shadow(6.0, 18.0, t.c.drop_shadow)
        .child(texture_overlay(app.textures.dial_dither(dark)))
        .child(inner)
}

fn bar_cap_segment(
    height: f32,
    top: Color,
    bottom: Color,
    cap: Color,
    texture: Option<&Image>,
) -> El {
    let mut seg = el()
        .w_full()
        .h(height)
        .radius(3.0)
        .clip_rounded(3.0)
        .gradient(top, bottom);
    if let Some(tex) = texture {
        seg = seg.child(texture_overlay(tex));
    }
    seg.child(
        el().pin(Some(0.0), Some(0.0), Some(0.0), None)
            .h(2.0)
            .fill(cap.alpha(0.88)),
    )
}

#[must_use]
pub fn velocity_sparkline(bars: &[(&str, u32, u32, u32)], app: &DesktopApp, t: &StudioTheme) -> El {
    let dark = is_dark_theme(t);
    let max_total = bars
        .iter()
        .map(|(_, a, b, c)| a.saturating_add(*b).saturating_add(*c))
        .max()
        .unwrap_or(1)
        .max(1) as f32;
    let total_allow: u32 = bars.iter().map(|(_, a, _, _)| *a).sum();
    let total_ask: u32 = bars.iter().map(|(_, _, b, _)| *b).sum();
    let total_block: u32 = bars.iter().map(|(_, _, _, c)| *c).sum();
    let total_all = total_allow
        .saturating_add(total_ask)
        .saturating_add(total_block);
    let avg_day = if bars.is_empty() {
        0
    } else {
        total_all / (bars.len() as u32)
    };

    let mut grid = Shape::new();
    grid.view_box = Some([880.0, 74.0]);
    for line_y in [14.0_f32, 36.0, 58.0] {
        let mut x = 0.0_f32;
        while x < 874.0 {
            grid = grid.line(
                [x, line_y],
                [(x + 6.0).min(880.0), line_y],
                1.0,
                LineCap::Butt,
                t.c.grid_line,
            );
            x += 13.0;
        }
    }

    let mut cols = row().w_full().h(94.0).gap(10.0).items_end();
    for &(day, allowed, ask, block) in bars {
        let day_total = allowed.saturating_add(ask).saturating_add(block);
        let h_allow = if allowed > 0 {
            ((allowed as f32 / max_total) * 52.0).max(5.0)
        } else {
            0.0
        };
        let h_ask = if ask > 0 {
            ((ask as f32 / max_total) * 52.0).max(6.0)
        } else {
            0.0
        };
        let h_block = if block > 0 {
            ((block as f32 / max_total) * 52.0).max(6.0)
        } else {
            0.0
        };

        let mut stack = col()
            .w(34.0)
            .h(72.0)
            .radius(7.0)
            .padding(2.5)
            .gap(1.5)
            .fill(t.c.inset_well)
            .border(1.0, t.c.border_subtle)
            .box_shadow(Shadow {
                x: 0.0,
                y: 1.0,
                blur: 3.0,
                spread: 0.0,
                color: Color::BLACK.alpha(0.18),
                inset: true,
            })
            .justify_end()
            .items_center();

        if h_block > 0.0 {
            stack = stack.child(bar_cap_segment(
                h_block,
                t.c.viz_block_start,
                t.c.viz_block_end,
                t.c.block,
                Some(&app.textures.stripe_bar_block),
            ));
        }
        if h_ask > 0.0 {
            stack = stack.child(bar_cap_segment(
                h_ask,
                t.c.viz_ask_start,
                t.c.viz_ask_end,
                t.c.ask,
                Some(&app.textures.stripe_bar_ask),
            ));
        }
        if h_allow > 0.0 {
            stack = stack.child(bar_cap_segment(
                h_allow,
                t.c.viz_allow_start,
                t.c.viz_allow_end,
                t.c.viz_allow_edge,
                None,
            ));
        }

        cols = cols.child(
            col().grow(1.0).gap(4.0).items_center().child(stack).child(
                text(format!("{day} · {day_total}"))
                    .font(t.caption)
                    .color(t.c.ink_muted),
            ),
        );
    }

    let plot = el()
        .w_full()
        .child(
            el().pin(Some(0.0), Some(0.0), Some(0.0), Some(22.0))
                .child(canvas(grid).w_full().h_full()),
        )
        .child(
            row()
                .pin(Some(0.0), Some(16.0), Some(2.0), None)
                .child(spacer())
                .child(
                    text(format!("avg {avg_day}"))
                        .font(t.caption)
                        .color(t.c.ink_muted),
                ),
        )
        .child(cols);

    let inner = col()
        .w_full()
        .padding(14.0)
        .gap(10.0)
        .child(
            row()
                .w_full()
                .center_y()
                .gap(8.0)
                .child(icon(&icons::ACTIVITY, 15.0).color(t.c.viz_allow_start))
                .child(
                    text(format!("7-day decision velocity ({total_all})"))
                        .font(t.body_strong)
                        .color(t.c.ink_primary),
                )
                .child(spacer())
                .child(status_pill_with_icon(
                    &format!("Allowed ({total_allow})"),
                    Some(&icons::CHECK_CIRCLE),
                    t.c.allow_bg,
                    t.c.allow,
                    t,
                ))
                .child(status_pill_with_icon(
                    &format!("Ask ({total_ask})"),
                    Some(&icons::HAND),
                    t.c.ask_bg,
                    t.c.ask,
                    t,
                ))
                .child(status_pill_with_icon(
                    &format!("Blocked ({total_block})"),
                    Some(&icons::BAN),
                    t.c.block_bg,
                    t.c.block,
                    t,
                )),
        )
        .child(plot);

    hardware_panel("velocity-panel", 14.0, app.textures.dither(dark), t, inner)
}

#[must_use]
pub fn flow_stage_node(
    glyph: &'static rune::Icon,
    title: &str,
    sub: &str,
    accent: Color,
    hatch: Option<&Image>,
    t: &StudioTheme,
) -> El {
    let inner = col()
        .w_full()
        .h_full()
        .padding(12.0)
        .gap(6.0)
        .child(
            row()
                .gap(8.0)
                .center_y()
                .child(el().size(6.0, 6.0).radius(3.0).fill(accent))
                .child(icon(glyph, 14.0).color(accent))
                .child(text(title).font(t.body_strong).color(t.c.ink_primary)),
        )
        .child(text(sub).font(t.caption).color(t.c.ink_secondary));

    let mut card = el()
        .grow(1.0)
        .h_full()
        .continuous_corners()
        .radius(10.0)
        .clip_rounded(10.0)
        .gradient(t.c.panel_top, t.c.panel_bottom)
        .border_gradient(1.0, t.c.rim_top, t.c.border_subtle)
        .shadow(3.0, 10.0, t.c.drop_shadow);

    if let Some(img) = hatch {
        card = card.child(texture_overlay(img));
    }
    card.child(inner)
}

#[must_use]
pub fn flow_connector(accent: Color, t: &StudioTheme) -> El {
    let conduit = Shape::new()
        .line([2.0, 10.0], [2.0, 10.0], 4.5, LineCap::Round, accent)
        .line(
            [4.0, 10.0],
            [18.0, 10.0],
            1.5,
            LineCap::Butt,
            t.c.border_strong,
        )
        .fill(vec![[16.0, 6.5], [23.0, 10.0], [16.0, 13.5]], accent);
    el().w(24.0)
        .h_full()
        .center()
        .child(canvas(conduit).size(24.0, 20.0))
}
