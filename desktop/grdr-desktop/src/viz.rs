use rune::{
    Color, El, LineCap, Shadow, Shape, TextStyle, canvas, col, el, icon, row, spacer, text,
};

use crate::icons;
use crate::kit::legend_dot;
use crate::theme::StudioTheme;

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
pub fn elevated_card(key: &str, radius: f32, t: &StudioTheme, body: El) -> El {
    el().key(key)
        .continuous_corners()
        .radius(radius)
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
        .shadow(3.0, 12.0, t.c.drop_shadow)
        .child(body)
}

#[must_use]
pub fn attention_card(key: &str, radius: f32, t: &StudioTheme, body: El) -> El {
    el().key(key)
        .continuous_corners()
        .radius(radius)
        .gradient(t.c.panel_top, t.c.panel_bottom)
        .linear_gradient(
            std::f32::consts::FRAC_PI_2,
            [
                (0.0, t.c.attention_wash_start),
                (0.34, t.c.attention_wash_mid),
                (0.76, Color::TRANSPARENT),
            ],
        )
        .border(1.0, t.c.attention_border)
        .shadow(2.0, 10.0, t.c.drop_shadow)
        .child(body)
}

#[must_use]
pub fn coverage_visual(pct: u8, boundary_count: usize, total: usize, t: &StudioTheme) -> El {
    let clamped = f32::from(pct.min(100)) / 100.0;
    let accent = if pct >= 80 { t.c.allow } else { t.c.accent };

    let start_deg = -90.0_f32;
    let full_sweep = 360.0_f32;
    let cx = 56.0_f32;
    let cy = 50.0_f32;
    let radius = 38.0_f32;

    let mut dial = Shape::new().stroke_with(
        arc_points(cx, cy, radius, start_deg, full_sweep, 64),
        true,
        6.0,
        LineCap::Round,
        t.c.dial_track,
    );

    if clamped > 0.01 {
        let active_sweep = (full_sweep * clamped).max(8.0);
        dial = dial.stroke_with(
            arc_points(cx, cy, radius, start_deg, active_sweep, 48),
            false,
            6.0,
            LineCap::Round,
            accent,
        );
    }

    let pct_style = TextStyle {
        size: 22.0,
        weight: 600.0,
        line_height: 24.0,
        ..t.display_headline
    };

    let dial_stage = el()
        .size(112.0, 100.0)
        .center()
        .child(canvas(dial).size(112.0, 100.0))
        .child(
            col()
                .pin(Some(0.0), Some(32.0), Some(0.0), None)
                .items_center()
                .gap(2.0)
                .child(
                    text(format!("{pct}%"))
                        .font(pct_style)
                        .color(t.c.ink_primary),
                )
                .child(text("Boundary").font(t.caption).color(t.c.ink_muted)),
        );

    let inner = col()
        .w_full()
        .padding(16.0)
        .gap(6.0)
        .items_center()
        .child(dial_stage)
        .child(
            text(format!("{boundary_count} of {total} sandboxed"))
                .font(t.caption)
                .color(t.c.ink_secondary),
        );

    el().key("coverage-dial-card")
        .continuous_corners()
        .radius(16.0)
        .fill(t.c.panel_top.alpha(0.92))
        .border(1.0, t.c.border_subtle)
        .shadow(8.0, 26.0, t.c.drop_shadow)
        .w(212.0)
        .child(inner)
}

#[must_use]
pub fn velocity_sparkline(bars: &[(&str, u32, u32, u32)], t: &StudioTheme) -> El {
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

    let vb_w = 700.0_f32;
    let vb_h = 84.0_f32;
    let base_y = 78.0_f32;
    let scale_h = 62.0_f32;

    let overlay = Shape {
        view_box: Some([vb_w, vb_h]),
        ..Shape::new()
            .line([0.0, 20.0], [vb_w, 20.0], 1.0, LineCap::Butt, t.c.grid_line)
            .line([0.0, 49.0], [vb_w, 49.0], 1.0, LineCap::Butt, t.c.grid_line)
            .line(
                [0.0, base_y],
                [vb_w, base_y],
                1.0,
                LineCap::Butt,
                t.c.border_subtle,
            )
    };

    let mut cols = row().w_full().h(102.0).gap(10.0).items_end();
    for &(day, allowed, ask, block) in bars {
        let h_allow = if allowed > 0 {
            ((allowed as f32 / max_total) * scale_h).max(4.0)
        } else {
            0.0
        };
        let h_ask = if ask > 0 {
            ((ask as f32 / max_total) * scale_h).max(4.0)
        } else {
            0.0
        };
        let h_block = if block > 0 {
            ((block as f32 / max_total) * scale_h).max(4.0)
        } else {
            0.0
        };

        let mut stack = col().w(18.0).h(78.0).gap(1.0).justify_end().items_center();

        if h_block > 0.0 {
            stack = stack.child(
                el().w(16.0)
                    .h(h_block)
                    .radius(2.5)
                    .fill(t.c.viz_block_start),
            );
        }
        if h_ask > 0.0 {
            stack = stack.child(el().w(16.0).h(h_ask).radius(2.5).fill(t.c.viz_ask_start));
        }
        if h_allow > 0.0 {
            stack = stack.child(el().w(16.0).h(h_allow).radius(2.5).fill(t.c.viz_allow_end));
        }

        cols = cols.child(
            col().grow(1.0).gap(6.0).items_center().child(stack).child(
                text(day)
                    .font(t.caption)
                    .color(t.c.ink_muted),
            ),
        );
    }

    let plot = el()
        .w_full()
        .child(
            el().pin(Some(0.0), Some(0.0), Some(0.0), Some(20.0))
                .child(canvas(overlay).w_full().h_full()),
        )
        .child(cols);

    let inner = col()
        .w_full()
        .padding(16.0)
        .gap(12.0)
        .child(
            row()
                .w_full()
                .center_y()
                .gap(10.0)
                .child(icon(&icons::ACTIVITY, 14.0).color(t.c.ink_muted))
                .child(
                    text(format!("7-day decision velocity ({total_all})"))
                        .font(t.body_strong)
                        .color(t.c.ink_primary),
                )
                .child(
                    text(format!("avg {avg_day}/day"))
                        .font(t.caption)
                        .color(t.c.ink_muted),
                )
                .child(spacer())
                .child(legend_dot(
                    &format!("Allowed {total_allow}"),
                    t.c.viz_allow_end,
                    t,
                ))
                .child(legend_dot(
                    &format!("Ask {total_ask}"),
                    t.c.viz_ask_start,
                    t,
                ))
                .child(legend_dot(
                    &format!("Blocked {total_block}"),
                    t.c.viz_block_start,
                    t,
                )),
        )
        .child(plot);

    elevated_card("velocity-panel", 12.0, t, inner).w_full()
}

#[must_use]
pub fn flow_stage_node(
    glyph: &'static rune::Icon,
    title: &str,
    sub: &str,
    accent: Color,
    t: &StudioTheme,
) -> El {
    col()
        .grow(1.0)
        .h_full()
        .padding(14.0)
        .continuous_corners()
        .radius(10.0)
        .fill(t.c.canvas)
        .border(1.0, t.c.border_subtle)
        .gap(6.0)
        .child(
            row()
                .gap(8.0)
                .center_y()
                .child(icon(glyph, 14.0).color(accent))
                .child(text(title).font(t.body_strong).color(t.c.ink_primary)),
        )
        .child(text(sub).font(t.caption).color(t.c.ink_secondary))
}

#[must_use]
pub fn flow_connector(t: &StudioTheme) -> El {
    let conduit = Shape::new()
        .line(
            [2.0, 10.0],
            [17.0, 10.0],
            1.4,
            LineCap::Round,
            t.c.border_strong,
        )
        .fill(vec![[15.0, 6.5], [22.0, 10.0], [15.0, 13.5]], t.c.ink_muted);
    el().w(24.0)
        .h_full()
        .center()
        .child(canvas(conduit).size(24.0, 20.0))
}
