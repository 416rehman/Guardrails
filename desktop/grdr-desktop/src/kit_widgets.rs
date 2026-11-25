use grdr_strings::sanitize_untrusted_text;
use grdr_ui_model::{Intent, ModeLevel};
use rune::{Cursor, El, Shadow, Tx, col, el, row, spacer, text};
use rune_kit::{Divider, Progress, SegmentedControl, State};

use crate::kit::{ChipSurface, DesktopApp};
use crate::theme::StudioTheme;

#[must_use]
pub fn secondary_button(
    key: &'static str,
    label: &str,
    t: &StudioTheme,
    on_press: impl Fn(&mut DesktopApp) + 'static,
) -> El {
    row()
        .key(key)
        .role("button")
        .label(label)
        .focusable(true)
        .cursor(Cursor::Pointer)
        .continuous_corners()
        .h(34.0)
        .px(12.0)
        .radius(8.0)
        .fill(t.c.recessed)
        .border(1.0, t.c.border_strong)
        .hover(t.c.hover)
        .press_scale(0.97)
        .focus_ring(2.0, 2.0, t.c.accent)
        .center()
        .child(text(label).font(t.body_strong).color(t.c.ink_primary))
        .on_press(on_press)
}

#[must_use]
pub fn quoted_chip(raw: &str, surface: ChipSurface, t: &StudioTheme) -> El {
    let safe = sanitize_untrusted_text(raw);
    let (fill, border) = match surface {
        ChipSurface::OnCanvas => (t.c.recessed, t.c.border_subtle),
        ChipSurface::OnRecessed => (t.c.canvas, t.c.border_strong),
    };
    row()
        .px(8.0)
        .pt(4.0)
        .pb(4.0)
        .radius(5.0)
        .fill(fill)
        .border(1.0, border)
        .box_shadow(Shadow {
            x: 0.0,
            y: 1.0,
            blur: 2.0,
            spread: 0.0,
            color: t.c.inset_well,
            inset: true,
        })
        .child(text(safe).font(t.mono).color(t.c.ink_primary).wrap())
}

#[must_use]
pub fn quoted_box(raw: &str, surface: ChipSurface, t: &StudioTheme) -> El {
    let safe = sanitize_untrusted_text(raw);
    let (fill, border) = match surface {
        ChipSurface::OnCanvas => (t.c.recessed, t.c.border_subtle),
        ChipSurface::OnRecessed => (t.c.canvas, t.c.border_strong),
    };
    col()
        .w_full()
        .px(10.0)
        .pt(6.0)
        .pb(6.0)
        .radius(6.0)
        .fill(fill)
        .border(1.0, border)
        .box_shadow(Shadow {
            x: 0.0,
            y: 1.0,
            blur: 2.0,
            spread: 0.0,
            color: t.c.inset_well,
            inset: true,
        })
        .child(text(safe).font(t.mono).color(t.c.ink_primary).wrap().w_full())
}

#[must_use]
pub fn ledger_header(title: &str, right_meta: &str, t: &StudioTheme) -> El {
    col()
        .w_full()
        .gap(8.0)
        .child(
            row()
                .w_full()
                .center_y()
                .child(text(title).font(t.section_title).color(t.c.ink_primary))
                .child(spacer())
                .child(text(right_meta).font(t.caption).color(t.c.ink_secondary)),
        )
        .child(Divider::horizontal().build(&t.kit))
}

#[must_use]
pub fn metric_strip(metrics: &[(&str, &str, &str)], t: &StudioTheme) -> El {
    let mut strip = row().w_full().pt(12.0).pb(4.0).gap(20.0).items_stretch();

    for (idx, &(value, label, note)) in metrics.iter().enumerate() {
        if idx > 0 {
            strip = strip.child(el().w(1.0).h(52.0).fill(t.c.border_subtle));
        }
        strip = strip.child(
            col()
                .grow(1.0)
                .gap(2.0)
                .child(text(value).font(t.metric_num).color(t.c.ink_primary))
                .child(text(label).font(t.caption).color(t.c.ink_secondary))
                .child(text(note).font(t.caption).color(t.c.ink_muted)),
        );
    }
    strip
}

#[must_use]
pub fn mode_segmented(rule_id: String, current: ModeLevel, locked: bool, t: &StudioTheme) -> El {
    let selected = Some(current as usize);
    let mut control = SegmentedControl::new(&["Off", "Watch", "Ask", "Block"], selected)
        .label(format!("Enforcement mode for {rule_id}"))
        .fit()
        .on_pick(move |s: &mut DesktopApp, idx: usize, _: &mut Tx| {
            let next_mode = match idx {
                0 => ModeLevel::Off,
                1 => ModeLevel::Watch,
                2 => ModeLevel::Ask,
                _ => ModeLevel::Block,
            };
            s.dispatch(Intent::SetRuleMode {
                rule_id: rule_id.clone(),
                next_mode,
            });
        });

    if locked {
        for idx in 0..3 {
            if idx != current as usize {
                control = control.segment_state(idx, State::Disabled);
            }
        }
    }
    control.build(&t.kit)
}

#[must_use]
pub fn setup_progress(done: usize, total: usize, t: &StudioTheme) -> El {
    let pct = if total == 0 {
        0.0
    } else {
        (done as f32) / (total as f32)
    };
    Progress::new(Some(pct))
        .label(format!("{done} of {total} setup steps complete"))
        .show_value()
        .build(&t.kit)
}
