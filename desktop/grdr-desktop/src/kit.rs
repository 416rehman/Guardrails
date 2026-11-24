use grdr_strings::sanitize_untrusted_text;
use grdr_ui_model::{AppVm, Intent, ModeLevel, Screen, ThemeChoice, reduce};
use rune::{Color, El, TextStyle, Tx, col, el, icon, row, spacer, text};
use rune_kit::{Button, ButtonVariant, ControlSize, Divider, Progress, SegmentedControl, State};

use crate::icons;
use crate::theme::StudioTheme;

pub struct DesktopApp {
    pub vm: AppVm,
    pub last_notice: Option<String>,
}

impl DesktopApp {
    #[must_use]
    pub fn new(vm: AppVm) -> Self {
        Self {
            vm,
            last_notice: None,
        }
    }

    pub fn dispatch(&mut self, intent: Intent) {
        let effects = reduce(&mut self.vm, intent);
        for effect in effects {
            self.last_notice = Some(match effect {
                grdr_ui_model::Effect::ApplyLocalRuleMode { rule_id, mode } => {
                    format!("Applied {} mode cleanly to {rule_id}", mode.as_str())
                }
                grdr_ui_model::Effect::ProposeWidening {
                    rule_id,
                    target_mode,
                } => format!(
                    "Proposal queued for grdr-approve: widen {rule_id} -> {}",
                    target_mode.as_str()
                ),
                grdr_ui_model::Effect::LaunchApprove { request_id } => {
                    format!("Opening OS approval prompt for {request_id}")
                }
                grdr_ui_model::Effect::OpenWebConsole { route } => {
                    format!("Opening local console route /{route}")
                }
                grdr_ui_model::Effect::NotifyReadOnly { reason } => reason,
            });
        }
    }
}

#[must_use]
pub fn sidebar_rail(app: &DesktopApp, t: &StudioTheme) -> El {
    let nav_items: &[(Screen, &str, &str, &rune::Icon)] = &[
        (Screen::Home, "nav-home", "Home", &icons::HOME),
        (
            Screen::MyActivity,
            "nav-activity",
            "My activity",
            &icons::ACTIVITY,
        ),
        (Screen::Rules, "nav-rules", "Rules", &icons::SHIELD),
        (Screen::FirstRun, "nav-first-run", "Setup", &icons::LAYERS),
        (Screen::Privacy, "nav-privacy", "Privacy", &icons::EYE),
        (
            Screen::Settings,
            "nav-settings",
            "Settings",
            &icons::SLIDERS,
        ),
    ];

    let brand = row()
        .key("brand")
        .gap(10.0)
        .center_y()
        .padding(4.0)
        .child(
            el().size(32.0, 32.0)
                .radius(8.0)
                .fill(t.c.action_bg)
                .center()
                .child(icon(&icons::BRAND_MARK, 20.0).color(t.c.action_ink)),
        )
        .child(
            col()
                .gap(2.0)
                .child(
                    text("Guardrails ADR")
                        .font(t.body_strong)
                        .color(t.c.ink_primary),
                )
                .child(text("Desktop console").font(t.caption).color(t.c.ink_muted)),
        );

    let mut nav = col().key("nav-list").gap(4.0).w_full();
    for &(screen, key, label, glyph) in nav_items {
        let active = app.vm.screen == screen;
        let fill = if active {
            t.c.canvas
        } else {
            Color::TRANSPARENT
        };
        let border = if active {
            t.c.border_subtle
        } else {
            Color::TRANSPARENT
        };
        let ink = if active {
            t.c.ink_primary
        } else {
            t.c.ink_secondary
        };
        let icon_color = if active { t.c.accent } else { t.c.ink_muted };
        let label_font = if active { t.body_strong } else { t.body };

        let mut item = row()
            .key(key)
            .role("button")
            .label(label)
            .focusable(true)
            .w_full()
            .h(38.0)
            .px(12.0)
            .radius(8.0)
            .fill(fill)
            .border(1.0, border)
            .center_y()
            .gap(10.0)
            .child(icon(glyph, 15.0).color(icon_color))
            .child(text(label).font(label_font).color(ink))
            .on_press(move |s: &mut DesktopApp| {
                s.dispatch(Intent::Navigate(screen));
            });

        if screen == Screen::Home && !app.vm.home.pending_approvals.is_empty() {
            item = item.child(spacer()).child(status_pill(
                &app.vm.home.pending_approvals.len().to_string(),
                t.c.ask_bg,
                t.c.ask,
                t,
            ));
        }
        nav = nav.child(item);
    }

    let (toggle_label, toggle_icon) = match app.vm.preferences.theme {
        ThemeChoice::Light => ("Dark mode", &icons::MOON),
        ThemeChoice::Dark => ("Light mode", &icons::SUN),
    };

    col()
        .key("sidebar-rail")
        .w(232.0)
        .h_full()
        .fill(t.c.rail)
        .pt(20.0)
        .pb(20.0)
        .pl(16.0)
        .pr(16.0)
        .gap(20.0)
        .border(1.0, t.c.border_subtle)
        .child(brand)
        .child(nav)
        .child(spacer())
        .child(Divider::horizontal().build(&t.kit))
        .child(
            col()
                .gap(8.0)
                .child(
                    row()
                        .gap(8.0)
                        .center_y()
                        .child(icon(&icons::SHIELD_CHECK, 14.0).color(t.c.allow))
                        .child(
                            text(app.vm.tray_vm().status_label)
                                .font(t.caption)
                                .color(t.c.ink_secondary),
                        ),
                )
                .child(
                    Button::new(toggle_label)
                        .icon(toggle_icon)
                        .variant(ButtonVariant::Ghost)
                        .control_size(ControlSize::Regular)
                        .on_press(|s: &mut DesktopApp| s.dispatch(Intent::ToggleTheme))
                        .build(&t.kit)
                        .key("toggle-theme"),
                ),
        )
}

#[must_use]
pub fn primary_button(
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
        .h(34.0)
        .px(14.0)
        .radius(8.0)
        .fill(t.c.action_bg)
        .center()
        .gap(8.0)
        .child(text(label).font(t.body_strong).color(t.c.action_ink))
        .child(icon(&icons::ARROW_RIGHT, 13.0).color(t.c.action_ink))
        .on_press(on_press)
}

#[must_use]
pub fn status_pill(label: &str, bg: Color, fg: Color, t: &StudioTheme) -> El {
    status_pill_with_icon(label, None, bg, fg, t)
}

#[must_use]
pub fn status_pill_with_icon(
    label: &str,
    glyph: Option<&'static rune::Icon>,
    bg: Color,
    fg: Color,
    t: &StudioTheme,
) -> El {
    let font = TextStyle {
        size: 11.5,
        weight: 600.0,
        line_height: 14.0,
        ..t.kit.ty.small_medium
    };
    let mut r = row()
        .role("status")
        .label(label)
        .h(22.0)
        .px(8.0)
        .radius(4.0)
        .fill(bg)
        .center()
        .gap(5.0);
    if let Some(g) = glyph {
        r = r.child(icon(g, 11.5).color(fg));
    }
    r.child(text(label).font(font).color(fg))
}

#[must_use]
pub fn assurance_pill(level: &str, boundary: bool, t: &StudioTheme) -> El {
    let (bg, fg) = if boundary {
        (t.c.accent_soft, t.c.accent)
    } else {
        (t.c.recessed, t.c.ink_secondary)
    };
    status_pill_with_icon(level, Some(icons::for_assurance(level)), bg, fg, t)
}

#[must_use]
pub fn mode_pill(mode: ModeLevel, t: &StudioTheme) -> El {
    let (bg, fg) = match mode {
        ModeLevel::Off => (t.c.recessed, t.c.ink_muted),
        ModeLevel::Watch => (t.c.watch_bg, t.c.watch),
        ModeLevel::Ask => (t.c.ask_bg, t.c.ask),
        ModeLevel::Block => (t.c.block_bg, t.c.block),
    };
    status_pill_with_icon(mode.as_str(), Some(icons::for_mode(mode)), bg, fg, t)
}

#[must_use]
pub fn coverage_visual(pct: u8, boundary_count: usize, total: usize, t: &StudioTheme) -> El {
    let ring_pct = (f32::from(pct.min(100))) / 100.0;
    let fill_w = (156.0 * ring_pct).max(4.0);
    let accent = if pct >= 80 { t.c.allow } else { t.c.accent };

    col()
        .w(212.0)
        .padding(18.0)
        .radius(12.0)
        .fill(t.c.recessed)
        .border(1.0, t.c.border_subtle)
        .gap(10.0)
        .child(
            row()
                .w_full()
                .center_y()
                .gap(8.0)
                .child(icon(&icons::SHIELD_CHECK, 16.0).color(accent))
                .child(
                    text("Boundary gauge")
                        .font(t.caption)
                        .color(t.c.ink_secondary),
                ),
        )
        .child(
            text(format!("{pct}%"))
                .font(t.display_headline)
                .color(t.c.ink_primary),
        )
        .child(
            el().w(156.0)
                .h(8.0)
                .radius(4.0)
                .fill(t.c.border_strong)
                .child(el().w(fill_w).h(8.0).radius(4.0).fill(accent)),
        )
        .child(
            text(format!("{boundary_count} of {total} agents contained"))
                .font(t.caption)
                .color(t.c.ink_muted),
        )
}

#[must_use]
pub fn velocity_sparkline(bars: &[(&str, u32, u32, u32)], t: &StudioTheme) -> El {
    let max_total = bars
        .iter()
        .map(|(_, a, b, c)| a.saturating_add(*b).saturating_add(*c))
        .max()
        .unwrap_or(1)
        .max(1) as f32;

    let mut cols = row().w_full().h(84.0).gap(10.0).items_end();
    for &(day, allowed, ask, block) in bars {
        let total = allowed.saturating_add(ask).saturating_add(block) as f32;
        let h_allow = ((allowed as f32 / max_total) * 52.0).max(4.0);
        let h_ask = if ask > 0 {
            ((ask as f32 / max_total) * 52.0).max(5.0)
        } else {
            0.0
        };
        let h_block = if block > 0 {
            ((block as f32 / max_total) * 52.0).max(5.0)
        } else {
            0.0
        };

        let mut stack = col().w(18.0).gap(2.0).items_center();
        if h_block > 0.0 {
            stack = stack.child(el().w(14.0).h(h_block).radius(3.0).fill(t.c.block));
        }
        if h_ask > 0.0 {
            stack = stack.child(el().w(14.0).h(h_ask).radius(3.0).fill(t.c.ask));
        }
        if total > 0.0 {
            stack = stack.child(el().w(14.0).h(h_allow).radius(3.0).fill(t.c.border_strong));
        }

        cols = cols.child(
            col()
                .grow(1.0)
                .gap(6.0)
                .items_center()
                .child(stack)
                .child(text(day).font(t.caption).color(t.c.ink_muted)),
        );
    }

    col()
        .w_full()
        .padding(16.0)
        .radius(12.0)
        .fill(t.c.recessed)
        .border(1.0, t.c.border_subtle)
        .gap(12.0)
        .child(
            row()
                .w_full()
                .center_y()
                .gap(8.0)
                .child(icon(&icons::ACTIVITY, 15.0).color(t.c.accent))
                .child(
                    text("7-day decision velocity")
                        .font(t.body_strong)
                        .color(t.c.ink_primary),
                )
                .child(spacer())
                .child(status_pill("Allowed", t.c.canvas, t.c.ink_secondary, t))
                .child(status_pill("Ask", t.c.ask_bg, t.c.ask, t))
                .child(status_pill("Block", t.c.block_bg, t.c.block, t)),
        )
        .child(cols)
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
        .padding(12.0)
        .radius(10.0)
        .fill(t.c.recessed)
        .border(1.0, t.c.border_subtle)
        .gap(6.0)
        .child(
            row()
                .gap(8.0)
                .center_y()
                .child(icon(glyph, 15.0).color(accent))
                .child(text(title).font(t.body_strong).color(t.c.ink_primary)),
        )
        .child(text(sub).font(t.caption).color(t.c.ink_secondary))
}

#[must_use]
pub fn quoted_chip(raw: &str, t: &StudioTheme) -> El {
    let safe = sanitize_untrusted_text(raw);
    row()
        .px(8.0)
        .pt(4.0)
        .pb(4.0)
        .radius(4.0)
        .fill(t.c.recessed)
        .border(1.0, t.c.border_subtle)
        .child(text(safe).font(t.mono).color(t.c.ink_primary))
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
    let mut strip = row().w_full().pt(20.0).pb(8.0).gap(20.0).items_stretch();

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
