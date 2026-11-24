use grdr_strings::sanitize_untrusted_text;
use grdr_ui_model::{AppVm, Intent, ModeLevel, Screen, ThemeChoice, reduce};
use rune::{Color, El, TextStyle, Tx, col, el, icon, row, spacer, text};
use rune_kit::{
    Badge, BadgeVariant, Button, ButtonVariant, ControlSize, Divider, Progress, SegmentedControl,
    State, glyphs,
};

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
    let nav_items: &[(Screen, &str, &str)] = &[
        (Screen::Home, "nav-home", "Home"),
        (Screen::MyActivity, "nav-activity", "My activity"),
        (Screen::Rules, "nav-rules", "Rules"),
        (Screen::FirstRun, "nav-first-run", "Setup"),
        (Screen::Privacy, "nav-privacy", "Privacy"),
        (Screen::Settings, "nav-settings", "Settings"),
    ];

    let brand = row()
        .key("brand")
        .gap(10.0)
        .center_y()
        .padding(4.0)
        .child(
            el().size(30.0, 30.0)
                .radius(8.0)
                .fill(t.c.action_bg)
                .center()
                .child(icon(&glyphs::LOCK, 15.0).color(t.c.action_ink)),
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
    for &(screen, key, label) in nav_items {
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

    let toggle_label = match app.vm.preferences.theme {
        ThemeChoice::Light => "Dark mode",
        ThemeChoice::Dark => "Light mode",
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
                    text(app.vm.tray_vm().status_label)
                        .font(t.caption)
                        .color(t.c.ink_secondary),
                )
                .child(
                    Button::new(toggle_label)
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
        .px(16.0)
        .radius(8.0)
        .fill(t.c.action_bg)
        .center()
        .child(text(label).font(t.body_strong).color(t.c.action_ink))
        .on_press(on_press)
}

#[must_use]
pub fn status_pill(label: &str, bg: Color, fg: Color, t: &StudioTheme) -> El {
    let font = TextStyle {
        size: 11.5,
        weight: 600.0,
        line_height: 14.0,
        ..t.kit.ty.small_medium
    };
    row()
        .role("status")
        .label(label)
        .h(22.0)
        .px(8.0)
        .radius(4.0)
        .fill(bg)
        .center()
        .child(text(label).font(font).color(fg))
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

#[must_use]
pub fn info_badge(label: &str, variant: BadgeVariant, t: &StudioTheme) -> El {
    Badge::new(label).variant(variant).standard().build(&t.kit)
}
