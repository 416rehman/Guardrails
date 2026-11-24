use grdr_strings::sanitize_untrusted_text;
use grdr_ui_model::{AppVm, Intent, ModeLevel, Screen, ThemeChoice, reduce};
use rune::{Color, Cursor, El, Shadow, Span, TextStyle, Tx, col, el, icon, row, spacer, text};
use rune_kit::{
    Button, ButtonVariant, ControlSize, Divider, IconButton, IconButtonVariant, Progress,
    SegmentedControl, State,
};

use crate::icons;
use crate::theme::StudioTheme;
use crate::viz::DesktopTextures;

const BRAND_MARK_PNG: &[u8] = include_bytes!("../assets/guardrails-mark.png");

pub struct DesktopApp {
    pub vm: AppVm,
    pub last_notice: Option<String>,
    pub brand_mark: rune::Image,
    pub textures: DesktopTextures,
    pub sidebar_collapsed: bool,
}

impl DesktopApp {
    #[must_use]
    pub fn new(vm: AppVm) -> Self {
        let cache = rune::ImageCache::new(std::sync::Arc::new(|| {}));
        let brand_mark = cache.load(BRAND_MARK_PNG);
        let _ = brand_mark.wait();
        let textures = DesktopTextures::new(&cache);
        Self {
            vm,
            last_notice: None,
            brand_mark,
            textures,
            sidebar_collapsed: false,
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
                    "Approval request queued: widen {rule_id} -> {}",
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

    let collapsed = app.sidebar_collapsed;
    let collapse_icon = if collapsed {
        &icons::PANEL_OPEN
    } else {
        &icons::PANEL_CLOSE
    };
    let collapse_label = if collapsed {
        "Expand navigation"
    } else {
        "Collapse navigation"
    };
    let collapse_btn = IconButton::new(collapse_icon)
        .variant(IconButtonVariant::GhostMuted)
        .control_size(ControlSize::Regular)
        .label(collapse_label)
        .help(collapse_label)
        .on_press(|s: &mut DesktopApp| {
            s.sidebar_collapsed = !s.sidebar_collapsed;
        })
        .build(&t.kit)
        .key("toggle-sidebar");

    let logo_tile = el()
        .size(34.0, 34.0)
        .radius(8.0)
        .fill(t.c.brand_tile)
        .border(1.0, t.c.border_strong)
        .padding(2.0)
        .child(
            el().w_full()
                .h_full()
                .pixels_fit(app.brand_mark.pixels(), rune::SurfaceFit::Fit),
        );

    let brand = if collapsed {
        col()
            .key("brand")
            .gap(10.0)
            .items_center()
            .child(logo_tile)
            .child(collapse_btn)
    } else {
        row()
            .key("brand")
            .w_full()
            .gap(8.0)
            .center_y()
            .padding(2.0)
            .child(logo_tile)
            .child(
                col()
                    .gap(2.0)
                    .child(
                        text("Guardrails ADR")
                            .font(t.body_strong)
                            .color(t.c.ink_primary),
                    )
                    .child(text("Desktop console").font(t.caption).color(t.c.ink_muted)),
            )
            .child(spacer())
            .child(collapse_btn)
    };

    let mut nav = col().key("nav-list").gap(4.0).w_full();
    for &(screen, key, label, glyph) in nav_items {
        let active = app.vm.screen == screen;
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
            .cursor(Cursor::Pointer)
            .continuous_corners()
            .h(38.0)
            .radius(8.0)
            .hover_group()
            .hover(t.c.hover)
            .press_scale(0.98)
            .focus_ring(2.0, 2.0, t.c.accent)
            .on_press(move |s: &mut DesktopApp| {
                s.dispatch(Intent::Navigate(screen));
            });

        if active {
            item = item
                .gradient(t.c.panel_top, t.c.canvas)
                .border_gradient(1.0, t.c.rim_top, t.c.border_subtle)
                .box_shadow(Shadow {
                    x: 0.0,
                    y: 1.0,
                    blur: 0.0,
                    spread: 0.0,
                    color: t.c.specular_rim,
                    inset: true,
                })
                .shadow(2.0, 6.0, t.c.drop_shadow);
        } else {
            item = item
                .fill(Color::TRANSPARENT)
                .border(1.0, Color::TRANSPARENT);
        }

        if collapsed {
            item = item
                .size(40.0, 38.0)
                .center()
                .child(icon(glyph, 16.0).color(icon_color));
        } else {
            item = item
                .w_full()
                .px(12.0)
                .center_y()
                .gap(10.0)
                .child(
                    icon(glyph, 15.0)
                        .color(icon_color)
                        .group_color(t.c.ink_primary),
                )
                .child(
                    text(label)
                        .font(label_font)
                        .color(ink)
                        .group_color(t.c.ink_primary),
                );
            if screen == Screen::Home && !app.vm.home.pending_approvals.is_empty() {
                item = item.child(spacer()).child(status_pill(
                    &app.vm.home.pending_approvals.len().to_string(),
                    t.c.ask_bg,
                    t.c.ask,
                    t,
                ));
            } else if active {
                item = item
                    .child(spacer())
                    .child(el().size(5.0, 5.0).radius(3.0).fill(t.c.accent));
            }
        }
        nav = nav.child(item);
    }

    let (toggle_label, toggle_icon) = match app.vm.preferences.theme {
        ThemeChoice::Light => ("Dark mode", &icons::MOON),
        ThemeChoice::Dark => ("Light mode", &icons::SUN),
    };

    let rail_w = if collapsed { 68.0 } else { 244.0 };
    let pad_x = if collapsed { 14.0 } else { 16.0 };

    let mut rail = col()
        .key("sidebar-rail")
        .w(rail_w)
        .h_full()
        .gradient(t.c.rail_top, t.c.rail)
        .pt(20.0)
        .pb(20.0)
        .pl(pad_x)
        .pr(pad_x)
        .gap(20.0)
        .border(1.0, t.c.border_subtle)
        .child(brand)
        .child(nav)
        .child(spacer())
        .child(Divider::horizontal().build(&t.kit));

    let setup_confirmed = app
        .vm
        .first_run
        .steps
        .iter()
        .any(|s| s.id == "turn-on-protection" && s.done);
    let (status_glyph, status_color, status_text) = if setup_confirmed {
        (
            &icons::SHIELD_CHECK,
            t.c.allow,
            app.vm.tray_vm().status_label.to_owned(),
        )
    } else {
        (&icons::LAYERS, t.c.ask, "Setup in progress".to_owned())
    };

    if collapsed {
        rail = rail.child(
            IconButton::new(toggle_icon)
                .variant(IconButtonVariant::Ghost)
                .control_size(ControlSize::Regular)
                .label(toggle_label)
                .help(toggle_label)
                .on_press(|s: &mut DesktopApp| s.dispatch(Intent::ToggleTheme))
                .build(&t.kit)
                .key("toggle-theme"),
        );
    } else {
        rail = rail.child(
            col()
                .gap(8.0)
                .child(
                    row()
                        .gap(8.0)
                        .center_y()
                        .child(icon(status_glyph, 14.0).color(status_color))
                        .child(text(status_text).font(t.caption).color(t.c.ink_secondary)),
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
        );
    }
    rail
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
        .cursor(Cursor::Pointer)
        .continuous_corners()
        .h(34.0)
        .px(14.0)
        .radius(8.0)
        .fill(t.c.action_bg)
        .press_scale(0.97)
        .focus_ring(2.0, 2.0, t.c.accent)
        .shadow(2.0, 8.0, t.c.drop_shadow)
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
    let label = match level {
        "AL0" => "Observed",
        "AL1" => "App hook",
        "AL2" => "Tool proxy",
        "AL3" => "Sandboxed",
        "AL4" => "Enforced",
        other => other,
    };
    let (bg, fg) = if boundary {
        (t.c.allow_bg, t.c.allow)
    } else {
        (t.c.ask_bg, t.c.ask)
    };
    status_pill_with_icon(label, Some(icons::for_assurance(level)), bg, fg, t)
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

#[derive(Clone, Copy)]
pub enum ChipSurface {
    OnCanvas,
    OnRecessed,
}

#[must_use]
pub fn agent_glyph(name: &str) -> &'static rune::Icon {
    let lower = name.to_ascii_lowercase();
    if lower.contains("claude") || lower.contains("codex") || lower.contains("gemini") {
        &icons::TERMINAL
    } else {
        &icons::CPU
    }
}

#[must_use]
pub fn entity_link(
    key: &'static str,
    glyph: &'static rune::Icon,
    label: &str,
    t: &StudioTheme,
    on_press: impl Fn(&mut DesktopApp) + 'static,
) -> El {
    let link_style = TextStyle {
        size: 12.5,
        weight: 500.0,
        line_height: 17.0,
        ..t.body
    };
    let spans = vec![Span::new(0, label.len()).underline(t.c.border_strong)];
    row()
        .key(key)
        .role("link")
        .label(label)
        .focusable(true)
        .cursor(Cursor::Pointer)
        .pl(0.0)
        .pr(4.0)
        .py(1.0)
        .radius(4.0)
        .fill(Color::TRANSPARENT)
        .hover_group()
        .hover(t.c.accent_soft)
        .press(t.c.accent_soft)
        .press_scale(0.98)
        .focus_ring(2.0, 2.0, t.c.accent)
        .center_y()
        .gap(4.0)
        .child(
            icon(glyph, 11.5)
                .color(t.c.ink_muted)
                .group_color(t.c.accent),
        )
        .child(
            text(label)
                .font(link_style)
                .color(t.c.ink_primary)
                .group_color(t.c.accent)
                .spans(spans),
        )
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
