use grdr_ui_model::{Intent, Screen};
use rune::{Color, El, Shadow, col, el, icon, row, spacer, text};

use crate::icons;
use crate::kit::{
    ChipSurface, DesktopApp, agent_glyph, entity_link, ledger_header, primary_button, quoted_chip,
    status_pill_with_icon,
};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let vm = &app.vm.activity;
    let rows = vm.sessions.current_page();

    let mut sessions_col = col().w_full().gap(6.0).child(ledger_header(
        "Recorded sessions",
        &format!("{} active", rows.len()),
        t,
    ));

    for sess in &rows {
        let sess_id = sess.id.clone();
        let selected = vm.selected_session_id.as_deref() == Some(sess.id.as_str());
        let bg = if selected {
            t.c.accent_soft
        } else {
            t.c.canvas
        };
        let glyph = agent_glyph(&sess.agent_name);
        let verdict_pill = if sess.blocked_count > 0 {
            status_pill_with_icon(
                &format!("{} blocked", sess.blocked_count),
                Some(&icons::BAN),
                t.c.block_bg,
                t.c.block,
                t,
            )
        } else {
            status_pill_with_icon(
                &format!("{} waiting", sess.ask_count),
                Some(&icons::HAND),
                t.c.ask_bg,
                t.c.ask,
                t,
            )
        };

        sessions_col = sessions_col.child(
            row()
                .key(sess.id.as_str())
                .w_full()
                .pt(10.0)
                .pb(10.0)
                .px(12.0)
                .radius(8.0)
                .fill(bg)
                .border(1.0, t.c.border_subtle)
                .center_y()
                .gap(12.0)
                .child(
                    el().size(28.0, 28.0)
                        .radius(6.0)
                        .fill(t.c.recessed)
                        .center()
                        .child(icon(glyph, 14.0).color(t.c.ink_primary)),
                )
                .child(
                    col()
                        .gap(2.0)
                        .child(
                            text(&sess.agent_name)
                                .font(t.body_strong)
                                .color(t.c.ink_primary),
                        )
                        .child(
                            text(&sess.verdict_summary)
                                .font(t.caption)
                                .color(t.c.ink_secondary),
                        ),
                )
                .child(spacer())
                .child(verdict_pill)
                .on_press(move |s: &mut DesktopApp| {
                    s.dispatch(Intent::SelectSession(sess_id.clone()));
                }),
        );
    }

    let selected_session = rows
        .iter()
        .find(|sess| vm.selected_session_id.as_deref() == Some(sess.id.as_str()))
        .or_else(|| rows.first());

    let mut card_section = col().w_full().gap(10.0);
    if let Some(sess) = selected_session {
        if let Some(card) = &sess.block_card {
            let card_body = col()
                .w_full()
                .padding(16.0)
                .gap(10.0)
                .child(
                    row()
                        .w_full()
                        .center_y()
                        .gap(8.0)
                        .child(icon(&icons::SHIELD_ALERT, 16.0).color(t.c.block))
                        .child(
                            text(&card.heading)
                                .font(t.body_strong)
                                .color(t.c.ink_primary),
                        )
                        .child(spacer())
                        .child(status_pill_with_icon(
                            "Signed receipt",
                            Some(&icons::KEY),
                            t.c.allow_bg,
                            t.c.allow,
                            t,
                        )),
                )
                .child(
                    row()
                        .gap(5.0)
                        .center_y()
                        .child(entity_link(
                            "act-card-agent",
                            agent_glyph(&sess.agent_name),
                            &sess.agent_name,
                            t,
                            |s| s.dispatch(Intent::Navigate(Screen::Home)),
                        ))
                        .child(text("on").font(t.caption).color(t.c.ink_muted))
                        .child(entity_link(
                            "act-card-device",
                            &icons::HARD_DRIVE,
                            &sess.device_name,
                            t,
                            |s| s.dispatch(Intent::Navigate(Screen::Settings)),
                        ))
                        .child(text("·").font(t.caption).color(t.c.ink_muted))
                        .child(entity_link(
                            "act-card-rule",
                            &icons::SHIELD_CHECK,
                            &card.rule_id,
                            t,
                            |s| s.dispatch(Intent::Navigate(Screen::Rules)),
                        )),
                )
                .child(quoted_chip(&card.target_quoted, ChipSurface::OnRecessed, t))
                .child(
                    text("Blocked by baseline protection to keep agent hooks and local configuration tamper-resistant.")
                        .font(t.caption)
                        .color(t.c.ink_secondary)
                        .wrap()
                        .w_full(),
                )
                .child(row().child(primary_button(
                    "block-card-action",
                    &card.primary_action_label,
                    t,
                    |s| {
                        s.dispatch(Intent::OpenWebConsole {
                            route: "sessions".to_owned(),
                        });
                    },
                )));

            let card_el = col()
                .w_full()
                .continuous_corners()
                .radius(12.0)
                .clip_rounded(12.0)
                .gradient(t.c.panel_top, t.c.panel_bottom)
                .radial_gradient(
                    [0.08, 0.25],
                    160.0,
                    [(0.0, t.c.block.alpha(0.10)), (1.0, Color::TRANSPARENT)],
                )
                .border_gradient(1.0, t.c.block.alpha(0.32), t.c.border_subtle)
                .box_shadow(Shadow {
                    x: 0.0,
                    y: 1.0,
                    blur: 0.0,
                    spread: 0.0,
                    color: t.c.specular_rim,
                    inset: true,
                })
                .shadow(5.0, 14.0, t.c.drop_shadow)
                .child(card_body);

            card_section = card_section
                .child(ledger_header("Latest blocked action", &sess.agent_name, t))
                .child(card_el);
        } else {
            let card_el = col()
                .w_full()
                .padding(16.0)
                .continuous_corners()
                .radius(12.0)
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
                .shadow(4.0, 12.0, t.c.drop_shadow)
                .gap(10.0)
                .child(
                    row()
                        .w_full()
                        .center_y()
                        .gap(8.0)
                        .child(icon(&icons::HAND, 16.0).color(t.c.ask))
                        .child(
                            text(format!("{} session active", sess.agent_name))
                                .font(t.body_strong)
                                .color(t.c.ink_primary),
                        ),
                )
                .child(
                    row()
                        .gap(5.0)
                        .center_y()
                        .child(entity_link(
                            "act-detail-agent",
                            agent_glyph(&sess.agent_name),
                            &sess.agent_name,
                            t,
                            |s| s.dispatch(Intent::Navigate(Screen::Home)),
                        ))
                        .child(text("on").font(t.caption).color(t.c.ink_muted))
                        .child(entity_link(
                            "act-detail-device",
                            &icons::HARD_DRIVE,
                            &sess.device_name,
                            t,
                            |s| s.dispatch(Intent::Navigate(Screen::Settings)),
                        ))
                        .child(text("·").font(t.caption).color(t.c.ink_muted))
                        .child(
                            text(format!("{} (0 blocked)", sess.verdict_summary))
                                .font(t.caption)
                                .color(t.c.ink_secondary),
                        ),
                )
                .child(row().child(primary_button(
                    "session-detail-action",
                    "Inspect session in web console",
                    t,
                    |s| {
                        s.dispatch(Intent::OpenWebConsole {
                            route: "sessions".to_owned(),
                        });
                    },
                )));

            card_section = card_section
                .child(ledger_header("Session details", &sess.agent_name, t))
                .child(card_el);
        }
    }

    col()
        .key("screen-activity")
        .w_full()
        .gap(24.0)
        .child(
            text("My activity")
                .font(t.display_headline)
                .color(t.c.ink_primary),
        )
        .child(
            text("Recent agent sessions on this device and local enforcement receipts.")
                .font(t.body)
                .color(t.c.ink_secondary),
        )
        .child(sessions_col)
        .child(card_section)
}
