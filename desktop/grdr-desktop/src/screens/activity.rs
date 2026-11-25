use grdr_ui_model::{Intent, Screen};
use rune::{El, col, el, icon, row, spacer, text};

use crate::icons;
use crate::kit::{
    ChipSurface, DesktopApp, agent_glyph, entity_link, ledger_header, primary_button, quoted_box,
    quoted_chip, secondary_button, status_pill, status_pill_with_icon,
};
use crate::theme::StudioTheme;
use crate::viz::{attention_card, elevated_card};

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
                .pt(8.0)
                .pb(8.0)
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
    if let Some(ref_code) = &vm.inspected_receipt_ref {
        card_section = card_section
            .child(ledger_header("Why explanation", ref_code, t))
            .child(super::why_card::render_why_panel(ref_code, vm, selected_session, t));
    } else if let Some(sess) = selected_session {
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
                    text(&card.reason)
                        .font(t.body)
                        .color(t.c.ink_primary)
                        .wrap()
                        .w_full(),
                )
                .child(
                    col()
                        .w_full()
                        .gap(4.0)
                        .child(
                            text("What the agent was told (max 600 chars)")
                                .font(t.caption)
                                .color(t.c.ink_secondary),
                        )
                        .child(quoted_box(&card.agent_told, ChipSurface::OnCanvas, t)),
                )
                .child(
                    row()
                        .w_full()
                        .center_y()
                        .gap(8.0)
                        .child(
                            text(format!("{} · Pack {}", card.component, card.pack_id))
                                .font(t.caption)
                                .color(t.c.ink_muted),
                        )
                        .child(spacer())
                        .child(if vm.inspected_receipt_ref.is_some() {
                            secondary_button("why-close-btn", "Close Why", t, |s| {
                                s.dispatch(Intent::DismissWhyCard);
                            })
                        } else {
                            secondary_button("why-open-btn", "Why?", t, |s| {
                                s.dispatch(Intent::InspectReceipt {
                                    reference: "8F2KQ-M41TZW".to_owned(),
                                });
                            })
                        })
                        .child(primary_button(
                            "block-card-action",
                            &card.primary_action_label,
                            t,
                            |s| {
                                s.dispatch(Intent::OpenWebConsole {
                                    route: "sessions".to_owned(),
                                });
                            },
                        )),
                );

            let card_el = attention_card("act-block-card", 12.0, t, card_body).w_full();

            card_section = card_section
                .child(ledger_header("Latest blocked action", "", t))
                .child(card_el);
        } else {
            let detail_body = col()
                .w_full()
                .padding(16.0)
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
                .child(elevated_card("act-detail-card", 12.0, t, detail_body).w_full());
        }
    }

    let open_clusters = vm.review_clusters.iter().filter(|c| !c.decided).count();
    let mut review_col = col().w_full().gap(8.0).child(ledger_header(
        "Review queue clusters",
        &format!("{open_clusters} open"),
        t,
    ));
    for cluster in &vm.review_clusters {
        let cluster_id = cluster.id.clone();
        let why_ref = cluster.receipt_ref.clone();
        let (pill_bg, pill_fg) = if cluster.bucket_label == "Worth a look" {
            (t.c.ask_bg, t.c.ask)
        } else {
            (t.c.recessed, t.c.ink_secondary)
        };
        review_col = review_col.child(
            row()
                .w_full()
                .pt(8.0)
                .pb(8.0)
                .px(12.0)
                .radius(8.0)
                .fill(t.c.canvas)
                .border(1.0, t.c.border_subtle)
                .center_y()
                .gap(10.0)
                .child(status_pill(&cluster.bucket_label, pill_bg, pill_fg, t))
                .child(
                    col()
                        .grow(1.0)
                        .gap(3.0)
                        .child(
                            text(&cluster.rule_title)
                                .font(t.body_strong)
                                .color(t.c.ink_primary),
                        )
                        .child(
                            row()
                                .gap(6.0)
                                .center_y()
                                .child(quoted_chip(&cluster.target_preview, ChipSurface::OnCanvas, t))
                                .child(
                                    text(if cluster.occurrence_count == 1 {
                                        "1 hit".to_owned()
                                    } else {
                                        format!("{} hits", cluster.occurrence_count)
                                    })
                                    .font(t.caption)
                                    .color(t.c.ink_secondary),
                                ),
                        ),
                )
                .child(secondary_button("cluster-why-btn", "Why?", t, move |s| {
                    s.dispatch(Intent::InspectReceipt {
                        reference: why_ref.clone(),
                    });
                }))
                .child(if cluster.decided {
                    status_pill("Triaged", t.c.allow_bg, t.c.allow, t)
                } else {
                    secondary_button("cluster-suppress-btn", "Suppress", t, move |s| {
                        s.dispatch(Intent::TriageReviewCluster {
                            cluster_id: cluster_id.clone(),
                            action: "suppress".to_owned(),
                        });
                    })
                }),
        );
    }

    col()
        .key("screen-activity")
        .w_full()
        .gap(14.0)
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
        .child(review_col)
}
