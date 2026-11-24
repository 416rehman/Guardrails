use grdr_ui_model::Intent;
use rune::{El, col, row, spacer, text};
use rune_kit::{Card, glyphs};

use crate::kit::{DesktopApp, ledger_header, primary_button, quoted_chip, status_pill};
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
        let verdict_pill = if sess.blocked_count > 0 {
            status_pill(
                &format!("{} blocked", sess.blocked_count),
                t.c.block_bg,
                t.c.block,
                t,
            )
        } else {
            status_pill(
                &format!("{} waiting", sess.ask_count),
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
                .center_y()
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

    let mut card_section = col().w_full().gap(10.0);
    if let Some(sess) = rows.first()
        && let Some(card) = &sess.block_card
    {
        let card_el = Card::new()
            .accent(t.c.block)
            .title(&card.heading, Some(&glyphs::LOCK))
            .description(format!("Rule {} (pack {})", card.rule_id, card.pack_id))
            .child(quoted_chip(&card.target_quoted, t))
            .child(
                text(&card.agent_told)
                    .font(t.caption)
                    .color(t.c.ink_secondary)
                    .wrap()
                    .w_full(),
            )
            .action(primary_button(
                "block-card-action",
                &card.primary_action_label,
                t,
                |s| {
                    s.dispatch(Intent::OpenWebConsole {
                        route: "sessions".to_owned(),
                    });
                },
            ))
            .build(&t.kit);

        card_section = card_section
            .child(ledger_header("Latest block card", &card.rule_id, t))
            .child(card_el);
    }

    col()
        .key("screen-activity")
        .w_full()
        .gap(24.0)
        .child(text("My activity").font(t.display_headline).color(t.c.ink_primary))
        .child(
            text("Session history capped at 500 mounted rows per list with full local receipt inspection.")
                .font(t.body)
                .color(t.c.ink_secondary),
        )
        .child(sessions_col)
        .child(card_section)
}
