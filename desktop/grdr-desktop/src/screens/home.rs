use grdr_ui_model::{Intent, Screen};
use rune::{El, col, el, icon, row, spacer, text};

use crate::icons;
use crate::kit::{
    DesktopApp, assurance_pill, coverage_visual, ledger_header, metric_strip, primary_button,
    quoted_chip, status_pill, status_pill_with_icon, velocity_sparkline,
};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let vm = &app.vm.home;
    let boundary_count = vm
        .agents
        .iter()
        .filter(|a| a.control_mode == "Boundary")
        .count();
    let total_agents = vm.agents.len();
    let pending_str = vm.pending_approvals.len().to_string();
    let agents_str = total_agents.to_string();
    let rules_str = app.vm.rules.rules.len().to_string();

    let headline = if vm.pending_approvals.is_empty() {
        vm.summary_line.clone()
    } else {
        format!(
            "{} action waiting for your decision",
            vm.pending_approvals.len()
        )
    };

    let cta = if let Some(first_apr) = vm.pending_approvals.first() {
        let req_id = first_apr.id.clone();
        primary_button("hero-review-btn", "Review waiting action", t, move |s| {
            s.dispatch(Intent::OpenApproval {
                request_id: req_id.clone(),
            });
        })
    } else {
        primary_button("hero-review-btn", "Inspect rules", t, |s| {
            s.dispatch(Intent::Navigate(Screen::Rules));
        })
    };

    let hero_copy = col()
        .grow(1.0)
        .gap(12.0)
        .child(
            text(headline)
                .font(t.display_headline)
                .color(t.c.ink_primary),
        )
        .child(
            text(&vm.summary_line)
                .font(t.body)
                .color(t.c.ink_secondary)
                .wrap()
                .w_full(),
        )
        .child(row().pt(6.0).gap(12.0).child(cta));

    let hero = col()
        .w_full()
        .gap(16.0)
        .child(
            row()
                .w_full()
                .gap(24.0)
                .center_y()
                .child(hero_copy)
                .child(coverage_visual(
                    vm.boundary_pct,
                    boundary_count,
                    total_agents,
                    t,
                )),
        )
        .child(metric_strip(
            &[
                (&agents_str, "Agents on device", "Local discovery"),
                (&pending_str, "Waiting approvals", "Native OS prompt"),
                (&rules_str, "Policy rules", "Compiled locally"),
                ("169", "Calls this week", "156 allowed · 8 Ask"),
            ],
            t,
        ))
        .child(velocity_sparkline(
            &[
                ("Mon", 18, 1, 0),
                ("Tue", 24, 2, 1),
                ("Wed", 21, 0, 1),
                ("Thu", 32, 3, 2),
                ("Fri", 28, 1, 0),
                ("Sat", 14, 0, 0),
                ("Sun", 19, 1, 1),
            ],
            t,
        ));

    let mut approvals_col = col().w_full().gap(10.0).child(ledger_header(
        "Waiting on you",
        &format!("{} open", vm.pending_approvals.len()),
        t,
    ));

    if vm.pending_approvals.is_empty() {
        approvals_col = approvals_col.child(
            text("All active agent calls comply with current local rules.")
                .font(t.body)
                .color(t.c.ink_secondary),
        );
    } else {
        for apr in &vm.pending_approvals {
            let req_id = apr.id.clone();
            approvals_col = approvals_col.child(
                row()
                    .key(apr.id.as_str())
                    .w_full()
                    .pt(10.0)
                    .pb(10.0)
                    .center_y()
                    .gap(16.0)
                    .child(
                        col()
                            .grow(1.0)
                            .gap(6.0)
                            .child(
                                row()
                                    .gap(8.0)
                                    .center_y()
                                    .child(status_pill_with_icon(
                                        "ASK",
                                        Some(&icons::HAND),
                                        t.c.ask_bg,
                                        t.c.ask,
                                        t,
                                    ))
                                    .child(
                                        text(&apr.rule_title)
                                            .font(t.body_strong)
                                            .color(t.c.ink_primary),
                                    ),
                            )
                            .child(
                                text(format!(
                                    "{} on {} · Requires your approval ({})",
                                    apr.agent_name, apr.device_name, apr.approver_label,
                                ))
                                .font(t.caption)
                                .color(t.c.ink_secondary),
                            )
                            .child(quoted_chip(&apr.target_quoted, t)),
                    )
                    .child(primary_button("review-apr", "Review", t, move |s| {
                        s.dispatch(Intent::OpenApproval {
                            request_id: req_id.clone(),
                        });
                    })),
            );
        }
    }

    let mut agents_col = col().grow(1.0).gap(8.0).child(ledger_header(
        "Agents on this device",
        &format!("{} detected", vm.agents.len()),
        t,
    ));
    for agent in &vm.agents {
        let is_boundary = agent.control_mode == "Boundary";
        let agent_glyph = if agent.name.contains("Claude") {
            &icons::TERMINAL
        } else {
            &icons::CPU
        };
        agents_col = agents_col.child(
            row()
                .w_full()
                .pt(8.0)
                .pb(8.0)
                .center_y()
                .gap(10.0)
                .child(
                    el().size(28.0, 28.0)
                        .radius(6.0)
                        .fill(t.c.recessed)
                        .border(1.0, t.c.border_subtle)
                        .center()
                        .child(icon(agent_glyph, 14.0).color(t.c.ink_primary)),
                )
                .child(
                    col()
                        .gap(2.0)
                        .child(text(&agent.name).font(t.body_strong).color(t.c.ink_primary))
                        .child(
                            text(&agent.hook_health)
                                .font(t.caption)
                                .color(t.c.ink_secondary),
                        ),
                )
                .child(spacer())
                .child(assurance_pill(&agent.assurance_level, is_boundary, t)),
        );
    }

    let mut signals_col = col().grow(1.0).gap(8.0).child(ledger_header(
        "Status checks",
        &format!("{} active", vm.tiles.len()),
        t,
    ));
    for (idx, tile) in vm.tiles.iter().enumerate() {
        let tile_glyph = if idx == 0 {
            &icons::SHIELD_ALERT
        } else {
            &icons::ACTIVITY
        };
        let tile_color = if idx == 0 { t.c.ask } else { t.c.accent };
        signals_col = signals_col.child(
            row()
                .w_full()
                .pt(8.0)
                .pb(8.0)
                .center_y()
                .gap(10.0)
                .child(
                    el().size(28.0, 28.0)
                        .radius(6.0)
                        .fill(t.c.recessed)
                        .border(1.0, t.c.border_subtle)
                        .center()
                        .child(icon(tile_glyph, 14.0).color(tile_color)),
                )
                .child(
                    col()
                        .grow(1.0)
                        .gap(2.0)
                        .child(
                            text(&tile.headline)
                                .font(t.body_strong)
                                .color(t.c.ink_primary),
                        )
                        .child(
                            text(&tile.comparison)
                                .font(t.caption)
                                .color(t.c.ink_secondary),
                        ),
                )
                .child(status_pill(&tile.metric, t.c.recessed, t.c.ink_primary, t)),
        );
    }

    col()
        .key("screen-home")
        .w_full()
        .gap(24.0)
        .child(hero)
        .child(approvals_col)
        .child(
            row()
                .w_full()
                .gap(28.0)
                .items_stretch()
                .child(agents_col)
                .child(signals_col),
        )
}
