use rune::{El, col, icon, row, spacer, text};

use crate::icons;
use crate::kit::{DesktopApp, flow_stage_node, ledger_header, status_pill_with_icon};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let vm = &app.vm.privacy;
    let rows = [
        ("Capture level", vm.capture_scope.clone(), &icons::EYE),
        (
            "Local retention",
            format!("{} days on this endpoint", vm.local_retention_days),
            &icons::HARD_DRIVE,
        ),
        (
            "Telemetry egress",
            vm.telemetry_destination.clone(),
            &icons::GLOBE,
        ),
        (
            "Organization readers",
            vm.managed_org
                .clone()
                .unwrap_or_else(|| "None (standalone mode)".to_owned()),
            &icons::KEY,
        ),
    ];

    let data_flow = row()
        .w_full()
        .gap(10.0)
        .items_stretch()
        .center_y()
        .child(flow_stage_node(
            &icons::TERMINAL,
            "1. Agent calls",
            "Claude Code, Cursor, Codex",
            t.c.ink_primary,
            t,
        ))
        .child(icon(&icons::ARROW_RIGHT, 14.0).color(t.c.ink_muted))
        .child(flow_stage_node(
            &icons::SHIELD_CHECK,
            "2. Policy check",
            "Evaluated locally",
            t.c.accent,
            t,
        ))
        .child(icon(&icons::ARROW_RIGHT, 14.0).color(t.c.ink_muted))
        .child(flow_stage_node(
            &icons::HARD_DRIVE,
            "3. Local receipts",
            "Signed log on disk",
            t.c.allow,
            t,
        ))
        .child(icon(&icons::ARROW_RIGHT, 14.0).color(t.c.ink_muted))
        .child(flow_stage_node(
            &icons::CIRCLE_OFF,
            "4. External egress",
            "0 bytes uploaded",
            t.c.ink_secondary,
            t,
        ));

    let mut table =
        col()
            .w_full()
            .gap(4.0)
            .child(ledger_header("Privacy guarantees", "Cannot be disabled", t));

    for (label, value, glyph) in rows {
        table = table.child(
            row()
                .w_full()
                .pt(12.0)
                .pb(12.0)
                .center_y()
                .gap(10.0)
                .child(icon(glyph, 15.0).color(t.c.ink_muted))
                .child(text(label).font(t.body_strong).color(t.c.ink_primary))
                .child(spacer())
                .child(text(value).font(t.caption).color(t.c.ink_secondary)),
        );
    }

    col()
        .key("screen-privacy")
        .w_full()
        .gap(24.0)
        .child(
            text(&vm.disclosure_header)
                .font(t.display_headline)
                .color(t.c.ink_primary),
        )
        .child(
            row()
                .gap(8.0)
                .center_y()
                .child(status_pill_with_icon(
                    "Local only",
                    Some(&icons::LOCK),
                    t.c.allow_bg,
                    t.c.allow,
                    t,
                ))
                .child(
                    text(
                        "Guardrails prompts stay local unless you explicitly join an organization.",
                    )
                    .font(t.body)
                    .color(t.c.ink_secondary),
                ),
        )
        .child(ledger_header(
            "Data handling pipeline",
            "Zero remote content route",
            t,
        ))
        .child(data_flow)
        .child(table)
}
