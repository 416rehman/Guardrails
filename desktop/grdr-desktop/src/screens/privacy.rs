use rune::{El, col, row, spacer, text};

use crate::kit::{DesktopApp, ledger_header, status_pill};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let vm = &app.vm.privacy;
    let rows = [
        ("Capture level", vm.capture_scope.clone()),
        (
            "Local retention",
            format!("{} days on this endpoint", vm.local_retention_days),
        ),
        ("Telemetry egress", vm.telemetry_destination.clone()),
        (
            "Organisation readers",
            vm.managed_org
                .clone()
                .unwrap_or_else(|| "None (standalone mode)".to_owned()),
        ),
    ];

    let mut table =
        col()
            .w_full()
            .gap(4.0)
            .child(ledger_header("Privacy guarantees", "Cannot be disabled", t));

    for (label, value) in rows {
        table = table.child(
            row()
                .w_full()
                .pt(12.0)
                .pb(12.0)
                .center_y()
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
                .child(status_pill("Local only", t.c.allow_bg, t.c.allow, t))
                .child(
                    text(
                        "Guardrails prompts stay local unless you explicitly join an organisation.",
                    )
                    .font(t.body)
                    .color(t.c.ink_secondary),
                ),
        )
        .child(table)
}
