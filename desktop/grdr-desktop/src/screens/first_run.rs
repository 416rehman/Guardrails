use grdr_ui_model::{InstallProfile, Intent};
use rune::{El, Tx, col, icon, row, spacer, text};
use rune_kit::SegmentedControl;

use crate::icons;
use crate::kit::{DesktopApp, ledger_header, primary_button, setup_progress, status_inline};
use crate::theme::StudioTheme;
use crate::viz::elevated_card;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let vm = &app.vm.first_run;
    let done = vm.steps.iter().filter(|s| s.done).count();
    let total = vm.steps.len();

    let selected = match vm.selected_profile {
        InstallProfile::Protected => Some(0),
        InstallProfile::User => Some(1),
    };

    let profile_picker = SegmentedControl::new(
        &["Protected boundary", "User mode (requests only)"],
        selected,
    )
        .label("Protection install profile")
        .fit()
        .on_pick(|s: &mut DesktopApp, idx: usize, _: &mut Tx| {
            let p = if idx == 0 {
                InstallProfile::Protected
            } else {
                InstallProfile::User
            };
            s.dispatch(Intent::SelectInstallProfile(p));
        })
        .build(&t.kit);

    let mut list = col().w_full().gap(4.0).child(ledger_header(
        "Onboarding progress",
        &format!("{done} / {total}"),
        t,
    ));

    for step in &vm.steps {
        let (step_glyph, icon_color) = if step.done {
            (&icons::CHECK_CIRCLE, t.c.allow)
        } else {
            (&icons::SHIELD, t.c.ink_muted)
        };
        let status_el = if step.done {
            status_inline("Done", Some(&icons::CHECK_CIRCLE), t.c.allow, t)
        } else {
            status_inline("Pending", Some(&icons::LAYERS), t.c.ink_muted, t)
        };
        list = list.child(
            row()
                .w_full()
                .pt(8.0)
                .pb(8.0)
                .center_y()
                .gap(12.0)
                .child(icon(step_glyph, 16.0).color(icon_color))
                .child(
                    col()
                        .grow(1.0)
                        .gap(2.0)
                        .child(text(&step.label).font(t.body_strong).color(t.c.ink_primary))
                        .child(text(&step.detail).font(t.caption).color(t.c.ink_secondary)),
                )
                .child(spacer())
                .child(status_el),
        );
    }

    col()
        .key("screen-first-run")
        .w_full()
        .gap(24.0)
        .child(
            text("First run setup")
                .font(t.display_headline)
                .color(t.c.ink_primary),
        )
        .child(
            text("Read-only agent scan complete. Choose Protected so your agents cannot remove hooks or local rules.")
                .font(t.body)
                .color(t.c.ink_secondary)
                .wrap()
                .w_full(),
        )
        .child(
            elevated_card(
                "first-run-stage",
                12.0,
                t,
                col()
                    .w_full()
                    .padding(16.0)
                    .gap(10.0)
                    .child(
                        row()
                            .w_full()
                            .center_y()
                            .gap(8.0)
                            .child(icon(&icons::SHIELD_CHECK, 15.0).color(t.c.accent))
                            .child(
                                text("Setup progress")
                                    .font(t.body_strong)
                                    .color(t.c.ink_primary),
                            )
                            .child(spacer())
                            .child(
                                text(format!("{done} / {total}"))
                                    .font(t.caption)
                                    .color(t.c.ink_muted),
                            ),
                    )
                    .child(setup_progress(done, total, t)),
            )
            .w_full(),
        )
        .child(
            row()
                .gap(16.0)
                .center_y()
                .child(profile_picker)
                .child(primary_button(
                    "confirm-protection-btn",
                    "Confirm protection",
                    t,
                    |s| {
                        s.dispatch(Intent::ConfirmProtection);
                    },
                )),
        )
        .child(list)
}
