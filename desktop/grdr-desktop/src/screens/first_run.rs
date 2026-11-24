use grdr_ui_model::{InstallProfile, Intent};
use rune::{El, Tx, col, row, spacer, text};
use rune_kit::{Button, ButtonVariant, SegmentedControl, glyphs};

use crate::kit::{DesktopApp, ledger_header, setup_progress, status_pill};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let vm = &app.vm.first_run;
    let done = vm.steps.iter().filter(|s| s.done).count();
    let total = vm.steps.len();

    let selected = match vm.selected_profile {
        InstallProfile::Protected => Some(0),
        InstallProfile::User => Some(1),
    };

    let profile_picker =
        SegmentedControl::new(&["Protected (boundary)", "User (requests only)"], selected)
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
        let icon_color = if step.done { t.c.allow } else { t.c.ink_muted };
        let status_el = if step.done {
            status_pill("Done", t.c.allow_bg, t.c.allow, t)
        } else {
            status_pill("Pending", t.c.recessed, t.c.ink_secondary, t)
        };
        list = list.child(
            row()
                .w_full()
                .pt(8.0)
                .pb(8.0)
                .center_y()
                .gap(12.0)
                .child(rune::icon(&glyphs::CHECK, 14.0).color(icon_color))
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
        .child(text("First run setup").font(t.display_headline).color(t.c.ink_primary))
        .child(
            text("Read-only agent scan complete. Choose Protected so your agents cannot remove hooks or local rules.")
                .font(t.body)
                .color(t.c.ink_secondary)
                .wrap()
                .w_full(),
        )
        .child(setup_progress(done, total, t))
        .child(
            row()
                .gap(16.0)
                .center_y()
                .child(profile_picker)
                .child(
                    Button::new("Confirm protection")
                        .variant(ButtonVariant::Outline)
                        .build(&t.kit),
                ),
        )
        .child(list)
}
