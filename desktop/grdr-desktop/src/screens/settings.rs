use grdr_ui_model::{InstallProfile, Intent, ThemeChoice};
use rune::{El, Tx, col, icon, row, spacer, text};
use rune_kit::SegmentedControl;

use crate::icons;
use crate::kit::{DesktopApp, ledger_header, primary_button, status_pill};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let prefs = &app.vm.preferences;
    let settings = &app.vm.settings;

    let profile_idx = match settings.install_profile {
        InstallProfile::Protected => Some(0),
        InstallProfile::User => Some(1),
    };
    let theme_idx = match prefs.theme {
        ThemeChoice::Light => Some(0),
        ThemeChoice::Dark => Some(1),
    };

    let profile_ctrl = SegmentedControl::new(&["Protected", "User mode"], profile_idx)
        .label("Protection profile")
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

    let theme_ctrl = SegmentedControl::new(&["Light", "Dark"], theme_idx)
        .label("Appearance theme")
        .fit()
        .on_pick(|s: &mut DesktopApp, idx: usize, _: &mut Tx| {
            let want_dark = idx == 1;
            let is_dark = matches!(s.vm.preferences.theme, ThemeChoice::Dark);
            if want_dark != is_dark {
                s.dispatch(Intent::ToggleTheme);
            }
        })
        .build(&t.kit);

    let rows = col()
        .w_full()
        .gap(4.0)
        .child(ledger_header("Preferences", "Saved locally", t))
        .child(
            row()
                .w_full()
                .pt(12.0)
                .pb(12.0)
                .center_y()
                .gap(10.0)
                .child(icon(&icons::SHIELD_CHECK, 15.0).color(t.c.ink_muted))
                .child(
                    text("Protection profile")
                        .font(t.body_strong)
                        .color(t.c.ink_primary),
                )
                .child(spacer())
                .child(profile_ctrl),
        )
        .child(
            row()
                .w_full()
                .pt(12.0)
                .pb(12.0)
                .center_y()
                .gap(10.0)
                .child(icon(&icons::SUN, 15.0).color(t.c.ink_muted))
                .child(
                    text("Appearance")
                        .font(t.body_strong)
                        .color(t.c.ink_primary),
                )
                .child(spacer())
                .child(theme_ctrl),
        )
        .child(
            row()
                .w_full()
                .pt(12.0)
                .pb(12.0)
                .center_y()
                .gap(10.0)
                .child(icon(&icons::GLOBE, 15.0).color(t.c.ink_muted))
                .child(text("Language").font(t.body_strong).color(t.c.ink_primary))
                .child(spacer())
                .child(status_pill(
                    prefs.locale.code(),
                    t.c.recessed,
                    t.c.ink_secondary,
                    t,
                )),
        );

    col()
        .key("screen-settings")
        .w_full()
        .gap(24.0)
        .child(
            text("Settings")
                .font(t.display_headline)
                .color(t.c.ink_primary),
        )
        .child(
            text("Choose protection mode, appearance, and open the full web console.")
                .font(t.body)
                .color(t.c.ink_secondary),
        )
        .child(rows)
        .child(row().gap(12.0).child(primary_button(
            "open-web-settings",
            "Open web console",
            t,
            |s| {
                s.dispatch(Intent::OpenWebConsole {
                    route: "home".to_owned(),
                });
            },
        )))
}
