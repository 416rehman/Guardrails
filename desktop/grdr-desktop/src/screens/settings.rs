use grdr_ui_model::{InstallProfile, Intent, RenderTier, ThemeChoice};
use rune::{El, col, el, icon, row, spacer, text};

use crate::icons;
use crate::kit::{DesktopApp, ledger_header, primary_button, status_pill};
use crate::theme::StudioTheme;

#[must_use]
pub fn render(app: &DesktopApp, t: &StudioTheme) -> El {
    let prefs = &app.vm.preferences;
    let settings = &app.vm.settings;

    let profile_text = match settings.install_profile {
        InstallProfile::Protected => "Protected (machine boundary)",
        InstallProfile::User => "User (requests only)",
    };
    let tier_text = match prefs.render_tier {
        RenderTier::Full => "Full hardware GPU (Rune)",
        RenderTier::Lite => "Lite reduced motion",
        RenderTier::Web => "Web fallback",
    };
    let theme_text = match prefs.theme {
        ThemeChoice::Light => "Paper Light",
        ThemeChoice::Dark => "Nocturne Dark",
    };

    let mut rows =
        col()
            .w_full()
            .gap(4.0)
            .child(ledger_header("Runtime & preferences", "Local config", t));

    for (k, v, glyph) in [
        (
            "Install profile",
            profile_text.to_owned(),
            &icons::SHIELD_CHECK,
        ),
        ("Render tier", tier_text.to_owned(), &icons::CPU),
        ("Appearance theme", theme_text.to_owned(), &icons::SUN),
        ("UI locale", prefs.locale.code().to_owned(), &icons::GLOBE),
    ] {
        rows = rows.child(
            row()
                .w_full()
                .pt(12.0)
                .pb(12.0)
                .center_y()
                .gap(10.0)
                .child(icon(glyph, 15.0).color(t.c.ink_muted))
                .child(text(k).font(t.body_strong).color(t.c.ink_primary))
                .child(spacer())
                .child(status_pill(&v, t.c.recessed, t.c.ink_secondary, t)),
        );
    }

    col()
        .key("screen-settings")
        .w_full()
        .gap(24.0)
        .child(
            row()
                .gap(12.0)
                .center_y()
                .child(
                    el().size(36.0, 36.0)
                        .radius(9.0)
                        .fill(t.c.accent_soft)
                        .center()
                        .child(icon(&icons::SLIDERS, 18.0).color(t.c.accent)),
                )
                .child(
                    text("Settings")
                        .font(t.display_headline)
                        .color(t.c.ink_primary),
                ),
        )
        .child(
            text("Manage render tier, appearance, locale, and local web console bridge.")
                .font(t.body)
                .color(t.c.ink_secondary),
        )
        .child(rows)
        .child(
            row()
                .gap(12.0)
                .child(primary_button(
                    "toggle-theme-settings",
                    "Switch appearance",
                    t,
                    |s| {
                        s.dispatch(Intent::ToggleTheme);
                    },
                ))
                .child(primary_button(
                    "open-web-settings",
                    "Open local web console",
                    t,
                    |s| {
                        s.dispatch(Intent::OpenWebConsole {
                            route: "home".to_owned(),
                        });
                    },
                )),
        )
}
