#![forbid(unsafe_code)]

mod icons;
mod kit;
mod screens;
mod theme;

use grdr_ui_model::{AppVm, Screen, ThemeChoice};
use kit::DesktopApp;
use rune::{AppSpec, Cx, El, col, row, text};

type SceneSpec = (&'static str, fn(&mut DesktopApp));

const SCENES: &[SceneSpec] = &[
    ("home-light", |s| {
        s.vm.screen = Screen::Home;
        s.vm.preferences.theme = ThemeChoice::Light;
    }),
    ("home-dark", |s| {
        s.vm.screen = Screen::Home;
        s.vm.preferences.theme = ThemeChoice::Dark;
    }),
    ("first-run", |s| {
        s.vm.screen = Screen::FirstRun;
        s.vm.preferences.theme = ThemeChoice::Light;
    }),
    ("activity", |s| {
        s.vm.screen = Screen::MyActivity;
        s.vm.preferences.theme = ThemeChoice::Light;
    }),
    ("rules", |s| {
        s.vm.screen = Screen::Rules;
        s.vm.preferences.theme = ThemeChoice::Light;
    }),
    ("privacy", |s| {
        s.vm.screen = Screen::Privacy;
        s.vm.preferences.theme = ThemeChoice::Light;
    }),
    ("settings", |s| {
        s.vm.screen = Screen::Settings;
        s.vm.preferences.theme = ThemeChoice::Light;
    }),
];

fn init() -> DesktopApp {
    DesktopApp::new(AppVm::demo())
}

fn view(app: &DesktopApp, _cx: &mut Cx<DesktopApp>) -> El {
    let t = theme::build_theme(app.vm.preferences.theme);
    let page = match app.vm.screen {
        Screen::FirstRun => screens::first_run::render(app, &t),
        Screen::Home => screens::home::render(app, &t),
        Screen::MyActivity => screens::activity::render(app, &t),
        Screen::Rules => screens::rules::render(app, &t),
        Screen::Privacy => screens::privacy::render(app, &t),
        Screen::Settings => screens::settings::render(app, &t),
    };

    let mut content = col()
        .key("content-area")
        .grow(1.0)
        .h_full()
        .fill(t.c.canvas)
        .pt(32.0)
        .pb(32.0)
        .pl(44.0)
        .pr(44.0)
        .gap(20.0);

    if let Some(notice) = &app.last_notice {
        content = content.child(
            row()
                .key("notice-banner")
                .w_full()
                .px(14.0)
                .pt(10.0)
                .pb(10.0)
                .radius(8.0)
                .fill(t.c.accent_soft)
                .border(1.0, t.c.accent)
                .child(text(notice).font(t.caption).color(t.c.ink_primary)),
        );
    }

    content = content.child(page);

    rune_kit::root(
        row()
            .key("desktop-shell")
            .w_full()
            .h_full()
            .fill(t.c.canvas)
            .child(kit::sidebar_rail(app, &t))
            .child(content),
        std::iter::empty(),
    )
}

fn main() {
    rune::run(AppSpec {
        scenes: SCENES,
        ..AppSpec::new("Guardrails ADR", (1240.0, 820.0), init, view)
    });
}

#[cfg(test)]
mod tests {
    use super::*;
    use rune::{Env, Runtime};

    #[test]
    fn every_screen_builds_and_renders_cleanly_on_both_themes() {
        for (name, setup) in SCENES {
            let mut app = init();
            setup(&mut app);
            let dark = matches!(app.vm.preferences.theme, ThemeChoice::Dark);
            let mut rt = Runtime::new(app, view, (1240.0, 820.0), Env::new(dark, 1.0));
            rt.frame(0.0);
            assert!(
                rt.find("desktop-shell").is_some(),
                "scene {name} failed to mount desktop-shell"
            );
        }
    }

    #[test]
    fn clicking_sidebar_navigates_to_rules_and_privacy() {
        let mut rt = Runtime::new(init(), view, (1240.0, 820.0), Env::new(false, 1.0));
        rt.frame(0.0);

        let (rx, ry) = rt.find("nav-rules").expect("nav-rules missing");
        rt.pointer_down(rx, ry);
        rt.pointer_up(rx, ry);
        rt.frame(0.016);
        assert_eq!(rt.state.vm.screen, Screen::Rules);
        assert!(rt.find("screen-rules").is_some());

        let (px, py) = rt.find("nav-privacy").expect("nav-privacy missing");
        rt.pointer_down(px, py);
        rt.pointer_up(px, py);
        rt.frame(0.016);
        assert_eq!(rt.state.vm.screen, Screen::Privacy);
        assert!(rt.find("screen-privacy").is_some());

        let (sx, sy) = rt.find("toggle-sidebar").expect("toggle-sidebar missing");
        rt.pointer_down(sx, sy);
        rt.pointer_up(sx, sy);
        rt.frame(0.016);
        assert!(rt.state.sidebar_collapsed);
    }
}
