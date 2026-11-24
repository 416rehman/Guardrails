use grdr_ui_model::ModeLevel;
use rune::Icon;

pub static BRAND_MARK: Icon = Icon {
    name: "grdr-brand-mark",
    view: 64.0,
    body: r#"<path d="M 8 47.5 V 25 C 8 17.8 13.8 14 20.5 14 H 43.5 C 50.2 14 56 17.8 56 25 V 47.5 C 56 49.4 53.7 50.2 52.5 48.7 L 47.5 41.2 V 25.8 C 47.5 22.3 45.2 20.5 41.8 20.5 H 22.2 C 18.8 20.5 16.5 22.3 16.5 25.8 V 41.2 L 11.5 48.7 C 10.3 50.2 8 49.4 8 47.5 Z" fill="currentColor"/><path d="M 18.0 43.6 H 46.0 L 49.8 50.5 H 14.2 Z" fill="currentColor"/><path d="M 22.0 36.2 H 42.0 L 45.0 41.6 H 19.0 Z" fill="currentColor" fill-opacity="0.68"/><path d="M 25.4 30.0 H 38.6 L 41.0 34.4 H 23.0 Z" fill="currentColor" fill-opacity="0.44"/>"#,
};

pub static HOME: Icon = Icon {
    name: "grdr-home",
    view: 24.0,
    body: r#"<path d="M3 10.5L12 3l9 7.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M5 9.5V20a1 1 0 0 0 1 1h4v-6h4v6h4a1 1 0 0 0 1-1V9.5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static ACTIVITY: Icon = Icon {
    name: "grdr-activity",
    view: 24.0,
    body: r#"<path d="M22 12h-4l-3 9L9 3l-3 9H2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static SHIELD: Icon = Icon {
    name: "grdr-shield",
    view: 24.0,
    body: r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static SHIELD_CHECK: Icon = Icon {
    name: "grdr-shield-check",
    view: 24.0,
    body: r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M9 12l2 2 4-4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static SHIELD_ALERT: Icon = Icon {
    name: "grdr-shield-alert",
    view: 24.0,
    body: r#"<path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><path d="M12 8v4M12 16h.01" fill="none" stroke="currentColor" stroke-width="2.0" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static SLIDERS: Icon = Icon {
    name: "grdr-sliders",
    view: 24.0,
    body: r#"<path d="M4 21v-7M4 10V3M12 21v-9M12 8V3M20 21v-5M20 12V3M1 14h6M9 8h6M17 16h6" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static LOCK: Icon = Icon {
    name: "grdr-lock",
    view: 24.0,
    body: r#"<rect x="4" y="11" width="16" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M7 11V7a5 5 0 0 1 10 0v4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#,
};

pub static EYE: Icon = Icon {
    name: "grdr-eye",
    view: 24.0,
    body: r#"<path d="M2 12s3.5-7 10-7 10 7 10 7-3.5 7-10 7-10-7-10-7z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><circle cx="12" cy="12" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>"#,
};

pub static HAND: Icon = Icon {
    name: "grdr-hand",
    view: 24.0,
    body: r#"<path d="M18 11V6a2 2 0 0 0-4 0v4M14 10V4a2 2 0 0 0-4 0v6M10 10V6a2 2 0 0 0-4 0v8l-1.5-1.5a2 2 0 0 0-2.8 2.8l4.8 5A6 6 0 0 0 10.8 22H14a6 6 0 0 0 6-6v-5a2 2 0 0 0-2 0z" fill="none" stroke="currentColor" stroke-width="1.7" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static BAN: Icon = Icon {
    name: "grdr-ban",
    view: 24.0,
    body: r#"<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M5.6 5.6l12.8 12.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#,
};

pub static CIRCLE_OFF: Icon = Icon {
    name: "grdr-circle-off",
    view: 24.0,
    body: r#"<path d="M3 3l18 18" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/><path d="M8.5 4.2A9 9 0 0 1 19.8 15.5M5.2 6.8A9 9 0 0 0 17.2 18.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#,
};

pub static CPU: Icon = Icon {
    name: "grdr-cpu",
    view: 24.0,
    body: r#"<rect x="6" y="6" width="12" height="12" rx="2" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M9 2v4M15 2v4M9 18v4M15 18v4M2 9h4M2 15h4M18 9h4M18 15h4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#,
};

pub static TERMINAL: Icon = Icon {
    name: "grdr-terminal",
    view: 24.0,
    body: r#"<path d="M4 17l6-6-6-6M12 19h8" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static BINOCULARS: Icon = Icon {
    name: "grdr-binoculars",
    view: 24.0,
    body: r#"<path d="M10 10h4M6 6l-2 9M18 6l2 9M6 6h3v4H5M18 6h-3v4h4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/><circle cx="6.5" cy="17" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="17.5" cy="17" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/>"#,
};

pub static ROUTE: Icon = Icon {
    name: "grdr-route",
    view: 24.0,
    body: r#"<circle cx="6" cy="19" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/><circle cx="18" cy="5" r="3" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M9 19h8.5a3.5 3.5 0 0 0 0-7h-11a3.5 3.5 0 0 1 0-7H15" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#,
};

pub static BOX: Icon = Icon {
    name: "grdr-box",
    view: 24.0,
    body: r#"<path d="M21 16V8a2 2 0 0 0-1-1.7l-7-4a2 2 0 0 0-2 0l-7 4A2 2 0 0 0 3 8v8a2 2 0 0 0 1 1.7l7 4a2 2 0 0 0 2 0l7-4A2 2 0 0 0 21 16z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M3.3 7L12 12l8.7-5M12 22V12" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/>"#,
};

pub static LIST: Icon = Icon {
    name: "grdr-list",
    view: 24.0,
    body: r#"<path d="M8 6h13M8 12h13M8 18h13M3 6h.01M3 12h.01M3 18h.01" fill="none" stroke="currentColor" stroke-width="2.0" stroke-linecap="round"/>"#,
};

pub static MOON: Icon = Icon {
    name: "grdr-moon",
    view: 24.0,
    body: r#"<path d="M21 12.8A9 9 0 1 1 11.2 3a7 7 0 0 0 9.8 9.8z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static SUN: Icon = Icon {
    name: "grdr-sun",
    view: 24.0,
    body: r#"<circle cx="12" cy="12" r="4" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"/>"#,
};

pub static KEY: Icon = Icon {
    name: "grdr-key",
    view: 24.0,
    body: r#"<circle cx="7.5" cy="15.5" r="4.5" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M10.7 12.3L21 2M18 5l3 3M15 8l2 2" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static HARD_DRIVE: Icon = Icon {
    name: "grdr-hard-drive",
    view: 24.0,
    body: r#"<path d="M22 12H2M5.4 5.1L2 12v6a2 2 0 0 0 2 2h16a2 2 0 0 0 2-2v-6l-3.4-6.9A2 2 0 0 0 16.8 4H7.2a2 2 0 0 0-1.8 1.1z" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round"/><path d="M6 16h.01M10 16h.01" fill="none" stroke="currentColor" stroke-width="2.0" stroke-linecap="round"/>"#,
};

pub static GLOBE: Icon = Icon {
    name: "grdr-globe",
    view: 24.0,
    body: r#"<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M3.6 9h16.8M3.6 15h16.8M12 3a14 14 0 0 1 0 18M12 3a14 14 0 0 0 0 18" fill="none" stroke="currentColor" stroke-width="1.8"/>"#,
};

pub static LAYERS: Icon = Icon {
    name: "grdr-layers",
    view: 24.0,
    body: r#"<path d="M12 2L2 7l10 5 10-5-10-5zM2 17l10 5 10-5M2 12l10 5 10-5" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static CHECK_CIRCLE: Icon = Icon {
    name: "grdr-check-circle",
    view: 24.0,
    body: r#"<circle cx="12" cy="12" r="9" fill="none" stroke="currentColor" stroke-width="1.8"/><path d="M8.5 12.2l2.3 2.3 4.7-4.8" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

pub static ARROW_RIGHT: Icon = Icon {
    name: "grdr-arrow-right",
    view: 24.0,
    body: r#"<path d="M5 12h14M13 6l6 6-6 6" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round"/>"#,
};

#[must_use]
pub fn for_mode(mode: ModeLevel) -> &'static Icon {
    match mode {
        ModeLevel::Off => &CIRCLE_OFF,
        ModeLevel::Watch => &EYE,
        ModeLevel::Ask => &HAND,
        ModeLevel::Block => &BAN,
    }
}

#[must_use]
pub fn for_assurance(level: &str) -> &'static Icon {
    match level {
        "AL0" => &LIST,
        "AL1" => &BINOCULARS,
        "AL2" => &ROUTE,
        "AL3" => &BOX,
        "AL4" => &SHIELD_CHECK,
        _ => &SHIELD,
    }
}
