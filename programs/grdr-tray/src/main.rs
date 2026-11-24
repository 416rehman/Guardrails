use clap::Parser;
use grdr_strings::Locale;
use grdr_ui_model::{AppVm, RenderTier, Screen, TrayVm};
use serde::{Deserialize, Serialize};
use thiserror::Error;

// grdr:allow-s4 clap CLI flags for tray snapshot output
#[derive(Debug, Parser)]
#[command(name = "grdr-tray", about = "Guardrails per-user session tray helper")]
struct Cli {
    /// Print tray status snapshot as JSON
    #[arg(long)]
    status: bool,
    #[arg(long)]
    json: bool,
    /// Open or validate a grdr:// deep link
    #[arg(long)]
    open_uri: Option<String>,
}

#[derive(Debug, Error, PartialEq, Eq)]
pub enum TrayError {
    #[error("{code}: invalid or disallowed deep link '{uri}'")]
    InvalidDeepLink { code: &'static str, uri: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum DeepLinkTarget {
    OpenRoute {
        screen: Screen,
        item_id: Option<String>,
        server: Option<String>,
    },
    LaunchApprove {
        request_id: String,
    },
}

/// Selects the desktop render tier per `design/28` section 2: Web fallback for software GPU,
/// remote desktop sessions, or RTL locales while upstream Rune #244 remains open.
#[must_use]
pub fn select_render_tier(
    has_hardware_gpu: bool,
    remote_session: bool,
    locale: Locale,
    prefer_lite: bool,
) -> RenderTier {
    if !has_hardware_gpu || remote_session || matches!(locale, Locale::ArXb) {
        RenderTier::Web
    } else if prefer_lite {
        RenderTier::Lite
    } else {
        RenderTier::Full
    }
}

/// Validates and parses `grdr://` navigation links (`design/28` section 14). Deep links may
/// only navigate routes or open an existing approval request; they never mutate policy.
pub fn parse_deep_link(uri: &str) -> Result<DeepLinkTarget, TrayError> {
    let err = || TrayError::InvalidDeepLink {
        code: "GRDR-TRAY-0001",
        uri: uri.to_owned(),
    };
    let rest = uri.strip_prefix("grdr://").ok_or_else(err)?;
    let (path_part, query_part) = match rest.split_once('?') {
        Some((p, q)) => (p, Some(q)),
        None => (rest, None),
    };

    if let Some(req) = path_part.strip_prefix("approval/") {
        if req.is_empty() || req.contains('/') || query_part.is_some() {
            return Err(err());
        }
        return Ok(DeepLinkTarget::LaunchApprove {
            request_id: req.to_owned(),
        });
    }

    let route_rest = path_part.strip_prefix("open/").ok_or_else(err)?;
    let mut parts = route_rest.split('/');
    let route = parts.next().ok_or_else(err)?;
    let item_id = parts.next().filter(|s| !s.is_empty()).map(str::to_owned);
    if parts.next().is_some() {
        return Err(err());
    }

    let screen = match route {
        "first-run" => Screen::FirstRun,
        "home" => Screen::Home,
        "activity" => Screen::MyActivity,
        "rules" => Screen::Rules,
        "privacy" => Screen::Privacy,
        "settings" => Screen::Settings,
        _ => return Err(err()),
    };

    let mut server = None;
    if let Some(q) = query_part {
        for kv in q.split('&').filter(|s| !s.is_empty()) {
            let (k, v) = kv.split_once('=').ok_or_else(err)?;
            if k != "server" || v.is_empty() {
                return Err(err());
            }
            server = Some(v.to_owned());
        }
    }

    Ok(DeepLinkTarget::OpenRoute {
        screen,
        item_id,
        server,
    })
}

fn main() {
    let cli = Cli::parse();
    if let Some(uri) = cli.open_uri.as_deref() {
        match parse_deep_link(uri) {
            Ok(target) => {
                if let Ok(json) = serde_json::to_string_pretty(&target) {
                    println!("{json}");
                }
            }
            Err(e) => {
                eprintln!("{e}");
                std::process::exit(2);
            }
        }
        return;
    }

    let app = AppVm::demo();
    let vm: TrayVm = app.tray_vm();
    if cli.status && cli.json {
        if let Ok(json) = serde_json::to_string_pretty(&vm) {
            println!("{json}");
        }
    } else {
        println!(
            "Guardrails tray: {} ({} pending, {:?} tier)",
            vm.surface_state.label(app.preferences.locale),
            vm.pending_count,
            vm.render_tier
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn selects_web_tier_for_remote_or_software_or_rtl() {
        assert_eq!(
            select_render_tier(true, false, Locale::EnUs, false),
            RenderTier::Full
        );
        assert_eq!(
            select_render_tier(true, false, Locale::EnUs, true),
            RenderTier::Lite
        );
        assert_eq!(
            select_render_tier(false, false, Locale::EnUs, false),
            RenderTier::Web
        );
        assert_eq!(
            select_render_tier(true, true, Locale::EnUs, false),
            RenderTier::Web
        );
        assert_eq!(
            select_render_tier(true, false, Locale::ArXb, false),
            RenderTier::Web
        );
    }

    #[test]
    fn parses_safe_deep_links_and_rejects_credential_params() {
        let parsed = parse_deep_link("grdr://open/settings?server=adr.example.com")
            .expect("valid invite link");
        assert_eq!(
            parsed,
            DeepLinkTarget::OpenRoute {
                screen: Screen::Settings,
                item_id: None,
                server: Some("adr.example.com".to_owned()),
            }
        );

        assert!(parse_deep_link("grdr://open/settings?token=secret").is_err());
        assert!(parse_deep_link("grdr://approval/apr-demo-01").is_ok());
    }
}
