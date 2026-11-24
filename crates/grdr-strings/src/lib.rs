use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Locale identifier supported by Guardrails desktop, CLI, and pseudo-locale CI checks (D-69).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Locale {
    #[default]
    EnUs,
    /// Pseudo-locale testing string expansion (+35% accented width).
    EnXa,
    /// Pseudo-locale testing RTL bidi isolation.
    ArXb,
    /// Pseudo-locale testing CJK line wrapping.
    JaXc,
}

impl Locale {
    #[must_use]
    pub fn code(self) -> &'static str {
        match self {
            Self::EnUs => "en-US",
            Self::EnXa => "en-XA",
            Self::ArXb => "ar-XB",
            Self::JaXc => "ja-XC",
        }
    }

    pub fn parse(raw: &str) -> Result<Self, StringsError> {
        match raw.trim().to_ascii_lowercase().as_str() {
            "en" | "en-us" | "c" | "posix" => Ok(Self::EnUs),
            "en-xa" => Ok(Self::EnXa),
            "ar-xb" => Ok(Self::ArXb),
            "ja-xc" => Ok(Self::JaXc),
            _ => Err(StringsError::UnsupportedLocale {
                code: "GRDR-STR-0001",
                locale: raw.to_owned(),
            }),
        }
    }
}

/// Errors returned by the localized string catalog (`GRDR-STR-*`).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StringsError {
    #[error("{code}: unsupported locale '{locale}'")]
    UnsupportedLocale { code: &'static str, locale: String },
}

/// Typed language-token identifiers used by desktop, CLI, tray, and `grdr-approve`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MessageKey {
    BrandName,
    NavFirstRun,
    NavHome,
    NavActivity,
    NavRules,
    NavPrivacy,
    NavSettings,
    ProfileProtectedStatus,
    ProfileUserRequestsOnly,
    ScanOnlyStatus,
    ApproverSelf,
    ApproverSponsor,
    ApproverAdmin,
    ApproverQuorum,
    WhyBlocked,
    WhyStepUp,
    WhyModified,
    WhyDelayed,
    WideningWarningTitle,
    PrivacyNoticeHeader,
    RenderWebNotice,
}

impl MessageKey {
    #[must_use]
    pub fn token_id(self) -> &'static str {
        match self {
            Self::BrandName => "grdr.brand.name",
            Self::NavFirstRun => "desktop.nav.first_run",
            Self::NavHome => "desktop.nav.home",
            Self::NavActivity => "desktop.nav.activity",
            Self::NavRules => "desktop.nav.rules",
            Self::NavPrivacy => "desktop.nav.privacy",
            Self::NavSettings => "desktop.nav.settings",
            Self::ProfileProtectedStatus => "desktop.status.protected",
            Self::ProfileUserRequestsOnly => "desktop.status.requests_only",
            Self::ScanOnlyStatus => "desktop.status.scan_only",
            Self::ApproverSelf => "desktop.approver.self",
            Self::ApproverSponsor => "desktop.approver.sponsor",
            Self::ApproverAdmin => "desktop.approver.admin",
            Self::ApproverQuorum => "desktop.approver.quorum",
            Self::WhyBlocked => "desktop.why.blocked",
            Self::WhyStepUp => "desktop.why.step_up",
            Self::WhyModified => "desktop.why.modified",
            Self::WhyDelayed => "desktop.why.delayed",
            Self::WideningWarningTitle => "desktop.rules.widening_confirm",
            Self::PrivacyNoticeHeader => "desktop.privacy.disclosure",
            Self::RenderWebNotice => "desktop.render.web_fallback",
        }
    }

    #[must_use]
    pub fn english(self) -> &'static str {
        match self {
            Self::BrandName => "Guardrails ADR",
            Self::NavFirstRun => "First run",
            Self::NavHome => "Home",
            Self::NavActivity => "My activity",
            Self::NavRules => "Rules",
            Self::NavPrivacy => "Privacy",
            Self::NavSettings => "Settings",
            Self::ProfileProtectedStatus => "Protected",
            Self::ProfileUserRequestsOnly => "On (requests only)",
            Self::ScanOnlyStatus => "Scan only, not protecting",
            Self::ApproverSelf => "You",
            Self::ApproverSponsor => "Your team's sponsor",
            Self::ApproverAdmin => "An administrator",
            Self::ApproverQuorum => "Two approvers",
            Self::WhyBlocked => "Why this was blocked",
            Self::WhyStepUp => "Why this needs approval",
            Self::WhyModified => "Why this was changed",
            Self::WhyDelayed => "Why this was delayed",
            Self::WideningWarningTitle => "Guardrails will stop enforcing below this floor",
            Self::PrivacyNoticeHeader => "What Guardrails observes and retains on this device",
            Self::RenderWebNotice => "Running in Web tier; opening local console",
        }
    }
}

/// Renders a language token cleanly for the requested locale.
#[must_use]
pub fn lookup(locale: Locale, key: MessageKey) -> String {
    let base = key.english();
    match locale {
        Locale::EnUs => base.to_owned(),
        Locale::EnXa => format!("[{base} ~~~]"),
        Locale::ArXb => format!("\u{2066}{base}\u{2069}"),
        Locale::JaXc => format!("「{base}」"),
    }
}

/// Strips dangerous directional and C0 control characters before rendering untrusted agent text.
#[must_use]
pub fn sanitize_untrusted_text(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        let is_bidi = matches!(
            ch,
            '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}' | '\u{200E}' | '\u{200F}'
        );
        if is_bidi || (ch.is_control() && ch != ' ') {
            out.push(' ');
        } else {
            out.push(ch);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pseudo_locales_preserve_semantics_and_isolate_rtl() {
        let rtl = lookup(Locale::ArXb, MessageKey::NavHome);
        assert!(rtl.starts_with('\u{2066}') && rtl.ends_with('\u{2069}'));
        assert!(lookup(Locale::EnXa, MessageKey::NavRules).contains("Rules"));
        assert!(lookup(Locale::JaXc, MessageKey::NavPrivacy).starts_with('「'));
    }

    #[test]
    fn sanitizes_bidi_and_control_characters() {
        let dirty = "rm\u{202E}-rf\n~/.ssh";
        let clean = sanitize_untrusted_text(dirty);
        assert!(!clean.contains('\u{202E}'));
        assert!(!clean.contains('\n'));
        assert!(clean.contains("~/.ssh"));
    }

    #[test]
    fn unknown_locale_returns_error_code() {
        let err = Locale::parse("xx-UNKNOWN").expect_err("expected unsupported locale");
        assert!(err.to_string().contains("GRDR-STR-0001"));
    }
}
