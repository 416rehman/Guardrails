mod generated;

use thiserror::Error;

pub use generated::{
    BRAND_NAME, BRAND_SHORT_NAME, ICONS, IconRegistryEntry, Locale, MessageKey, PRESENTATIONS,
    PresentationRegistryEntry, english_by_id, format_for_locale, lookup,
};

/// Errors returned by the localized string catalog (`GRDR-STR-*`).
#[derive(Debug, Error, PartialEq, Eq)]
pub enum StringsError {
    #[error("{code}: unsupported locale '{locale}'")]
    UnsupportedLocale { code: &'static str, locale: String },
}

impl Locale {
    pub fn parse(raw: &str) -> Result<Self, StringsError> {
        Self::parse_tag(raw).ok_or_else(|| StringsError::UnsupportedLocale {
            code: "GRDR-STR-0001",
            locale: raw.to_owned(),
        })
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
        assert_eq!(Locale::ArXb.direction(), "rtl");
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
