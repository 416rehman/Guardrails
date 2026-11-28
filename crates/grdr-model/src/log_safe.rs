// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::fmt;

use grdr_schema::{ContentKind, DataClass as CanonicalDataClass};
use serde::{Deserialize, Serialize};

use crate::domain::{ActionClass, ControlPoint, Mode, Verdict};

pub const REDACTED_MARKER: &str = "[REDACTED]";
pub const DEFAULT_LOG_SNIPPET_LEN: usize = 64;

/// Logging redaction taxonomy; preserves legacy `Public`/`Secret` variants until Post-Wave consolidation onto `grdr_schema::DataClass` + `ContentKind` (#133).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Public,
    Metadata,
    Pseudonym,
    Identifier,
    Content,
    Secret,
}

pub trait LogSafe {
    fn log_safe(&self) -> String;
}

#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Redacted<T>(pub T);

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct OpaqueDigest {
    digest_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct LogSafeText {
    sanitized: String,
    class: DataClass,
}

impl DataClass {
    #[must_use]
    pub const fn sensitivity_rank(self) -> u8 {
        match self {
            Self::Public => 0,
            Self::Metadata => 1,
            Self::Pseudonym => 2,
            Self::Identifier => 3,
            Self::Content => 4,
            Self::Secret => 5,
        }
    }

    #[must_use]
    pub const fn may_log_raw(self) -> bool {
        matches!(self, Self::Public | Self::Metadata | Self::Pseudonym)
    }

    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Public => "public",
            Self::Metadata => "metadata",
            Self::Identifier => "identifier",
            Self::Pseudonym => "pseudonym",
            Self::Content => "content",
            Self::Secret => "secret",
        }
    }

    #[must_use]
    pub const fn to_canonical(self) -> (CanonicalDataClass, Option<ContentKind>) {
        match self {
            Self::Public | Self::Metadata => (CanonicalDataClass::Structural, None),
            Self::Pseudonym => (CanonicalDataClass::Derived, None),
            Self::Identifier => (CanonicalDataClass::Identifier, None),
            Self::Content => (CanonicalDataClass::Content, Some(ContentKind::Body)),
            Self::Secret => (CanonicalDataClass::Content, Some(ContentKind::Argument)),
        }
    }

    #[must_use]
    pub const fn canonical_class(self) -> CanonicalDataClass {
        self.to_canonical().0
    }

    #[must_use]
    pub const fn from_canonical_with_kind(
        class: CanonicalDataClass,
        kind: Option<ContentKind>,
    ) -> Self {
        match (class, kind) {
            (CanonicalDataClass::Structural, _) => Self::Metadata,
            (CanonicalDataClass::Derived, _) => Self::Pseudonym,
            (CanonicalDataClass::Identifier, _) => Self::Identifier,
            (CanonicalDataClass::Content, Some(ContentKind::Body)) => Self::Content,
            (CanonicalDataClass::Content, Some(ContentKind::Argument) | None) => Self::Secret,
        }
    }

    #[must_use]
    pub const fn from_canonical(class: CanonicalDataClass) -> Self {
        Self::from_canonical_with_kind(class, None)
    }
}

impl PartialOrd for DataClass {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for DataClass {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sensitivity_rank().cmp(&other.sensitivity_rank())
    }
}

impl From<CanonicalDataClass> for DataClass {
    fn from(value: CanonicalDataClass) -> Self {
        Self::from_canonical(value)
    }
}

impl LogSafe for CanonicalDataClass {
    fn log_safe(&self) -> String {
        DataClass::from_canonical(*self).log_safe()
    }
}

impl<T> Redacted<T> {
    pub fn new(value: T) -> Self {
        Self(value)
    }

    pub fn inner(&self) -> &T {
        &self.0
    }

    pub fn into_inner(self) -> T {
        self.0
    }
}

impl<T> fmt::Debug for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl<T> fmt::Display for Redacted<T> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(REDACTED_MARKER)
    }
}

impl<T> LogSafe for Redacted<T> {
    fn log_safe(&self) -> String {
        REDACTED_MARKER.to_string()
    }
}

impl OpaqueDigest {
    #[must_use]
    pub fn from_bytes(domain: &str, bytes: &[u8]) -> Self {
        Self {
            digest_hex: grdr_crypto::domain_sha256_hex(domain, bytes),
        }
    }

    #[must_use]
    pub fn as_hex(&self) -> &str {
        &self.digest_hex
    }

    #[must_use]
    pub fn short_prefix(&self) -> &str {
        let end = self.digest_hex.len().min(12);
        self.digest_hex.get(..end).unwrap_or(&self.digest_hex)
    }
}

impl fmt::Display for OpaqueDigest {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "sha256:{}", self.short_prefix())
    }
}

impl LogSafe for OpaqueDigest {
    fn log_safe(&self) -> String {
        self.to_string()
    }
}

impl LogSafeText {
    #[must_use]
    pub fn new(class: DataClass, raw: &str) -> Self {
        let sanitized = if class.may_log_raw() {
            sanitize_log_fragment(raw, DEFAULT_LOG_SNIPPET_LEN)
        } else {
            format!("[REDACTED:{}:{}B]", class.as_str(), raw.len())
        };
        Self { sanitized, class }
    }

    #[must_use]
    pub fn data_class(&self) -> DataClass {
        self.class
    }

    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.sanitized
    }
}

impl fmt::Display for LogSafeText {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.sanitized)
    }
}

impl LogSafe for LogSafeText {
    fn log_safe(&self) -> String {
        self.sanitized.clone()
    }
}

impl LogSafe for DataClass {
    fn log_safe(&self) -> String {
        self.as_str().to_string()
    }
}

impl LogSafe for ActionClass {
    fn log_safe(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| "unknown".into())
            .trim_matches('"')
            .to_string()
    }
}

impl LogSafe for ControlPoint {
    fn log_safe(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| "unknown".into())
            .trim_matches('"')
            .to_string()
    }
}

impl LogSafe for Mode {
    fn log_safe(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| "unknown".into())
            .trim_matches('"')
            .to_string()
    }
}

impl LogSafe for Verdict {
    fn log_safe(&self) -> String {
        serde_json::to_string(self)
            .unwrap_or_else(|_| "unknown".into())
            .trim_matches('"')
            .to_string()
    }
}

fn is_disallowed_log_char(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{00AD}'
                | '\u{061C}'
                | '\u{180E}'
                | '\u{200B}'..='\u{200F}'
                | '\u{202A}'..='\u{202E}'
                | '\u{2060}'..='\u{206F}'
                | '\u{FEFF}'
                | '\u{FFF9}'..='\u{FFFB}'
        )
}

#[must_use]
pub fn sanitize_log_fragment(raw: &str, max_bytes: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_bytes));
    let mut bytes_used: usize = 0;
    let mut truncated = false;
    for ch in raw.chars() {
        let mapped = if is_disallowed_log_char(ch) { ' ' } else { ch };
        let len = mapped.len_utf8();
        if bytes_used.saturating_add(len) > max_bytes {
            truncated = true;
            break;
        }
        out.push(mapped);
        bytes_used = bytes_used.saturating_add(len);
    }
    if truncated {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn redacted_never_reveals_secret_value() {
        let token = Redacted::new("sk-secret-bearer-token-9999");
        assert_eq!(format!("{token}"), REDACTED_MARKER);
        assert_eq!(format!("{token:?}"), REDACTED_MARKER);
        assert_eq!(token.log_safe(), REDACTED_MARKER);
        assert!(!format!("{token}").contains("bearer"));
    }

    #[test]
    fn class_enforcement_blocks_content_and_secret_logs() {
        let secret = LogSafeText::new(DataClass::Secret, "super-secret-value");
        assert!(!secret.as_str().contains("super-secret-value"));
        assert!(secret.as_str().starts_with("[REDACTED:secret:"));

        let prompt = LogSafeText::new(DataClass::Content, "user prompt body");
        assert!(!prompt.as_str().contains("user prompt"));

        let safe_meta = LogSafeText::new(DataClass::Metadata, "policy-pack\nv1\r\nok");
        assert_eq!(safe_meta.log_safe(), "policy-pack v1  ok");

        let bidi_meta = LogSafeText::new(DataClass::Metadata, "ok\u{202E}evil\u{2066}\u{200B}text");
        assert_eq!(bidi_meta.log_safe(), "ok evil  text");
    }

    #[test]
    fn opaque_digest_truncates_safely() {
        let d = OpaqueDigest::from_bytes("audit.prompt", b"untrusted input");
        let rendered = d.log_safe();
        assert!(rendered.starts_with("sha256:"));
        assert_eq!(rendered.len(), 19);
    }

    #[test]
    fn data_class_maps_cleanly_to_canonical_schema_taxonomy() {
        assert!(DataClass::Public < DataClass::Metadata);
        assert!(DataClass::Metadata < DataClass::Pseudonym);
        assert!(DataClass::Pseudonym < DataClass::Identifier);
        assert!(DataClass::Identifier < DataClass::Content);
        assert!(DataClass::Content < DataClass::Secret);

        assert_eq!(
            DataClass::Identifier.to_canonical(),
            (CanonicalDataClass::Identifier, None)
        );
        assert_eq!(
            DataClass::Metadata.to_canonical(),
            (CanonicalDataClass::Structural, None)
        );
        assert_eq!(
            DataClass::Pseudonym.to_canonical(),
            (CanonicalDataClass::Derived, None)
        );
        assert_eq!(
            DataClass::Content.to_canonical(),
            (CanonicalDataClass::Content, Some(ContentKind::Body))
        );
        assert_eq!(
            DataClass::Secret.to_canonical(),
            (CanonicalDataClass::Content, Some(ContentKind::Argument))
        );
        assert_eq!(
            DataClass::from_canonical_with_kind(
                CanonicalDataClass::Content,
                Some(ContentKind::Argument)
            ),
            DataClass::Secret
        );
        assert_eq!(
            DataClass::from_canonical_with_kind(
                CanonicalDataClass::Content,
                Some(ContentKind::Body)
            ),
            DataClass::Content
        );
        assert_eq!(
            DataClass::from_canonical(CanonicalDataClass::Content),
            DataClass::Secret
        );
        assert_eq!(
            DataClass::from(CanonicalDataClass::Structural),
            DataClass::Metadata
        );
        assert!(!DataClass::Secret.may_log_raw());
        assert!(!DataClass::Content.may_log_raw());
        assert!(!DataClass::Identifier.may_log_raw());
        assert!(DataClass::Pseudonym.may_log_raw());
    }
}
