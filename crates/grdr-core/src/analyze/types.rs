// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Typed analysis resolution contracts and limits for `grdr_core::analyze` (`D-10`).

use std::fmt;

use serde::{Deserialize, Serialize};

use grdr_model::{CodedError, DataClass, LogSafe};

use crate::analyze::limits_schema::{
    analyze_limits_from_schema, shell_limits_from_schema, shell_limits_from_toml,
};

pub const CODE_ANALYZE_UNTERMINATED_QUOTE: &str = "GRDR-ANALYZE-0001";
pub const CODE_ANALYZE_UNMATCHED_DELIM: &str = "GRDR-ANALYZE-0002";
pub const CODE_ANALYZE_UNEXPECTED_EOF: &str = "GRDR-ANALYZE-0003";
pub const CODE_ANALYZE_SYNTAX: &str = "GRDR-ANALYZE-0004";
pub const CODE_ANALYZE_ZERO_LIMIT: &str = "GRDR-ANALYZE-0005";
pub const CODE_ANALYZE_LIMIT_EXCEEDED: &str = "GRDR-ANALYZE-0006";

pub const DEFAULT_SHELL_INPUT_MAX_BYTES: u32 = 1_048_576;
pub const DEFAULT_SHELL_ENV_MAX_BYTES: u32 = 1_048_576;
pub const DEFAULT_SHELL_NESTING_DEPTH_MAX: u32 = 8;
pub const DEFAULT_SHELL_WORDS_MAX: u32 = 65_536;
pub const DEFAULT_SHELL_EXPANDED_MAX_BYTES: u32 = 1_048_576;

pub(crate) const MAX_SHELL_BYTE_CAP: u32 = 16 * 1024 * 1024;
pub(crate) const MAX_SHELL_DEPTH_CAP: u32 = 64;
pub(crate) const MAX_SHELL_WORDS_CAP: u32 = 1_048_576;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Span {
    pub start: u32,
    pub end: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ShellDialect {
    Posix,
    PowerShell,
    Cmd,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LimitKind {
    InputBytes,
    EnvBytes,
    NestingDepth,
    Words,
    ExpandedBytes,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UnresolvedKind {
    LimitExceeded(LimitKind),
    UnknownVariable,
    IfsExpansion,
    SubstitutionInCommandPosition,
    SubstitutionInWord,
    ArithmeticInCommandPosition,
    ArithmeticInWord,
    ProcessSubstitution,
    DynamicEval,
    DynamicSource,
    UndefinedAlias,
    UnsupportedConstruct,
    OpaqueEncoding,
    PendingSymlink,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum MalformedKind {
    UnterminatedQuote,
    UnmatchedDelimiter,
    UnexpectedEof,
    SyntaxError,
    InvalidEncoding,
    InvalidUrl,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UnresolvedReason {
    pub kind: UnresolvedKind,
    pub span: Span,
    pub detail: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MalformedReason {
    pub code: String,
    pub kind: MalformedKind,
    pub span: Span,
    pub detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum ShellLimitsError {
    #[error("GRDR-ANALYZE-0005: limit `{0:?}` cannot be zero")]
    ZeroLimit(LimitKind),
    #[error("GRDR-ANALYZE-0006: limit `{0:?}` is out of valid bounds")]
    OutOfRange(LimitKind),
}

#[derive(Debug, Clone, Copy, Deserialize)]
#[serde(deny_unknown_fields)]
struct RawShellLimits {
    input_max: u32,
    env_max: u32,
    nesting_depth_max: u32,
    words_max: u32,
    expanded_max: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(try_from = "RawShellLimits")]
pub struct ShellLimits {
    pub input_max: u32,
    pub env_max: u32,
    pub nesting_depth_max: u32,
    pub words_max: u32,
    pub expanded_max: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct AnalyzeLimits {
    pub decode_max_layers: u8,
    pub decode_max_bytes: usize,
    pub decode_max_nodes: usize,
    pub deflate_max_blocks: usize,
    pub deflate_max_empty_blocks: usize,
    pub deflate_max_members: usize,
    pub content_max_scan_bytes: usize,
    pub net_long_query_chars: usize,
    pub net_high_entropy_milli_bits: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum Resolution<T> {
    Resolved(T),
    Unresolved(Vec<UnresolvedReason>),
    Malformed(MalformedReason),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FactOriginTag {
    Deterministic,
    Heuristic,
    Model,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AnalyzeFact {
    pub key: String,
    pub value: String,
    pub origin: FactOriginTag,
    pub span: Option<Span>,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SecretRedactedBytes {
    bytes: Vec<u8>,
}

impl Span {
    #[must_use]
    pub fn from_usize(start: usize, end: usize) -> Self {
        Self {
            start: u32::try_from(start).unwrap_or(u32::MAX),
            end: u32::try_from(end).unwrap_or(u32::MAX),
        }
    }
}

impl ShellDialect {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Posix => "posix",
            Self::PowerShell => "powershell",
            Self::Cmd => "cmd",
        }
    }
}

impl LogSafe for ShellDialect {
    fn log_safe(&self) -> String {
        self.as_str().to_owned()
    }
}

impl LogSafe for LimitKind {
    fn log_safe(&self) -> String {
        format!("{self:?}")
    }
}

impl LogSafe for UnresolvedKind {
    fn log_safe(&self) -> String {
        format!("{self:?}")
    }
}

impl LogSafe for UnresolvedReason {
    fn log_safe(&self) -> String {
        format!("{:?}@{}:{}", self.kind, self.span.start, self.span.end)
    }
}

impl LogSafe for MalformedReason {
    fn log_safe(&self) -> String {
        format!(
            "{}:{:?}@{}:{}",
            self.code, self.kind, self.span.start, self.span.end
        )
    }
}

impl MalformedReason {
    #[must_use]
    pub fn new(kind: MalformedKind, span: Span, detail: impl Into<String>) -> Self {
        let code = match kind {
            MalformedKind::UnterminatedQuote => CODE_ANALYZE_UNTERMINATED_QUOTE,
            MalformedKind::UnmatchedDelimiter => CODE_ANALYZE_UNMATCHED_DELIM,
            MalformedKind::UnexpectedEof => CODE_ANALYZE_UNEXPECTED_EOF,
            MalformedKind::SyntaxError
            | MalformedKind::InvalidEncoding
            | MalformedKind::InvalidUrl => CODE_ANALYZE_SYNTAX,
        };
        Self {
            code: code.to_owned(),
            kind,
            span,
            detail: detail.into(),
        }
    }
}

impl TryFrom<RawShellLimits> for ShellLimits {
    type Error = ShellLimitsError;

    fn try_from(raw: RawShellLimits) -> Result<Self, Self::Error> {
        Self::new(
            raw.input_max,
            raw.env_max,
            raw.nesting_depth_max,
            raw.words_max,
            raw.expanded_max,
        )
    }
}

impl ShellLimits {
    pub fn new(
        input_max: u32,
        env_max: u32,
        nesting_depth_max: u32,
        words_max: u32,
        expanded_max: u32,
    ) -> Result<Self, ShellLimitsError> {
        let checks = [
            (LimitKind::InputBytes, input_max, MAX_SHELL_BYTE_CAP),
            (LimitKind::EnvBytes, env_max, MAX_SHELL_BYTE_CAP),
            (
                LimitKind::NestingDepth,
                nesting_depth_max,
                MAX_SHELL_DEPTH_CAP,
            ),
            (LimitKind::Words, words_max, MAX_SHELL_WORDS_CAP),
            (LimitKind::ExpandedBytes, expanded_max, MAX_SHELL_BYTE_CAP),
        ];
        for (kind, value, cap) in checks {
            if value == 0 {
                return Err(ShellLimitsError::ZeroLimit(kind));
            }
            if value > cap {
                return Err(ShellLimitsError::OutOfRange(kind));
            }
        }
        Ok(Self {
            input_max,
            env_max,
            nesting_depth_max,
            words_max,
            expanded_max,
        })
    }

    #[must_use]
    pub const fn default_bounds() -> Self {
        Self {
            input_max: DEFAULT_SHELL_INPUT_MAX_BYTES,
            env_max: DEFAULT_SHELL_ENV_MAX_BYTES,
            nesting_depth_max: DEFAULT_SHELL_NESTING_DEPTH_MAX,
            words_max: DEFAULT_SHELL_WORDS_MAX,
            expanded_max: DEFAULT_SHELL_EXPANDED_MAX_BYTES,
        }
    }

    #[must_use]
    pub fn from_schema() -> Self {
        shell_limits_from_schema()
    }

    pub fn try_from_limits_toml(src: &str) -> Result<Self, ShellLimitsError> {
        shell_limits_from_toml(src)
    }
}

impl AnalyzeLimits {
    #[must_use]
    pub fn from_schema() -> Self {
        analyze_limits_from_schema()
    }
}

impl From<ShellLimitsError> for CodedError {
    fn from(err: ShellLimitsError) -> Self {
        let code = match err {
            ShellLimitsError::ZeroLimit(_) => CODE_ANALYZE_ZERO_LIMIT,
            ShellLimitsError::OutOfRange(_) => CODE_ANALYZE_LIMIT_EXCEEDED,
        };
        CodedError::new(
            code,
            err.to_string(),
            "Configure non-zero bounded analyzer limits within allowed range.",
        )
    }
}

impl<T> Resolution<T> {
    #[must_use]
    pub const fn is_resolved(&self) -> bool {
        matches!(self, Self::Resolved(_))
    }

    #[must_use]
    pub const fn is_unresolved(&self) -> bool {
        matches!(self, Self::Unresolved(_))
    }

    #[must_use]
    pub const fn is_malformed(&self) -> bool {
        matches!(self, Self::Malformed(_))
    }

    #[must_use]
    pub fn as_ref(&self) -> Option<&T> {
        match self {
            Self::Resolved(val) => Some(val),
            Self::Unresolved(_) | Self::Malformed(_) => None,
        }
    }
}

impl SecretRedactedBytes {
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    #[must_use]
    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    #[must_use]
    pub const fn data_class() -> DataClass {
        DataClass::Content
    }
}

impl fmt::Debug for SecretRedactedBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "SecretRedactedBytes({} bytes)", self.bytes.len())
    }
}

/// Sanitizes untrusted token or variable names embedded in diagnostic details.
#[must_use]
pub(crate) fn sanitize_detail_token(raw: &str, max_chars: usize) -> String {
    let mut out = String::with_capacity(raw.len().min(max_chars));
    let mut count = 0usize;
    for ch in raw.chars() {
        if count >= max_chars {
            out.push_str("...");
            break;
        }
        if ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '.' | ':') {
            out.push(ch);
        } else {
            out.push('?');
        }
        count = count.saturating_add(1);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn shell_limits_rejects_zero_and_out_of_range_both_in_new_and_serde() {
        assert_eq!(
            ShellLimits::new(0, 1024, 4, 100, 1024).unwrap_err(),
            ShellLimitsError::ZeroLimit(LimitKind::InputBytes)
        );
        assert_eq!(
            ShellLimits::new(1024, 1024, 65, 100, 1024).unwrap_err(),
            ShellLimitsError::OutOfRange(LimitKind::NestingDepth)
        );
        assert_eq!(
            ShellLimits::new(1024, 1024, 4, 2_000_000, 1024).unwrap_err(),
            ShellLimitsError::OutOfRange(LimitKind::Words)
        );

        let zero_json = r#"{"input_max":1024,"env_max":0,"nesting_depth_max":4,"words_max":100,"expanded_max":1024}"#;
        assert!(serde_json::from_str::<ShellLimits>(zero_json).is_err());

        let huge_depth = r#"{"input_max":1024,"env_max":1024,"nesting_depth_max":999,"words_max":100,"expanded_max":1024}"#;
        assert!(serde_json::from_str::<ShellLimits>(huge_depth).is_err());
    }

    #[test]
    fn shell_limits_from_schema_parses_embedded_and_custom_bound_sections() {
        let schema_limits = ShellLimits::from_schema();
        assert_eq!(schema_limits.input_max, 1_048_576);
        assert_eq!(schema_limits.nesting_depth_max, 8);
        assert_eq!(schema_limits.words_max, 65_536);

        let analyze_limits = AnalyzeLimits::from_schema();
        assert_eq!(analyze_limits.decode_max_bytes, 1_048_576);
        assert_eq!(analyze_limits.content_max_scan_bytes, 524_288);

        let custom = r#"
[bound.analyze.shell]
input-max = 8192
env-max = 4096
nesting-depth-max = 4
words-max = 256
expanded-max = 16384
"#;
        let parsed = ShellLimits::try_from_limits_toml(custom).expect("valid custom bounds");
        assert_eq!(parsed.input_max, 8192);
        assert_eq!(parsed.env_max, 4096);
        assert_eq!(parsed.nesting_depth_max, 4);
        assert_eq!(parsed.words_max, 256);
        assert_eq!(parsed.expanded_max, 16384);

        let zero_toml = "[bound.analyze.shell]\ninput-max = 0\n";
        assert_eq!(
            ShellLimits::try_from_limits_toml(zero_toml).unwrap_err(),
            ShellLimitsError::ZeroLimit(LimitKind::InputBytes)
        );
    }

    #[test]
    fn sanitize_detail_token_strips_control_chars_and_bounds_len() {
        assert_eq!(
            sanitize_detail_token("FOO\nBAR\x1b[31m", 32),
            "FOO?BAR??31m"
        );
        assert_eq!(sanitize_detail_token("abcdef", 4), "abcd...");
    }

    #[test]
    fn shell_limits_denies_unknown_fields_and_parses_custom_ipc_and_analyze_bounds() {
        let extra_json = r#"{"input_max":1024,"env_max":1024,"nesting_depth_max":4,"words_max":100,"expanded_max":1024,"extra":1}"#;
        assert!(serde_json::from_str::<ShellLimits>(extra_json).is_err());

        let ipc_toml = "[endpoint.ipc]\nmax_frame_bytes = 2048\n";
        let from_ipc = ShellLimits::try_from_limits_toml(ipc_toml).expect("ipc bound accepted");
        assert_eq!(from_ipc.input_max, 2048);

        let custom_analyze = r#"
[bound.analyze.decode]
max_nodes = 77

[bound.analyze.deflate]
max_blocks = 88
max_empty_blocks = 12
max_members = 3
"#;
        let al = crate::analyze::limits_schema::analyze_limits_from_toml(custom_analyze);
        assert_eq!(al.decode_max_nodes, 77);
        assert_eq!(al.deflate_max_blocks, 88);
        assert_eq!(al.deflate_max_empty_blocks, 12);
        assert_eq!(al.deflate_max_members, 3);
    }
}
