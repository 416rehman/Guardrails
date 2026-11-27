// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Brand manifest identity parsing and canonical privacy ordering (`P8`, `P14`, `D-66`).

use serde::{Deserialize, Serialize};

const BRAND_MANIFEST_RAW: &str = include_str!("../../../contracts/interface/brand/brand.toml");

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandIdentity {
    pub namespace: String,
    pub domain: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrandDisplayStrings {
    pub product_name: String,
    pub short_name: String,
    pub namespace: String,
    pub macos_agent_label: String,
    pub windows_program_dir: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DataClass {
    Identifier = 1,
    Structural = 2,
    Derived = 3,
    Content = 4,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContentKind {
    Argument = 1,
    Body = 2,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CommitmentClass {
    Identifier,
    Structural,
    Derived,
    ContentArgument,
    ContentBody,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum AuditLane {
    Event,
    Decision,
    Spine,
    Evidence,
    Discovery,
    LocalDevice,
    Bulk,
}

#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FiveWayCommitments {
    pub d_identifier: String,
    pub d_structural: String,
    pub d_derived: String,
    pub d_argument: String,
    pub d_body: String,
    pub salt_identifier: Option<Vec<u8>>,
    pub salt_structural: Option<Vec<u8>>,
    pub salt_derived: Option<Vec<u8>>,
    pub salt_argument: Option<Vec<u8>>,
    pub salt_body: Option<Vec<u8>>,
}

impl DataClass {
    pub const fn sensitivity_rank(self) -> u8 {
        match self {
            Self::Structural => 0,
            Self::Derived => 1,
            Self::Identifier => 2,
            Self::Content => 3,
        }
    }

    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Identifier => "identifier",
            Self::Structural => "structural",
            Self::Derived => "derived",
            Self::Content => "content",
        }
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

impl ContentKind {
    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Argument => "argument",
            Self::Body => "body",
        }
    }
}

impl CommitmentClass {
    pub const ALL: [Self; 5] = [
        Self::Identifier,
        Self::Structural,
        Self::Derived,
        Self::ContentArgument,
        Self::ContentBody,
    ];

    pub const fn sensitivity_rank(self) -> u8 {
        match self {
            Self::Structural => 0,
            Self::Derived => 1,
            Self::Identifier => 2,
            Self::ContentArgument => 3,
            Self::ContentBody => 4,
        }
    }

    pub const fn wire_name(&self) -> &'static str {
        match self {
            Self::Structural => "structural",
            Self::Derived => "derived",
            Self::Identifier => "identifier",
            Self::ContentArgument => "content.argument",
            Self::ContentBody => "content.body",
        }
    }
}

impl PartialOrd for CommitmentClass {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for CommitmentClass {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.sensitivity_rank().cmp(&other.sensitivity_rank())
    }
}

impl AuditLane {
    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "event" | "events" => Some(Self::Event),
            "decision" | "decisions" => Some(Self::Decision),
            "spine" => Some(Self::Spine),
            "evidence" => Some(Self::Evidence),
            "discovery" => Some(Self::Discovery),
            "local-device" | "local_device" | "local" => Some(Self::LocalDevice),
            "bulk" => Some(Self::Bulk),
            _ => None,
        }
    }

    pub const fn as_str(&self) -> &'static str {
        match self {
            Self::Event => "event",
            Self::Decision => "decision",
            Self::Spine => "spine",
            Self::Evidence => "evidence",
            Self::Discovery => "discovery",
            Self::LocalDevice => "local-device",
            Self::Bulk => "bulk",
        }
    }
}

impl FiveWayCommitments {
    pub fn slot(&self, cls: CommitmentClass) -> (&str, Option<&[u8]>) {
        match cls {
            CommitmentClass::Identifier => (&self.d_identifier, self.salt_identifier.as_deref()),
            CommitmentClass::Structural => (&self.d_structural, self.salt_structural.as_deref()),
            CommitmentClass::Derived => (&self.d_derived, self.salt_derived.as_deref()),
            CommitmentClass::ContentArgument => (&self.d_argument, self.salt_argument.as_deref()),
            CommitmentClass::ContentBody => (&self.d_body, self.salt_body.as_deref()),
        }
    }
}

pub fn parse_brand_identity_toml(raw: &str) -> BrandIdentity {
    let mut in_identity = false;
    let mut namespace = String::new();
    let mut domain = String::new();
    for raw_line in raw.lines() {
        let trimmed = strip_toml_comment_quote_aware(raw_line).trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') && trimmed.ends_with(']') {
            in_identity = trimmed == "[identity]";
            continue;
        }
        if in_identity && let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim();
            let val = unquote_toml_scalar(v);
            if key == "namespace" {
                namespace = val;
            } else if key == "domain" {
                domain = val;
            }
        }
    }
    BrandIdentity { namespace, domain }
}

pub fn is_valid_brand_namespace(ns: &str) -> bool {
    let mut chars = ns.chars();
    matches!(chars.next(), Some('a'..='z'))
        && chars.all(|c| matches!(c, 'a'..='z' | '0'..='9' | '_'))
}

pub fn is_valid_brand_domain(domain: &str) -> bool {
    if domain.is_empty() || domain.len() > 253 {
        return false;
    }
    if domain == "localhost" {
        return true;
    }
    if !domain.contains('.') {
        return false;
    }
    domain.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|b| matches!(b, b'a'..=b'z' | b'0'..=b'9' | b'-'))
    })
}

pub fn is_valid_brand_identity(identity: &BrandIdentity) -> bool {
    is_valid_brand_namespace(&identity.namespace) && is_valid_brand_domain(&identity.domain)
}

pub fn brand_identity() -> BrandIdentity {
    parse_brand_identity_toml(BRAND_MANIFEST_RAW)
}

pub fn load_embedded_brand_display() -> Result<BrandDisplayStrings, String> {
    parse_brand_display_toml(BRAND_MANIFEST_RAW)
}

pub fn parse_brand_display_toml(raw: &str) -> Result<BrandDisplayStrings, String> {
    let mut section = String::new();
    let (mut id_prod, mut short_name, mut ns, mut disp_name, mut mac_label, mut win_dir) =
        (None, None, None, None, None, None);

    for (idx, raw_line) in raw.lines().enumerate() {
        let trimmed = strip_toml_comment_quote_aware(raw_line).trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Some(sec) = trimmed.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
            section = sec.trim().to_owned();
            continue;
        }
        let Some((raw_k, raw_v)) = trimmed.split_once('=') else {
            continue;
        };
        let key = raw_k.trim();
        let val_str = raw_v.trim();
        if !(val_str.starts_with('"') || val_str.starts_with('\'')) {
            continue;
        }
        let val = decode_toml_string(val_str).ok_or_else(|| {
            format!(
                "invalid TOML string on line {} for `{}.{key}`",
                idx.saturating_add(1),
                section
            )
        })?;
        match (section.as_str(), key) {
            ("identity", "product_name") => id_prod = Some(val),
            ("identity", "short_name") => short_name = Some(val),
            ("identity", "namespace") => ns = Some(val),
            ("os_identity", "macos_agent_label") => mac_label = Some(val),
            ("os_identity", "windows_program_dir") => win_dir = Some(val),
            ("display", "name") => disp_name = Some(val),
            _ => {}
        }
    }

    let product_name = disp_name
        .or(id_prod)
        .filter(|s| !s.is_empty())
        .ok_or_else(|| "brand manifest missing display.name or identity.product_name".to_owned())?;
    let short = short_name
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| product_name.clone());
    let namespace = ns
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "grdr".into());
    let macos_agent_label = mac_label
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| format!("local.{namespace}.agent"));
    let windows_program_dir = win_dir
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| product_name.clone());

    Ok(BrandDisplayStrings {
        product_name,
        short_name: short,
        namespace,
        macos_agent_label,
        windows_program_dir,
    })
}

fn decode_toml_string(raw: &str) -> Option<String> {
    if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        if inner
            .chars()
            .any(|c| c == '\'' || (c.is_control() && c != '\t'))
        {
            return None;
        }
        return Some(inner.to_owned());
    }
    let inner = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"'))?;
    let mut out = String::with_capacity(inner.len());
    let mut chars = inner.chars();
    while let Some(ch) = chars.next() {
        if ch == '"' || (ch.is_control() && ch != '\t') {
            return None;
        }
        if ch != '\\' {
            out.push(ch);
            continue;
        }
        match chars.next()? {
            'b' => out.push('\u{0008}'),
            't' => out.push('\t'),
            'n' => out.push('\n'),
            'f' => out.push('\u{000C}'),
            'r' => out.push('\r'),
            '"' => out.push('"'),
            '\\' => out.push('\\'),
            'u' => out.push(parse_hex_scalar(&mut chars, 4)?),
            'U' => out.push(parse_hex_scalar(&mut chars, 8)?),
            _ => return None,
        }
    }
    Some(out)
}

fn parse_hex_scalar(chars: &mut std::str::Chars<'_>, digits: usize) -> Option<char> {
    let mut hex = String::with_capacity(digits);
    for _ in 0..digits {
        hex.push(chars.next()?);
    }
    let code = u32::from_str_radix(&hex, 16).ok()?;
    char::from_u32(code)
}

pub fn schema_base_uri() -> String {
    let identity = brand_identity();
    let domain = if is_valid_brand_domain(&identity.domain) {
        identity.domain.as_str()
    } else {
        "localhost"
    };
    format!("https://{domain}/schemas/v1")
}

fn strip_toml_comment_quote_aware(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if ch == '\\' && quote == Some('"') {
            escaped = true;
            continue;
        }
        if let Some(q) = quote {
            if ch == q {
                quote = None;
            }
            continue;
        }
        if ch == '"' || ch == '\'' {
            quote = Some(ch);
            continue;
        }
        if ch == '#' {
            return line.get(..idx).unwrap_or(line);
        }
    }
    line
}

fn unquote_toml_scalar(raw: &str) -> String {
    let s = raw.trim();
    if let Some(inner) = s.strip_prefix('"').and_then(|v| v.strip_suffix('"'))
        && !inner.contains('"')
    {
        return inner.to_owned();
    }
    if let Some(inner) = s.strip_prefix('\'').and_then(|v| v.strip_suffix('\''))
        && !inner.contains('\'')
    {
        return inner.to_owned();
    }
    if s.starts_with('"') || s.starts_with('\'') || s.ends_with('"') || s.ends_with('\'') {
        return String::new();
    }
    s.to_owned()
}
