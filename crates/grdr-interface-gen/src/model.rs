// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;
use std::path::PathBuf;

use serde::Deserialize;
use thiserror::Error;

use crate::toml_doc::TomlParseError;

/// Typed errors emitted by `grdr-interface-gen` (`GRDR-GEN-*`).
#[derive(Debug, Error)]
pub enum GenError {
    #[error("GRDR-GEN-0001: failed reading {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("GRDR-GEN-0002: failed parsing TOML {path}: {source}")]
    Toml {
        path: PathBuf,
        #[source]
        source: TomlParseError,
    },
    #[error("GRDR-GEN-0003: failed parsing JSON {path}: {source}")]
    Json {
        path: PathBuf,
        #[source]
        source: serde_json::Error,
    },
    #[error("GRDR-GEN-0004: invalid interface schema in {file}: {detail}")]
    Validation { file: String, detail: String },
    #[error("GRDR-GEN-0005: unresolved token reference '{reference}'")]
    UnresolvedTokenRef { reference: String },
    #[error("GRDR-GEN-0006: generated artifacts out of sync ({count} file(s)): {files}")]
    Drift { count: usize, files: String },
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrandSpec {
    pub product_name: String,
    pub short_name: String,
    pub accent: String,
    pub accent_dark: String,
    pub surface_light: String,
    pub surface_dark: String,
    pub font_sans: String,
    pub font_mono: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IconSpec {
    pub key: String,
    pub lucide: String,
    pub mirror: bool,
    pub same_as: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct HarnessIconSpec {
    pub id: String,
    pub display_name: String,
    pub vendor: String,
    pub kind: String,
    pub aliases: Vec<String>,
    pub simple_icon: String,
    pub lucide: String,
    pub tone: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct OsIconSpec {
    pub id: String,
    pub display_name: String,
    pub aliases: Vec<String>,
    pub simple_icon: String,
    pub lucide: String,
    pub tone: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IconCatalogSpec {
    pub icons: Vec<IconSpec>,
    pub harnesses: Vec<HarnessIconSpec>,
    pub operating_systems: Vec<OsIconSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PresentationSpec {
    pub enum_name: String,
    pub value: String,
    pub label: String,
    pub description: Option<String>,
    pub icon: String,
    pub tone: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct RouteSpec {
    pub id: String,
    pub title: String,
    pub icon: String,
    pub area: String,
    pub scopes: Vec<String>,
    pub requires: String,
    pub path: String,
    pub shell_nav: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LocaleSpec {
    pub tag: String,
    pub rust_variant: String,
    pub native_name: String,
    pub tier: String,
    pub script: String,
    pub direction: String,
    pub fallback: String,
    pub aliases: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MessageSpec {
    pub id: String,
    pub namespace: String,
    pub rust_variant: Option<String>,
    pub desc: String,
    pub max: Option<i64>,
    pub risk: String,
    pub msg: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TranslationCatalog {
    pub locale_tag: String,
    pub entries: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VocabularyTerm {
    pub key: String,
    pub term: String,
    pub translate: bool,
    pub desc: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ForbiddenTerm {
    pub word: String,
    pub replacement: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct VocabularySpec {
    pub brand_name: String,
    pub brand_short_name: String,
    pub terms: Vec<VocabularyTerm>,
    pub forbidden: Vec<ForbiddenTerm>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliExitCodeSpec {
    pub code: i64,
    pub name: String,
    pub desc: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliCommandSpec {
    pub name: String,
    pub kind: String,
    pub verbs: Vec<String>,
    pub desc: String,
    pub flags: Vec<String>,
    pub agent_callable: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CliSpec {
    pub schema: String,
    pub exit_codes: Vec<CliExitCodeSpec>,
    pub commands: Vec<CliCommandSpec>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ShortcutSpec {
    pub action: String,
    pub scope: String,
    pub keys: String,
    pub macos_keys: String,
    pub desc: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NotificationSpec {
    pub class: String,
    pub channels: Vec<String>,
    pub dedup_window_secs: i64,
    pub quiet_hours: bool,
    pub tone: String,
    pub icon: String,
    pub title_token: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ScriptTypographySpec {
    pub font_sans: String,
    pub min_font_size_px: u32,
    pub line_height_step: f32,
    pub allow_italic: bool,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct BaseTokensFile {
    pub meta: TokensMeta,
    pub typography: TypographyTokens,
    pub radius: RadiusTokens,
    pub light: BTreeMap<String, String>,
    pub dark: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TokensMeta {
    pub name: String,
    pub version: String,
    pub spacing_base_px: u32,
    pub spacing_scale: Vec<u32>,
}

#[derive(Clone, Debug, Deserialize)]
pub struct TypographyTokens {
    pub sans: String,
    pub mono: String,
}

#[derive(Clone, Debug, Deserialize)]
pub struct RadiusTokens {
    pub sm: String,
    pub md: String,
    pub lg: String,
    pub pill: String,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExtendedTokensFile {
    pub font_imports: Vec<String>,
    #[serde(default)]
    pub scripts: BTreeMap<String, ScriptTypographySpec>,
    pub spacing: BTreeMap<String, String>,
    pub motion: MotionTokens,
    pub light: BTreeMap<String, String>,
    pub dark: BTreeMap<String, String>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct MotionTokens {
    pub quick_ms: u32,
    pub standard_ms: u32,
    pub emphasis_ms: u32,
    pub approval_arm_default_ms: u32,
    pub approval_arm_irreversible_ms: u32,
}

#[derive(Clone, Debug)]
pub struct TokenBundle {
    pub base: BaseTokensFile,
    pub extended: ExtendedTokensFile,
    pub light_resolved: BTreeMap<String, String>,
    pub dark_resolved: BTreeMap<String, String>,
}

#[derive(Clone, Debug)]
pub struct InterfaceBundle {
    pub brand: BrandSpec,
    pub tokens: TokenBundle,
    pub locales: Vec<LocaleSpec>,
    pub messages: Vec<MessageSpec>,
    pub translations: Vec<TranslationCatalog>,
    pub vocabulary: VocabularySpec,
    pub icons: Vec<IconSpec>,
    pub harness_icons: Vec<HarnessIconSpec>,
    pub os_icons: Vec<OsIconSpec>,
    pub presentations: Vec<PresentationSpec>,
    pub routes: Vec<RouteSpec>,
    pub cli: Option<CliSpec>,
    pub shortcuts: Vec<ShortcutSpec>,
    pub notifications: Vec<NotificationSpec>,
}
