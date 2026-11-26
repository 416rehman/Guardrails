// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::Read;
use std::path::Path;

use grdr_crypto::hmac_sha256_hex;
use regex::Regex;
use serde::{Deserialize, Serialize};

use crate::IdentityError;
use crate::broker_types::{ContainmentStatus, CredentialClass};
use crate::locator_extract::{extract_public_part, glob_matches, normalize_path_slashes};
use crate::locator_parse::{parse_hygiene_yaml, parse_locators_yaml};

const MAX_YAML_BYTES: usize = 512 * 1024;
const MAX_SCAN_CONTENT_BYTES: usize = 256 * 1024;
const MAX_ARTIFACT_PATH_BYTES: usize = 4_096;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialStoreKind {
    Dotenv,
    PlaintextFile,
    IniProfile,
    JsonOauth,
    ServiceAccountJson,
    JsonTokenCache,
    DockerConfig,
    Kubeconfig,
    IniToken,
    Netrc,
    KeyringDir,
    PrivateKeyFile,
    YamlHosts,
    AgentStore,
    McpEnv,
    ShellProfile,
    Honeytoken,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum HygieneRuleId {
    H1,
    H2,
    H3,
    H4,
    H5,
    H6,
    H7,
    H8,
    H9,
    H10,
    H11,
    H12,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HygieneMode {
    Off,
    Watch,
    Ask,
    Block,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum HygieneSignal {
    LongLivedSetupToken,
    SharedWithHuman,
    FederationConfigured,
    SponsorMissing,
    UnauthenticatedLocalEndpoint,
    ModelModeDrifted,
    K8sAutomountSaToken,
}

#[derive(Debug, Clone)]
pub struct CredentialLocatorDef {
    pub id: String,
    pub credential_class: CredentialClass,
    pub store_kind: CredentialStoreKind,
    pub path_globs: Vec<String>,
    pub content_regex: Regex,
    pub prefix: String,
    pub length_class: String,
    pub public_part_extractor: String,
    pub readable_expiry: bool,
    pub honeytoken: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HygieneRuleDef {
    pub id: HygieneRuleId,
    pub name: String,
    pub default_mode: HygieneMode,
    pub finding_class: String,
    pub page: bool,
    pub requires: String,
    pub description: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactScanContext {
    pub artifact_path: String,
    pub readable_by_agent_lineages: Vec<String>,
    pub containment: ContainmentStatus,
    pub signals: BTreeSet<HygieneSignal>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct HygieneFinding {
    pub rule_id: HygieneRuleId,
    pub mode: HygieneMode,
    pub finding_class: String,
    pub page: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLocationFinding {
    pub crd_id: String,
    pub locator_id: String,
    pub credential_class: CredentialClass,
    pub store_kind: CredentialStoreKind,
    pub path_class: String,
    pub expiry_readable: bool,
    pub honeytoken: bool,
    pub readable_by: Vec<String>,
    pub hygiene_findings: Vec<HygieneFinding>,
}

#[derive(Debug, Clone)]
pub struct CredentialLocatorPack {
    locators: Vec<CredentialLocatorDef>,
    hygiene_rules: Vec<HygieneRuleDef>,
}

impl Default for ArtifactScanContext {
    fn default() -> Self {
        Self {
            artifact_path: String::new(),
            readable_by_agent_lineages: Vec::new(),
            containment: ContainmentStatus::Contained,
            signals: BTreeSet::new(),
        }
    }
}

impl CredentialLocatorPack {
    pub fn load_from_dir(pack_dir: &Path) -> Result<Self, IdentityError> {
        let loc_raw = read_bounded(&pack_dir.join("lists").join("locators.yaml"))?;
        let hyg_raw = read_bounded(&pack_dir.join("lists").join("hygiene-rules.yaml"))?;
        Self::from_yaml_strs(&loc_raw, &hyg_raw)
    }

    pub fn from_yaml_strs(locators_yaml: &str, hygiene_yaml: &str) -> Result<Self, IdentityError> {
        let locators = parse_locators_yaml(locators_yaml)?;
        let hygiene_rules = parse_hygiene_yaml(hygiene_yaml)?;
        if locators.is_empty() {
            return Err(IdentityError::LocatorPack(
                "credential locator pack must define at least one locator".to_string(),
            ));
        }
        Ok(Self {
            locators,
            hygiene_rules,
        })
    }

    pub fn locators(&self) -> &[CredentialLocatorDef] {
        &self.locators
    }

    pub fn hygiene_rules(&self) -> &[HygieneRuleDef] {
        &self.hygiene_rules
    }

    pub fn scan_artifact(
        &self,
        hmac_key: &[u8],
        content: &str,
        ctx: &ArtifactScanContext,
    ) -> Result<Option<CredentialLocationFinding>, IdentityError> {
        if ctx.artifact_path.len() > MAX_ARTIFACT_PATH_BYTES || ctx.artifact_path.contains('\0') {
            return Err(IdentityError::LocatorPack(
                "artifact path exceeds 4096 byte limit or contains NUL".to_string(),
            ));
        }
        if content.len() > MAX_SCAN_CONTENT_BYTES {
            return Err(IdentityError::LocatorPack(
                "artifact exceeds bounded scan byte limit".to_string(),
            ));
        }
        let norm_path = normalize_path_slashes(&ctx.artifact_path);
        let Some(loc) = self
            .locators
            .iter()
            .find(|l| l.path_globs.iter().any(|g| glob_matches(g, &norm_path)))
        else {
            return Ok(None);
        };

        let public_part = extract_public_part(&loc.public_part_extractor, &norm_path, content);
        let crd_digest = hmac_sha256_hex(hmac_key, format!("{}:{public_part}", loc.id).as_bytes());
        let crd_id = format!("crd_{}", crd_digest.get(..32).unwrap_or(&crd_digest));
        let has_secret_shape = loc.content_regex.is_match(content);
        let unencrypted_ssh = loc.store_kind == CredentialStoreKind::PrivateKeyFile
            && has_secret_shape
            && !content.contains("ENCRYPTED");
        let triggered = collect_triggered_hygiene(loc, ctx, has_secret_shape, unencrypted_ssh);

        let hygiene_findings = triggered
            .into_iter()
            .filter_map(|id| self.hygiene_rules.iter().find(|r| r.id == id))
            .map(|r| HygieneFinding {
                rule_id: r.id,
                mode: r.default_mode,
                finding_class: r.finding_class.clone(),
                page: r.page,
            })
            .collect();

        Ok(Some(CredentialLocationFinding {
            crd_id,
            locator_id: loc.id.clone(),
            credential_class: loc.credential_class,
            store_kind: loc.store_kind,
            path_class: loc.length_class.clone(),
            expiry_readable: loc.readable_expiry,
            honeytoken: loc.honeytoken,
            readable_by: ctx.readable_by_agent_lineages.clone(),
            hygiene_findings,
        }))
    }
}

fn collect_triggered_hygiene(
    loc: &CredentialLocatorDef,
    ctx: &ArtifactScanContext,
    has_secret_shape: bool,
    unencrypted_ssh: bool,
) -> Vec<HygieneRuleId> {
    let mut out = Vec::new();
    let has_sig = |sig| ctx.signals.contains(&sig);
    if has_sig(HygieneSignal::LongLivedSetupToken) {
        out.push(HygieneRuleId::H1);
    }
    if has_secret_shape && !ctx.readable_by_agent_lineages.is_empty() {
        out.push(HygieneRuleId::H2);
    }
    if loc.store_kind == CredentialStoreKind::McpEnv && has_secret_shape {
        out.push(HygieneRuleId::H3);
    }
    if unencrypted_ssh {
        out.push(HygieneRuleId::H4);
    }
    if loc.store_kind == CredentialStoreKind::ShellProfile && has_secret_shape {
        out.push(HygieneRuleId::H5);
    }
    if loc.credential_class == CredentialClass::Cloud
        && has_sig(HygieneSignal::FederationConfigured)
        && has_secret_shape
    {
        out.push(HygieneRuleId::H6);
    }
    if has_sig(HygieneSignal::UnauthenticatedLocalEndpoint) {
        out.push(HygieneRuleId::H7);
    }
    if has_sig(HygieneSignal::SharedWithHuman) && !ctx.readable_by_agent_lineages.is_empty() {
        out.push(HygieneRuleId::H8);
    }
    if has_sig(HygieneSignal::SponsorMissing) {
        out.push(HygieneRuleId::H9);
    }
    if loc.credential_class == CredentialClass::Production
        && ctx.containment == ContainmentStatus::Uncontained
        && !ctx.readable_by_agent_lineages.is_empty()
    {
        out.push(HygieneRuleId::H10);
    }
    if has_sig(HygieneSignal::ModelModeDrifted) {
        out.push(HygieneRuleId::H11);
    }
    if has_sig(HygieneSignal::K8sAutomountSaToken) {
        out.push(HygieneRuleId::H12);
    }
    out
}

fn read_bounded(path: &Path) -> Result<String, IdentityError> {
    let meta = fs::symlink_metadata(path).map_err(|e| {
        IdentityError::LocatorPack(format!("cannot stat `{}`: {e}", path.display()))
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(IdentityError::LocatorPack(format!(
            "locator pack `{}` must be a regular non-symlink file",
            path.display()
        )));
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0400;
        if (meta.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT) != 0 {
            return Err(IdentityError::LocatorPack(format!(
                "locator pack `{}` reparse point forbidden",
                path.display()
            )));
        }
    }
    let mut opts = OpenOptions::new();
    opts.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.custom_flags(libc::O_NOFOLLOW);
    }
    let file = opts.open(path).map_err(|e| {
        IdentityError::LocatorPack(format!("cannot open `{}`: {e}", path.display()))
    })?;
    let cap = u64::try_from(MAX_YAML_BYTES.saturating_add(1)).unwrap_or(u64::MAX);
    let mut raw_bytes = Vec::new();
    file.take(cap).read_to_end(&mut raw_bytes).map_err(|e| {
        IdentityError::LocatorPack(format!("cannot read `{}`: {e}", path.display()))
    })?;
    if raw_bytes.len() > MAX_YAML_BYTES {
        return Err(IdentityError::LocatorPack(format!(
            "locator pack `{}` exceeds max byte size",
            path.display()
        )));
    }
    String::from_utf8(raw_bytes).map_err(|e| {
        IdentityError::LocatorPack(format!("invalid UTF-8 in `{}`: {e}", path.display()))
    })
}
