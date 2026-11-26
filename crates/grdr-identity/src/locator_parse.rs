// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use regex::Regex;

use crate::IdentityError;
use crate::broker_types::CredentialClass;
use crate::locator::{
    CredentialLocatorDef, CredentialStoreKind, HygieneMode, HygieneRuleDef, HygieneRuleId,
};

struct RawLocatorBuilder {
    id: String,
    credential_class: Option<CredentialClass>,
    store_kind: Option<CredentialStoreKind>,
    path_globs: Vec<String>,
    content_regex: String,
    prefix: String,
    length_class: String,
    public_part_extractor: String,
    readable_expiry: bool,
    honeytoken: bool,
}

impl RawLocatorBuilder {
    fn new(id: String) -> Result<Self, IdentityError> {
        if id.trim().is_empty() {
            return Err(IdentityError::LocatorPack(
                "locator entry has empty id".to_string(),
            ));
        }
        Ok(Self {
            id,
            credential_class: None,
            store_kind: None,
            path_globs: Vec::new(),
            content_regex: String::new(),
            prefix: String::new(),
            length_class: String::new(),
            public_part_extractor: "file_basename".to_string(),
            readable_expiry: false,
            honeytoken: false,
        })
    }

    fn assign(&mut self, key: &str, val: String) -> Result<(), IdentityError> {
        match key {
            "credential_class" => self.credential_class = Some(parse_cred_class(&val)?),
            "store_kind" => self.store_kind = Some(parse_store_kind(&val)?),
            "content_regex" => self.content_regex = val,
            "prefix" => self.prefix = val,
            "length_class" => self.length_class = val,
            "public_part_extractor" => {
                validate_extractor(&val)?;
                self.public_part_extractor = val;
            }
            "readable_expiry" => self.readable_expiry = parse_bool(&val, key)?,
            "honeytoken" => self.honeytoken = parse_bool(&val, key)?,
            other => {
                return Err(IdentityError::LocatorPack(format!(
                    "unknown locator key `{other}` in `{}`",
                    self.id
                )));
            }
        }
        Ok(())
    }

    fn build(self) -> Result<CredentialLocatorDef, IdentityError> {
        if self.path_globs.is_empty() || self.path_globs.iter().any(|g| g.trim().is_empty()) {
            return Err(IdentityError::LocatorPack(format!(
                "locator `{}` requires non-empty path_globs",
                self.id
            )));
        }
        if self.content_regex.trim().is_empty() {
            return Err(IdentityError::LocatorPack(format!(
                "locator `{}` requires non-empty content_regex",
                self.id
            )));
        }
        validate_extractor(&self.public_part_extractor)?;
        let re = Regex::new(&self.content_regex).map_err(|e| {
            IdentityError::LocatorPack(format!("invalid locator regex for `{}`: {e}", self.id))
        })?;
        Ok(CredentialLocatorDef {
            id: self.id,
            credential_class: self.credential_class.ok_or_else(|| {
                IdentityError::LocatorPack("locator missing credential_class".to_string())
            })?,
            store_kind: self.store_kind.ok_or_else(|| {
                IdentityError::LocatorPack("locator missing store_kind".to_string())
            })?,
            path_globs: self.path_globs,
            content_regex: re,
            prefix: self.prefix,
            length_class: self.length_class,
            public_part_extractor: self.public_part_extractor,
            readable_expiry: self.readable_expiry,
            honeytoken: self.honeytoken,
        })
    }
}

pub(crate) fn parse_locators_yaml(raw: &str) -> Result<Vec<CredentialLocatorDef>, IdentityError> {
    let mut items = Vec::new();
    let mut cur: Option<RawLocatorBuilder> = None;
    let mut in_path_globs = false;

    for (line_idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- id:") {
            if let Some(prev) = cur.take() {
                items.push(prev.build()?);
            }
            cur = Some(RawLocatorBuilder::new(unquote(rest))?);
            in_path_globs = false;
            continue;
        }
        let Some(builder) = cur.as_mut() else {
            let key = trimmed.split(':').next().unwrap_or("").trim();
            if matches!(key, "format" | "pack_id" | "locators") {
                continue;
            }
            return Err(IdentityError::LocatorPack(format!(
                "unexpected header key `{key}` at locator line {}",
                line_idx.saturating_add(1)
            )));
        };
        if trimmed == "path_globs:" {
            in_path_globs = true;
            continue;
        }
        if in_path_globs && let Some(glob) = trimmed.strip_prefix("- ") {
            builder.path_globs.push(unquote(glob));
            continue;
        }
        in_path_globs = false;
        let Some((k, v)) = trimmed.split_once(':') else {
            return Err(IdentityError::LocatorPack(format!(
                "malformed YAML line {} in locators",
                line_idx.saturating_add(1)
            )));
        };
        builder.assign(k.trim(), unquote(v))?;
    }
    if let Some(last) = cur.take() {
        items.push(last.build()?);
    }
    Ok(items)
}

pub(crate) fn parse_hygiene_yaml(raw: &str) -> Result<Vec<HygieneRuleDef>, IdentityError> {
    let mut rules = Vec::new();
    let mut cur: Option<HygieneRuleDef> = None;

    for (line_idx, line) in raw.lines().enumerate() {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        if let Some(rest) = trimmed.strip_prefix("- id:") {
            if let Some(prev) = cur.take() {
                validate_hygiene_rule(&prev)?;
                rules.push(prev);
            }
            let id = parse_hygiene_id(&unquote(rest))?;
            cur = Some(HygieneRuleDef {
                id,
                name: String::new(),
                default_mode: HygieneMode::Watch,
                finding_class: "policy_violation".to_string(),
                page: false,
                requires: "sensor".to_string(),
                description: String::new(),
            });
            continue;
        }
        let Some(rule) = cur.as_mut() else {
            let key = trimmed.split(':').next().unwrap_or("").trim();
            if matches!(key, "format" | "pack_id" | "rules") {
                continue;
            }
            return Err(IdentityError::LocatorPack(format!(
                "unexpected header key `{key}` at hygiene line {}",
                line_idx.saturating_add(1)
            )));
        };
        let Some((k, v)) = trimmed.split_once(':') else {
            return Err(IdentityError::LocatorPack(format!(
                "malformed YAML line {} in hygiene rules",
                line_idx.saturating_add(1)
            )));
        };
        let val = unquote(v);
        match k.trim() {
            "name" => rule.name = val,
            "default_mode" => rule.default_mode = parse_hygiene_mode(&val)?,
            "finding_class" => rule.finding_class = val,
            "page" => rule.page = parse_bool(&val, "page")?,
            "requires" => rule.requires = val,
            "description" => rule.description = val,
            other => {
                return Err(IdentityError::LocatorPack(format!(
                    "unknown hygiene rule key `{other}`"
                )));
            }
        }
    }
    if let Some(last) = cur.take() {
        validate_hygiene_rule(&last)?;
        rules.push(last);
    }
    Ok(rules)
}

fn validate_hygiene_rule(rule: &HygieneRuleDef) -> Result<(), IdentityError> {
    if rule.name.trim().is_empty() || rule.description.trim().is_empty() {
        return Err(IdentityError::LocatorPack(format!(
            "hygiene rule {:?} requires non-empty name and description",
            rule.id
        )));
    }
    Ok(())
}

fn validate_extractor(raw: &str) -> Result<(), IdentityError> {
    match raw {
        "key_name" | "url_host_and_user" | "access_key_prefix" | "json_client_id"
        | "json_client_email" | "registry_host" | "cluster_context" | "yaml_host_user"
        | "json_account_uuid" | "file_basename" => Ok(()),
        other => Err(IdentityError::LocatorPack(format!(
            "unknown public_part_extractor `{other}`"
        ))),
    }
}

fn parse_bool(raw: &str, key: &str) -> Result<bool, IdentityError> {
    match raw {
        "true" => Ok(true),
        "false" => Ok(false),
        other => Err(IdentityError::LocatorPack(format!(
            "invalid boolean `{other}` for `{key}`"
        ))),
    }
}

fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.len() >= 2
        && ((trimmed.starts_with('"') && trimmed.ends_with('"'))
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')))
    {
        return trimmed
            .get(1..trimmed.len().saturating_sub(1))
            .unwrap_or_default()
            .replace("''", "'");
    }
    trimmed.to_string()
}

fn parse_cred_class(raw: &str) -> Result<CredentialClass, IdentityError> {
    match raw {
        "model" => Ok(CredentialClass::Model),
        "cloud" => Ok(CredentialClass::Cloud),
        "forge" => Ok(CredentialClass::Forge),
        "ssh" => Ok(CredentialClass::Ssh),
        "publish" => Ok(CredentialClass::Publish),
        "production" => Ok(CredentialClass::Production),
        other => Err(IdentityError::LocatorPack(format!(
            "unknown credential_class `{other}`"
        ))),
    }
}

fn parse_store_kind(raw: &str) -> Result<CredentialStoreKind, IdentityError> {
    match raw {
        "dotenv" => Ok(CredentialStoreKind::Dotenv),
        "plaintext_file" => Ok(CredentialStoreKind::PlaintextFile),
        "ini_profile" => Ok(CredentialStoreKind::IniProfile),
        "json_oauth" => Ok(CredentialStoreKind::JsonOauth),
        "service_account_json" => Ok(CredentialStoreKind::ServiceAccountJson),
        "json_token_cache" => Ok(CredentialStoreKind::JsonTokenCache),
        "docker_config" => Ok(CredentialStoreKind::DockerConfig),
        "kubeconfig" => Ok(CredentialStoreKind::Kubeconfig),
        "ini_token" => Ok(CredentialStoreKind::IniToken),
        "netrc" => Ok(CredentialStoreKind::Netrc),
        "keyring_dir" => Ok(CredentialStoreKind::KeyringDir),
        "private_key_file" => Ok(CredentialStoreKind::PrivateKeyFile),
        "yaml_hosts" => Ok(CredentialStoreKind::YamlHosts),
        "agent_store" => Ok(CredentialStoreKind::AgentStore),
        "mcp_env" => Ok(CredentialStoreKind::McpEnv),
        "shell_profile" => Ok(CredentialStoreKind::ShellProfile),
        "honeytoken" => Ok(CredentialStoreKind::Honeytoken),
        other => Err(IdentityError::LocatorPack(format!(
            "unknown store_kind `{other}`"
        ))),
    }
}

fn parse_hygiene_id(raw: &str) -> Result<HygieneRuleId, IdentityError> {
    match raw {
        "H1" => Ok(HygieneRuleId::H1),
        "H2" => Ok(HygieneRuleId::H2),
        "H3" => Ok(HygieneRuleId::H3),
        "H4" => Ok(HygieneRuleId::H4),
        "H5" => Ok(HygieneRuleId::H5),
        "H6" => Ok(HygieneRuleId::H6),
        "H7" => Ok(HygieneRuleId::H7),
        "H8" => Ok(HygieneRuleId::H8),
        "H9" => Ok(HygieneRuleId::H9),
        "H10" => Ok(HygieneRuleId::H10),
        "H11" => Ok(HygieneRuleId::H11),
        "H12" => Ok(HygieneRuleId::H12),
        other => Err(IdentityError::LocatorPack(format!(
            "unknown hygiene rule `{other}`"
        ))),
    }
}

fn parse_hygiene_mode(raw: &str) -> Result<HygieneMode, IdentityError> {
    match raw {
        "Off" | "off" => Ok(HygieneMode::Off),
        "Watch" | "watch" => Ok(HygieneMode::Watch),
        "Ask" | "ask" => Ok(HygieneMode::Ask),
        "Block" | "block" => Ok(HygieneMode::Block),
        other => Err(IdentityError::LocatorPack(format!(
            "unknown hygiene mode `{other}`"
        ))),
    }
}
