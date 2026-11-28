// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Pass 4 bespoke agent TOML declarations, CycloneDX 1.7 / OCSF 5020 ABOM export, and ABOM diff (`docs/design/05`).

use std::collections::{BTreeMap, BTreeSet};

use grdr_core::discover::{IdentityHints, ProgramIdentity};
use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::abom::{AgentBom, AgentDeclaration, DiffState};
use crate::catalogue::validate_slug_id;

const MIN_EXPORT_SALT_BYTES: usize = 32;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum IdentityProofLevel {
    SelfAsserted,
    Attested,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeclaredToolSpec {
    pub name: String,
    pub action_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentDeclarationToml {
    pub schema: String,
    pub slug: String,
    pub sponsor_team: String,
    pub identity: ProgramIdentity,
    pub session_exclusive: bool,
    pub tools: Vec<DeclaredToolSpec>,
    pub mcp_servers: Vec<String>,
    pub model_endpoints: Vec<String>,
    pub credential_mode: String,
    pub expected_children: Vec<String>,
    pub expected_children_inert: bool,
    pub identity_proof: IdentityProofLevel,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum AbomChangeKind {
    Added,
    Removed,
    Changed,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AbomDiffEntry {
    pub agent_id: String,
    pub kind: AbomChangeKind,
    pub before_program_id: Option<String>,
    pub after_program_id: Option<String>,
}

impl AgentDeclarationToml {
    #[must_use]
    pub fn to_agent_declaration(&self) -> AgentDeclaration {
        let mut allowed_hosts = BTreeSet::new();
        for url in &self.model_endpoints {
            let trimmed = url
                .trim()
                .strip_prefix("https://")
                .or_else(|| url.trim().strip_prefix("http://"))
                .unwrap_or(url.trim());
            let before_query = trimmed.split(['?', '#']).next().unwrap_or("");
            let authority = before_query.split('/').next().unwrap_or("");
            let host = authority.rsplit('@').next().unwrap_or("").trim();
            if !host.is_empty() {
                allowed_hosts.insert(host.to_ascii_lowercase());
            }
        }
        AgentDeclaration {
            agent_id: self.slug.clone(),
            expected_program_id: Some(self.identity.canonical_id()),
            expected_signer: None,
            allowed_hosts,
            approved_artifacts: BTreeMap::new(),
        }
    }
}

pub fn parse_grdr_agent_toml(raw: &str) -> Result<AgentDeclarationToml, CodedError> {
    let mut fields: BTreeMap<String, String> = BTreeMap::new();
    let mut in_root = true;
    for line in raw.lines() {
        let no_comment = strip_toml_comment(line);
        let trimmed = no_comment.trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') {
            in_root = false;
            continue;
        }
        if !in_root {
            continue;
        }
        if let Some((k, v)) = trimmed.split_once('=') {
            fields.insert(k.trim().to_owned(), v.trim().to_owned());
        }
    }
    let schema = unquote_toml(
        fields
            .get("schema")
            .ok_or_else(|| abom_err("missing `schema` in grdr-agent.toml"))?,
    );
    if schema != "grdr.agent/v1alpha1" {
        return Err(abom_err(format!(
            "unsupported declaration schema `{schema}`"
        )));
    }
    let slug = unquote_toml(
        fields
            .get("slug")
            .ok_or_else(|| abom_err("missing `slug` in grdr-agent.toml"))?,
    );
    validate_slug_id(&slug, "GRDR-AGENTS-0005")?;
    let sponsor_team = unquote_toml(
        fields
            .get("sponsor_team")
            .ok_or_else(|| abom_err("missing `sponsor_team` in grdr-agent.toml"))?,
    );
    validate_toml_text("sponsor_team", &sponsor_team)?;
    if sponsor_team.is_empty() {
        return Err(abom_err("sponsor_team must be non-empty team slug"));
    }
    let id_raw = fields
        .get("identity")
        .ok_or_else(|| abom_err("missing `identity` in grdr-agent.toml"))?;
    let identity = parse_inline_identity(id_raw)?;
    let session_exclusive = fields
        .get("session_exclusive")
        .is_some_and(|v| v.trim() == "true");
    let credential_mode = fields
        .get("credential_mode")
        .map(|s| unquote_toml(s))
        .unwrap_or_else(|| "none".into());
    validate_toml_text("credential_mode", &credential_mode)?;
    let mcp_servers = fields
        .get("mcp_servers")
        .map(|s| parse_toml_str_array(s))
        .unwrap_or_default();
    for item in &mcp_servers {
        validate_toml_text("mcp_servers", item)?;
    }
    let model_endpoints = fields
        .get("model_endpoints")
        .map(|s| parse_toml_str_array(s))
        .unwrap_or_default();
    for item in &model_endpoints {
        validate_toml_text("model_endpoints", item)?;
    }
    let expected_children = fields
        .get("expected_children")
        .map(|s| parse_toml_str_array(s))
        .unwrap_or_default();
    for item in &expected_children {
        validate_toml_text("expected_children", item)?;
    }
    let tools = fields
        .get("tools")
        .map(|s| parse_toml_tools(s))
        .unwrap_or_default();
    for tool in &tools {
        validate_toml_text("tools.name", &tool.name)?;
        validate_toml_text("tools.action_class", &tool.action_class)?;
    }

    Ok(AgentDeclarationToml {
        schema,
        slug,
        sponsor_team,
        identity,
        session_exclusive,
        tools,
        mcp_servers,
        model_endpoints,
        credential_mode,
        expected_children,
        // expected_children stays inert until triage confirms the declaration.
        expected_children_inert: true,
        identity_proof: IdentityProofLevel::SelfAsserted,
    })
}

pub fn export_cyclonedx_1_7(abom: &AgentBom, org_salt: &[u8]) -> Result<Value, CodedError> {
    validate_export_salt(org_salt)?;
    let device_pseudonym =
        pseudonymize_abom_token(org_salt, "grdr.abom.device.v1", "dev", &abom.device_id);
    let serial = format!(
        "urn:uuid:00000000-0000-4000-8000-{}",
        abom.bom_digest.get(..12).unwrap_or("000000000000")
    );
    let components: Vec<Value> = abom
        .components
        .iter()
        .map(|c| {
            let safe_program_id = redact_private_program_id(org_salt, &c.program_id);
            json!({
                "type": "application",
                "bom-ref": safe_program_id,
                "name": c.agent_id,
                "properties": [
                    { "name": "grdr:program_id", "value": safe_program_id },
                    { "name": "grdr:diff_state", "value": format!("{:?}", c.diff_state) },
                    { "name": "grdr:artifact_count", "value": c.artifact_digests.len().to_string() }
                ]
            })
        })
        .collect();
    Ok(json!({
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": serial,
        "version": 1,
        "metadata": {
            "component": {
                "type": "device",
                "name": device_pseudonym,
                "bom-ref": format!("device:{device_pseudonym}"),
            }
        },
        "components": components,
        "dependencies": []
    }))
}

pub fn export_ocsf_5020(abom: &AgentBom, org_salt: &[u8]) -> Result<Value, CodedError> {
    validate_export_salt(org_salt)?;
    let device_pseudonym =
        pseudonymize_abom_token(org_salt, "grdr.abom.device.v1", "dev", &abom.device_id);
    let resources: Vec<Value> = abom
        .components
        .iter()
        .map(|c| {
            let safe_program_id = redact_private_program_id(org_salt, &c.program_id);
            json!({
                "uid": safe_program_id,
                "name": c.agent_id,
                "type": "Agent",
                "data": {
                    "diff_state": format!("{:?}", c.diff_state),
                    "drift_count": c.drift_kinds.len(),
                    "matched": c.diff_state == DiffState::DeclaredAndRunning
                        || c.diff_state == DiffState::DeclaredAndInstalled,
                }
            })
        })
        .collect();
    Ok(json!({
        "class_uid": 5020,
        "category_uid": 5,
        "activity_id": 2,
        "device": { "uid": device_pseudonym },
        "resources": resources,
        "metadata": {
            "version": "1.3.0",
            "product": { "name": "grdr", "uid": abom.bom_digest }
        }
    }))
}

#[must_use]
pub fn diff_agent_boms(before: &AgentBom, after: &AgentBom) -> Vec<AbomDiffEntry> {
    let b_map: BTreeMap<&str, &crate::abom::AbomComponent> = before
        .components
        .iter()
        .map(|c| (c.agent_id.as_str(), c))
        .collect();
    let a_map: BTreeMap<&str, &crate::abom::AbomComponent> = after
        .components
        .iter()
        .map(|c| (c.agent_id.as_str(), c))
        .collect();
    let all: BTreeSet<&str> = b_map.keys().chain(a_map.keys()).copied().collect();
    let mut diffs = Vec::new();
    for id in all {
        match (b_map.get(id), a_map.get(id)) {
            (None, Some(a)) => diffs.push(AbomDiffEntry {
                agent_id: id.into(),
                kind: AbomChangeKind::Added,
                before_program_id: None,
                after_program_id: Some(a.program_id.clone()),
            }),
            (Some(b), None) => diffs.push(AbomDiffEntry {
                agent_id: id.into(),
                kind: AbomChangeKind::Removed,
                before_program_id: Some(b.program_id.clone()),
                after_program_id: None,
            }),
            (Some(b), Some(a)) if b != a => diffs.push(AbomDiffEntry {
                agent_id: id.into(),
                kind: AbomChangeKind::Changed,
                before_program_id: Some(b.program_id.clone()),
                after_program_id: Some(a.program_id.clone()),
            }),
            _ => {}
        }
    }
    diffs
}

fn parse_inline_identity(raw: &str) -> Result<ProgramIdentity, CodedError> {
    let trimmed = raw.trim();
    let Some(inner) = trimmed.strip_prefix('{').and_then(|s| s.strip_suffix('}')) else {
        return Err(abom_err("identity must be an inline TOML table `{ ... }`"));
    };
    let mut hints = IdentityHints::default();
    let mut parsed_count = 0usize;
    for pair in split_outside_quotes(inner, ',') {
        if let Some((k, v)) = pair.split_once('=') {
            let val = unquote_toml(v);
            if val.is_empty() {
                continue;
            }
            match k.trim() {
                "pkg" => {
                    if let Some((eco, pkg)) = val.split_once(':')
                        && !eco.trim().is_empty()
                        && !pkg.trim().is_empty()
                    {
                        hints.ecosystem = Some(eco.trim().into());
                        hints.package_name = Some(pkg.trim().into());
                        parsed_count = parsed_count.saturating_add(1);
                    }
                }
                "src" => {
                    hints.workspace_id = Some(val);
                    hints.tree_digest = Some("declared".into());
                    parsed_count = parsed_count.saturating_add(1);
                }
                "sig" => {
                    hints.code_signer = Some(val);
                    hints.binary_digest = Some("declared".into());
                    parsed_count = parsed_count.saturating_add(1);
                }
                _ => {}
            }
        }
    }
    if parsed_count == 0 {
        return Err(abom_err(
            "identity table must contain at least one non-empty `pkg`, `src`, or `sig` key",
        ));
    }
    Ok(ProgramIdentity::from_hints(&hints))
}

fn parse_toml_str_array(raw: &str) -> Vec<String> {
    let trimmed = raw.trim();
    let inner = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .unwrap_or(trimmed);
    split_outside_quotes(inner, ',')
        .into_iter()
        .map(unquote_toml)
        .filter(|s| !s.is_empty())
        .collect()
}

fn parse_toml_tools(raw: &str) -> Vec<DeclaredToolSpec> {
    let mut tools = Vec::new();
    for segment in raw.split('{').skip(1) {
        let body = segment.split('}').next().unwrap_or("");
        let mut name = String::new();
        let mut action_class = String::new();
        for pair in split_outside_quotes(body, ',') {
            if let Some((k, v)) = pair.split_once('=') {
                match k.trim() {
                    "name" => name = unquote_toml(v),
                    "action_class" => action_class = unquote_toml(v),
                    _ => {}
                }
            }
        }
        if !name.is_empty() && !action_class.is_empty() {
            tools.push(DeclaredToolSpec { name, action_class });
        }
    }
    tools
}

fn strip_toml_comment(line: &str) -> &str {
    let mut quote: Option<char> = None;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            escaped = true;
            continue;
        }
        if quote.is_none() && (ch == '"' || ch == '\'') {
            quote = Some(ch);
        } else if quote == Some(ch) {
            quote = None;
        } else if ch == '#' && quote.is_none() {
            return line.get(..idx).unwrap_or(line);
        }
    }
    line
}

fn split_outside_quotes(raw: &str, delim: char) -> Vec<&str> {
    let mut out = Vec::new();
    let mut quote: Option<char> = None;
    let mut escaped = false;
    let mut start = 0usize;
    for (idx, ch) in raw.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        if quote == Some('"') && ch == '\\' {
            escaped = true;
            continue;
        }
        if quote.is_none() && (ch == '"' || ch == '\'') {
            quote = Some(ch);
        } else if quote == Some(ch) {
            quote = None;
        } else if ch == delim && quote.is_none() {
            if let Some(piece) = raw.get(start..idx) {
                out.push(piece);
            }
            start = idx.saturating_add(ch.len_utf8());
        }
    }
    if let Some(tail) = raw.get(start..) {
        out.push(tail);
    }
    out
}

fn validate_toml_text(field: &str, value: &str) -> Result<(), CodedError> {
    if value.chars().any(is_unsafe_control_or_bidi) {
        return Err(abom_err(format!(
            "field `{field}` contains forbidden control or bidirectional override characters"
        )));
    }
    Ok(())
}

fn is_unsafe_control_or_bidi(ch: char) -> bool {
    ch.is_control()
        || matches!(
            ch,
            '\u{200E}' | '\u{200F}' | '\u{202A}'..='\u{202E}' | '\u{2066}'..='\u{2069}'
        )
}

fn unquote_toml(raw: &str) -> String {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            if ch == '\\' {
                match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('t') => out.push('\t'),
                    Some('r') => out.push('\r'),
                    Some(other) => {
                        out.push('\\');
                        out.push(other);
                    }
                    None => out.push('\\'),
                }
            } else {
                out.push(ch);
            }
        }
        return out;
    }
    if let Some(inner) = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
    {
        return inner.to_owned();
    }
    trimmed.to_owned()
}

fn validate_export_salt(org_salt: &[u8]) -> Result<(), CodedError> {
    if org_salt.len() < MIN_EXPORT_SALT_BYTES {
        return Err(abom_err(format!(
            "ABOM export org_salt must be at least {MIN_EXPORT_SALT_BYTES} bytes, got {}",
            org_salt.len()
        )));
    }
    Ok(())
}

fn pseudonymize_abom_token(org_salt: &[u8], domain: &str, prefix: &str, raw: &str) -> String {
    let mac = domain_hmac_sha256(org_salt, domain, raw.as_bytes());
    let hex = encode_lower_hex(&mac);
    format!("{prefix}_{}", hex.get(..16).unwrap_or(hex.as_str()))
}

fn redact_private_program_id(org_salt: &[u8], program_id: &str) -> String {
    if program_id.starts_with("sig:") || program_id.starts_with("pkg:") {
        return program_id.to_owned();
    }
    if program_id.starts_with("src:hmac_") || program_id.starts_with("img:hmac_") {
        return program_id.to_owned();
    }
    pseudonymize_abom_token(org_salt, "grdr.abom.program.v1", "prog", program_id)
}

fn abom_err(msg: impl Into<String>) -> CodedError {
    CodedError::new(
        "GRDR-AGENTS-0005",
        msg.into(),
        "Provide a valid grdr.agent/v1alpha1 TOML declaration.",
    )
}
