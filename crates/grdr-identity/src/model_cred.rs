// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::IdentityError;
use crate::locator::{CredentialLocationFinding, CredentialStoreKind, HygieneRuleId};

const STATIC_MODEL_ENV_KEYS: &[&str] = &[
    "ANTHROPIC_API_KEY",
    "OPENAI_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "MISTRAL_API_KEY",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelCredentialMode {
    VendorLogin,
    Gateway,
    KeyHelper,
    Federated,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelCredentialSpec {
    pub agent_family: String,
    pub mode: ModelCredentialMode,
    pub gateway_base_url: Option<String>,
    pub key_helper_command: Option<String>,
    pub federated_audience: Option<String>,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompiledModelEnv {
    pub agent_family: String,
    pub mode: ModelCredentialMode,
    pub set_env: BTreeMap<String, String>,
    pub unset_env: Vec<String>,
    pub cli_flags: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ModelModeDriftReport {
    pub rule_id: HygieneRuleId,
    pub agent_family: String,
    pub expected_mode: ModelCredentialMode,
    pub reason: String,
}

impl std::fmt::Debug for CompiledModelEnv {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let redacted_env: BTreeMap<&str, &str> = self
            .set_env
            .iter()
            .map(|(k, v)| {
                let is_secret = k.contains("TOKEN")
                    || k.contains("KEY")
                    || k.contains("SECRET")
                    || k.contains("PASSWORD");
                (
                    k.as_str(),
                    if is_secret { "<redacted>" } else { v.as_str() },
                )
            })
            .collect();
        f.debug_struct("CompiledModelEnv")
            .field("agent_family", &self.agent_family)
            .field("mode", &self.mode)
            .field("set_env", &redacted_env)
            .field("unset_env", &self.unset_env)
            .field("cli_flags", &self.cli_flags)
            .finish()
    }
}

pub fn compile_model_credential_env(
    spec: &ModelCredentialSpec,
    phantom_bearer: Option<&str>,
    observed_env: &BTreeMap<String, String>,
) -> Result<CompiledModelEnv, IdentityError> {
    if spec.agent_family.trim().is_empty() {
        return Err(IdentityError::CredentialHelper(
            "agent_family cannot be empty".to_string(),
        ));
    }

    let mut set_env = BTreeMap::new();
    let unset_env: Vec<String> = STATIC_MODEL_ENV_KEYS
        .iter()
        .map(|k| (*k).to_string())
        .collect();
    let mut cli_flags = Vec::new();

    match spec.mode {
        ModelCredentialMode::VendorLogin => {
            if let Some(conflicting) = find_present_static_key(observed_env) {
                return Err(IdentityError::CredentialHelper(format!(
                    "vendor-login mode rejects static key `{conflicting}` in agent environment"
                )));
            }
            set_env.insert(
                "GRDR_MODEL_CRED_MODE".to_string(),
                "vendor-login".to_string(),
            );
            if spec.agent_family.eq_ignore_ascii_case("claude") {
                set_env.insert("CLAUDE_CODE_USE_OAUTH".to_string(), "1".to_string());
            } else if spec.agent_family.eq_ignore_ascii_case("codex") {
                cli_flags.push("--login".to_string());
            }
        }
        ModelCredentialMode::Gateway => {
            if let Some(conflicting) = find_present_static_key(observed_env) {
                return Err(IdentityError::CredentialHelper(format!(
                    "gateway mode rejects static key `{conflicting}` in agent environment"
                )));
            }
            let base = spec
                .gateway_base_url
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    IdentityError::CredentialHelper(
                        "gateway mode requires gateway_base_url".to_string(),
                    )
                })?;
            let parsed = crate::http_security::validate_exact_endpoint_url(base, true)?;
            let canonical_url = parsed.as_str().trim_end_matches('/').to_owned();
            let token = phantom_bearer
                .map(str::trim)
                .filter(|v| !v.is_empty() && !v.chars().any(char::is_control))
                .ok_or_else(|| {
                    IdentityError::CredentialHelper(
                        "gateway mode requires short-lived phantom bearer token".to_string(),
                    )
                })?;
            set_env.insert("GRDR_MODEL_CRED_MODE".to_string(), "gateway".to_string());
            set_env.insert("ANTHROPIC_BASE_URL".to_string(), canonical_url.clone());
            set_env.insert("OPENAI_BASE_URL".to_string(), canonical_url);
            set_env.insert("GRDR_GATEWAY_TOKEN".to_string(), token.to_owned());
        }
        ModelCredentialMode::KeyHelper => {
            let helper = spec
                .key_helper_command
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty() && !v.chars().any(char::is_control))
                .ok_or_else(|| {
                    IdentityError::CredentialHelper(
                        "key-helper mode requires key_helper_command".to_string(),
                    )
                })?;
            set_env.insert("GRDR_MODEL_CRED_MODE".to_string(), "key-helper".to_string());
            set_env.insert("ANTHROPIC_API_KEY_HELPER".to_string(), helper.to_owned());
        }
        ModelCredentialMode::Federated => {
            let aud = spec
                .federated_audience
                .as_deref()
                .map(str::trim)
                .filter(|v| !v.is_empty())
                .ok_or_else(|| {
                    IdentityError::CredentialHelper(
                        "federated mode requires federated_audience".to_string(),
                    )
                })?;
            set_env.insert("GRDR_MODEL_CRED_MODE".to_string(), "federated".to_string());
            set_env.insert("GRDR_FEDERATED_AUDIENCE".to_string(), aud.to_owned());
        }
    }

    Ok(CompiledModelEnv {
        agent_family: spec.agent_family.clone(),
        mode: spec.mode,
        set_env,
        unset_env,
        cli_flags,
    })
}

#[must_use]
pub fn detect_model_credential_drift(
    spec: &ModelCredentialSpec,
    observed_env: &BTreeMap<String, String>,
    discovered_locations: &[CredentialLocationFinding],
) -> Option<ModelModeDriftReport> {
    if matches!(
        spec.mode,
        ModelCredentialMode::VendorLogin
            | ModelCredentialMode::Gateway
            | ModelCredentialMode::Federated
    ) && let Some(key_name) = find_present_static_key(observed_env)
    {
        return Some(ModelModeDriftReport {
            rule_id: HygieneRuleId::H11,
            agent_family: spec.agent_family.clone(),
            expected_mode: spec.mode,
            reason: format!("static model key `{key_name}` observed in agent environment"),
        });
    }

    if spec.mode == ModelCredentialMode::Gateway
        && let Some(expected_base) = spec.gateway_base_url.as_deref()
    {
        let expected_norm = expected_base.trim().trim_end_matches('/');
        let actual_anthropic = observed_env
            .get("ANTHROPIC_BASE_URL")
            .map(|s| s.trim().trim_end_matches('/'));
        let actual_openai = observed_env
            .get("OPENAI_BASE_URL")
            .map(|s| s.trim().trim_end_matches('/'));
        if actual_anthropic != Some(expected_norm) || actual_openai != Some(expected_norm) {
            return Some(ModelModeDriftReport {
                rule_id: HygieneRuleId::H11,
                agent_family: spec.agent_family.clone(),
                expected_mode: spec.mode,
                reason: "model base URL drifted from configured local gateway".to_string(),
            });
        }
    }

    if spec.mode != ModelCredentialMode::VendorLogin
        && discovered_locations
            .iter()
            .any(|loc| loc.store_kind == CredentialStoreKind::AgentStore)
    {
        return Some(ModelModeDriftReport {
            rule_id: HygieneRuleId::H11,
            agent_family: spec.agent_family.clone(),
            expected_mode: spec.mode,
            reason: "plaintext agent credential store found despite managed credential_mode"
                .to_string(),
        });
    }

    None
}

fn find_present_static_key(env: &BTreeMap<String, String>) -> Option<&'static str> {
    STATIC_MODEL_ENV_KEYS
        .iter()
        .copied()
        .find(|key| env.get(*key).is_some_and(|v| !v.trim().is_empty()))
}
