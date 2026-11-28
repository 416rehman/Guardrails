// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Secret-free Pass 4 credential locator inventory (`docs/design/05`).

use std::sync::OnceLock;

use grdr_core::analyze::content::scan_deterministic_content;
use grdr_core::detect::yaml::{YamlValue, parse_yaml};
use grdr_crypto::{domain_hmac_sha256, encode_lower_hex};
use grdr_model::CodedError;
use serde::{Deserialize, Serialize};

use crate::endpoints_pack::load_model_endpoints_pack;

const CRED_ID_HMAC_DOMAIN: &str = "grdr.inventory.credential.v1";
const MIN_SALT_BYTES: usize = 32;
const EMBEDDED_LOCATORS_YAML: &str =
    include_str!("../../../packs/credential-locator/lists/locators.yaml");

static EMBEDDED_LOCATOR_SPECS: OnceLock<Result<Vec<CredentialLocatorSpec>, String>> =
    OnceLock::new();

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialStoreKind {
    PlaintextFile,
    OsKeystore,
    EnvReference,
    Helper,
    VaultReference,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CredentialExposure {
    SafeReference,
    Plaintext,
    Honeytoken,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialLocatorSpec {
    pub id: String,
    pub credential_class: String,
    pub store_kind: String,
    pub prefix: String,
    pub honeytoken: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialInventoryRecord {
    pub id: String,
    pub cred_type: String,
    pub locator_id: String,
    pub store: CredentialStoreKind,
    pub scope: Option<String>,
    pub field_path: String,
    pub exposure: CredentialExposure,
    pub mtime_lower_bound_secs: Option<u64>,
    pub policy_violation_finding: bool,
}

pub fn load_embedded_credential_locators() -> Result<&'static [CredentialLocatorSpec], CodedError> {
    EMBEDDED_LOCATOR_SPECS
        .get_or_init(parse_embedded_locators)
        .as_deref()
        .map_err(|detail| {
            CodedError::new(
                "GRDR-AGENTS-0005",
                detail.clone(),
                "Fix malformed embedded credential locator pack.",
            )
        })
}

pub fn build_credential_inventory_record(
    org_salt: &[u8],
    field_path: &str,
    scope: Option<&str>,
    candidate_value: Option<&str>,
    mtime_lower_bound_secs: Option<u64>,
) -> Result<CredentialInventoryRecord, CodedError> {
    if org_salt.len() < MIN_SALT_BYTES {
        return Err(CodedError::new(
            "GRDR-AGENTS-0005",
            format!(
                "organization HMAC salt must be at least {MIN_SALT_BYTES} bytes, got {}",
                org_salt.len()
            ),
            "Provide at least 32 random bytes for P8 credential pseudonymization.",
        ));
    }
    let locators = load_embedded_credential_locators()?;
    let val = candidate_value.unwrap_or("");
    let content_hits = scan_deterministic_content(val.as_bytes());
    let matched_loc = locators
        .iter()
        .find(|loc| matches_credential_prefix(val, &loc.prefix));

    let cred_type = matched_loc
        .map(|l| l.credential_class.clone())
        .or_else(|| (!content_hits.matches.is_empty()).then(|| "secret".into()))
        .unwrap_or_else(|| "token_reference".into());
    let locator_id = matched_loc
        .map(|l| l.id.clone())
        .unwrap_or_else(|| "generic-env-ref".into());
    let (store, plaintext) = classify_store_and_plaintext(
        field_path,
        val,
        !content_hits.matches.is_empty(),
        matched_loc,
    );
    let pack = load_model_endpoints_pack()?;
    let honeytoken = pack
        .honeytoken_prefixes
        .iter()
        .any(|prefix| !prefix.is_empty() && val.contains(prefix))
        || matched_loc.is_some_and(|l| l.honeytoken);
    let exposure = if honeytoken {
        CredentialExposure::Honeytoken
    } else if plaintext {
        CredentialExposure::Plaintext
    } else {
        CredentialExposure::SafeReference
    };

    // Identity derives strictly from non-secret type + config field path, never from secret bytes.
    let public_part = format!("{store:?}:{field_path}");
    let mac = domain_hmac_sha256(
        org_salt,
        CRED_ID_HMAC_DOMAIN,
        format!("{cred_type}:{public_part}").as_bytes(),
    );
    let hex = encode_lower_hex(&mac);
    let short = hex.get(..16).unwrap_or(hex.as_str());

    Ok(CredentialInventoryRecord {
        id: format!("crd_{short}"),
        cred_type,
        locator_id,
        store,
        scope: scope.map(str::to_owned),
        field_path: field_path.into(),
        exposure,
        mtime_lower_bound_secs,
        policy_violation_finding: exposure != CredentialExposure::SafeReference,
    })
}

fn classify_store_and_plaintext(
    field_path: &str,
    value: &str,
    content_secret: bool,
    matched_loc: Option<&CredentialLocatorSpec>,
) -> (CredentialStoreKind, bool) {
    let trimmed = value.trim();
    let path_lower = field_path.to_ascii_lowercase();
    let secret_detected = content_secret || matched_loc.is_some();
    if trimmed.starts_with("${") && trimmed.ends_with('}') && !secret_detected {
        return (CredentialStoreKind::EnvReference, false);
    }
    let store = if path_lower.contains("keychain") || path_lower.contains("keystore") {
        CredentialStoreKind::OsKeystore
    } else if path_lower.contains("vault") {
        CredentialStoreKind::VaultReference
    } else if path_lower.contains("helper") {
        CredentialStoreKind::Helper
    } else {
        CredentialStoreKind::PlaintextFile
    };
    // Never downgrade detected raw secret material because of the field name.
    let has_plaintext = secret_detected
        || (store == CredentialStoreKind::PlaintextFile
            && !trimmed.is_empty()
            && !trimmed.starts_with('$'));
    (store, has_plaintext)
}

fn matches_credential_prefix(val: &str, prefix: &str) -> bool {
    if prefix.is_empty() || val.len() < prefix.len() {
        return false;
    }
    let min_tail = if prefix.len() <= 4 { 6 } else { 4 };
    for (idx, _) in val.match_indices(prefix) {
        let boundary_ok = idx == 0
            || val
                .get(..idx)
                .and_then(|s| s.chars().next_back())
                .is_some_and(|ch| !ch.is_ascii_alphanumeric() && ch != '_');
        if !boundary_ok {
            continue;
        }
        let tail = val.get(idx.saturating_add(prefix.len())..).unwrap_or("");
        let token_len = tail
            .chars()
            .take_while(|ch| {
                ch.is_ascii_alphanumeric() || matches!(ch, '_' | '-' | '+' | '/' | '=')
            })
            .count();
        if token_len >= min_tail {
            return true;
        }
    }
    false
}

fn parse_embedded_locators() -> Result<Vec<CredentialLocatorSpec>, String> {
    let root = parse_yaml(EMBEDDED_LOCATORS_YAML)
        .map_err(|e| format!("failed parsing locators.yaml: {e}"))?;
    let map = root
        .as_map()
        .ok_or_else(|| "locators.yaml root must be a YAML map".to_owned())?;
    let Some(YamlValue::Seq(items)) = map.get("locators") else {
        return Err("locators.yaml missing `locators` sequence".to_owned());
    };
    let specs: Vec<CredentialLocatorSpec> = items
        .iter()
        .filter_map(YamlValue::as_map)
        .filter_map(|m| {
            let id = m.get("id").and_then(YamlValue::as_str)?.to_owned();
            let credential_class = m
                .get("credential_class")
                .and_then(YamlValue::as_str)
                .unwrap_or("model")
                .to_owned();
            let store_kind = m
                .get("store_kind")
                .and_then(YamlValue::as_str)
                .unwrap_or("plaintext_file")
                .to_owned();
            let prefix = m
                .get("prefix")
                .and_then(YamlValue::as_str)
                .unwrap_or("")
                .to_owned();
            let honeytoken = m
                .get("honeytoken")
                .and_then(YamlValue::as_bool)
                .unwrap_or(false);
            Some(CredentialLocatorSpec {
                id,
                credential_class,
                store_kind,
                prefix,
                honeytoken,
            })
        })
        .collect();
    if specs.is_empty() {
        return Err("locators.yaml resolved zero valid locator specs".to_owned());
    }
    Ok(specs)
}
