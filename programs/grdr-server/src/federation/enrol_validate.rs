// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, State};
use serde::{Deserialize, Serialize};

use crate::auth::AuthContext;

use super::runtime::{api_bad_request, api_conflict, require_console_scope};
use super::types::{FedError, FederationState};

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum MdmTargetVendor {
    Intune,
    Jamf,
    Fleet,
    Nanomdm,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum WindowsSessionTopology {
    SingleSession,
    MultiSessionVdi,
}

#[derive(Debug, Copy, Clone, PartialEq, Eq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum GoldenImageResidualArtifact {
    DeviceKeys,
    LeaseCache,
    UserTokens,
}

#[derive(Debug, Deserialize)]
pub struct MdmValidateRequest {
    pub vendor: MdmTargetVendor,
    pub payload: String,
}

#[derive(Debug, Serialize)]
pub struct MdmValidateResponse {
    pub vendor: MdmTargetVendor,
    pub valid: bool,
    pub checks_passed: Vec<String>,
    pub detail: String,
}

#[derive(Debug, Deserialize)]
pub struct GoldenImageCheckRequest {
    pub os: String,
    pub windows_topology: WindowsSessionTopology,
    #[serde(default)]
    pub residual_artifacts: Vec<GoldenImageResidualArtifact>,
}

#[derive(Debug, Serialize)]
pub struct GoldenImageCheckResponse {
    pub clone_ready: bool,
    pub clean_reasons: Vec<String>,
}

pub async fn validate_mdm_artifact(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<MdmValidateRequest>,
) -> Result<Json<MdmValidateResponse>, FedError> {
    st.ensure_healthy()?;
    let _ = require_console_scope(auth.as_deref(), "identity:read")?;
    let body = req.payload.trim();
    if body.is_empty() {
        return Err(api_bad_request("MDM payload cannot be empty"));
    }
    let checks = match req.vendor {
        MdmTargetVendor::Intune => validate_intune_script(body)?,
        MdmTargetVendor::Jamf => validate_xml_plist(body, "PayloadType", "jamf")?,
        MdmTargetVendor::Fleet => validate_fleet_json(body)?,
        MdmTargetVendor::Nanomdm => validate_xml_plist(body, "CommandUUID", "nanomdm")?,
    };
    Ok(Json(MdmValidateResponse {
        vendor: req.vendor,
        valid: true,
        checks_passed: checks,
        detail: "MDM artifact passed schema validation".to_string(),
    }))
}

pub async fn check_golden_image_prepare(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<GoldenImageCheckRequest>,
) -> Result<Json<GoldenImageCheckResponse>, FedError> {
    st.ensure_healthy()?;
    let _ = require_console_scope(auth.as_deref(), "identity:read")?;
    if is_windows_os(&req.os) && req.windows_topology == WindowsSessionTopology::MultiSessionVdi {
        return Err(api_conflict(
            "Windows multi-session VDI hosts are refused for golden-image prepare (24-11)",
        ));
    }
    if !req.residual_artifacts.is_empty() {
        return Err(api_conflict(
            "golden image must strip device keys, broker leases, and user tokens before seal",
        ));
    }
    Ok(Json(GoldenImageCheckResponse {
        clone_ready: true,
        clean_reasons: vec![
            "zero_device_keys".to_string(),
            "zero_lease_cache".to_string(),
            "zero_user_tokens".to_string(),
        ],
    }))
}

fn validate_intune_script(body: &str) -> Result<Vec<String>, FedError> {
    let mut has_profile = false;
    let mut has_token = false;
    for line in body.lines() {
        let trimmed = line.trim();
        if let Some((k, v)) = trimmed.split_once('=') {
            let key = k.trim().trim_start_matches('$').to_ascii_lowercase();
            let val = v.trim().trim_matches(['"', '\'']);
            if key == "install_profile" && matches!(val, "protected" | "user" | "standard") {
                has_profile = true;
            }
            if key == "enrollment_token" && !val.is_empty() {
                has_token = true;
            }
        }
    }
    if !has_profile || !has_token {
        return Err(api_bad_request(
            "Intune script requires structured install_profile and non-empty enrollment_token assignments",
        ));
    }
    Ok(vec![
        "intune_ps_install_profile".to_string(),
        "intune_enrollment_token".to_string(),
    ])
}

fn validate_xml_plist(
    body: &str,
    required_key: &str,
    label: &str,
) -> Result<Vec<String>, FedError> {
    let lower = body.to_ascii_lowercase();
    if lower.contains("<!doctype") || lower.contains("<!entity") {
        return Err(api_bad_request(
            "XML DOCTYPE/ENTITY declarations are forbidden",
        ));
    }
    let plist_start = body
        .find("<plist")
        .ok_or_else(|| api_bad_request(&format!("{label} XML missing <plist root element")))?;
    let plist_end = body
        .rfind("</plist>")
        .ok_or_else(|| api_bad_request(&format!("{label} XML missing </plist> closing element")))?;
    if plist_end <= plist_start {
        return Err(api_bad_request(&format!("{label} malformed plist bounds")));
    }
    let inner = body
        .get(plist_start..plist_end)
        .ok_or_else(|| api_bad_request(&format!("{label} malformed plist bounds")))?;
    if !inner.contains("<dict>") || !inner.contains("</dict>") {
        return Err(api_bad_request(&format!(
            "{label} plist requires balanced <dict>"
        )));
    }
    let key_tag = format!("<key>{required_key}</key>");
    let key_idx = inner
        .find(&key_tag)
        .ok_or_else(|| api_bad_request(&format!("{label} plist missing {required_key}")))?;
    let after_key = inner
        .get(key_idx.saturating_add(key_tag.len())..)
        .map(str::trim_start)
        .unwrap_or_default();
    let extracted = after_key
        .strip_prefix("<string>")
        .and_then(|rest| rest.split_once("</string>"))
        .map(|(v, _)| v.trim())
        .filter(|v| !v.is_empty());
    if extracted.is_none() {
        return Err(api_bad_request(&format!(
            "{label} plist {required_key} must carry non-empty <string> value"
        )));
    }
    Ok(vec![
        format!("{label}_xml_plist"),
        format!("{label}_{}", required_key.to_ascii_lowercase()),
    ])
}

fn validate_fleet_json(body: &str) -> Result<Vec<String>, FedError> {
    let parsed: serde_json::Value = serde_json::from_str(body)
        .map_err(|e| api_bad_request(&format!("Fleet payload must be valid JSON: {e}")))?;
    let has_team = parsed
        .get("team_id")
        .and_then(|v| v.as_str())
        .is_some_and(|s| !s.trim().is_empty());
    let has_profile = parsed
        .get("profile")
        .is_some_and(|v| v.is_object() || v.as_str().is_some_and(|s| !s.trim().is_empty()));
    if !has_team && !has_profile {
        return Err(api_bad_request(
            "Fleet JSON requires non-empty team_id or profile",
        ));
    }
    Ok(vec!["fleet_json_schema".to_string()])
}

fn is_windows_os(os: &str) -> bool {
    let lower = os.trim().to_ascii_lowercase();
    lower == "windows"
        || lower.starts_with("windows")
        || lower.starts_with("win32")
        || lower.starts_with("win10")
        || lower.starts_with("win11")
}
