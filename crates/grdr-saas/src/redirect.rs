// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_compat::SemVer;
use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_model::CodedError;
use grdr_ports::OrgId;

use crate::framing::{CanonicalFrame, ensure_clean_token, validate_https_endpoint};
use crate::{
    CODE_SAAS_INVALID_INPUT, CODE_SAAS_SIGNATURE_INVALID, CODE_SAAS_TENANT_MISMATCH, saas_error,
};

const REDIRECT_DOMAIN: &str = "grdr.saas.device-redirect.v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceRedirectSpec {
    pub org_id: OrgId,
    pub device_id: String,
    pub old_cell: String,
    pub new_cell: String,
    pub new_endpoint: String,
    pub min_client_version: SemVer,
    pub issued_at_s: i64,
    pub ttl_seconds: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SignedDeviceRedirect {
    pub org_id: OrgId,
    pub device_id: String,
    pub old_cell: String,
    pub new_cell: String,
    pub new_endpoint: String,
    pub min_client_version: SemVer,
    pub issued_at_s: i64,
    pub expires_at_s: i64,
    pub signer_key_id: String,
    pub signature_b64: String,
}

pub fn sign_device_redirect(
    signer: &SigningKeypair,
    spec: DeviceRedirectSpec,
) -> Result<SignedDeviceRedirect, CodedError> {
    ensure_clean_token("device_id", &spec.device_id)?;
    ensure_clean_token("old_cell", &spec.old_cell)?;
    ensure_clean_token("new_cell", &spec.new_cell)?;
    validate_https_endpoint(&spec.new_endpoint)?;
    if spec.ttl_seconds <= 0 {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            "Device redirect requires a positive TTL.",
            "Pass positive ttl_seconds.",
        ));
    }
    let expires_at_s = spec
        .issued_at_s
        .checked_add(spec.ttl_seconds)
        .ok_or_else(|| {
            saas_error(
                CODE_SAAS_INVALID_INPUT,
                "Device redirect expiration timestamp overflowed.",
                "Use a bounded ttl_seconds.",
            )
        })?;
    let signer_key_id = signer.key_id().to_owned();
    ensure_clean_token("signer_key_id", &signer_key_id)?;
    let mut redirect = SignedDeviceRedirect {
        org_id: spec.org_id,
        device_id: spec.device_id,
        old_cell: spec.old_cell,
        new_cell: spec.new_cell,
        new_endpoint: spec.new_endpoint,
        min_client_version: spec.min_client_version,
        issued_at_s: spec.issued_at_s,
        expires_at_s,
        signer_key_id,
        signature_b64: String::new(),
    };
    let frame = canonical_redirect_frame(&redirect);
    redirect.signature_b64 = signer.sign_bytes(REDIRECT_DOMAIN, frame.as_bytes());
    Ok(redirect)
}

pub fn verify_device_redirect(
    public_key_b64: &str,
    redirect: &SignedDeviceRedirect,
    expected_org: &OrgId,
    expected_device_id: &str,
    client_version: SemVer,
    now_s: i64,
) -> Result<(), CodedError> {
    ensure_clean_token("expected_device_id", expected_device_id)?;
    ensure_clean_token("device_id", &redirect.device_id)?;
    ensure_clean_token("old_cell", &redirect.old_cell)?;
    ensure_clean_token("new_cell", &redirect.new_cell)?;
    ensure_clean_token("signer_key_id", &redirect.signer_key_id)?;
    validate_https_endpoint(&redirect.new_endpoint)?;
    if redirect.org_id != *expected_org || redirect.device_id != expected_device_id {
        return Err(saas_error(
            CODE_SAAS_TENANT_MISMATCH,
            "Device redirect org or device identifier mismatch.",
            "Reject cross-tenant or cross-device redirects.",
        ));
    }
    if redirect.expires_at_s <= redirect.issued_at_s || now_s > redirect.expires_at_s {
        return Err(saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Signed device redirect expired or invalid.",
            "Request a fresh cell redirect receipt.",
        ));
    }
    if client_version < redirect.min_client_version {
        return Err(saas_error(
            CODE_SAAS_INVALID_INPUT,
            format!(
                "Client version {client_version} is below redirect minimum {}.",
                redirect.min_client_version
            ),
            "Update the endpoint daemon before accepting cell redirect.",
        ));
    }
    let frame = canonical_redirect_frame(redirect);
    verify_bytes(
        public_key_b64,
        REDIRECT_DOMAIN,
        frame.as_bytes(),
        &redirect.signature_b64,
    )
    .map_err(|_| {
        saas_error(
            CODE_SAAS_SIGNATURE_INVALID,
            "Device redirect Ed25519 signature verification failed.",
            "Keep previous pinned cell endpoint and reject unsigned redirect.",
        )
    })
}

fn canonical_redirect_frame(redirect: &SignedDeviceRedirect) -> CanonicalFrame {
    let mut frame = CanonicalFrame::new("device_redirect_v1");
    frame.push_str(redirect.org_id.as_str());
    frame.push_str(&redirect.device_id);
    frame.push_str(&redirect.old_cell);
    frame.push_str(&redirect.new_cell);
    frame.push_str(&redirect.new_endpoint);
    frame.push_str(&redirect.min_client_version.to_string());
    frame.push_i64(redirect.issued_at_s);
    frame.push_i64(redirect.expires_at_s);
    frame.push_str(&redirect.signer_key_id);
    frame
}
