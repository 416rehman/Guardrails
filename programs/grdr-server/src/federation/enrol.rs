// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use axum::Json;
use axum::extract::{Extension, State};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as B64;
use grdr_identity::attest::{
    BootKeyCertificate, FederatedWorkloadClaim, FederatedWorkloadSource,
    verify_federated_workload_claim,
};
use grdr_identity::jwt_keys::{MAX_FEDERATION_TOKEN_TTL_SECS, verify_jwt_with_jwks};
use grdr_identity::spiffe::SpiffeId;
use grdr_model::{DeploymentKeyStatus, Device, InstallProfile};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::auth::AuthContext;

use super::runtime::{
    api_bad_request, api_conflict, api_denied, api_internal, api_not_found, auth_actor,
    require_console_scope, tenant_trust_domain,
};
use super::types::{
    EnrolledDeviceRecord, EnrolmentMethod, FedError, FederationState, ServerEnrolmentState,
};

#[derive(Debug, Deserialize)]
pub struct AdmitDeploymentKeyRequest {
    pub deployment_key_id: String,
    pub device_id: String,
    pub hostname: String,
    pub boot_id: String,
    pub public_key_b64: String,
    pub approve_admission: Option<bool>,
}

#[derive(Debug, Serialize)]
pub struct EnrolmentDecisionResponse {
    pub device: EnrolledDeviceRecord,
    pub cert: Option<BootKeyCertificate>,
    pub workload_spiffe_id: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorkloadOidcClaims {
    pub iss: String,
    pub sub: String,
    pub aud: String,
    pub jti: String,
    pub iat: i64,
    pub exp: i64,
    #[serde(default)]
    pub repository: Option<String>,
    #[serde(default)]
    pub project_path: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct WorkloadOidcEnrolRequest {
    pub id_token_jwt: String,
    pub claim: FederatedWorkloadClaim,
    pub device_id: String,
    pub hostname: String,
    pub boot_id: String,
    pub public_key_b64: String,
}

#[derive(Debug, Deserialize)]
pub struct HardwareAttestationPayload {
    pub device_id: String,
    pub boot_id: String,
    pub hardware_vendor: String,
    pub device_pubkey_b64: String,
    pub nonce: String,
    pub iat: i64,
    pub exp: i64,
}

#[derive(Debug, Deserialize)]
pub struct AttestedEnrolRequest {
    pub device_id: String,
    pub hostname: String,
    pub boot_id: String,
    pub hardware_vendor: String,
    pub attestation_signature_b64: String,
    pub attestation_payload: String,
}

pub async fn admit_deployment_key(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<AdmitDeploymentKeyRequest>,
) -> Result<Json<EnrolmentDecisionResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    if req.device_id.trim().is_empty()
        || req.hostname.trim().is_empty()
        || req.public_key_b64.trim().is_empty()
    {
        return Err(api_bad_request(
            "device_id, hostname, and public_key_b64 are required",
        ));
    }
    grdr_crypto::validate_public_key_b64(&req.public_key_b64)
        .map_err(|e| api_bad_request(&format!("invalid device public key: {e}")))?;

    let now = Timestamp::now();
    let now_str = now.to_string();
    let mut store_guard = st.app.inner.write().await;
    let mut rt = st.runtime.write().await;
    {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        if tenant.enrolled_devices.contains_key(&req.device_id)
            || store_guard.devices.iter().any(|d| d.id == req.device_id)
        {
            return Err(api_conflict(&format!(
                "device_id `{}` is already enrolled",
                req.device_id
            )));
        }
        if tenant.enrolled_devices.len() >= rt.limits.max_devices {
            return Err(api_denied("tenant enrolled device cap reached"));
        }
    }

    let key_idx = store_guard
        .deployment_keys
        .iter()
        .position(|k| k.id == req.deployment_key_id)
        .ok_or_else(|| api_not_found("deployment key not found"))?;
    let key_ref = store_guard
        .deployment_keys
        .get_mut(key_idx)
        .ok_or_else(|| api_not_found("deployment key missing"))?;
    match key_ref.effective_status(&now_str) {
        DeploymentKeyStatus::Active => {}
        DeploymentKeyStatus::Exhausted => return Err(api_denied("deployment key quota exhausted")),
        DeploymentKeyStatus::Expired => return Err(api_denied("deployment key expired")),
        DeploymentKeyStatus::Revoked => return Err(api_denied("deployment key revoked")),
    }
    if key_ref.used_count >= key_ref.max_uses {
        return Err(api_denied("deployment key quota reached"));
    }
    let profile = parse_deployment_profile(&key_ref.install_profile)?;
    let essentials_locked = profile == InstallProfile::Protected;
    let initial_state =
        if req.approve_admission == Some(true) && profile == InstallProfile::Protected {
            ServerEnrolmentState::Admitted
        } else {
            ServerEnrolmentState::Pending
        };
    let cert = (initial_state == ServerEnrolmentState::Admitted).then(|| BootKeyCertificate {
        device_id: req.device_id.clone(),
        boot_id: req.boot_id.clone(),
        key_id: format!("bk_{}", Uuid::now_v7().simple()),
        public_key_b64: req.public_key_b64.clone(),
        issued_at: now,
    });
    let dev_key_id = cert.as_ref().map_or_else(
        || format!("dk_{}", req.deployment_key_id),
        |c| c.key_id.clone(),
    );
    key_ref.used_count = key_ref.used_count.saturating_add(1);
    store_guard.devices.push(Device {
        id: req.device_id.clone(),
        hostname: req.hostname.clone(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        install_profile: profile,
        daemon_version: env!("CARGO_PKG_VERSION").to_string(),
        online: true,
        hook_effective: false,
        agents: Vec::new(),
        mcp_servers: Vec::new(),
        artifacts: Vec::new(),
        user_id: None,
        user_display: None,
        last_seen: now,
        public_key: Some(grdr_model::TrustedKeyInfo {
            key_id: dev_key_id,
            public_key_b64: req.public_key_b64.clone(),
        }),
    });
    st.app
        .persist_store(&store_guard)
        .map_err(|e| api_internal(&e.message))?;
    drop(store_guard);

    let dev = EnrolledDeviceRecord {
        device_id: req.device_id.clone(),
        hostname: req.hostname,
        profile,
        essentials_floor_locked: essentials_locked,
        state: initial_state,
        method: EnrolmentMethod::DeploymentKey,
        key_id: cert.as_ref().map(|c| c.key_id.clone()),
        deployment_key_id: Some(req.deployment_key_id),
        enrolled_at: now,
    };

    rt.tenant_mut(&ctx.tenant_id)
        .enrolled_devices
        .insert(dev.device_id.clone(), dev.clone());
    st.persist_runtime(&rt)?;
    drop(rt);
    st.append_audit(
        "connect.enrol.deployment_key",
        auth_actor(auth.as_deref()),
        format!(
            "Enrolled device `{}` via deployment key (profile={:?}, state={:?})",
            dev.device_id, dev.profile, dev.state
        ),
        dev.device_id.clone(),
    )
    .await?;

    Ok(Json(EnrolmentDecisionResponse {
        device: dev,
        cert,
        workload_spiffe_id: None,
    }))
}

pub async fn enrol_workload_oidc(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<WorkloadOidcEnrolRequest>,
) -> Result<Json<EnrolmentDecisionResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    grdr_crypto::validate_public_key_b64(&req.public_key_b64)
        .map_err(|e| api_bad_request(&format!("invalid workload key: {e}")))?;
    let now = Timestamp::now();
    let now_sec = now.as_second();

    let mut rt = st.runtime.write().await;
    let expected_aud = rt.issuer_url.clone();
    let expected_domain = tenant_trust_domain(&ctx.tenant_id);
    let max_skew = rt.limits.max_skew_secs;
    let max_devices = rt.limits.max_devices;
    let (oidc_claims, spiffe) = {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        if tenant.enrolled_devices.contains_key(&req.device_id) {
            return Err(api_conflict(&format!(
                "device_id `{}` is already enrolled",
                req.device_id
            )));
        }
        if tenant.enrolled_devices.len() >= max_devices {
            return Err(api_denied("tenant enrolled device cap reached"));
        }
        let oidc_claims: WorkloadOidcClaims = verify_jwt_with_jwks(
            req.id_token_jwt.trim(),
            None,
            &tenant.trusted_federated_jwks,
        )
        .map_err(|e| api_denied(&format!("OIDC JWT verification failed: {e}")))?;
        if oidc_claims.iss != req.claim.issuer
            || oidc_claims.sub != req.claim.subject
            || oidc_claims.aud != expected_aud
            || oidc_claims.jti.trim().is_empty()
            || oidc_claims.iat > now_sec.saturating_add(max_skew)
            || oidc_claims.exp <= now_sec
            || oidc_claims.exp.saturating_sub(oidc_claims.iat) > MAX_FEDERATION_TOKEN_TTL_SECS
        {
            return Err(api_denied(
                "OIDC JWT claims failed binding or expiry validation",
            ));
        }
        verify_oidc_workload_subject_binding(&oidc_claims, &req.claim)?;
        let spiffe: SpiffeId =
            verify_federated_workload_claim(&req.claim, &tenant.trusted_federated_issuers, now)
                .map_err(|e| api_denied(&e.to_string()))?;
        let dom = spiffe.trust_domain();
        if dom != expected_domain
            && (dom == "local" || !tenant.trusted_spiffe_domains.contains(dom))
        {
            return Err(api_denied(
                "workload SPIFFE trust domain not permitted for tenant",
            ));
        }
        (oidc_claims, spiffe)
    };

    let enrol_replay_key = format!("{}:{}:{}", ctx.tenant_id, oidc_claims.iss, oidc_claims.jti);
    if rt.oidc_enrol_jti_replay.is_revoked(&enrol_replay_key) {
        return Err(api_denied("OIDC enrollment jti replay rejected"));
    }
    rt.oidc_enrol_jti_replay
        .revoke(enrol_replay_key, oidc_claims.exp, now_sec)
        .map_err(|e| api_denied(&e.to_string()))?;

    let cert = BootKeyCertificate {
        device_id: req.device_id.clone(),
        boot_id: req.boot_id,
        key_id: format!("wk_{}", Uuid::now_v7().simple()),
        public_key_b64: req.public_key_b64,
        issued_at: now,
    };
    let dev = EnrolledDeviceRecord {
        device_id: req.device_id.clone(),
        hostname: req.hostname,
        profile: InstallProfile::Protected,
        essentials_floor_locked: true,
        state: ServerEnrolmentState::Admitted,
        method: EnrolmentMethod::WorkloadOidc,
        key_id: Some(cert.key_id.clone()),
        deployment_key_id: None,
        enrolled_at: now,
    };
    rt.tenant_mut(&ctx.tenant_id)
        .enrolled_devices
        .insert(dev.device_id.clone(), dev.clone());
    st.persist_runtime(&rt)?;
    Ok(Json(EnrolmentDecisionResponse {
        device: dev,
        cert: Some(cert),
        workload_spiffe_id: Some(spiffe.as_str().to_owned()),
    }))
}

pub async fn enrol_attested_hardware(
    State(st): State<FederationState>,
    auth: Option<Extension<AuthContext>>,
    Json(req): Json<AttestedEnrolRequest>,
) -> Result<Json<EnrolmentDecisionResponse>, FedError> {
    st.ensure_healthy()?;
    let ctx = require_console_scope(auth.as_deref(), "identity:write")?;
    if !matches!(
        req.hardware_vendor.as_str(),
        "tpm2" | "apple_secure_enclave" | "mdm_scep_ca"
    ) {
        return Err(api_bad_request(
            "hardware_vendor must be tpm2, apple_secure_enclave, or mdm_scep_ca",
        ));
    }
    let now = Timestamp::now();
    let now_sec = now.as_second();
    let mut rt = st.runtime.write().await;
    let max_skew = rt.limits.max_skew_secs;
    let max_devices = rt.limits.max_devices;

    let payload: HardwareAttestationPayload = {
        let tenant = rt.tenant_mut(&ctx.tenant_id);
        if tenant.enrolled_devices.contains_key(&req.device_id) {
            return Err(api_conflict(&format!(
                "device_id `{}` is already enrolled",
                req.device_id
            )));
        }
        if tenant.enrolled_devices.len() >= max_devices {
            return Err(api_denied("tenant enrolled device cap reached"));
        }
        let ca_keys = tenant
            .trusted_hardware_ca_keys
            .get(&req.hardware_vendor)
            .filter(|keys| !keys.is_empty())
            .ok_or_else(|| {
                api_denied("no pinned hardware CA keys configured for requested vendor")
            })?;
        let sig_ok = ca_keys.iter().any(|jwk| {
            jwk.public_key_bytes().is_ok_and(|pk| {
                grdr_crypto::verify_bytes(
                    &B64.encode(pk),
                    "grdr.enrol.hardware.v1",
                    req.attestation_payload.as_bytes(),
                    &req.attestation_signature_b64,
                )
                .is_ok()
            })
        });
        if !sig_ok {
            return Err(api_denied(
                "hardware attestation signature did not match any pinned CA key",
            ));
        }
        let parsed: HardwareAttestationPayload = serde_json::from_str(&req.attestation_payload)
            .map_err(|e| api_bad_request(&format!("invalid hardware attestation payload: {e}")))?;
        if parsed.device_id != req.device_id
            || parsed.boot_id != req.boot_id
            || parsed.hardware_vendor != req.hardware_vendor
            || parsed.nonce.trim().is_empty()
            || parsed.iat > now_sec.saturating_add(max_skew)
            || parsed.exp <= now_sec
            || parsed.exp.saturating_sub(parsed.iat) > MAX_FEDERATION_TOKEN_TTL_SECS
        {
            return Err(api_denied(
                "hardware attestation claims failed device/boot/freshness binding",
            ));
        }
        grdr_crypto::validate_public_key_b64(&parsed.device_pubkey_b64)
            .map_err(|e| api_bad_request(&format!("invalid attested device key: {e}")))?;
        parsed
    };

    let hw_replay_key = format!(
        "{}:{}:{}",
        ctx.tenant_id, req.hardware_vendor, payload.nonce
    );
    if rt.hw_nonce_replay.is_revoked(&hw_replay_key) {
        return Err(api_denied("hardware attestation nonce replay rejected"));
    }
    rt.hw_nonce_replay
        .revoke(hw_replay_key, payload.exp, now_sec)
        .map_err(|e| api_denied(&e.to_string()))?;

    let cert = BootKeyCertificate {
        device_id: req.device_id.clone(),
        boot_id: req.boot_id,
        key_id: format!("hw_{}", Uuid::now_v7().simple()),
        public_key_b64: payload.device_pubkey_b64,
        issued_at: now,
    };
    let dev = EnrolledDeviceRecord {
        device_id: req.device_id.clone(),
        hostname: req.hostname,
        profile: InstallProfile::Protected,
        essentials_floor_locked: true,
        state: ServerEnrolmentState::Admitted,
        method: EnrolmentMethod::AttestedHardware,
        key_id: Some(cert.key_id.clone()),
        deployment_key_id: None,
        enrolled_at: now,
    };
    rt.tenant_mut(&ctx.tenant_id)
        .enrolled_devices
        .insert(dev.device_id.clone(), dev.clone());
    st.persist_runtime(&rt)?;
    Ok(Json(EnrolmentDecisionResponse {
        device: dev,
        cert: Some(cert),
        workload_spiffe_id: None,
    }))
}

fn verify_oidc_workload_subject_binding(
    claims: &WorkloadOidcClaims,
    claim: &FederatedWorkloadClaim,
) -> Result<(), FedError> {
    let wl_ref = claim.workload_ref.trim();
    let cluster_or_repo = claim.cluster_or_repo.trim();
    if wl_ref.is_empty() || cluster_or_repo.is_empty() {
        return Err(api_denied("workload_ref and cluster_or_repo are required"));
    }
    if !claims.sub.split([':', '/']).any(|seg| seg == wl_ref) {
        return Err(api_denied(
            "OIDC sub claim does not match asserted workload_ref",
        ));
    }
    let repo_ok = match claim.source {
        FederatedWorkloadSource::GitHubActionsOidc | FederatedWorkloadSource::GitLabOidc => {
            claims.repository.as_deref() == Some(cluster_or_repo)
                || claims.project_path.as_deref() == Some(cluster_or_repo)
                || claims.sub.split(':').any(|seg| seg == cluster_or_repo)
        }
        FederatedWorkloadSource::KubernetesOidc
        | FederatedWorkloadSource::SpireFederation
        | FederatedWorkloadSource::AwsIrsa
        | FederatedWorkloadSource::GcpWif => claims
            .sub
            .split([':', '/'])
            .any(|seg| seg == cluster_or_repo || seg == wl_ref),
    };
    if !repo_ok {
        return Err(api_denied(
            "OIDC sub claim does not match asserted cluster_or_repo",
        ));
    }
    Ok(())
}

fn parse_deployment_profile(raw: &str) -> Result<InstallProfile, FedError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "user" | "watch" => Ok(InstallProfile::User),
        "protected" | "enforced" | "standard" => Ok(InstallProfile::Protected),
        other => Err(api_bad_request(&format!(
            "unsupported deployment key install_profile `{other}`"
        ))),
    }
}
