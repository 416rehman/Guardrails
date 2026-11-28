// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use grdr_crypto::fill_random;
use grdr_identity::attest::{AgentInstanceAliasMap, SponsorState};
use grdr_identity::broker_types::{Ceiling, CredentialClass};
use grdr_identity::jwt_keys::TokenKeyRing;
use grdr_identity::registry_correlation::Agent365LicenseState;
use grdr_identity::spiffe::AgentLifecycle;
use grdr_identity::standards_adapters::{IdJagReplayCache, SecurityEventToken, TokenStatusList};
use grdr_identity::token_exchange::{DpopProofVerifier, JtiDenyList};
use grdr_model::error::{
    CODE_CONFLICT, CODE_NOT_FOUND, CODE_POLICY_DENIED, CODE_STORE_CORRUPT, CODE_STORE_IO,
    CODE_UNAUTHORIZED,
};
use grdr_model::{AuditEntry, CodedError};
use grdr_proto::common::ErrorClass;
use jiff::Timestamp;
use tokio::sync::RwLock;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::auth::AuthContext;
use crate::connect_error::{
    ApiError, ApiErrorInner, CODE_API_BAD_REQUEST, CODE_API_INTERNAL, ConnectCode,
};
use crate::store::AppState;

use super::persist::{
    load_defaults_config, load_snapshot_strict, persist_snapshot_atomic, resolve_state_dir,
};
use super::types::{
    ActiveServerLease, FedError, FederationDefaultsConfig, FederationLimits, FederationRuntime,
    FederationState, MAX_LOCAL_CEILING_TTL_SECS, SsfStreamState, TenantFederationState,
};

impl TenantFederationState {
    pub fn new(tenant_id: &str, issuer_url: &str, defaults: &FederationDefaultsConfig) -> Self {
        let mut trusted_spiffe_domains = BTreeSet::new();
        trusted_spiffe_domains.insert(tenant_trust_domain(tenant_id));
        for dom in &defaults.default_spiffe_domains {
            trusted_spiffe_domains.insert(dom.clone());
        }
        let mut trusted_federated_issuers = vec![issuer_url.to_owned()];
        for iss in &defaults.trusted_federated_issuers {
            if !trusted_federated_issuers.contains(iss) {
                trusted_federated_issuers.push(iss.clone());
            }
        }
        let status_list = TokenStatusList::with_capacity_bits(4096);
        let status_list_bytes = status_list.as_bytes().to_vec();
        Self {
            tenant_id: tenant_id.to_owned(),
            trusted_spiffe_domains,
            trusted_federated_issuers,
            trusted_idp_keys: Vec::new(),
            trusted_ssf_keys: Vec::new(),
            trusted_federated_jwks: Vec::new(),
            trusted_hardware_ca_keys: BTreeMap::new(),
            user_bindings: BTreeMap::new(),
            scim_users: BTreeMap::new(),
            scim_groups: BTreeMap::new(),
            instances: BTreeMap::new(),
            instance_ceilings: BTreeMap::new(),
            alias_map: AgentInstanceAliasMap::default(),
            leases: Vec::new(),
            next_status_index: 1,
            status_list_bytes,
            status_list,
            ssf_stream: SsfStreamState {
                stream_id: format!("ssf-stream-{tenant_id}"),
                audience: issuer_url.to_owned(),
                delivery_method: "urn:ietf:rfc:8936".to_string(),
                events_requested: defaults.ssf_events_requested.clone(),
            },
            ssf_events: Vec::new(),
            outward_receipts: Vec::new(),
            enrolled_devices: BTreeMap::new(),
            adopted_credentials: Vec::new(),
            external_registries: Vec::new(),
            agent365_license: Agent365LicenseState::Licensed,
        }
    }
}

impl FederationRuntime {
    pub fn tenant_mut(&mut self, tenant_id: &str) -> &mut TenantFederationState {
        let issuer = self.issuer_url.clone();
        let defaults = self.defaults.clone();
        self.tenants
            .entry(tenant_id.to_owned())
            .or_insert_with(|| TenantFederationState::new(tenant_id, &issuer, &defaults))
    }

    pub fn tenant(&self, tenant_id: &str) -> Option<&TenantFederationState> {
        self.tenants.get(tenant_id)
    }
}

impl FederationState {
    pub fn try_new(app: AppState) -> Result<Self, CodedError> {
        let (st, load_error) = build_federation_state(app)?;
        if let Some(err) = load_error {
            return Err(err);
        }
        Ok(st)
    }

    #[must_use]
    pub fn from_app(app: AppState) -> Self {
        match build_federation_state(app.clone()) {
            Ok((st, Some(err))) => Self {
                load_error: Some(err),
                ..st
            },
            Ok((st, None)) => st,
            Err(err) => {
                let state_dir = resolve_state_dir(&app.backend);
                let (defaults, limits) = load_defaults_config();
                let rt = empty_runtime(&app, defaults, limits);
                Self {
                    app,
                    runtime: Arc::new(RwLock::new(rt)),
                    state_dir,
                    load_error: Some(err),
                }
            }
        }
    }

    pub fn ensure_healthy(&self) -> Result<(), FedError> {
        if let Some(ref err) = self.load_error {
            if err.code == CODE_STORE_CORRUPT || err.code == CODE_STORE_IO {
                return Err(FedError(ApiError::new(ApiErrorInner {
                    code: ConnectCode::Internal,
                    grdr_code: err.code.clone(),
                    reason: "FEDERATION_STORE_UNHEALTHY".into(),
                    class: ErrorClass::Internal,
                    message: err.message.clone(),
                    fix: err.next_step.clone(),
                    metadata: BTreeMap::new(),
                })));
            }
            return Err(FedError(ApiError::from_coded(err.clone())));
        }
        Ok(())
    }

    pub fn persist_runtime(&self, rt: &FederationRuntime) -> Result<(), FedError> {
        self.ensure_healthy()?;
        let Some(dir) = &self.state_dir else {
            return Ok(());
        };
        persist_snapshot_atomic(dir, rt)
    }

    pub async fn append_audit(
        &self,
        kind: &str,
        actor: &str,
        summary: String,
        target: String,
    ) -> Result<(), FedError> {
        let mut guard = self.app.inner.write().await;
        guard.audit.insert(
            0,
            AuditEntry {
                id: format!("aud-{}", Uuid::now_v7().simple()),
                kind: kind.to_owned(),
                actor: actor.to_owned(),
                summary,
                target,
                timestamp: Timestamp::now(),
            },
        );
        self.app.persist_store(&guard).map_err(|err| {
            FedError(ApiError::from_coded(CodedError::new(
                CODE_STORE_IO,
                err.message,
                "Verify persistence storage health and retry.",
            )))
        })
    }
}

fn build_federation_state(
    app: AppState,
) -> Result<(FederationState, Option<CodedError>), CodedError> {
    let state_dir = resolve_state_dir(&app.backend);
    let (defaults, limits) = load_defaults_config();
    let max_bytes = limits.max_snapshot_bytes;
    let snapshot_key = app.signing_key.derive_aead_key("grdr.fed.snapshot.v1");
    let mut rt = empty_runtime(&app, defaults, limits);
    let load_err = state_dir
        .as_ref()
        .and_then(|dir| load_snapshot_strict(dir, &snapshot_key, max_bytes, &mut rt).err());
    Ok((
        FederationState {
            app,
            runtime: Arc::new(RwLock::new(rt)),
            state_dir,
            load_error: None,
        },
        load_err,
    ))
}

fn empty_runtime(
    app: &AppState,
    defaults: FederationDefaultsConfig,
    limits: FederationLimits,
) -> FederationRuntime {
    let issuer_url = grdr_identity::jwt_keys::default_issuer_origin();
    let org_sig = app
        .signing_key
        .sign_bytes("grdr.fed.org.v1", b"org-hmac-key");
    let dev_sig = app
        .signing_key
        .sign_bytes("grdr.fed.dev.v1", b"dev-hmac-key");
    let org_hmac_key = Zeroizing::new(grdr_crypto::sha256_digest(org_sig.as_bytes()));
    let device_hmac_key = Zeroizing::new(grdr_crypto::sha256_digest(dev_sig.as_bytes()));
    let snapshot_key = app.signing_key.derive_aead_key("grdr.fed.snapshot.v1");
    let key_ring = TokenKeyRing::from_active(Arc::new(app.signing_key.clone()));
    let mut tenants = BTreeMap::new();
    tenants.insert(
        "org-default".to_string(),
        TenantFederationState::new("org-default", &issuer_url, &defaults),
    );
    FederationRuntime {
        issuer_url,
        limits,
        defaults,
        org_hmac_key,
        device_hmac_key,
        snapshot_key,
        key_ring,
        dpop_verifier: DpopProofVerifier::new(),
        jti_deny_list: JtiDenyList::new(),
        id_jag_replay: IdJagReplayCache::new(),
        ssf_jti_replay: JtiDenyList::new(),
        oidc_enrol_jti_replay: JtiDenyList::new(),
        hw_nonce_replay: JtiDenyList::new(),
        device_codes: BTreeMap::new(),
        user_code_index: BTreeMap::new(),
        tenants,
    }
}

pub fn tenant_trust_domain(tenant_id: &str) -> String {
    let lower = tenant_id.trim().to_ascii_lowercase();
    if lower.starts_with("org-") {
        lower
    } else {
        format!("org-{lower}")
    }
}

pub fn random_token_hex(prefix: &str, bytes: usize) -> Result<String, FedError> {
    let mut raw = vec![0u8; bytes];
    fill_random(&mut raw).map_err(|e| api_internal(&format!("entropy generation failed: {e}")))?;
    Ok(format!("{prefix}{}", grdr_crypto::encode_lower_hex(&raw)))
}

pub fn push_bounded_ssf_event(
    events: &mut Vec<SecurityEventToken>,
    max_events: usize,
    event: SecurityEventToken,
) {
    if events.len() >= max_events && max_events > 0 {
        let keep = max_events / 2;
        let drop_count = events.len().saturating_sub(keep);
        events.drain(..drop_count);
    }
    events.push(event);
}

pub fn revoke_tenant_leases(
    tenant: &mut TenantFederationState,
    deny_list: &mut JtiDenyList,
    now_sec: i64,
    predicate: impl Fn(&ActiveServerLease) -> bool,
) -> Result<Vec<String>, FedError> {
    let mut revoked_jtis = Vec::new();
    for lease in &mut tenant.leases {
        if !lease.revoked && predicate(lease) {
            lease.revoked = true;
            deny_list
                .revoke(
                    lease.jti.clone(),
                    lease.expires_at.max(now_sec.saturating_add(900)),
                    now_sec,
                )
                .map_err(|e| api_internal(&e.to_string()))?;
            tenant
                .status_list
                .set_revoked(lease.status_index, true)
                .map_err(|e| api_internal(&e.to_string()))?;
            revoked_jtis.push(lease.jti.clone());
        }
    }
    tenant.status_list_bytes = tenant.status_list.as_bytes().to_vec();
    Ok(revoked_jtis)
}

pub fn orphan_sponsor_instances(
    tenant: &mut TenantFederationState,
    deny_list: &mut JtiDenyList,
    sponsor_id: &str,
    now: Timestamp,
) -> Result<(Vec<String>, Vec<String>), FedError> {
    let mut orphaned_agis = Vec::new();
    for inst in tenant.instances.values_mut() {
        let matches = inst
            .sponsor
            .as_ref()
            .is_some_and(|s| s.sponsor_id == sponsor_id);
        if matches && inst.lifecycle != AgentLifecycle::Retired {
            let _ = inst.transition_lifecycle(AgentLifecycle::Orphaned, now);
            if let Some(sp) = inst.sponsor.as_mut() {
                sp.state = SponsorState::Deprovisioned;
            }
            orphaned_agis.push(inst.agi_id.clone());
        }
    }
    let revoked_jtis = revoke_tenant_leases(tenant, deny_list, now.as_second(), |lease| {
        lease.sponsor_id == sponsor_id || orphaned_agis.contains(&lease.instance_agi_id)
    })?;
    Ok((orphaned_agis, revoked_jtis))
}

pub fn require_console_scope<'a>(
    auth: Option<&'a AuthContext>,
    scope: &str,
) -> Result<&'a AuthContext, FedError> {
    let ctx = auth.ok_or_else(|| api_unauthorized("authenticated console principal required"))?;
    if !ctx.allows_scope(scope) {
        return Err(api_denied(&format!(
            "principal `{}` lacks required `{scope}` scope",
            ctx.principal_id
        )));
    }
    Ok(ctx)
}

pub fn auth_actor(auth: Option<&AuthContext>) -> &str {
    auth.map_or("federation", |ctx| ctx.principal_id.as_str())
}

pub fn api_bad_request(msg: &str) -> FedError {
    FedError(ApiError::from_coded(CodedError::new(
        CODE_API_BAD_REQUEST,
        msg,
        "Verify federation request parameters and retry.",
    )))
}

pub fn api_denied(msg: &str) -> FedError {
    FedError(ApiError::from_coded(CodedError::new(
        CODE_POLICY_DENIED,
        msg,
        "Satisfy policy requirements or re-authenticate.",
    )))
}

pub fn api_not_found(msg: &str) -> FedError {
    FedError(ApiError::from_coded(CodedError::new(
        CODE_NOT_FOUND,
        msg,
        "Verify the target identifier and retry.",
    )))
}

pub fn api_conflict(msg: &str) -> FedError {
    FedError(ApiError::from_coded(CodedError::new(
        CODE_CONFLICT,
        msg,
        "Resolve state conflict before retrying.",
    )))
}

pub fn api_unauthorized(msg: &str) -> FedError {
    FedError(ApiError::from_coded(CodedError::new(
        CODE_UNAUTHORIZED,
        msg,
        "Provide a valid bearer credential.",
    )))
}

pub fn api_internal(msg: &str) -> FedError {
    FedError(ApiError::new(ApiErrorInner {
        code: ConnectCode::Internal,
        grdr_code: CODE_API_INTERNAL.into(),
        reason: "INTERNAL_ERROR".into(),
        class: ErrorClass::Internal,
        message: msg.to_owned(),
        fix: "Inspect server logs and retry.".into(),
        metadata: BTreeMap::new(),
    }))
}

pub fn default_instance_ceiling(issuer_url: &str) -> Ceiling {
    Ceiling {
        allowed_classes: BTreeSet::from([CredentialClass::Model, CredentialClass::Forge]),
        allowed_accounts: BTreeSet::from(["default".to_string()]),
        allowed_actions: BTreeSet::from(["read".to_string(), "invoke".to_string()]),
        allowed_resource_prefixes: vec![issuer_url.trim_end_matches('/').to_owned()],
        max_ttl_secs: MAX_LOCAL_CEILING_TTL_SECS,
        max_depth: 4,
    }
}
