// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};
use std::path::PathBuf;
use std::sync::Arc;

use axum::response::{IntoResponse, Response};
use grdr_crypto::AeadKey;
use grdr_identity::attest::{AgentInstanceAliasMap, AgentInstanceRecord};
use grdr_identity::broker_types::Ceiling;
use grdr_identity::jwt_keys::{OkpEd25519Jwk, TokenKeyRing};
use grdr_identity::registry_correlation::{Agent365LicenseState, ExternalRegistryRecord};
use grdr_identity::standards_adapters::{IdJagReplayCache, SecurityEventToken, TokenStatusList};
use grdr_identity::token_exchange::{DpopProofVerifier, JtiDenyList};
use grdr_model::{CodedError, InstallProfile};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use zeroize::Zeroizing;

use crate::connect_error::{ApiError, WireEncoding, encode_connect_error};
use crate::store::AppState;

pub const FEDERATION_STATE_FILENAME: &str = "federation.json";
pub const MAX_LOCAL_CEILING_TTL_SECS: i64 = 900;

#[derive(Debug, Clone, Deserialize)]
pub struct FederationDefaultsConfig {
    pub default_spiffe_domains: Vec<String>,
    pub allowed_oidc_scopes: Vec<String>,
    pub trusted_federated_issuers: Vec<String>,
    pub ssf_events_requested: Vec<String>,
    pub max_snapshot_bytes: usize,
    pub device_expires_secs: i64,
    pub device_poll_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct FederationLimits {
    pub max_device_codes: usize,
    pub max_ssf_events: usize,
    pub max_leases: usize,
    pub max_devices: usize,
    pub max_skew_secs: i64,
    pub max_snapshot_bytes: usize,
    pub device_expires_secs: i64,
    pub device_poll_interval_secs: u64,
}

#[derive(Debug, Clone)]
pub struct FedError(pub ApiError);

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceFlowStatus {
    AuthorizationPending,
    Authorized,
    Denied,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServerEnrolmentState {
    Pending,
    Admitted,
    Rejected,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EnrolmentMethod {
    DeploymentKey,
    WorkloadOidc,
    AttestedHardware,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceCodeRecord {
    pub device_code: String,
    pub user_code: String,
    pub client_id: String,
    pub scope: String,
    pub expires_at: i64,
    pub status: DeviceFlowStatus,
    pub tenant_id: Option<String>,
    pub device_pseudonym: Option<String>,
    pub pseudonym_sub: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DeviceUserBinding {
    pub device_pseudonym: String,
    pub org_pseudonym: String,
    pub bound_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimUserRecord {
    pub id: String,
    pub external_id: Option<String>,
    pub user_name: String,
    pub display_name: String,
    pub email: String,
    pub active: bool,
    pub updated_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ScimGroupRecord {
    pub id: String,
    pub display_name: String,
    pub members: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ActiveServerLease {
    pub lease_id: String,
    pub jti: String,
    pub tenant_id: String,
    pub status_index: usize,
    pub session_id: String,
    pub instance_agi_id: String,
    pub device_id: String,
    pub sponsor_id: String,
    pub expires_at: i64,
    pub revoked: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SsfStreamState {
    pub stream_id: String,
    pub audience: String,
    pub delivery_method: String,
    pub events_requested: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OutwardReceiptRecord {
    pub receipt_id: String,
    pub agi_id: String,
    pub session_id: String,
    pub repo: String,
    pub commit_sha: String,
    pub patch_id: Option<String>,
    pub pr_number: Option<u64>,
    pub signature: String,
    pub recorded_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnrolledDeviceRecord {
    pub device_id: String,
    pub hostname: String,
    pub profile: InstallProfile,
    pub essentials_floor_locked: bool,
    pub state: ServerEnrolmentState,
    pub method: EnrolmentMethod,
    pub key_id: Option<String>,
    pub deployment_key_id: Option<String>,
    pub enrolled_at: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AdoptedCredentialMetadata {
    pub crd_id: String,
    pub locator_id: String,
    pub store_kind: String,
    pub owner_device_id: String,
    pub adopted_at: Timestamp,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TenantFederationState {
    pub tenant_id: String,
    pub trusted_spiffe_domains: BTreeSet<String>,
    pub trusted_federated_issuers: Vec<String>,
    pub trusted_idp_keys: Vec<OkpEd25519Jwk>,
    pub trusted_ssf_keys: Vec<OkpEd25519Jwk>,
    pub trusted_federated_jwks: Vec<OkpEd25519Jwk>,
    pub trusted_hardware_ca_keys: BTreeMap<String, Vec<OkpEd25519Jwk>>,
    pub user_bindings: BTreeMap<String, DeviceUserBinding>,
    pub scim_users: BTreeMap<String, ScimUserRecord>,
    pub scim_groups: BTreeMap<String, ScimGroupRecord>,
    pub instances: BTreeMap<String, AgentInstanceRecord>,
    pub instance_ceilings: BTreeMap<String, Ceiling>,
    pub alias_map: AgentInstanceAliasMap,
    pub leases: Vec<ActiveServerLease>,
    pub next_status_index: usize,
    pub status_list_bytes: Vec<u8>,
    #[serde(skip, default = "default_status_list")]
    pub status_list: TokenStatusList,
    pub ssf_stream: SsfStreamState,
    pub ssf_events: Vec<SecurityEventToken>,
    pub outward_receipts: Vec<OutwardReceiptRecord>,
    pub enrolled_devices: BTreeMap<String, EnrolledDeviceRecord>,
    pub adopted_credentials: Vec<AdoptedCredentialMetadata>,
    pub external_registries: Vec<ExternalRegistryRecord>,
    pub agent365_license: Agent365LicenseState,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PersistedFederationSnapshot {
    pub tenants: BTreeMap<String, TenantFederationState>,
    pub active_jti_deny_list: Vec<(String, i64)>,
    pub active_id_jag_replay: Vec<(String, String, i64)>,
    pub active_ssf_jti_replay: Vec<(String, i64)>,
    pub active_oidc_enrol_replay: Vec<(String, i64)>,
    pub active_hw_nonce_replay: Vec<(String, i64)>,
}

pub struct FederationRuntime {
    pub issuer_url: String,
    pub limits: FederationLimits,
    pub defaults: FederationDefaultsConfig,
    pub org_hmac_key: Zeroizing<[u8; 32]>,
    pub device_hmac_key: Zeroizing<[u8; 32]>,
    pub snapshot_key: AeadKey,
    pub key_ring: TokenKeyRing,
    pub dpop_verifier: DpopProofVerifier,
    pub jti_deny_list: JtiDenyList,
    pub id_jag_replay: IdJagReplayCache,
    pub ssf_jti_replay: JtiDenyList,
    pub oidc_enrol_jti_replay: JtiDenyList,
    pub hw_nonce_replay: JtiDenyList,
    pub device_codes: BTreeMap<String, DeviceCodeRecord>,
    pub user_code_index: BTreeMap<String, String>,
    pub tenants: BTreeMap<String, TenantFederationState>,
}

#[derive(Clone)]
pub struct FederationState {
    pub app: AppState,
    pub runtime: Arc<RwLock<FederationRuntime>>,
    pub state_dir: Option<PathBuf>,
    pub load_error: Option<CodedError>,
}

impl IntoResponse for FedError {
    fn into_response(self) -> Response {
        encode_connect_error(WireEncoding::Json, "", &self.0)
    }
}

pub(crate) fn default_status_list() -> TokenStatusList {
    TokenStatusList::with_capacity_bits(4096)
}
