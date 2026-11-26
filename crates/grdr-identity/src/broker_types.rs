// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;

use grdr_model::SessionLabel;
use jiff::Timestamp;
use serde::{Deserialize, Deserializer, Serialize, Serializer};

use zeroize::Zeroizing;

use crate::spiffe::{AgentLifecycle, SpiffeId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialClass {
    Model,
    Cloud,
    Forge,
    Ssh,
    Publish,
    Production,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CredentialMode {
    Inject,
    Release,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ContainmentStatus {
    Contained,
    Uncontained,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseState {
    Active,
    Revoked,
    Expired,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerPolicy {
    pub max_release_ttl_secs: i64,
    pub max_leases_per_window: u32,
    pub rate_window_secs: i64,
    pub min_attribution_grade: u8,
    pub enforce_containment_for_release: bool,
    pub max_retained_leases: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ceiling {
    pub allowed_classes: BTreeSet<CredentialClass>,
    pub allowed_accounts: BTreeSet<String>,
    pub allowed_actions: BTreeSet<String>,
    pub allowed_resource_prefixes: Vec<String>,
    pub max_ttl_secs: i64,
    pub max_depth: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CredentialBinding {
    pub credential_id: String,
    pub class: CredentialClass,
    pub account_id: String,
    pub allowed_programs: Vec<String>,
    pub allowed_hosts: Vec<String>,
    pub upstream_revocable: bool,
    pub upstream_min_ttl_secs: i64,
    pub phantom_prefix: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokerRequest {
    pub session_id: String,
    pub instance_spiffe_id: SpiffeId,
    pub device_id: String,
    pub caller_program: String,
    pub requested_class: CredentialClass,
    pub requested_action: String,
    pub requested_resource: String,
    pub requested_mode: CredentialMode,
    pub requested_ttl_secs: i64,
    pub session_remaining_secs: i64,
    pub attribution_grade: u8,
    pub has_session_container: bool,
    pub containment: ContainmentStatus,
    pub lifecycle: AgentLifecycle,
    pub ceiling: Option<Ceiling>,
    pub act_chain_depth: u32,
    pub dpop_jkt: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LeaseRecord {
    pub lease_id: String,
    pub credential_id: String,
    pub session_id: String,
    pub instance_spiffe_id: String,
    pub device_id: String,
    pub mode: CredentialMode,
    pub scope_digest: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub state: LeaseState,
    pub upstream_public_id: Option<String>,
    pub has_revocation_handle: bool,
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokeredToken {
    pub jti: String,
    pub lease_id: String,
    pub mode: CredentialMode,
    #[serde(
        serialize_with = "serialize_zeroizing_string",
        deserialize_with = "deserialize_zeroizing_string"
    )]
    pub token_value: Zeroizing<String>,
    pub non_transferable: bool,
    pub bound_session_id: String,
    pub bound_instance_spiffe_id: String,
    pub bound_device_id: String,
    pub dpop_jkt: Option<String>,
    pub scope_digest: String,
    pub issued_at: Timestamp,
    pub expires_at: Timestamp,
    pub session_label: Option<SessionLabel>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SessionRevocationReport {
    pub revoked: usize,
    pub pending_lease_ids: Vec<String>,
}

impl std::fmt::Debug for BrokeredToken {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BrokeredToken")
            .field("jti", &self.jti)
            .field("lease_id", &self.lease_id)
            .field("mode", &self.mode)
            .field("token_value", &"<redacted>")
            .field("non_transferable", &self.non_transferable)
            .field("bound_session_id", &self.bound_session_id)
            .field("bound_instance_spiffe_id", &self.bound_instance_spiffe_id)
            .field("bound_device_id", &self.bound_device_id)
            .field("scope_digest", &self.scope_digest)
            .field("issued_at", &self.issued_at)
            .field("expires_at", &self.expires_at)
            .finish_non_exhaustive()
    }
}

fn serialize_zeroizing_string<S: Serializer>(
    value: &Zeroizing<String>,
    serializer: S,
) -> Result<S::Ok, S::Error> {
    serializer.serialize_str(value.as_str())
}

fn deserialize_zeroizing_string<'de, D: Deserializer<'de>>(
    deserializer: D,
) -> Result<Zeroizing<String>, D::Error> {
    String::deserialize(deserializer).map(Zeroizing::new)
}

impl Default for BrokerPolicy {
    fn default() -> Self {
        Self {
            max_release_ttl_secs: 900,
            max_leases_per_window: 30,
            rate_window_secs: 300,
            min_attribution_grade: 3,
            enforce_containment_for_release: true,
            max_retained_leases: 4096,
        }
    }
}
