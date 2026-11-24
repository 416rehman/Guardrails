// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use grdr_crypto::{fill_random, sha256_hex};
use grdr_model::SessionLabel;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

use crate::IdentityError;
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
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrokeredToken {
    pub jti: String,
    pub lease_id: String,
    pub mode: CredentialMode,
    pub token_value: String,
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

#[derive(Debug, Clone)]
pub struct CredentialBroker {
    policy: BrokerPolicy,
    leases: BTreeMap<String, LeaseRecord>,
    sequence: u64,
}

impl Default for BrokerPolicy {
    fn default() -> Self {
        Self {
            max_release_ttl_secs: 900,
            max_leases_per_window: 30,
            rate_window_secs: 300,
            min_attribution_grade: 3,
            enforce_containment_for_release: true,
        }
    }
}

impl Ceiling {
    #[must_use]
    pub fn intersect(&self, child: &Self) -> Self {
        let allowed_classes = self
            .allowed_classes
            .intersection(&child.allowed_classes)
            .copied()
            .collect();
        let allowed_accounts = self
            .allowed_accounts
            .intersection(&child.allowed_accounts)
            .cloned()
            .collect();
        let allowed_actions = self
            .allowed_actions
            .intersection(&child.allowed_actions)
            .cloned()
            .collect();
        let allowed_resource_prefixes = intersect_prefixes(
            &self.allowed_resource_prefixes,
            &child.allowed_resource_prefixes,
        );
        Self {
            allowed_classes,
            allowed_accounts,
            allowed_actions,
            allowed_resource_prefixes,
            max_ttl_secs: self.max_ttl_secs.min(child.max_ttl_secs),
            max_depth: self.max_depth.min(child.max_depth),
        }
    }

    #[must_use]
    pub fn permits(
        &self,
        class: CredentialClass,
        account_id: &str,
        action: &str,
        resource: &str,
        depth: u32,
    ) -> bool {
        if depth > self.max_depth {
            return false;
        }
        if !self.allowed_classes.contains(&class) {
            return false;
        }
        if !self.allowed_accounts.is_empty() && !self.allowed_accounts.contains(account_id) {
            return false;
        }
        if !self.allowed_actions.contains(action) {
            return false;
        }
        self.allowed_resource_prefixes
            .iter()
            .any(|prefix| resource == prefix || resource.starts_with(prefix))
    }
}

impl CredentialBroker {
    #[must_use]
    pub fn new(policy: BrokerPolicy) -> Self {
        Self {
            policy,
            leases: BTreeMap::new(),
            sequence: 0,
        }
    }

    pub fn request_credential(
        &mut self,
        binding: &CredentialBinding,
        req: &BrokerRequest,
        now: Timestamp,
    ) -> Result<BrokeredToken, IdentityError> {
        if req.attribution_grade < self.policy.min_attribution_grade {
            return Err(IdentityError::InsufficientAttribution {
                found: req.attribution_grade,
                required: self.policy.min_attribution_grade,
            });
        }
        if req.requested_mode == CredentialMode::Release && !req.has_session_container {
            return Err(IdentityError::UncontainedReleaseRefused);
        }
        if !binding
            .allowed_programs
            .iter()
            .any(|p| p == &req.caller_program)
        {
            return Err(IdentityError::UnauthorizedProgram(
                req.caller_program.clone(),
            ));
        }

        let Some(ceiling) = req.ceiling.as_ref() else {
            return Err(IdentityError::NoCeiling);
        };
        if binding.class != req.requested_class
            || !ceiling.permits(
                req.requested_class,
                &binding.account_id,
                &req.requested_action,
                &req.requested_resource,
                req.act_chain_depth,
            )
        {
            return Err(IdentityError::ScopeExceedsCeiling(format!(
                "{:?}:{}:{}",
                req.requested_class, req.requested_action, req.requested_resource
            )));
        }

        self.enforce_containment(binding, req)?;

        if req.lifecycle != AgentLifecycle::Active {
            return Err(IdentityError::InstanceNotActive(req.lifecycle));
        }

        self.enforce_rate_limit(&req.session_id, now)?;

        let effective_ttl = compute_effective_ttl(
            req.requested_ttl_secs,
            ceiling.max_ttl_secs,
            self.policy.max_release_ttl_secs,
            req.session_remaining_secs,
        )?;

        self.sequence = self.sequence.saturating_add(1);
        let jti = format!("jti_{}", Uuid::now_v7());
        let lease_id = format!("lse_{}_{}", self.sequence, Uuid::now_v7());
        let scope_digest = sha256_hex(
            format!(
                "{}|{}|{}|{}|{}",
                req.session_id,
                req.instance_spiffe_id.as_str(),
                req.requested_action,
                req.requested_resource,
                binding.account_id
            )
            .as_bytes(),
        );
        let expires_at = Timestamp::from_second(now.as_second().saturating_add(effective_ttl))
            .map_err(|e| {
                IdentityError::VaultState(format!("invalid lease expiry timestamp: {e}"))
            })?;

        let (token_value, session_label) = match req.requested_mode {
            CredentialMode::Inject => {
                let phantom = mint_phantom_token(&binding.phantom_prefix)?;
                (phantom, None)
            }
            CredentialMode::Release => {
                let release_tok = mint_release_token(
                    &lease_id,
                    &jti,
                    &req.session_id,
                    req.instance_spiffe_id.as_str(),
                    &scope_digest,
                );
                (release_tok, Some(SessionLabel::CredentialAccessed))
            }
        };

        let lease = LeaseRecord {
            lease_id: lease_id.clone(),
            credential_id: binding.credential_id.clone(),
            session_id: req.session_id.clone(),
            instance_spiffe_id: req.instance_spiffe_id.as_str().to_owned(),
            device_id: req.device_id.clone(),
            mode: req.requested_mode,
            scope_digest: scope_digest.clone(),
            issued_at: now,
            expires_at,
            state: LeaseState::Active,
        };
        self.leases.insert(lease_id.clone(), lease);

        Ok(BrokeredToken {
            jti,
            lease_id,
            mode: req.requested_mode,
            token_value,
            non_transferable: true,
            bound_session_id: req.session_id.clone(),
            bound_instance_spiffe_id: req.instance_spiffe_id.as_str().to_owned(),
            bound_device_id: req.device_id.clone(),
            dpop_jkt: req.dpop_jkt.clone(),
            scope_digest,
            issued_at: now,
            expires_at,
            session_label,
        })
    }

    pub fn revoke_by_session(&mut self, session_id: &str) -> usize {
        self.revoke_matching(|lease| lease.session_id == session_id)
    }

    pub fn revoke_by_instance(&mut self, instance_spiffe_id: &str) -> usize {
        self.revoke_matching(|lease| lease.instance_spiffe_id == instance_spiffe_id)
    }

    fn revoke_matching<F>(&mut self, mut predicate: F) -> usize
    where
        F: FnMut(&LeaseRecord) -> bool,
    {
        let mut count: usize = 0;
        for lease in self.leases.values_mut() {
            if lease.state == LeaseState::Active && predicate(lease) {
                lease.state = LeaseState::Revoked;
                count = count.saturating_add(1);
            }
        }
        count
    }

    #[must_use]
    pub fn lease(&self, lease_id: &str) -> Option<&LeaseRecord> {
        self.leases.get(lease_id)
    }

    #[must_use]
    pub fn active_leases(&self, now: Timestamp) -> Vec<&LeaseRecord> {
        self.leases
            .values()
            .filter(|l| l.state == LeaseState::Active && l.expires_at > now)
            .collect()
    }

    fn enforce_containment(
        &self,
        binding: &CredentialBinding,
        req: &BrokerRequest,
    ) -> Result<(), IdentityError> {
        if req.requested_class == CredentialClass::Production
            && req.containment == ContainmentStatus::Uncontained
        {
            return Err(IdentityError::ProductionRequiresContainment);
        }

        if req.requested_mode == CredentialMode::Release {
            if self.policy.enforce_containment_for_release
                && req.containment == ContainmentStatus::Uncontained
            {
                return Err(IdentityError::UncontainedReleaseRefused);
            }
            if !binding.upstream_revocable
                && binding.upstream_min_ttl_secs > self.policy.max_release_ttl_secs
            {
                return Err(IdentityError::ReleaseUnsupportedByUpstream);
            }
        }
        Ok(())
    }

    fn enforce_rate_limit(&self, session_id: &str, now: Timestamp) -> Result<(), IdentityError> {
        let cutoff = now.as_second().saturating_sub(self.policy.rate_window_secs);
        let count = self
            .leases
            .values()
            .filter(|l| l.session_id == session_id && l.issued_at.as_second() >= cutoff)
            .count();
        let count_u32 = u32::try_from(count).unwrap_or(u32::MAX);
        if count_u32 >= self.policy.max_leases_per_window {
            return Err(IdentityError::RateLimitExceeded(session_id.to_owned()));
        }
        Ok(())
    }
}

fn intersect_prefixes(a: &[String], b: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    for pa in a {
        for pb in b {
            if pb.starts_with(pa) {
                out.push(pb.clone());
            } else if pa.starts_with(pb) {
                out.push(pa.clone());
            }
        }
    }
    out
}

fn compute_effective_ttl(
    requested: i64,
    ceiling_max: i64,
    policy_max: i64,
    session_remaining: i64,
) -> Result<i64, IdentityError> {
    let capped = requested
        .min(ceiling_max)
        .min(policy_max)
        .min(session_remaining);
    if capped <= 0 {
        return Err(IdentityError::ScopeExceedsCeiling(
            "effective TTL is non-positive".into(),
        ));
    }
    Ok(capped)
}

fn mint_phantom_token(prefix: &str) -> Result<String, IdentityError> {
    let mut entropy = [0u8; 20];
    fill_random(&mut entropy).map_err(|e| IdentityError::VaultState(e.to_string()))?;
    Ok(format!("{prefix}{}", B64_URL.encode(entropy)))
}

fn mint_release_token(
    lease_id: &str,
    jti: &str,
    session_id: &str,
    instance_spiffe_id: &str,
    scope_digest: &str,
) -> String {
    let digest = sha256_hex(
        format!("{lease_id}|{jti}|{session_id}|{instance_spiffe_id}|{scope_digest}").as_bytes(),
    );
    format!("grdr_rel_{digest}")
}
