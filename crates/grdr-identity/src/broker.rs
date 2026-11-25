// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use grdr_crypto::{fill_random, sha256_hex};
use grdr_model::SessionLabel;
use jiff::Timestamp;
use uuid::Uuid;

use crate::IdentityError;
use crate::broker_types::{
    BrokerPolicy, BrokerRequest, BrokeredToken, Ceiling, ContainmentStatus, CredentialBinding,
    CredentialClass, CredentialMode, LeaseRecord, LeaseState,
};
use crate::spiffe::AgentLifecycle;

#[derive(Debug, Clone)]
pub struct CredentialBroker {
    policy: BrokerPolicy,
    leases: BTreeMap<String, LeaseRecord>,
    recent_issuances: BTreeMap<String, Vec<Timestamp>>,
    sequence: u64,
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
        if !self.allowed_accounts.contains(account_id) {
            return false;
        }
        if !self.allowed_actions.contains(action) {
            return false;
        }
        self.allowed_resource_prefixes
            .iter()
            .any(|prefix| resource_matches_prefix(resource, prefix))
    }
}

impl CredentialBroker {
    #[must_use]
    pub fn new(policy: BrokerPolicy) -> Self {
        Self {
            policy,
            leases: BTreeMap::new(),
            recent_issuances: BTreeMap::new(),
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

        let effective_ttl = compute_effective_ttl(
            req.requested_ttl_secs,
            ceiling.max_ttl_secs,
            self.policy.max_release_ttl_secs,
            req.session_remaining_secs,
        )?;
        self.enforce_containment(binding, req, effective_ttl)?;

        if req.lifecycle != AgentLifecycle::Active {
            return Err(IdentityError::InstanceNotActive(req.lifecycle));
        }
        self.enforce_rate_limit(&req.session_id, now)?;
        self.prune_inactive_leases(now);
        if self.leases.len() >= self.policy.max_retained_leases {
            return Err(IdentityError::RateLimitExceeded(req.session_id.clone()));
        }

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
            CredentialMode::Inject => (
                mint_token_with_entropy::<20>(&binding.phantom_prefix)?,
                None,
            ),
            CredentialMode::Release => (
                mint_token_with_entropy::<32>("grdr_rel_")?,
                Some(SessionLabel::CredentialAccessed),
            ),
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
        self.recent_issuances
            .entry(req.session_id.clone())
            .or_default()
            .push(now);

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
        effective_ttl: i64,
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
            if !binding.upstream_revocable && binding.upstream_min_ttl_secs > effective_ttl {
                return Err(IdentityError::ReleaseUnsupportedByUpstream);
            }
        }
        Ok(())
    }

    fn enforce_rate_limit(
        &mut self,
        session_id: &str,
        now: Timestamp,
    ) -> Result<(), IdentityError> {
        let cutoff = now.as_second().saturating_sub(self.policy.rate_window_secs);
        if self.recent_issuances.len() >= self.policy.max_retained_leases {
            self.recent_issuances.retain(|_, times| {
                times.retain(|ts| ts.as_second() >= cutoff);
                !times.is_empty()
            });
            if !self.recent_issuances.contains_key(session_id)
                && self.recent_issuances.len() >= self.policy.max_retained_leases
            {
                return Err(IdentityError::RateLimitExceeded(session_id.to_owned()));
            }
        }
        let entries = self
            .recent_issuances
            .entry(session_id.to_owned())
            .or_default();
        entries.retain(|ts| ts.as_second() >= cutoff);
        let count_u32 = u32::try_from(entries.len()).unwrap_or(u32::MAX);
        if count_u32 >= self.policy.max_leases_per_window {
            return Err(IdentityError::RateLimitExceeded(session_id.to_owned()));
        }
        Ok(())
    }

    fn prune_inactive_leases(&mut self, now: Timestamp) {
        if self.leases.len() < self.policy.max_retained_leases {
            return;
        }
        self.leases
            .retain(|_, lease| lease.state == LeaseState::Active && lease.expires_at > now);
    }
}

fn resource_matches_prefix(resource: &str, prefix: &str) -> bool {
    if prefix.is_empty() || resource.is_empty() {
        return false;
    }
    if resource == prefix {
        return true;
    }
    let Some(rest) = resource.strip_prefix(prefix) else {
        return false;
    };
    prefix.ends_with(['/', ':', '-']) || rest.starts_with(['/', ':', '?'])
}

fn intersect_prefixes(a: &[String], b: &[String]) -> Vec<String> {
    let mut unique = BTreeSet::new();
    for pa in a {
        if pa.is_empty() {
            continue;
        }
        for pb in b {
            if pb.is_empty() {
                continue;
            }
            if resource_matches_prefix(pb, pa) {
                unique.insert(pb.clone());
            } else if resource_matches_prefix(pa, pb) {
                unique.insert(pa.clone());
            }
        }
    }
    unique.into_iter().collect()
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

fn mint_token_with_entropy<const N: usize>(prefix: &str) -> Result<String, IdentityError> {
    let mut entropy = [0u8; N];
    fill_random(&mut entropy).map_err(|e| IdentityError::VaultState(e.to_string()))?;
    Ok(format!("{prefix}{}", B64_URL.encode(entropy)))
}
