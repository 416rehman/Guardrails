// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use base64::Engine as _;
use base64::engine::general_purpose::URL_SAFE_NO_PAD as B64_URL;
use grdr_crypto::{constant_time_eq, fill_random, sha256_hex};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::IdentityError;
use crate::broker::CredentialBroker;
use crate::broker_types::{BrokeredToken, ContainmentStatus, CredentialMode, LeaseState};

const MIN_PHANTOM_RANDOM_BYTES: usize = 20;
const MIN_PHANTOM_SUFFIX_B64_CHARS: usize = 27;
const MAX_RETAINED_PHANTOMS: usize = 8_192;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PhantomMisuseReason {
    UnknownPhantom,
    RevokedOrExpired,
    UncontainedCaller,
    CrossSessionReplay,
    KernelPeerMismatch,
    DisallowedHost,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PeerProcessContext {
    pub session_id: String,
    pub instance_spiffe_id: String,
    pub device_id: String,
    pub pid: u32,
    pub uid: u32,
    pub containment: ContainmentStatus,
    pub target_host: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PhantomMisuseFinding {
    pub finding_kind: String,
    pub reason: PhantomMisuseReason,
    pub observed_session_id: String,
    pub observed_pid: u32,
    pub observed_uid: u32,
    pub bound_lease_id: Option<String>,
    pub timestamp: Timestamp,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum PhantomResolution {
    Authorized {
        real_secret_ref: String,
        lease_id: String,
        target_host: Option<String>,
    },
    Denied {
        finding: PhantomMisuseFinding,
        revoked_lease_count: usize,
    },
}

#[derive(Clone)]
struct PhantomRecord {
    token_digest: String,
    phantom_value: Zeroizing<String>,
    real_secret_ref: String,
    lease_id: String,
    bound_session_id: String,
    bound_instance_spiffe_id: String,
    bound_device_id: String,
    bound_pid: Option<u32>,
    bound_uid: Option<u32>,
    allowed_hosts: Vec<String>,
    expires_at: Timestamp,
    revoked: bool,
}

#[derive(Default)]
pub struct PhantomTokenTable {
    entries: BTreeMap<String, PhantomRecord>,
}

impl std::fmt::Debug for PhantomTokenTable {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PhantomTokenTable")
            .field("entry_count", &self.entries.len())
            .finish_non_exhaustive()
    }
}

pub fn mint_locator_shaped_phantom(prefix: &str) -> Result<Zeroizing<String>, IdentityError> {
    if prefix.trim().is_empty()
        || prefix.len() > 32
        || prefix.chars().any(|c| c.is_control() || c.is_whitespace())
    {
        return Err(IdentityError::CredentialHelper(
            "phantom prefix must be non-empty <= 32 non-control chars".to_string(),
        ));
    }
    let mut raw = [0u8; MIN_PHANTOM_RANDOM_BYTES];
    fill_random(&mut raw).map_err(|e| IdentityError::VaultState(e.to_string()))?;
    Ok(Zeroizing::new(format!("{prefix}{}", B64_URL.encode(raw))))
}

impl PhantomTokenTable {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_for_lease(
        &mut self,
        token: &BrokeredToken,
        phantom_prefix: &str,
        real_secret_ref: &str,
        allowed_hosts: Vec<String>,
        bound_pid: Option<u32>,
        bound_uid: Option<u32>,
    ) -> Result<(), IdentityError> {
        if token.mode != CredentialMode::Inject {
            return Err(IdentityError::CredentialHelper(
                "phantom table accepts CredentialMode::Inject tokens only".to_string(),
            ));
        }
        if phantom_prefix.trim().is_empty()
            || phantom_prefix.len() > 32
            || phantom_prefix
                .chars()
                .any(|c| c.is_control() || c.is_whitespace())
        {
            return Err(IdentityError::CredentialHelper(
                "phantom prefix must be non-empty <= 32 non-control chars".to_string(),
            ));
        }
        if real_secret_ref.trim().is_empty() {
            return Err(IdentityError::CredentialHelper(
                "real_secret_ref cannot be empty".to_string(),
            ));
        }
        if allowed_hosts.is_empty()
            || allowed_hosts.iter().any(|h| {
                h.trim().is_empty() || h.chars().any(|c| c.is_control() || c.is_whitespace())
            })
        {
            return Err(IdentityError::CredentialHelper(
                "phantom lease requires non-empty allowed_hosts".to_string(),
            ));
        }
        let Some(suffix) = token.token_value.as_str().strip_prefix(phantom_prefix) else {
            return Err(IdentityError::CredentialHelper(
                "phantom token does not carry configured prefix".to_string(),
            ));
        };
        if suffix.len() < MIN_PHANTOM_SUFFIX_B64_CHARS {
            return Err(IdentityError::CredentialHelper(
                "phantom token suffix below 160-bit minimum entropy".to_string(),
            ));
        }
        if self.entries.len() >= MAX_RETAINED_PHANTOMS {
            self.prune_revoked_and_expired(token.issued_at);
            if self.entries.len() >= MAX_RETAINED_PHANTOMS {
                return Err(IdentityError::RateLimitExceeded(
                    token.bound_session_id.clone(),
                ));
            }
        }
        let digest = sha256_hex(token.token_value.as_bytes());
        self.entries.insert(
            digest.clone(),
            PhantomRecord {
                token_digest: digest,
                phantom_value: token.token_value.clone(),
                real_secret_ref: real_secret_ref.to_owned(),
                lease_id: token.lease_id.clone(),
                bound_session_id: token.bound_session_id.clone(),
                bound_instance_spiffe_id: token.bound_instance_spiffe_id.clone(),
                bound_device_id: token.bound_device_id.clone(),
                bound_pid,
                bound_uid,
                allowed_hosts,
                expires_at: token.expires_at,
                revoked: false,
            },
        );
        Ok(())
    }

    pub fn swap_credential(
        &mut self,
        presented_phantom: &str,
        caller: &PeerProcessContext,
        broker: &mut CredentialBroker,
        now: Timestamp,
    ) -> PhantomResolution {
        let digest = sha256_hex(presented_phantom.as_bytes());
        let Some(rec) = self.entries.get(&digest).cloned() else {
            return build_denied(
                PhantomMisuseReason::UnknownPhantom,
                caller,
                None,
                broker,
                self,
                now,
            );
        };
        if !constant_time_eq(rec.phantom_value.as_bytes(), presented_phantom.as_bytes()) {
            return build_denied(
                PhantomMisuseReason::UnknownPhantom,
                caller,
                None,
                broker,
                self,
                now,
            );
        }

        let lease_active = broker
            .lease(&rec.lease_id)
            .is_some_and(|l| l.state == LeaseState::Active && l.expires_at > now);
        if rec.revoked || rec.expires_at <= now || !lease_active {
            return build_denied(
                PhantomMisuseReason::RevokedOrExpired,
                caller,
                Some(&rec),
                broker,
                self,
                now,
            );
        }
        if caller.containment != ContainmentStatus::Contained {
            return build_denied(
                PhantomMisuseReason::UncontainedCaller,
                caller,
                Some(&rec),
                broker,
                self,
                now,
            );
        }
        if !constant_time_eq(
            rec.bound_session_id.as_bytes(),
            caller.session_id.as_bytes(),
        ) || !constant_time_eq(
            rec.bound_instance_spiffe_id.as_bytes(),
            caller.instance_spiffe_id.as_bytes(),
        ) || !constant_time_eq(rec.bound_device_id.as_bytes(), caller.device_id.as_bytes())
        {
            return build_denied(
                PhantomMisuseReason::CrossSessionReplay,
                caller,
                Some(&rec),
                broker,
                self,
                now,
            );
        }
        if rec.bound_pid.is_some_and(|pid| pid != caller.pid)
            || rec.bound_uid.is_some_and(|uid| uid != caller.uid)
        {
            return build_denied(
                PhantomMisuseReason::KernelPeerMismatch,
                caller,
                Some(&rec),
                broker,
                self,
                now,
            );
        }
        if rec.allowed_hosts.is_empty()
            || caller
                .target_host
                .as_deref()
                .is_none_or(|host| !host_matches_allowlist(host, &rec.allowed_hosts))
        {
            return build_denied(
                PhantomMisuseReason::DisallowedHost,
                caller,
                Some(&rec),
                broker,
                self,
                now,
            );
        }

        PhantomResolution::Authorized {
            real_secret_ref: rec.real_secret_ref,
            lease_id: rec.lease_id,
            target_host: caller.target_host.clone(),
        }
    }

    pub fn revoke_by_session(&mut self, session_id: &str) -> usize {
        let mut count: usize = 0;
        for rec in self.entries.values_mut() {
            if !rec.revoked && rec.bound_session_id == session_id {
                rec.revoked = true;
                count = count.saturating_add(1);
            }
        }
        count
    }

    pub fn revoke_by_instance(&mut self, spiffe_id: &str) -> usize {
        let mut count: usize = 0;
        for rec in self.entries.values_mut() {
            if !rec.revoked && rec.bound_instance_spiffe_id == spiffe_id {
                rec.revoked = true;
                count = count.saturating_add(1);
            }
        }
        count
    }

    pub fn revoke_by_device(&mut self, device_id: &str) -> usize {
        let mut count: usize = 0;
        for rec in self.entries.values_mut() {
            if !rec.revoked && rec.bound_device_id == device_id {
                rec.revoked = true;
                count = count.saturating_add(1);
            }
        }
        count
    }

    #[must_use]
    pub fn active_count(&self, now: Timestamp) -> usize {
        self.entries
            .values()
            .filter(|rec| !rec.revoked && rec.expires_at > now)
            .count()
    }

    fn prune_revoked_and_expired(&mut self, now: Timestamp) {
        self.entries
            .retain(|_, rec| !rec.revoked && rec.expires_at > now);
    }
}

fn build_denied(
    reason: PhantomMisuseReason,
    caller: &PeerProcessContext,
    rec: Option<&PhantomRecord>,
    broker: &mut CredentialBroker,
    table: &mut PhantomTokenTable,
    now: Timestamp,
) -> PhantomResolution {
    let mut revoked = broker.revoke_by_session(&caller.session_id);
    let _ = table.revoke_by_session(&caller.session_id);
    if let Some(record) = rec {
        if record.bound_session_id != caller.session_id {
            revoked = revoked.saturating_add(broker.revoke_by_session(&record.bound_session_id));
            let _ = table.revoke_by_session(&record.bound_session_id);
        }
        if let Some(slot) = table.entries.get_mut(&record.token_digest) {
            slot.revoked = true;
        }
    }
    PhantomResolution::Denied {
        finding: PhantomMisuseFinding {
            finding_kind: "cred.phantom.misuse".to_string(),
            reason,
            observed_session_id: caller.session_id.clone(),
            observed_pid: caller.pid,
            observed_uid: caller.uid,
            bound_lease_id: rec.map(|r| r.lease_id.clone()),
            timestamp: now,
        },
        revoked_lease_count: revoked,
    }
}

fn host_matches_allowlist(target: &str, allowed: &[String]) -> bool {
    let clean = target.trim().trim_end_matches('.').to_ascii_lowercase();
    if clean.is_empty() {
        return false;
    }
    allowed.iter().any(|entry| {
        let norm = entry.trim().trim_end_matches('.').to_ascii_lowercase();
        !norm.is_empty() && clean == norm
    })
}
