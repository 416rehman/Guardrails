// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeMap;

use grdr_crypto::{SigningKeypair, constant_time_eq, sha256_hex};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::IdentityError;
use crate::broker::CredentialBroker;
use crate::broker_types::{ContainmentStatus, LeaseState};

pub const SSH_AGENT_FAILURE: u8 = 5;
pub const SSH_AGENTC_REQUEST_IDENTITIES: u8 = 11;
pub const SSH_AGENT_IDENTITIES_ANSWER: u8 = 12;
pub const SSH_AGENTC_SIGN_REQUEST: u8 = 13;
pub const SSH_AGENT_SIGN_RESPONSE: u8 = 14;
pub const SSH_AGENTC_ADD_IDENTITY: u8 = 17;
pub const SSH_AGENTC_REMOVE_IDENTITY: u8 = 18;
const MAX_SSH_FRAME_BYTES: usize = 256 * 1024;
const SSH_ED25519_ALG: &[u8] = b"ssh-ed25519";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SshCallerContext {
    pub session_id: String,
    pub containment: ContainmentStatus,
    pub target_host: Option<String>,
}

#[derive(Clone)]
struct BoundSshKey {
    comment: String,
    keypair: SigningKeypair,
    lease_id: String,
    session_id: String,
    allowed_hosts: Vec<String>,
    pubkey_blob: Vec<u8>,
}

#[derive(Default)]
pub struct SignOnlySshAgent {
    keys_by_blob_sha256: BTreeMap<String, BoundSshKey>,
}

impl std::fmt::Debug for SignOnlySshAgent {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SignOnlySshAgent")
            .field("bound_key_count", &self.keys_by_blob_sha256.len())
            .finish_non_exhaustive()
    }
}

#[must_use]
pub fn encode_ssh_ed25519_pubkey_blob(public_key: &[u8; 32]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4_usize
            .saturating_add(SSH_ED25519_ALG.len())
            .saturating_add(36),
    );
    push_ssh_string(&mut out, SSH_ED25519_ALG);
    push_ssh_string(&mut out, public_key);
    out
}

#[must_use]
pub fn encode_ssh_ed25519_signature_blob(signature: &[u8; 64]) -> Vec<u8> {
    let mut out = Vec::with_capacity(
        4_usize
            .saturating_add(SSH_ED25519_ALG.len())
            .saturating_add(68),
    );
    push_ssh_string(&mut out, SSH_ED25519_ALG);
    push_ssh_string(&mut out, signature);
    out
}

impl SignOnlySshAgent {
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    pub fn register_lease_key(
        &mut self,
        comment: impl Into<String>,
        keypair: SigningKeypair,
        lease_id: impl Into<String>,
        session_id: impl Into<String>,
        allowed_hosts: Vec<String>,
    ) -> Result<Vec<u8>, IdentityError> {
        let comment_str = comment.into();
        let lease_str = lease_id.into();
        let session_str = session_id.into();
        if comment_str.trim().is_empty()
            || lease_str.trim().is_empty()
            || session_str.trim().is_empty()
        {
            return Err(IdentityError::CredentialHelper(
                "SSH key registration requires non-empty comment, lease_id, and session_id"
                    .to_string(),
            ));
        }
        if allowed_hosts.is_empty()
            || allowed_hosts.iter().any(|h| {
                h.trim().is_empty() || h.chars().any(|c| c.is_control() || c.is_whitespace())
            })
        {
            return Err(IdentityError::CredentialHelper(
                "SSH key registration requires non-empty allowed_hosts".to_string(),
            ));
        }
        let max_keys = max_ssh_bound_keys();
        let pubkey_blob = encode_ssh_ed25519_pubkey_blob(&keypair.public_key_bytes());
        let digest = sha256_hex(&pubkey_blob);
        if !self.keys_by_blob_sha256.contains_key(&digest)
            && self.keys_by_blob_sha256.len() >= max_keys
        {
            return Err(IdentityError::RateLimitExceeded(session_str));
        }
        self.keys_by_blob_sha256.insert(
            digest,
            BoundSshKey {
                comment: comment_str,
                keypair,
                lease_id: lease_str,
                session_id: session_str,
                allowed_hosts,
                pubkey_blob: pubkey_blob.clone(),
            },
        );
        Ok(pubkey_blob)
    }

    pub fn prune_inactive(&mut self, broker: &CredentialBroker, now: Timestamp) -> usize {
        let before = self.keys_by_blob_sha256.len();
        self.keys_by_blob_sha256.retain(|_, key| {
            broker
                .lease(&key.lease_id)
                .is_some_and(|l| l.state == LeaseState::Active && l.expires_at > now)
        });
        before.saturating_sub(self.keys_by_blob_sha256.len())
    }

    pub fn revoke_by_session(&mut self, session_id: &str) -> usize {
        let before = self.keys_by_blob_sha256.len();
        self.keys_by_blob_sha256
            .retain(|_, key| key.session_id != session_id);
        before.saturating_sub(self.keys_by_blob_sha256.len())
    }

    pub fn handle_framed_packet(
        &self,
        packet: &[u8],
        caller: &SshCallerContext,
        broker: &CredentialBroker,
        now: Timestamp,
    ) -> Result<Vec<u8>, IdentityError> {
        if packet.len() < 5 || packet.len() > MAX_SSH_FRAME_BYTES {
            return Err(IdentityError::CredentialHelper(
                "SSH agent packet length out of bounds".to_string(),
            ));
        }
        let len_hdr: [u8; 4] = packet
            .get(..4)
            .and_then(|s| s.try_into().ok())
            .ok_or_else(|| IdentityError::CredentialHelper("missing packet length".into()))?;
        let declared_len = usize::try_from(u32::from_be_bytes(len_hdr))
            .map_err(|_| IdentityError::CredentialHelper("packet length overflow".into()))?;
        let body = packet
            .get(4..)
            .filter(|b| b.len() == declared_len && !b.is_empty())
            .ok_or_else(|| {
                IdentityError::CredentialHelper("SSH agent packet length mismatch".to_string())
            })?;

        let msg_type = body.first().copied().unwrap_or(0);
        let rest = body.get(1..).unwrap_or(&[]);
        let reply_body = match msg_type {
            SSH_AGENTC_REQUEST_IDENTITIES => self.build_identities_answer(caller, broker, now),
            SSH_AGENTC_SIGN_REQUEST => self.build_sign_response(rest, caller, broker, now),
            SSH_AGENTC_ADD_IDENTITY | SSH_AGENTC_REMOVE_IDENTITY => vec![SSH_AGENT_FAILURE],
            _ => vec![SSH_AGENT_FAILURE],
        };
        Ok(frame_packet(&reply_body))
    }

    fn build_identities_answer(
        &self,
        caller: &SshCallerContext,
        broker: &CredentialBroker,
        now: Timestamp,
    ) -> Vec<u8> {
        if caller.containment != ContainmentStatus::Contained {
            return vec![SSH_AGENT_FAILURE];
        }
        let active: Vec<&BoundSshKey> = self
            .keys_by_blob_sha256
            .values()
            .filter(|key| is_key_authorized(key, caller, broker, now))
            .collect();
        let mut out = vec![SSH_AGENT_IDENTITIES_ANSWER];
        let count_u32 = u32::try_from(active.len()).unwrap_or(u32::MAX);
        out.extend_from_slice(&count_u32.to_be_bytes());
        for key in active {
            push_ssh_string(&mut out, &key.pubkey_blob);
            push_ssh_string(&mut out, key.comment.as_bytes());
        }
        out
    }

    fn build_sign_response(
        &self,
        mut payload: &[u8],
        caller: &SshCallerContext,
        broker: &CredentialBroker,
        now: Timestamp,
    ) -> Vec<u8> {
        if caller.containment != ContainmentStatus::Contained {
            return vec![SSH_AGENT_FAILURE];
        }
        let Some(pubkey_blob) = read_ssh_string(&mut payload) else {
            return vec![SSH_AGENT_FAILURE];
        };
        let Some(data_to_sign) = read_ssh_string(&mut payload) else {
            return vec![SSH_AGENT_FAILURE];
        };
        let Some(_flags) = read_ssh_u32(&mut payload) else {
            return vec![SSH_AGENT_FAILURE];
        };
        if !payload.is_empty() {
            return vec![SSH_AGENT_FAILURE];
        }

        let digest = sha256_hex(pubkey_blob);
        let Some(key) = self.keys_by_blob_sha256.get(&digest) else {
            return vec![SSH_AGENT_FAILURE];
        };
        if !constant_time_eq(&key.pubkey_blob, pubkey_blob)
            || !is_key_authorized(key, caller, broker, now)
        {
            return vec![SSH_AGENT_FAILURE];
        }
        let sig_raw = key.keypair.sign_ed25519_raw(data_to_sign);
        let sig_blob = encode_ssh_ed25519_signature_blob(&sig_raw);
        let mut out = vec![SSH_AGENT_SIGN_RESPONSE];
        push_ssh_string(&mut out, &sig_blob);
        out
    }
}

fn is_key_authorized(
    key: &BoundSshKey,
    caller: &SshCallerContext,
    broker: &CredentialBroker,
    now: Timestamp,
) -> bool {
    if key.session_id != caller.session_id || key.allowed_hosts.is_empty() {
        return false;
    }
    let Some(lease) = broker.lease(&key.lease_id) else {
        return false;
    };
    if lease.state != LeaseState::Active || lease.expires_at <= now {
        return false;
    }
    let Some(host) = caller.target_host.as_deref() else {
        return false;
    };
    let norm = host.trim().trim_end_matches('.').to_ascii_lowercase();
    if norm.is_empty() {
        return false;
    }
    key.allowed_hosts.iter().any(|h| {
        let allowed = h.trim().trim_end_matches('.').to_ascii_lowercase();
        !allowed.is_empty() && allowed == norm
    })
}

fn max_ssh_bound_keys() -> usize {
    grdr_schema::limits::load_embedded_limits()
        .map(|l| l.broker.circuit_breaker.max_outcomes)
        .unwrap_or(4_096)
}

fn frame_packet(body: &[u8]) -> Vec<u8> {
    let len_u32 = u32::try_from(body.len()).unwrap_or(u32::MAX);
    let mut out = Vec::with_capacity(4_usize.saturating_add(body.len()));
    out.extend_from_slice(&len_u32.to_be_bytes());
    out.extend_from_slice(body);
    out
}

fn push_ssh_string(buf: &mut Vec<u8>, bytes: &[u8]) {
    let len_u32 = u32::try_from(bytes.len()).unwrap_or(u32::MAX);
    buf.extend_from_slice(&len_u32.to_be_bytes());
    buf.extend_from_slice(bytes);
}

fn read_ssh_u32(cursor: &mut &[u8]) -> Option<u32> {
    let bytes: [u8; 4] = cursor.get(..4)?.try_into().ok()?;
    *cursor = cursor.get(4..)?;
    Some(u32::from_be_bytes(bytes))
}

fn read_ssh_string<'a>(cursor: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = usize::try_from(read_ssh_u32(cursor)?).ok()?;
    let slice = cursor.get(..len)?;
    *cursor = cursor.get(len..)?;
    Some(slice)
}
