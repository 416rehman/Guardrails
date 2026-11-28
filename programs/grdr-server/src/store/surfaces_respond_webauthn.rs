// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Server-side WebAuthn Level 3 step-up assertion verification, replay state,
//! and chained hardware-attested approver rosters (`docs/design/18`, `22`).

use std::collections::{BTreeMap, BTreeSet};

use base64::Engine as _;
use base64::engine::general_purpose::{STANDARD as B64_STD, URL_SAFE_NO_PAD as B64_URL};
use serde::{Deserialize, Serialize};

use grdr_core::detect::kill_switch::server_operational_limits;
use grdr_crypto::{encode_lower_hex, sha256_digest, validate_public_key_b64, verify_ed25519_raw};
use grdr_model::CodedError;
use grdr_model::error::{
    CODE_CONFLICT, CODE_INVALID_INPUT, CODE_POLICY_STEP_UP, CODE_UNAUTHORIZED,
};

const WEBAUTHN_FLAG_UP_UV: u8 = 0x05;
const WEBAUTHN_FLAG_BE_BS: u8 = 0x18;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverAttestationStatus {
    HardwareAttested,
    BackupEligibleSynced,
    Unattested,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ApproverRole {
    OrgAdmin,
    OrgResponder,
    ProviderResponder,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverRosterEntry {
    pub key_id: String,
    pub public_key_b64: String,
    pub role: ApproverRole,
    pub attestation: ApproverAttestationStatus,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApproverRosterState {
    pub version: u64,
    pub org_id: String,
    pub claimed_org: bool,
    pub rp_id: String,
    pub origin: String,
    pub prev_digest_sha256: String,
    pub provider_delegated: bool,
    pub entries: Vec<ApproverRosterEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnStepUpAssertion {
    pub key_id: String,
    pub client_data_json: Vec<u8>,
    pub authenticator_data: Vec<u8>,
    pub signature: Vec<u8>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebAuthnReplayState {
    pub used_challenges: Vec<String>,
    pub signer_sign_counts: BTreeMap<String, u32>,
}

#[derive(Debug, Clone)]
pub(crate) struct VerifiedSigner {
    pub key_id: String,
    pub public_key_hex: String,
    pub role: ApproverRole,
}

#[derive(Debug, Clone)]
pub(crate) struct StagedReplayCommit {
    challenge_tag: String,
    max_replay_entries: usize,
    updates: Vec<(String, u32)>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "camelCase")]
struct WebAuthnClientData {
    #[serde(rename = "type")]
    kind: String,
    challenge: String,
    origin: String,
    #[serde(default)]
    cross_origin: Option<bool>,
}

impl ApproverRosterState {
    pub fn digest_sha256(&self) -> Result<String, CodedError> {
        let bytes = serde_json::to_vec(self).map_err(|err| {
            CodedError::new(
                CODE_INVALID_INPUT,
                format!("failed to encode roster state: {err}"),
                "Verify roster fields.",
            )
        })?;
        Ok(encode_lower_hex(&sha256_digest(&bytes)))
    }

    pub fn canonical_rotation_body(&self) -> Result<Vec<u8>, CodedError> {
        let payload = (
            "grdr.roster_rotate.v1",
            self.version,
            &self.org_id,
            self.claimed_org,
            &self.rp_id,
            &self.origin,
            &self.prev_digest_sha256,
            self.provider_delegated,
            &self.entries,
        );
        serde_json::to_vec(&payload).map_err(|err| {
            CodedError::new(
                CODE_INVALID_INPUT,
                format!("failed to encode canonical roster rotation body: {err}"),
                "Verify roster fields.",
            )
        })
    }

    /// Validates hardware attestation, HTTPS origin, unique Ed25519 keys, delegation scope,
    /// and server-derived canonical rotation quorum (`docs/design/18`, `22`).
    pub fn validate_registration_or_rotation(
        &self,
        prev: Option<&ApproverRosterState>,
        quorum_min: usize,
        rotation_assertions: &[WebAuthnStepUpAssertion],
        replay: &mut WebAuthnReplayState,
    ) -> Result<(), CodedError> {
        self.validate_entries_and_metadata()?;

        if let Some(prev_roster) = prev {
            if self.org_id != prev_roster.org_id {
                return Err(CodedError::new(
                    CODE_UNAUTHORIZED,
                    "roster rotation cannot change org_id",
                    "Rotate roster inside the owning organisation.",
                ));
            }
            if quorum_min < 2 {
                return Err(CodedError::new(
                    CODE_POLICY_STEP_UP,
                    "roster rotation quorum_min must be >= 2",
                    "Enforce dual hardware approver quorum for roster rotations.",
                ));
            }
            if self.version != prev_roster.version.saturating_add(1) {
                return Err(CodedError::new(
                    CODE_CONFLICT,
                    "roster version must increment monotonically",
                    "Increment roster version from active head.",
                ));
            }
            if self.prev_digest_sha256 != prev_roster.digest_sha256()? {
                return Err(CodedError::new(
                    CODE_CONFLICT,
                    "roster prev_digest_sha256 chain mismatch",
                    "Chain next roster against the previous canonical roster digest.",
                ));
            }
            let rotation_body = self.canonical_rotation_body()?;
            let (verified, staged) =
                verify_distinct_signers(prev_roster, &rotation_body, rotation_assertions, replay)?;
            let org_signers = verified
                .iter()
                .filter(|s| matches!(s.role, ApproverRole::OrgAdmin | ApproverRole::OrgResponder))
                .count();
            if org_signers < quorum_min {
                return Err(CodedError::new(
                    CODE_POLICY_STEP_UP,
                    format!(
                        "roster rotation requires {quorum_min} org approver signatures (provider responders excluded)"
                    ),
                    "Collect required hardware WebAuthn signatures from organisation approvers.",
                ));
            }
            staged.commit(replay);
        } else if self.version != 1 || self.prev_digest_sha256 != "0".repeat(64) {
            return Err(CodedError::new(
                CODE_CONFLICT,
                "genesis approver roster must use version 1 and 64-zero prev_digest_sha256",
                "Initialize v1 roster with zero hash chain genesis.",
            ));
        }
        Ok(())
    }

    pub(crate) fn validate_entries_and_metadata(&self) -> Result<(), CodedError> {
        if self.org_id.trim().is_empty()
            || self.entries.is_empty()
            || self.rp_id.trim().is_empty()
            || !is_valid_https_origin(&self.origin)
        {
            return Err(CodedError::new(
                CODE_INVALID_INPUT,
                "approver roster requires non-empty org_id, entries, rp_id, and https origin",
                "Provide non-empty FIDO2 RP metadata with valid HTTPS origin and attested approvers.",
            ));
        }
        let mut seen_ids = BTreeSet::new();
        let mut seen_pks = BTreeSet::new();
        for entry in &self.entries {
            if entry.key_id.trim().is_empty() {
                return Err(CodedError::new(
                    CODE_INVALID_INPUT,
                    "approver roster entry key_id must be non-empty",
                    "Provide valid WebAuthn key_id.",
                ));
            }
            if entry.attestation != ApproverAttestationStatus::HardwareAttested {
                return Err(CodedError::new(
                    CODE_UNAUTHORIZED,
                    format!(
                        "refused non-hardware or backup-eligible credential `{}` ({:?})",
                        entry.key_id, entry.attestation
                    ),
                    "Enroll a device-bound hardware-attested FIDO2 credential without backup eligibility.",
                ));
            }
            validate_public_key_b64(&entry.public_key_b64).map_err(|_| {
                CodedError::new(
                    CODE_INVALID_INPUT,
                    format!("approver `{}` has invalid Ed25519 public key", entry.key_id),
                    "Provide valid base64-encoded 32-byte Ed25519 public key.",
                )
            })?;
            let pk_bytes = decode_ed25519_pk(&entry.public_key_b64)?;
            if !seen_ids.insert(entry.key_id.clone()) || !seen_pks.insert(pk_bytes) {
                return Err(CodedError::new(
                    CODE_CONFLICT,
                    format!("duplicate approver key_id or public key `{}`", entry.key_id),
                    "Each enrolled hardware approver key must be unique.",
                ));
            }
            if entry.role == ApproverRole::ProviderResponder && !self.provider_delegated {
                return Err(CodedError::new(
                    CODE_UNAUTHORIZED,
                    format!(
                        "provider-responder `{}` requires active org delegation",
                        entry.key_id
                    ),
                    "Enable customer delegation before enrolling provider responders.",
                ));
            }
        }
        Ok(())
    }

    fn verify_assertion(
        &self,
        expected_challenge: &str,
        a: &WebAuthnStepUpAssertion,
        replay: &WebAuthnReplayState,
    ) -> Result<(VerifiedSigner, [u8; 32], u32), CodedError> {
        let entry = self
            .entries
            .iter()
            .find(|e| e.key_id == a.key_id)
            .ok_or_else(|| {
                CodedError::new(
                    CODE_UNAUTHORIZED,
                    format!("signer `{}` absent from roster", a.key_id),
                    "Use an enrolled hardware-attested key.",
                )
            })?;
        if entry.attestation != ApproverAttestationStatus::HardwareAttested {
            return Err(CodedError::new(
                CODE_UNAUTHORIZED,
                "synced or unattested signer refused",
                "Re-enroll with device-bound FIDO2 hardware attestation.",
            ));
        }

        let client: WebAuthnClientData =
            serde_json::from_slice(&a.client_data_json).map_err(|_| {
                CodedError::new(
                    CODE_UNAUTHORIZED,
                    "WebAuthn clientDataJSON parse failed",
                    "Supply valid WebAuthn Level 3 clientDataJSON.",
                )
            })?;
        if client.kind != "webauthn.get"
            || client.challenge != expected_challenge
            || client.origin != self.origin
            || client.cross_origin.unwrap_or(false)
        {
            return Err(CodedError::new(
                CODE_UNAUTHORIZED,
                "WebAuthn clientDataJSON challenge/origin/type verification failed",
                "Sign exact server challenge from pinned console HTTPS origin.",
            ));
        }

        let (Some(&flags), Some(rp_hash), Some(count_bytes)) = (
            a.authenticator_data.get(32),
            a.authenticator_data.get(..32),
            a.authenticator_data.get(33..37),
        ) else {
            return Err(CodedError::new(
                CODE_UNAUTHORIZED,
                "WebAuthn authenticatorData too short",
                "Present valid WebAuthn Level 3 authenticatorData (>= 37 bytes).",
            ));
        };
        if rp_hash != sha256_digest(self.rp_id.as_bytes())
            || (flags & WEBAUTHN_FLAG_UP_UV) != WEBAUTHN_FLAG_UP_UV
            || (flags & WEBAUTHN_FLAG_BE_BS) != 0
        {
            return Err(CodedError::new(
                CODE_UNAUTHORIZED,
                "WebAuthn RP ID hash, UP/UV flags, or backup-eligible (BE/BS) check failed",
                "Present device-bound non-backup-eligible hardware key with UP+UV.",
            ));
        }

        let count_arr: [u8; 4] = count_bytes.try_into().map_err(|_| {
            CodedError::new(
                CODE_UNAUTHORIZED,
                "WebAuthn signCount length invalid",
                "Present 4-byte authenticator signCount.",
            )
        })?;
        let sign_count = u32::from_be_bytes(count_arr);
        let pk_arr = decode_ed25519_pk(&entry.public_key_b64)?;
        let count_key = signer_counter_key(&self.org_id, &pk_arr);
        if sign_count == 0
            || replay
                .signer_sign_counts
                .get(&count_key)
                .is_some_and(|prev| sign_count <= *prev)
        {
            return Err(CodedError::new(
                CODE_UNAUTHORIZED,
                "WebAuthn signCount non-monotonic or zero (replayed credential rejected)",
                "Present strictly increasing authenticator signCount > 0.",
            ));
        }

        let sig_arr: [u8; 64] = a.signature.as_slice().try_into().map_err(|_| {
            CodedError::new(
                CODE_UNAUTHORIZED,
                "WebAuthn assertion signature length invalid",
                "Expected 64-byte Ed25519 signature.",
            )
        })?;
        let mut msg = Vec::with_capacity(a.authenticator_data.len().saturating_add(32));
        msg.extend_from_slice(&a.authenticator_data);
        msg.extend_from_slice(&sha256_digest(&a.client_data_json));
        verify_ed25519_raw(&pk_arr, &msg, &sig_arr).map_err(|_| {
            CodedError::new(
                CODE_UNAUTHORIZED,
                "WebAuthn assertion Ed25519 signature invalid",
                "Verify hardware signature payload.",
            )
        })?;
        Ok((
            VerifiedSigner {
                key_id: entry.key_id.clone(),
                public_key_hex: encode_lower_hex(&pk_arr),
                role: entry.role,
            },
            pk_arr,
            sign_count,
        ))
    }
}

impl StagedReplayCommit {
    pub(crate) fn commit(self, replay: &mut WebAuthnReplayState) {
        if replay.used_challenges.len() >= self.max_replay_entries {
            replay.used_challenges.remove(0);
        }
        replay.used_challenges.push(self.challenge_tag);
        for (ckey, sign_count) in self.updates {
            replay.signer_sign_counts.insert(ckey, sign_count);
        }
    }
}

pub(crate) fn verify_distinct_signers(
    roster: &ApproverRosterState,
    body: &[u8],
    assertions: &[WebAuthnStepUpAssertion],
    replay: &WebAuthnReplayState,
) -> Result<(Vec<VerifiedSigner>, StagedReplayCommit), CodedError> {
    let cfg = server_operational_limits().map_err(|err| {
        CodedError::new(
            CODE_CONFLICT,
            format!("operational limits unavailable: {err}"),
            "Restore valid embedded contracts/limits.toml configuration.",
        )
    })?;
    let max_replay_entries = usize::try_from(cfg.max_devices_default)
        .unwrap_or(10_000)
        .max(128);
    let expected_challenge = B64_URL.encode(sha256_digest(body));
    let challenge_tag = format!("{}:{expected_challenge}", roster.org_id);
    if replay.used_challenges.contains(&challenge_tag) {
        return Err(CodedError::new(
            CODE_CONFLICT,
            "WebAuthn challenge already consumed (replay rejected)",
            "Issue fresh monotonic command epoch/counter challenge.",
        ));
    }

    let mut seen_ids = BTreeSet::new();
    let mut seen_pks = BTreeSet::new();
    let mut verified = Vec::new();
    let mut updates = Vec::new();
    for assertion in assertions {
        let (signer, pk_arr, sign_count) =
            roster.verify_assertion(&expected_challenge, assertion, replay)?;
        if seen_ids.insert(signer.key_id.clone()) && seen_pks.insert(pk_arr) {
            updates.push((signer_counter_key(&roster.org_id, &pk_arr), sign_count));
            verified.push(signer);
        }
    }
    if verified.is_empty() {
        return Err(CodedError::new(
            CODE_UNAUTHORIZED,
            "no valid distinct WebAuthn assertions presented",
            "Collect distinct hardware WebAuthn signatures.",
        ));
    }
    Ok((
        verified,
        StagedReplayCommit {
            challenge_tag,
            max_replay_entries,
            updates,
        },
    ))
}

fn is_valid_https_origin(origin: &str) -> bool {
    let Some(rest) = origin.strip_prefix("https://") else {
        return false;
    };
    !rest.is_empty()
        && !rest.chars().any(|c| c.is_whitespace() || c.is_control())
        && !rest.contains('@')
        && !rest.contains('?')
        && !rest.contains('#')
        && !rest.contains('/')
}

fn decode_ed25519_pk(public_key_b64: &str) -> Result<[u8; 32], CodedError> {
    let bytes = B64_STD.decode(public_key_b64.trim()).map_err(|_| {
        CodedError::new(
            CODE_UNAUTHORIZED,
            "WebAuthn roster public key encoding invalid",
            "Re-enroll verified hardware approver key.",
        )
    })?;
    bytes.as_slice().try_into().map_err(|_| {
        CodedError::new(
            CODE_UNAUTHORIZED,
            "WebAuthn roster public key length invalid",
            "Expected 32-byte Ed25519 public key.",
        )
    })
}

fn signer_counter_key(org_id: &str, pk_arr: &[u8; 32]) -> String {
    format!("{org_id}:{}", encode_lower_hex(pk_arr))
}
