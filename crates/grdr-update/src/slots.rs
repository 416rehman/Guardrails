// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use grdr_model::TrustedKeyInfo;
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::UpdateError;
use crate::dsse::{DsseEnvelope, verify_dsse_envelope};
use crate::tuf::UpdateTrust;
use crate::tuf_types::canonical_sha256;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpdateSlot {
    SlotA,
    SlotB,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "state", rename_all = "snake_case")]
pub enum SlotState {
    Active {
        slot: UpdateSlot,
        version: String,
        generation: u64,
        artifact_sha256: String,
        security_floor: u64,
    },
    Staging {
        active: UpdateSlot,
        active_version: String,
        active_generation: u64,
        active_sha256: String,
        staging: UpdateSlot,
        candidate_version: String,
        candidate_generation: u64,
        candidate_sha256: String,
        security_floor: u64,
    },
    PendingActivation {
        active: UpdateSlot,
        active_version: String,
        active_generation: u64,
        active_sha256: String,
        staged: UpdateSlot,
        candidate_version: String,
        candidate_generation: u64,
        candidate_sha256: String,
        security_floor: u64,
    },
    RolledBack {
        active: UpdateSlot,
        failed_slot: UpdateSlot,
        active_version: String,
        active_generation: u64,
        active_sha256: String,
        security_floor: u64,
        reason: String,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RolloutHaltEntry {
    pub pack_id: String,
    pub version: String,
    pub reason: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapBundleEntry {
    pub path: String,
    pub pack_id: String,
    pub version: String,
    pub sha256: String,
    pub length: u64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapBundleManifest {
    pub bundle_id: String,
    pub bundle_version: String,
    pub created_at: Timestamp,
    pub entries: Vec<AirgapBundleEntry>,
    pub halted_releases: Vec<RolloutHaltEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapArtifact {
    pub path: String,
    pub bytes: Vec<u8>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "approval", rename_all = "snake_case")]
pub enum BundleApprovalState {
    AwaitingTermsAcceptance,
    TermsAccepted {
        operator_id: String,
        accepted_at: Timestamp,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AirgapVerificationOutcome {
    pub bundle_id: String,
    pub bundle_version: String,
    pub verified_entries: usize,
    pub operator_id: String,
}

impl UpdateSlot {
    #[must_use]
    pub const fn other(self) -> Self {
        match self {
            Self::SlotA => Self::SlotB,
            Self::SlotB => Self::SlotA,
        }
    }
}

impl SlotState {
    #[must_use]
    pub fn initial(
        version: impl Into<String>,
        generation: u64,
        artifact_sha256: impl Into<String>,
        security_floor: u64,
    ) -> Self {
        Self::Active {
            slot: UpdateSlot::SlotA,
            version: version.into(),
            generation,
            artifact_sha256: artifact_sha256.into(),
            security_floor,
        }
    }

    pub fn stage_candidate(
        self,
        candidate_version: impl Into<String>,
        candidate_generation: u64,
        candidate_sha256: impl Into<String>,
    ) -> Result<Self, UpdateError> {
        let (active, active_version, active_generation, active_sha256, security_floor) = match self
        {
            Self::Active {
                slot,
                version,
                generation,
                artifact_sha256,
                security_floor,
            } => (slot, version, generation, artifact_sha256, security_floor),
            Self::RolledBack {
                active,
                active_version,
                active_generation,
                active_sha256,
                security_floor,
                ..
            } => (
                active,
                active_version,
                active_generation,
                active_sha256,
                security_floor,
            ),
            Self::Staging { .. } | Self::PendingActivation { .. } => {
                return Err(UpdateError::InvalidSlotTransition(
                    "slot already holds an uncommitted candidate".into(),
                ));
            }
        };

        if candidate_generation < security_floor {
            return Err(UpdateError::SecurityFloorViolation {
                found: candidate_generation,
                floor: security_floor,
            });
        }
        if candidate_generation <= active_generation {
            return Err(UpdateError::RollbackDetected {
                role: "slot_candidate".into(),
                found: candidate_generation,
                trusted: active_generation,
            });
        }

        let staging = active.other();
        Ok(Self::Staging {
            active,
            active_version,
            active_generation,
            active_sha256,
            staging,
            candidate_version: candidate_version.into(),
            candidate_generation,
            candidate_sha256: candidate_sha256.into(),
            security_floor,
        })
    }

    pub fn mark_verified(self) -> Result<Self, UpdateError> {
        let Self::Staging {
            active,
            active_version,
            active_generation,
            active_sha256,
            staging,
            candidate_version,
            candidate_generation,
            candidate_sha256,
            security_floor,
        } = self
        else {
            return Err(UpdateError::InvalidSlotTransition(
                "mark_verified requires Staging state".into(),
            ));
        };

        Ok(Self::PendingActivation {
            active,
            active_version,
            active_generation,
            active_sha256,
            staged: staging,
            candidate_version,
            candidate_generation,
            candidate_sha256,
            security_floor,
        })
    }

    pub fn activate(self) -> Result<Self, UpdateError> {
        let Self::PendingActivation {
            staged,
            candidate_version,
            candidate_generation,
            candidate_sha256,
            security_floor,
            ..
        } = self
        else {
            return Err(UpdateError::InvalidSlotTransition(
                "activate requires verified PendingActivation state".into(),
            ));
        };

        if candidate_generation < security_floor {
            return Err(UpdateError::SecurityFloorViolation {
                found: candidate_generation,
                floor: security_floor,
            });
        }

        Ok(Self::Active {
            slot: staged,
            version: candidate_version,
            generation: candidate_generation,
            artifact_sha256: candidate_sha256,
            security_floor,
        })
    }

    pub fn rollback_to_previous(
        self,
        previous_version: impl Into<String>,
        previous_generation: u64,
        previous_sha256: impl Into<String>,
        reason: impl Into<String>,
    ) -> Result<Self, UpdateError> {
        let (failed_slot, security_floor) = match self {
            Self::Active {
                slot,
                security_floor,
                ..
            } => (slot, security_floor),
            Self::Staging {
                staging,
                security_floor,
                ..
            } => (staging, security_floor),
            Self::PendingActivation {
                staged,
                security_floor,
                ..
            } => (staged, security_floor),
            Self::RolledBack { .. } => {
                return Err(UpdateError::InvalidSlotTransition(
                    "slot is already in RolledBack state".into(),
                ));
            }
        };

        if previous_generation < security_floor {
            return Err(UpdateError::SecurityFloorViolation {
                found: previous_generation,
                floor: security_floor,
            });
        }

        Ok(Self::RolledBack {
            active: failed_slot.other(),
            failed_slot,
            active_version: previous_version.into(),
            active_generation: previous_generation,
            active_sha256: previous_sha256.into(),
            security_floor,
            reason: reason.into(),
        })
    }
}

pub fn verify_airgap_bundle(
    trust: &UpdateTrust,
    bundle_envelope: &DsseEnvelope,
    artifacts: &[AirgapArtifact],
    approval: &BundleApprovalState,
    external_halts: &[RolloutHaltEntry],
    now: Timestamp,
) -> Result<AirgapVerificationOutcome, UpdateError> {
    let BundleApprovalState::TermsAccepted { operator_id, .. } = approval else {
        return Err(UpdateError::TermsNotAccepted);
    };

    if trust.project_root_expires() <= now {
        return Err(UpdateError::MetadataExpired {
            role: "project_root".into(),
            expired_at: trust.project_root_expires().to_string(),
        });
    }

    let (role_keys, threshold) = trust.project_content_role_keys()?;
    let trusted_keys: Vec<TrustedKeyInfo> = role_keys.to_vec();
    let payload_bytes = verify_dsse_envelope(bundle_envelope, &trusted_keys, threshold)?;

    let manifest: AirgapBundleManifest = serde_json::from_slice(&payload_bytes).map_err(|e| {
        UpdateError::MalformedMetadata(format!("invalid airgap bundle manifest JSON: {e}"))
    })?;

    if manifest.entries.is_empty() {
        return Err(UpdateError::MalformedMetadata(
            "airgap bundle manifest has no entries".into(),
        ));
    }

    let mut artifact_map: BTreeMap<&str, &[u8]> = BTreeMap::new();
    for item in artifacts {
        artifact_map.insert(item.path.as_str(), item.bytes.as_slice());
    }

    for entry in &manifest.entries {
        if let Some(halt) = manifest
            .halted_releases
            .iter()
            .chain(external_halts.iter())
            .find(|h| h.pack_id == entry.pack_id && h.version == entry.version)
        {
            return Err(UpdateError::HaltedRelease(format!(
                "{}@{} ({})",
                halt.pack_id, halt.version, halt.reason
            )));
        }

        let Some(raw) = artifact_map.get(entry.path.as_str()) else {
            return Err(UpdateError::ArtifactIntegrity {
                target: entry.path.clone(),
                detail: "artifact missing from air-gap bundle".into(),
            });
        };

        let actual_len = u64::try_from(raw.len()).unwrap_or(u64::MAX);
        if actual_len != entry.length {
            return Err(UpdateError::ArtifactIntegrity {
                target: entry.path.clone(),
                detail: format!("length {actual_len} != expected {}", entry.length),
            });
        }

        let actual_sha = canonical_sha256(raw);
        if actual_sha != entry.sha256 {
            return Err(UpdateError::ArtifactIntegrity {
                target: entry.path.clone(),
                detail: format!("sha256 {actual_sha} != expected {}", entry.sha256),
            });
        }
    }

    Ok(AirgapVerificationOutcome {
        bundle_id: manifest.bundle_id,
        bundle_version: manifest.bundle_version,
        verified_entries: manifest.entries.len(),
        operator_id: operator_id.clone(),
    })
}
