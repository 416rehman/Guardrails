// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::UpdateError;
pub use crate::airgap_bundle_verify::{
    AirgapArtifact, AirgapBundleEntry, AirgapBundleManifest, AirgapVerificationOutcome,
    BundleApprovalState, RolloutHaltEntry, verify_airgap_bundle,
};

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
        let previous_version = previous_version.into();
        let previous_sha256 = previous_sha256.into();
        match self {
            Self::Active {
                slot,
                generation: active_generation,
                security_floor,
                ..
            } => {
                if previous_version.trim().is_empty() || previous_sha256.trim().is_empty() {
                    return Err(UpdateError::InvalidSlotTransition(
                        "rollback target version and sha256 must be non-empty".into(),
                    ));
                }
                if previous_generation < security_floor {
                    return Err(UpdateError::SecurityFloorViolation {
                        found: previous_generation,
                        floor: security_floor,
                    });
                }
                if previous_generation > active_generation {
                    return Err(UpdateError::InvalidSlotTransition(
                        "rollback generation cannot exceed active generation".into(),
                    ));
                }
                Ok(Self::RolledBack {
                    active: slot.other(),
                    failed_slot: slot,
                    active_version: previous_version,
                    active_generation: previous_generation,
                    active_sha256: previous_sha256,
                    security_floor,
                    reason: reason.into(),
                })
            }
            Self::Staging {
                active,
                active_version,
                active_generation,
                active_sha256,
                staging,
                security_floor,
                ..
            }
            | Self::PendingActivation {
                active,
                active_version,
                active_generation,
                active_sha256,
                staged: staging,
                security_floor,
                ..
            } => {
                if active_generation < security_floor {
                    return Err(UpdateError::SecurityFloorViolation {
                        found: active_generation,
                        floor: security_floor,
                    });
                }
                Ok(Self::RolledBack {
                    active,
                    failed_slot: staging,
                    active_version,
                    active_generation,
                    active_sha256,
                    security_floor,
                    reason: reason.into(),
                })
            }
            Self::RolledBack { .. } => Err(UpdateError::InvalidSlotTransition(
                "slot is already in RolledBack state".into(),
            )),
        }
    }
}
