// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Privacy floor hierarchy, signed narrowing checks (SR-26), and capture notice timers (`D-51`).

use std::collections::BTreeSet;

use grdr_crypto::{SigningKeypair, verify_bytes};
use grdr_model::{IdentityMode, TrustedKeyInfo};
use jiff::Timestamp;
use serde::{Deserialize, Serialize};

use crate::ComplyError;
use crate::retention::{PrivacyCeilingProfile, ceiling_spec};

const DOMAIN_PRIVACY_ARTEFACT: &str = "grdr.privacy.artefact.v1";
const SECONDS_PER_DAY: i64 = 86_400;

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum PrivacyLayerKind {
    DeviceFloor,
    Org,
    Provider,
    Operator,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum CaptureLevel {
    MetadataOnly,
    MetadataAndSignals,
    ContentGrantOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UserRiskScoringState {
    Disabled,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LocalDisclosureVisibility {
    Visible,
    HiddenForbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BannedTelemetryGuard {
    Blocked,
    ExposedForbidden,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GitNotesPolicy {
    Off,
    Enabled,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ModelReviewPolicy {
    Off,
    Chosen,
    CoSigned,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum NoticeChangeState {
    Immediate,
    Scheduled {
        announced_at: Timestamp,
        effective_at: Timestamp,
        notice_days: u32,
    },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyExclusions {
    pub principals: BTreeSet<String>,
    pub paths: BTreeSet<String>,
    pub repositories: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyArtefact {
    pub layer: PrivacyLayerKind,
    pub organisation: String,
    pub capture_level: CaptureLevel,
    pub profile: PrivacyCeilingProfile,
    pub identity_mode: IdentityMode,
    pub user_risk_scoring: UserRiskScoringState,
    pub local_disclosure: LocalDisclosureVisibility,
    pub banned_telemetry: BannedTelemetryGuard,
    pub git_notes: GitNotesPolicy,
    pub model_review: ModelReviewPolicy,
    pub privacy_contact: String,
    pub co_approver_group: BTreeSet<String>,
    pub exclusions: PrivacyExclusions,
    #[serde(default)]
    pub key_id: Option<String>,
    #[serde(default)]
    pub signature: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PrivacyNoticeSchedule {
    pub previous_level: CaptureLevel,
    pub next_level: CaptureLevel,
    pub notice_days: u32,
    pub schedule: NoticeChangeState,
}

#[derive(Serialize)]
struct CanonicalPrivacyPayload<'a> {
    layer: PrivacyLayerKind,
    organisation: &'a str,
    capture_level: CaptureLevel,
    profile: PrivacyCeilingProfile,
    identity_mode: IdentityMode,
    user_risk_scoring: UserRiskScoringState,
    local_disclosure: LocalDisclosureVisibility,
    banned_telemetry: BannedTelemetryGuard,
    git_notes: GitNotesPolicy,
    model_review: ModelReviewPolicy,
    privacy_contact: &'a str,
    co_approver_group: &'a BTreeSet<String>,
    exclusions: &'a PrivacyExclusions,
}

pub fn sign_privacy_artefact(
    keypair: &SigningKeypair,
    artefact: &mut PrivacyArtefact,
) -> Result<(), ComplyError> {
    let payload = canonical_privacy_bytes(artefact)?;
    artefact.key_id = Some(keypair.key_id().to_owned());
    artefact.signature = Some(keypair.sign_bytes(DOMAIN_PRIVACY_ARTEFACT, &payload));
    Ok(())
}

pub fn verify_privacy_artefact(
    artefact: &PrivacyArtefact,
    trusted_keys: &[TrustedKeyInfo],
) -> Result<(), ComplyError> {
    let (Some(kid), Some(sig)) = (artefact.key_id.as_deref(), artefact.signature.as_deref()) else {
        return Err(ComplyError::VerificationFailed {
            detail: "privacy artefact missing signing key_id or signature".into(),
        });
    };
    let trusted = trusted_keys
        .iter()
        .find(|k| k.key_id == kid)
        .ok_or_else(|| ComplyError::VerificationFailed {
            detail: format!("untrusted privacy artefact signer `{kid}`"),
        })?;
    let payload = canonical_privacy_bytes(artefact)?;
    verify_bytes(
        &trusted.public_key_b64,
        DOMAIN_PRIVACY_ARTEFACT,
        &payload,
        sig,
    )
    .map_err(|e| ComplyError::VerificationFailed {
        detail: format!("privacy artefact signature verification failed: {e}"),
    })
}

pub fn verify_and_enforce_privacy_hierarchy(
    device_floor: &PrivacyArtefact,
    parent_artefacts: &[&PrivacyArtefact],
    org_trusted_keys: &[TrustedKeyInfo],
    parent_trusted_keys: &[TrustedKeyInfo],
) -> Result<PrivacyArtefact, ComplyError> {
    if device_floor.layer != PrivacyLayerKind::DeviceFloor {
        return Err(ComplyError::VerificationFailed {
            detail: "privacy hierarchy root artefact must use layer `device-floor`".into(),
        });
    }
    verify_privacy_artefact(device_floor, org_trusted_keys)?;
    validate_floor_invariants(device_floor)?;

    let mut effective = device_floor.clone();
    let mut ordered: Vec<&PrivacyArtefact> = parent_artefacts.to_vec();
    ordered.sort_by_key(|a| a.layer);

    for layer in ordered {
        if layer.layer == PrivacyLayerKind::DeviceFloor {
            return Err(ComplyError::VerificationFailed {
                detail: "parent artefact list cannot include a `device-floor` layer".into(),
            });
        }
        if layer.organisation != device_floor.organisation {
            return Err(ComplyError::VerificationFailed {
                detail: format!(
                    "cross-organisation privacy artefact `{}` rejected",
                    layer.organisation
                ),
            });
        }
        verify_privacy_artefact(layer, parent_trusted_keys)?;
        validate_floor_invariants(layer)?;
        enforce_strict_narrowing(&effective, layer)?;
        effective = apply_narrower(&effective, layer);
    }
    Ok(effective)
}

pub fn schedule_capture_change(
    profile: PrivacyCeilingProfile,
    previous_level: CaptureLevel,
    next_level: CaptureLevel,
    announced_at: Timestamp,
) -> Result<PrivacyNoticeSchedule, ComplyError> {
    if next_level <= previous_level {
        return Ok(PrivacyNoticeSchedule {
            previous_level,
            next_level,
            notice_days: 0,
            schedule: NoticeChangeState::Immediate,
        });
    }
    let notice_days = ceiling_spec(profile)?.notice_days;
    let delta = i64::from(notice_days)
        .checked_mul(SECONDS_PER_DAY)
        .ok_or_else(|| ComplyError::InvalidEvidenceInput {
            detail: "capture notice delta seconds overflowed".into(),
        })?;
    let target_sec = announced_at.as_second().checked_add(delta).ok_or_else(|| {
        ComplyError::InvalidEvidenceInput {
            detail: "capture notice schedule timestamp overflowed".into(),
        }
    })?;
    let effective_at =
        Timestamp::from_second(target_sec).map_err(|e| ComplyError::InvalidEvidenceInput {
            detail: format!("capture notice timestamp out of valid range: {e}"),
        })?;
    Ok(PrivacyNoticeSchedule {
        previous_level,
        next_level,
        notice_days,
        schedule: NoticeChangeState::Scheduled {
            announced_at,
            effective_at,
            notice_days,
        },
    })
}

fn validate_floor_invariants(artefact: &PrivacyArtefact) -> Result<(), ComplyError> {
    if artefact.local_disclosure != LocalDisclosureVisibility::Visible
        || artefact.banned_telemetry != BannedTelemetryGuard::Blocked
    {
        return Err(ComplyError::VerificationFailed {
            detail: "privacy floor forbids hiding local disclosure or enabling banned telemetry"
                .into(),
        });
    }
    if artefact.privacy_contact.trim().is_empty() {
        return Err(ComplyError::InvalidEvidenceInput {
            detail: "privacy_contact must be present at organisation/device floor".into(),
        });
    }
    if artefact.profile == PrivacyCeilingProfile::WorksCouncil
        && (artefact.identity_mode != IdentityMode::Pseudonymous
            || artefact.user_risk_scoring != UserRiskScoringState::Disabled
            || artefact.git_notes != GitNotesPolicy::Off
            || artefact.model_review == ModelReviewPolicy::Chosen)
    {
        return Err(ComplyError::RetentionConflict {
            floor_clause: "works-council-floor".into(),
            ceiling_clause: "works-council-profile".into(),
            detail: "works-council locks pseudonymous identity, disabled scoring, git notes off, and co-signed model review".into(),
        });
    }
    Ok(())
}

fn enforce_strict_narrowing(
    floor: &PrivacyArtefact,
    layer: &PrivacyArtefact,
) -> Result<(), ComplyError> {
    if layer.capture_level > floor.capture_level {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "{:?} artefact widens capture_level above device/org floor",
                layer.layer
            ),
        });
    }
    if layer.profile < floor.profile {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "{:?} artefact widens works-council privacy profile back to standard",
                layer.layer
            ),
        });
    }
    if floor.identity_mode == IdentityMode::Pseudonymous
        && layer.identity_mode == IdentityMode::Named
    {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "{:?} artefact widens pseudonymous identity_mode back to named",
                layer.layer
            ),
        });
    }
    if layer.user_risk_scoring > floor.user_risk_scoring {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "{:?} artefact enables user risk scoring against floor",
                layer.layer
            ),
        });
    }
    if layer.git_notes > floor.git_notes || layer.model_review > floor.model_review {
        return Err(ComplyError::VerificationFailed {
            detail: format!(
                "{:?} artefact widens git_notes or model_review against floor",
                layer.layer
            ),
        });
    }
    Ok(())
}

fn apply_narrower(floor: &PrivacyArtefact, layer: &PrivacyArtefact) -> PrivacyArtefact {
    let mut merged = floor.clone();
    merged.capture_level = floor.capture_level.min(layer.capture_level);
    merged.profile = floor.profile.max(layer.profile);
    if merged.profile == PrivacyCeilingProfile::WorksCouncil {
        merged.identity_mode = IdentityMode::Pseudonymous;
        merged.user_risk_scoring = UserRiskScoringState::Disabled;
        merged.git_notes = GitNotesPolicy::Off;
    } else {
        if floor.identity_mode == IdentityMode::Pseudonymous
            || layer.identity_mode == IdentityMode::Pseudonymous
        {
            merged.identity_mode = IdentityMode::Pseudonymous;
        }
        merged.user_risk_scoring = floor.user_risk_scoring.min(layer.user_risk_scoring);
        merged.git_notes = floor.git_notes.min(layer.git_notes);
    }
    merged.model_review = floor.model_review.min(layer.model_review);
    merged
        .exclusions
        .principals
        .extend(layer.exclusions.principals.iter().cloned());
    merged
        .exclusions
        .paths
        .extend(layer.exclusions.paths.iter().cloned());
    merged
        .exclusions
        .repositories
        .extend(layer.exclusions.repositories.iter().cloned());
    merged
}

fn canonical_privacy_bytes(artefact: &PrivacyArtefact) -> Result<Vec<u8>, ComplyError> {
    serde_json::to_vec(&CanonicalPrivacyPayload {
        layer: artefact.layer,
        organisation: &artefact.organisation,
        capture_level: artefact.capture_level,
        profile: artefact.profile,
        identity_mode: artefact.identity_mode,
        user_risk_scoring: artefact.user_risk_scoring,
        local_disclosure: artefact.local_disclosure,
        banned_telemetry: artefact.banned_telemetry,
        git_notes: artefact.git_notes,
        model_review: artefact.model_review,
        privacy_contact: &artefact.privacy_contact,
        co_approver_group: &artefact.co_approver_group,
        exclusions: &artefact.exclusions,
    })
    .map_err(|e| ComplyError::Serialization {
        detail: e.to_string(),
    })
}
