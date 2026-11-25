// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod dsse;
pub mod slots;
pub mod tuf;
pub mod tuf_types;

#[cfg(test)]
mod tests;

pub use dsse::{
    DsseEnvelope, DsseLimits, DsseSignature, DsseTargetStatement, dsse_pae, sign_dsse_envelope,
    verify_dsse_envelope, verify_dsse_envelope_with_limits,
};
pub use slots::{
    AirgapArtifact, AirgapBundleEntry, AirgapBundleManifest, AirgapVerificationOutcome,
    BundleApprovalState, RolloutHaltEntry, SlotState, UpdateSlot, verify_airgap_bundle,
};
pub use tuf::UpdateTrust;
pub use tuf_types::{
    FreshnessEvaluation, FreshnessStatement, PackKind, RootKeyRole, RootMetadata, SignedMetadata,
    SignerClass, SnapshotMetadata, SnapshotTargetRef, TargetDescriptor, TargetsMetadata,
    TimestampMetadata, TrustVerificationResult, TufRole, TufRootKind, TufSignature,
    UpdateFreshness, canonical_sha256, sign_metadata,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum UpdateError {
    #[error("GRDR-UPD-0001: malformed update metadata or DSSE encoding: {0}")]
    MalformedMetadata(String),
    #[error("GRDR-UPD-0002: signature threshold or cryptographic verification failed: {0}")]
    InvalidSignature(String),
    #[error("GRDR-UPD-0003: rollback rejected for {role}: version {found} < trusted {trusted}")]
    RollbackDetected {
        role: String,
        found: u64,
        trusted: u64,
    },
    #[error("GRDR-UPD-0004: metadata freeze or expiry detected for {role} at {expired_at}")]
    MetadataExpired { role: String, expired_at: String },
    #[error("GRDR-UPD-0005: mix-and-match metadata mismatch: {0}")]
    MixAndMatchDetected(String),
    #[error("GRDR-UPD-0006: unauthorized root for target or role: {0}")]
    UnauthorizedRoot(String),
    #[error("GRDR-UPD-0007: artifact digest or length mismatch for {target}: {detail}")]
    ArtifactIntegrity { target: String, detail: String },
    #[error("GRDR-UPD-0008: security floor violation: generation {found} < floor {floor}")]
    SecurityFloorViolation { found: u64, floor: u64 },
    #[error("GRDR-UPD-0009: target {0} is halted by rollout metadata")]
    HaltedRelease(String),
    #[error("GRDR-UPD-0010: air-gap bundle requires operator terms acceptance before serving")]
    TermsNotAccepted,
    #[error("GRDR-UPD-0011: invalid A/B slot transition: {0}")]
    InvalidSlotTransition(String),
    #[error("GRDR-UPD-0012: target {0} not found in signed TUF targets")]
    TargetNotFound(String),
}
