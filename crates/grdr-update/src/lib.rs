// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

mod airgap_bundle_verify;
pub mod ceremony;
pub mod dsse;
pub mod fips_pq;
pub mod handshake;
pub mod mirror;
pub mod rollout;
pub mod rollout_admission;
pub mod rollout_sketch;
pub mod slots;
pub mod tuf;
mod tuf_helpers;
pub mod tuf_types;

#[cfg(test)]
mod tests;

pub use ceremony::{
    CeremonyIdentityConfig, CeremonyParticipant, CeremonyTranscript, DeploymentCeremonyBundle,
    MirrorConvergenceReport, MirrorExportKind, MirrorExportPlan, ProjectCeremonyBundle,
    SigstoreTrustedRoot, TRUSTED_ROOT_MEDIA_TYPE, TrustedRootAuthority, TrustedRootLogEntry,
    evaluate_mirror_convergence, evaluate_mirror_convergence_scoped, issue_freshness_vouch,
    plan_mirror_export, run_deployment_root_ceremony, run_project_root_ceremony,
};
pub use dsse::{
    DsseEnvelope, DsseLimits, DsseSignature, DsseTargetStatement, dsse_pae, sign_dsse_envelope,
    verify_dsse_envelope, verify_dsse_envelope_with_limits,
};
pub use fips_pq::{
    DualSignedPayload, FailClosedPqBackend, FipsKatCheck, FipsMode, FipsSbomProperty,
    FipsSelfTestReport, FipsSelfTestState, HostOsProfile, KatOutcome, ML_DSA_65_PUBKEY_BYTES,
    ML_DSA_65_SIG_BYTES, PqPolicyActivation, PqPublicKeyRecord, PqSignatureEntry,
    PqVerifierBackend, run_fips_startup_self_test, verify_dual_signed_payload,
};
pub use handshake::{
    HandshakeContractOffer, HandshakePolicy, HandshakeResolution, evaluate_offer_handshake,
};
pub use mirror::{DEFAULT_PLATFORM_MARKERS, target_matches_platforms};
pub use rollout::{
    AdmissionDecision, DEFAULT_SELF_HOSTED_JITTER_HOURS, DEFAULT_SELF_HOSTED_MIN_DELAY_HOURS,
    HaltRollbackStatus, OperatorResumeStatement, ReleasePublishStatus, ResumeAuthorization,
    RingDefinition, RolloutCoordinator, RolloutPhase, RolloutScope, SignedRolloutPlan,
    admit_device_at, default_canary_rings,
};
pub use rollout_sketch::{
    BPS_DENOM, CohortGateVerdict, CohortTelemetrySnapshot, DDSKETCH_MAX_BUCKET_INDEX,
    DDSKETCH_MAX_BUCKETS, HaltReason, LatencyDdSketch, RollbackDirective, RollbackTargetKind,
    RolloutGatePolicy,
};
pub use slots::{
    AirgapArtifact, AirgapBundleEntry, AirgapBundleManifest, AirgapVerificationOutcome,
    BundleApprovalState, RolloutHaltEntry, SlotState, UpdateSlot, verify_airgap_bundle,
};
pub use tuf::UpdateTrust;
pub use tuf_types::{
    FreshnessEvaluation, FreshnessStatement, PackKind, RootKeyRole, RootMetadata,
    SignatureAlgorithm, SignedMetadata, SignerClass, SnapshotMetadata, SnapshotTargetRef,
    TargetDescriptor, TargetsMetadata, TimestampMetadata, TrustVerificationResult, TufRole,
    TufRootKind, TufSignature, UpdateFreshness, YankReason, YankRecord, canonical_sha256,
    decode_base64, decode_ed25519_pubkey, encode_base64, sign_metadata, verify_root_self,
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
