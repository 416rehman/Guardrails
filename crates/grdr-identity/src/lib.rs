// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

pub mod broker;
pub mod broker_types;
pub mod pseudonym;
pub mod spiffe;
pub mod vault;
pub mod vault_types;

#[cfg(test)]
mod tests;

pub use broker::CredentialBroker;
pub use broker_types::{
    BrokerPolicy, BrokerRequest, BrokeredToken, Ceiling, ContainmentStatus, CredentialBinding,
    CredentialClass, CredentialMode, LeaseRecord, LeaseState,
};
pub use pseudonym::{
    QuarterKey, QuarterlyDisclosureEntry, derive_device_pseudonym, re_pseudonymize_for_org,
};
pub use spiffe::{
    AgentLifecycle, AttestationEvidence, ContainmentMode, IdentityProof, LocalAttestation,
    SpiffeId, evaluate_attestation_proof,
};
pub use vault::IdentityVault;
pub use vault_types::{
    ApproverRecord, ApproverRole, ReidentQuorumState, SubjectDisclosureState, VaultPolicy,
    VaultSubjectRecord,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityError {
    #[error("GRDR-ID-0001: invalid SPIFFE identifier: {0}")]
    InvalidSpiffeId(String),
    #[error("GRDR-ID-0002: insufficient attribution grade {found}, required >= {required}")]
    InsufficientAttribution { found: u8, required: u8 },
    #[error("GRDR-ID-0003: caller program `{0}` is not bound to credential")]
    UnauthorizedProgram(String),
    #[error("GRDR-ID-0004: requested scope exceeds effective ceiling: {0}")]
    ScopeExceedsCeiling(String),
    #[error("GRDR-ID-0005: identity.no-ceiling.deny: instance holds no credential ceiling")]
    NoCeiling,
    #[error(
        "GRDR-ID-0006: cred.release.requires-containment: credential release refused to uncontained session (@remedy(\"restart-contained\"))"
    )]
    UncontainedReleaseRefused,
    #[error(
        "GRDR-ID-0007: agents.min-assurance.prod-cred: production credentials require a contained session"
    )]
    ProductionRequiresContainment,
    #[error("GRDR-ID-0008: agent instance is not active (lifecycle: {0:?})")]
    InstanceNotActive(AgentLifecycle),
    #[error("GRDR-ID-0009: broker lease rate cap exceeded for session {0}")]
    RateLimitExceeded(String),
    #[error("GRDR-ID-0010: upstream credential cannot satisfy release TTL or revocation policy")]
    ReleaseUnsupportedByUpstream,
    #[error("GRDR-ID-0011: requester cannot self-approve re-identification request")]
    SelfApprovalForbidden,
    #[error("GRDR-ID-0012: duplicate approver `{0}` cannot satisfy dual-approver quorum")]
    DuplicateApprover(String),
    #[error("GRDR-ID-0013: legal-hold deferral exceeds 90-day cap (max {max_until})")]
    DeferralCapExceeded { max_until: String },
    #[error("GRDR-ID-0014: vault or quorum state error: {0}")]
    VaultState(String),
    #[error("GRDR-ID-0015: approver role combination does not satisfy re-identification policy")]
    InsufficientApproverRole,
}
