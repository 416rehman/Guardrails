// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![deny(clippy::arithmetic_side_effects)]

pub mod broker;
mod broker_revoke;
pub mod broker_types;
pub mod cred_helpers;
mod http_security;
pub mod issuer;
pub mod issuer_helpers;
pub mod locator;
mod locator_extract;
mod locator_parse;
pub mod oauth_issuer;
pub mod openbao_store;
pub mod pseudonym;
pub mod secret_store;
pub mod spiffe;
pub mod vault;
pub mod vault_types;

#[cfg(windows)]
mod dpapi;
#[cfg(windows)]
mod dpapi_fs;
#[cfg(target_os = "linux")]
mod linux_keyring;

#[cfg(test)]
mod issuer_tests;
#[cfg(test)]
mod locator_tests;
#[cfg(test)]
mod tests;

pub use broker::CredentialBroker;
pub use broker_types::{
    BrokerPolicy, BrokerRequest, BrokeredToken, Ceiling, ContainmentStatus, CredentialBinding,
    CredentialClass, CredentialMode, LeaseRecord, LeaseState, SessionRevocationReport,
};
pub use cred_helpers::{
    DockerCredentialQuery, GitCredentialQuery, format_aws_credential_process,
    format_docker_credential_get, format_gcp_external_account, format_git_credential_reply,
    format_kube_exec_credential, parse_git_credential_stdin,
};
pub use issuer::{AwsStsIssuer, CredentialIssuer, GitHubAppIssuer, IssuedCredential};
pub use issuer_helpers::{CallbackJwtSigner, Hs256JwtSigner, JwtAssertionSigner};
pub use locator::{
    ArtifactScanContext, CredentialLocationFinding, CredentialLocatorDef, CredentialLocatorPack,
    CredentialStoreKind, HygieneFinding, HygieneMode, HygieneRuleDef, HygieneRuleId, HygieneSignal,
};
pub use oauth_issuer::{GcpStsIssuer, OAuth2Rfc8693Issuer};
pub use openbao_store::OpenBaoSecretStore;
pub use pseudonym::{
    QuarterKey, QuarterlyDisclosureEntry, derive_device_pseudonym, re_pseudonymize_for_org,
};
pub use secret_store::{
    BoxFuture, DpapiSecretStore, KeychainSecretStore, LinuxKernelKeyringStore, SecretBytes,
    SecretStore, SecretStoreKind,
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
    #[error("GRDR-ID-0016: credential locator pack error: {0}")]
    LocatorPack(String),
    #[error("GRDR-ID-0017: secret store error: {0}")]
    SecretStore(String),
    #[error("GRDR-ID-0018: upstream credential issuer error: {0}")]
    IssuerError(String),
    #[error("GRDR-ID-0019: credential helper protocol error: {0}")]
    CredentialHelper(String),
    #[error("GRDR-ID-0020: invalid or insecure endpoint URL: {0}")]
    InvalidHttpEndpoint(String),
}
