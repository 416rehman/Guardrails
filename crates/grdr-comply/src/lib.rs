// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! Compliance engine, capability crosswalks, OSCAL 1.2.3 export, retention, holds, and RFP.

mod catalog_data;
pub mod evidence;
pub mod oscal;
pub mod registry;
pub mod retention;
pub mod rfp;

pub use evidence::{
    EvidenceDataClass, EvidenceItem, EvidencePipelineInput, EvidenceQuery, EvidenceResult,
    FieldRead, evaluate_evidence_item, sign_evidence_item, validate_evidence_query,
    verify_evidence_item,
};
pub use oscal::{
    BundleVerificationReport, ItemInclusionProof, OfflineEvidenceBundle, OscalAssessmentResultsDoc,
    OscalComponentDefinitionDoc, export_assessment_results, export_component_definition,
    export_evidence_csv, export_evidence_markdown, export_offline_bundle, verify_evidence_bundle,
};
pub use registry::{
    CapabilityId, CapabilityRecord, CapabilityRegistry, ControlCoverageStatus, ControlEntry,
    CrosswalkEntry, CrosswalkRelation, FrameworkCatalogue, FrameworkCoverageReport, Responsibility,
    default_registry, eo14434_display_label,
};
pub use retention::{
    ErasureOutcome, Hold, HoldCheckResult, HoldLifecycle, HoldNotice, HoldReviewFinding, HoldScope,
    HoldsLedger, PlaceHoldInput, PresetSpec, PrivacyCeilingProfile, RetentionPolicy,
    RetentionPreset, RetentionProposal, preset_spec, resolve_retention_policy,
};
pub use rfp::{
    BrokerReadiness, CertificationStatus, ConnectorCoverage, DeploymentTopology, ParityItemSpec,
    PlatformReadiness, RfpItemReport, RfpItemStatus, RfpParityReport, generate_rfp_response,
    render_rfp_markdown,
};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum ComplyError {
    #[error("GRDR-COMPLY-0001: unknown capability `{0}`")]
    UnknownCapability(String),
    #[error("GRDR-COMPLY-0002: unknown framework `{0}`")]
    UnknownFramework(String),
    #[error("GRDR-COMPLY-0003: invalid evidence query `{query_id}`: {detail}")]
    InvalidEvidenceQuery { query_id: String, detail: String },
    #[error("GRDR-COMPLY-0004: evidence signature or bundle verification failed: {detail}")]
    VerificationFailed { detail: String },
    #[error("GRDR-COMPLY-0005: cryptographic operation failed: {detail}")]
    Crypto { detail: String },
    #[error(
        "GRDR-COMPLY-0006: retention conflict between floor `{floor_clause}` and ceiling `{ceiling_clause}`: {detail}"
    )]
    RetentionConflict {
        floor_clause: String,
        ceiling_clause: String,
        detail: String,
    },
    #[error("GRDR-COMPLY-0007: invalid legal hold `{hold_id}`: {detail}")]
    InvalidHold { hold_id: String, detail: String },
    #[error("GRDR-COMPLY-0008: unknown legal hold `{0}`")]
    UnknownHold(String),
    #[error("GRDR-COMPLY-0009: serialization failed: {detail}")]
    Serialization { detail: String },
    #[error("GRDR-COMPLY-0010: missing legal basis for preset `{0}`")]
    MissingLegalBasis(String),
}
