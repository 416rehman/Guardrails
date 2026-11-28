// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! Compliance engine, YAML pack loader, OSCAL 1.2.3, retention, holds, DSAR/RoPA, oversight, and CRA/VPAT/SOC2.

pub mod evidence;
pub mod exports;
pub mod holds;
pub mod incident;
mod limits;
pub mod oscal;
pub mod oscal_validate;
pub mod oversight;
mod pack_fs;
pub mod pack_loader;
pub mod pack_toml;
mod pack_trust_roots;
pub mod pack_verify;
pub mod privacy_docs;
pub mod privacy_floor;
pub mod registry;
pub mod regulatory;
pub mod retention;
pub mod rfp;
pub mod subject_request;
mod toml_ast;
pub mod works_council;

use grdr_crypto::sha256_hex;
use uuid::Uuid;

pub use evidence::{
    EvidenceDataClass, EvidenceItem, EvidencePipelineInput, EvidenceQuery, EvidenceResult,
    FieldRead, evaluate_evidence_item, sign_evidence_item, validate_evidence_query,
    verify_evidence_item,
};
pub use exports::{
    ComplianceArtifactFormat, default_privacy_doc_config, render_compliance_artifact,
    render_incident_output, render_notice_output, render_rfp_output, render_ropa_output,
    resolve_default_retention,
};
pub use holds::{
    CoApproverQuorumPolicy, DrillDownAuditRecord, ErasureOutcome, Hold, HoldCheckQuery,
    HoldCheckResult, HoldLifecycle, HoldNotice, HoldReviewFinding, HoldScope, HoldsLedger,
    PlaceHoldInput, validate_purpose_bound_drill_down, validate_works_council_quorum,
};
pub use incident::{
    ClockAnchorKind, IncidentDeadline, IncidentFixtureInput, IncidentRegimeSpec,
    IncidentTimelineReport, RegimeStageSpec, export_incident_timeline,
    export_incident_timeline_from_specs, load_incident_regimes_yaml,
    render_incident_timeline_markdown,
};
pub use oscal::{
    BundleVerificationReport, ItemInclusionProof, OfflineEvidenceBundle, OscalAssessmentResultsDoc,
    OscalComponentDefinitionDoc, OscalSubjectReference, deployment_fingerprint,
    export_assessment_results, export_component_definition, export_evidence_csv,
    export_evidence_markdown, export_offline_bundle, verify_evidence_bundle,
};
pub use oscal_validate::{
    OscalArtifactKind, OscalValidationReport, validate_oscal_assessment_json,
    validate_oscal_component_json,
};
pub use oversight::{
    AgentLadderSnapshot, ComputeLadderLevel, FiveEyesControlState, FiveEyesReport,
    NcscContainmentReport, NetworkLadderLevel, OversightAssignment, OversightDecisionOutcome,
    OversightEventInput, OversightQualityReport, QueueLatencySummary, RuleClassOversightStats,
    compute_oversight_quality_report, evaluate_five_eyes_report, evaluate_ncsc_containment,
    format_utc_quarter, render_oversight_markdown,
};
pub use pack_loader::{
    LoadedCompliancePack, load_compliance_pack_from_dir, load_compliance_pack_with_trusted,
    load_embedded_compliance_pack, parse_registry_from_yaml,
};
pub use privacy_docs::{
    DpiaRiskItem, ImpactAssessmentPackDoc, MonitoringCatalogueDoc, NationalVariantTemplate,
    NoticeLocale, PackFieldReadSpec, PackPromotionVerdict, PrivacyDocConfig, PrivacyPackDiffReport,
    RuleCatalogSummary, WorkerNoticeDoc, WorksAgreementAnnexDoc, assess_privacy_pack_promotion,
    generate_impact_assessment_pack, generate_monitoring_catalogue, generate_worker_notice,
    generate_works_agreement_annex, render_worker_notice_markdown,
};
pub use privacy_floor::{
    BannedTelemetryGuard, CaptureLevel, GitNotesPolicy, LocalDisclosureVisibility,
    ModelReviewPolicy, NoticeChangeState, PrivacyArtefact, PrivacyExclusions, PrivacyLayerKind,
    PrivacyNoticeSchedule, UserRiskScoringState, schedule_capture_change, sign_privacy_artefact,
    verify_and_enforce_privacy_hierarchy, verify_privacy_artefact,
};
pub use registry::{
    CapabilityId, CapabilityRecord, CapabilityRegistry, ControlCoverageStatus, ControlEntry,
    CrosswalkEntry, CrosswalkRelation, FrameworkCatalogue, FrameworkCoverageReport, Responsibility,
    default_compliance_pack_digest, default_evidence_queries, default_registry,
    eo14434_display_label, load_registry_from_dir, try_default_registry,
};
pub use regulatory::{
    CraAnnexIMatrixReport, CraAnnexIRow, CryptoAllowlistReport, Soc2ControlOwnershipRow,
    Soc2ReadinessPack, Vpat25Report, VpatConformanceLevel, VpatCriterionRow, VpatSurface,
    extract_workspace_crypto_crates, generate_cra_annex_i_matrix, generate_soc2_readiness_pack,
    generate_vpat_report, render_vpat_markdown, verify_cargo_lock_crypto, verify_crypto_allowlist,
};
pub use retention::{
    CeilingSpec, PresetSpec, PrivacyCeilingProfile, RetentionCatalogue, RetentionPolicy,
    RetentionPreset, RetentionProposal, ceiling_spec, default_retention_catalogue,
    load_retention_catalogue_yaml, preset_spec, resolve_retention_policy,
    resolve_retention_policy_with_catalogue,
};
pub use rfp::{
    BrokerReadiness, CertificationStatus, ConnectorCoverage, DeploymentTopology, ParityItemSpec,
    PlatformReadiness, RfpItemReport, RfpItemStatus, RfpParityReport, generate_rfp_response,
    generate_rfp_response_with_registry, load_parity_items_yaml, render_rfp_markdown,
};
pub use subject_request::{
    ErasureLegalBasis, RecordOfProcessing, RopaInput, SubjectAccessBundle, SubjectErasureCascade,
    SubjectRequestExecution, SubjectRequestKind, SubjectRequestLifecycle, SubjectRequestRecord,
    execute_subject_request, generate_ropa, render_ropa_markdown,
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
    #[error("GRDR-COMPLY-0011: invalid evidence pipeline input: {detail}")]
    InvalidEvidenceInput { detail: String },
}

fn deterministic_v5_uuid(seed: &str) -> Uuid {
    let hex = sha256_hex(format!("grdr.oid.v5:{seed}").as_bytes());
    let slice = hex.get(0..32).unwrap_or("00000000000000000000000000000000");
    let raw = u128::from_str_radix(slice, 16).unwrap_or(0);
    let with_version = (raw & !(0xF000_u128 << 64)) | (0x5000_u128 << 64);
    let with_variant = (with_version & !(0xC0_u128 << 56)) | (0x80_u128 << 56);
    Uuid::from_u128(with_variant)
}

pub(crate) fn deterministic_uuid_string(seed: &str) -> String {
    deterministic_v5_uuid(seed).hyphenated().to_string()
}

pub(crate) fn deterministic_prefixed_id(prefix: &str, seed: &str) -> String {
    let simple = deterministic_v5_uuid(seed).simple().to_string();
    format!("{prefix}_{simple}")
}

pub(crate) fn markdown_safe(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\r' | '\n' | '\t' => out.push(' '),
            '\\' | '`' | '|' | '<' | '>' | '[' | ']' | '#' => {
                out.push('\\');
                out.push(ch);
            }
            other => out.push(other),
        }
    }
    out
}
