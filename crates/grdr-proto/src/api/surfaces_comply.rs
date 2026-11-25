// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::api::overview::SetupStep;
use crate::common::{RevisionMeta, reid_request_status_serde, subject_request_status_serde};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FrameworkCoverageSummary {
    #[prost(string, tag = "1")]
    #[serde(alias = "framework_id")]
    pub framework_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "display_title")]
    pub display_title: String,
    #[prost(uint32, tag = "3")]
    #[serde(alias = "total_controls")]
    pub total_controls: u32,
    #[prost(uint32, tag = "4")]
    #[serde(alias = "addressed_controls")]
    pub addressed_controls: u32,
    #[prost(uint32, tag = "5")]
    #[serde(alias = "coverage_percent")]
    pub coverage_percent: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComplianceEvidenceEntry {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub capability: String,
    #[prost(string, tag = "3")]
    pub statement: String,
    #[prost(string, tag = "4")]
    pub result: String,
    #[prost(string, tag = "5")]
    pub responsibility: String,
    #[prost(string, repeated, tag = "6")]
    #[serde(alias = "control_refs")]
    pub control_refs: Vec<String>,
    #[prost(string, repeated, tag = "7")]
    #[serde(alias = "sample_ids")]
    pub sample_ids: Vec<String>,
    #[prost(string, tag = "8")]
    #[serde(alias = "period_end")]
    pub period_end: String,
    #[prost(string, tag = "9")]
    #[serde(alias = "signature_status")]
    pub signature_status: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RetentionStateSummary {
    #[prost(string, tag = "1")]
    pub organisation: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "privacy_profile")]
    pub privacy_profile: String,
    #[prost(string, repeated, tag = "3")]
    pub presets: Vec<String>,
    #[prost(uint32, tag = "4")]
    #[serde(alias = "content_days")]
    pub content_days: u32,
    #[prost(uint32, tag = "5")]
    #[serde(alias = "activity_days")]
    pub activity_days: u32,
    #[prost(uint32, tag = "6")]
    #[serde(alias = "decision_days")]
    pub decision_days: u32,
    #[prost(uint32, tag = "7")]
    #[serde(alias = "audit_days")]
    pub audit_days: u32,
    #[prost(uint32, tag = "8")]
    #[serde(alias = "hot_days")]
    pub hot_days: u32,
    #[prost(uint32, tag = "9")]
    #[serde(alias = "backup_days_max")]
    pub backup_days_max: u32,
    #[prost(string, repeated, tag = "10")]
    #[serde(alias = "legal_basis")]
    pub legal_basis: Vec<String>,
    #[prost(string, tag = "11")]
    #[serde(alias = "conflict_note")]
    pub conflict_note: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct LegalHoldEntry {
    #[prost(string, tag = "1")]
    #[serde(alias = "hold_id")]
    pub hold_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "matter_ref")]
    pub matter_ref: String,
    #[prost(string, tag = "3")]
    pub reason: String,
    #[prost(string, tag = "4")]
    pub lifecycle: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "created_by")]
    pub created_by: String,
    #[prost(string, repeated, tag = "6")]
    pub approvers: Vec<String>,
    #[prost(string, tag = "7")]
    #[serde(alias = "created_at")]
    pub created_at: String,
    #[prost(string, tag = "8")]
    #[serde(alias = "review_by")]
    pub review_by: String,
    #[prost(string, tag = "9")]
    #[serde(alias = "notice_mode")]
    pub notice_mode: String,
    #[prost(string, tag = "10")]
    #[serde(alias = "scope_summary")]
    pub scope_summary: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by SubjectRequestStatus codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SubjectRequestEntry {
    #[prost(string, tag = "1")]
    #[serde(alias = "request_id")]
    pub request_id: String,
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "subject_ref")]
    pub subject_ref: String,
    #[prost(enumeration = "crate::common::SubjectRequestStatus", tag = "4")]
    #[serde(with = "subject_request_status_serde")]
    pub status: i32,
    #[prost(string, repeated, tag = "5")]
    #[serde(alias = "hold_ids")]
    pub hold_ids: Vec<String>,
    #[prost(string, tag = "6")]
    #[serde(alias = "requested_at")]
    pub requested_at: String,
    #[prost(string, tag = "7")]
    pub detail: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ComplianceConnectorEntry {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(string, tag = "3")]
    pub kind: String,
    #[prost(string, tag = "4")]
    pub stability: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "circuit_state")]
    pub circuit_state: String,
    #[prost(uint32, tag = "6")]
    #[serde(alias = "queued_items")]
    pub queued_items: u32,
    #[prost(uint32, tag = "7")]
    #[serde(alias = "delivered_items")]
    pub delivered_items: u32,
    #[prost(string, tag = "8")]
    #[serde(alias = "capture_ceiling")]
    pub capture_ceiling: String,
    #[prost(string, tag = "9")]
    #[serde(alias = "assurance_label")]
    pub assurance_label: String,
    #[prost(string, optional, tag = "10")]
    #[serde(alias = "last_delivery_at")]
    pub last_delivery_at: Option<String>,
    #[prost(string, tag = "11")]
    pub summary: String,
}

// grdr:allow-s4 prost enumeration wire representation uses i32 backed by ReidRequestStatus codec
#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ReidentificationRequestEntry {
    #[prost(string, tag = "1")]
    #[serde(alias = "request_id")]
    pub request_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "pseudonym_id")]
    pub pseudonym_id: String,
    #[prost(string, tag = "3")]
    pub requester: String,
    #[prost(string, tag = "4")]
    pub reason: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "legal_basis")]
    pub legal_basis: String,
    #[prost(enumeration = "crate::common::ReidRequestStatus", tag = "6")]
    #[serde(with = "reid_request_status_serde")]
    pub status: i32,
    #[prost(string, repeated, tag = "7")]
    pub approvers: Vec<String>,
    #[prost(uint32, tag = "8")]
    #[serde(alias = "required_approvals")]
    pub required_approvals: u32,
    #[prost(string, optional, tag = "9")]
    #[serde(alias = "resolved_identity")]
    pub resolved_identity: Option<String>,
    #[prost(string, tag = "10")]
    #[serde(alias = "created_at")]
    pub created_at: String,
    #[prost(string, optional, tag = "11")]
    #[serde(alias = "resolved_at")]
    pub resolved_at: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DisclosureLedgerEntry {
    #[prost(string, tag = "1")]
    pub id: String,
    #[prost(string, tag = "2")]
    pub kind: String,
    #[prost(string, tag = "3")]
    pub actor: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "target_ref")]
    pub target_ref: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "legal_basis")]
    pub legal_basis: String,
    #[prost(string, tag = "6")]
    pub timestamp: String,
    #[prost(string, tag = "7")]
    pub quarter: String,
    #[prost(string, tag = "8")]
    pub summary: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct DisclosureMetrics {
    #[prost(string, tag = "1")]
    pub quarter: String,
    #[prost(uint32, tag = "2")]
    #[serde(alias = "total_reidentifications")]
    pub total_reidentifications: u32,
    #[prost(uint32, tag = "3")]
    #[serde(alias = "total_holds")]
    pub total_holds: u32,
    #[prost(uint32, tag = "4")]
    #[serde(alias = "total_erasures")]
    pub total_erasures: u32,
    #[prost(uint32, tag = "5")]
    #[serde(alias = "total_exports")]
    pub total_exports: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct FirstRunState {
    #[prost(string, tag = "1")]
    #[serde(alias = "selected_profile")]
    pub selected_profile: String,
    #[prost(bool, tag = "2")]
    pub confirmed: bool,
    #[prost(bool, tag = "3")]
    #[serde(alias = "step_up_enabled")]
    pub step_up_enabled: bool,
    #[prost(message, repeated, tag = "4")]
    pub steps: Vec<SetupStep>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetComplianceWorkspaceRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetComplianceWorkspaceResponse {
    #[prost(message, repeated, tag = "1")]
    pub frameworks: Vec<FrameworkCoverageSummary>,
    #[prost(message, repeated, tag = "2")]
    #[serde(alias = "evidence_items")]
    pub evidence_items: Vec<ComplianceEvidenceEntry>,
    #[prost(message, optional, tag = "3")]
    pub retention: Option<RetentionStateSummary>,
    #[prost(message, repeated, tag = "4")]
    #[serde(alias = "legal_holds")]
    pub legal_holds: Vec<LegalHoldEntry>,
    #[prost(message, repeated, tag = "5")]
    #[serde(alias = "subject_requests")]
    pub subject_requests: Vec<SubjectRequestEntry>,
    #[prost(message, repeated, tag = "6")]
    pub connectors: Vec<ComplianceConnectorEntry>,
    #[prost(message, repeated, tag = "7")]
    #[serde(alias = "reid_requests")]
    pub reid_requests: Vec<ReidentificationRequestEntry>,
    #[prost(message, repeated, tag = "8")]
    pub disclosures: Vec<DisclosureLedgerEntry>,
    #[prost(message, optional, tag = "9")]
    #[serde(alias = "disclosure_metrics")]
    pub disclosure_metrics: Option<DisclosureMetrics>,
    #[prost(message, optional, tag = "10")]
    #[serde(alias = "first_run")]
    pub first_run: Option<FirstRunState>,
    #[prost(message, optional, tag = "11")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateCompliancePolicyRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "privacy_profile")]
    pub privacy_profile: String,
    #[prost(string, repeated, tag = "2")]
    pub presets: Vec<String>,
    #[prost(string, optional, tag = "3")]
    #[serde(alias = "override_legal_basis")]
    pub override_legal_basis: Option<String>,
    #[prost(string, optional, tag = "4")]
    #[serde(alias = "capture_level")]
    pub capture_level: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UpdateCompliancePolicyResponse {
    #[prost(message, optional, tag = "1")]
    pub retention: Option<RetentionStateSummary>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateLegalHoldRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "matter_ref")]
    pub matter_ref: String,
    #[prost(string, tag = "2")]
    pub reason: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "pseudonym_or_session")]
    pub pseudonym_or_session: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CreateLegalHoldResponse {
    #[prost(message, optional, tag = "1")]
    pub hold: Option<LegalHoldEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApproveLegalHoldRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "hold_id")]
    pub hold_id: String,
    #[prost(string, optional, tag = "2")]
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApproveLegalHoldResponse {
    #[prost(message, optional, tag = "1")]
    pub hold: Option<LegalHoldEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportComplianceArtifactRequest {
    #[prost(string, tag = "1")]
    pub format: String,
    #[prost(string, optional, tag = "2")]
    #[serde(alias = "framework_id")]
    pub framework_id: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ExportComplianceArtifactResponse {
    #[prost(string, tag = "1")]
    pub format: String,
    #[prost(string, tag = "2")]
    pub filename: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "content_type")]
    pub content_type: String,
    #[prost(string, tag = "4")]
    pub payload: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "oscal_version")]
    pub oscal_version: String,
    #[prost(string, tag = "6")]
    pub digest: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PushGrcEvidenceRequest {
    #[prost(string, tag = "1")]
    pub target: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PushGrcEvidenceResponse {
    #[prost(string, tag = "1")]
    pub target: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "envelope_id")]
    pub envelope_id: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "outbox_state")]
    pub outbox_state: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "circuit_state")]
    pub circuit_state: String,
    #[prost(string, tag = "5")]
    pub summary: String,
    #[prost(string, tag = "6")]
    #[serde(alias = "payload_preview")]
    pub payload_preview: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RequestReidentificationRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "pseudonym_id")]
    pub pseudonym_id: String,
    #[prost(string, tag = "2")]
    pub reason: String,
    #[prost(string, tag = "3")]
    #[serde(alias = "legal_basis")]
    pub legal_basis: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RequestReidentificationResponse {
    #[prost(message, optional, tag = "1")]
    pub request: Option<ReidentificationRequestEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApproveReidentificationRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "request_id")]
    pub request_id: String,
    #[prost(string, optional, tag = "2")]
    pub note: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ApproveReidentificationResponse {
    #[prost(message, optional, tag = "1")]
    pub request: Option<ReidentificationRequestEntry>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CompleteFirstRunRequest {
    #[prost(string, tag = "1")]
    pub profile: String,
    #[prost(bool, tag = "2")]
    #[serde(alias = "confirm_protection")]
    pub confirm_protection: bool,
    #[prost(bool, tag = "3")]
    #[serde(alias = "step_up_enabled")]
    pub step_up_enabled: bool,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct CompleteFirstRunResponse {
    #[prost(message, optional, tag = "1")]
    #[serde(alias = "first_run")]
    pub first_run: Option<FirstRunState>,
}
