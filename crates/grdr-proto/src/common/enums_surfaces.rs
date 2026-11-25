// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use crate::proto_enum_codec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ReviewClusterStatus {
    Unspecified = 0,
    Open = 1,
    Promoted = 2,
    Suppressed = 3,
    Dismissed = 4,
    Escalated = 5,
}
proto_enum_codec!(ReviewClusterStatus, review_cluster_status_serde, [
    ReviewClusterStatus::Unspecified => "REVIEW_CLUSTER_STATUS_UNSPECIFIED",
    ReviewClusterStatus::Open => "REVIEW_CLUSTER_STATUS_OPEN" | "open",
    ReviewClusterStatus::Promoted => "REVIEW_CLUSTER_STATUS_PROMOTED" | "promoted",
    ReviewClusterStatus::Suppressed => "REVIEW_CLUSTER_STATUS_SUPPRESSED" | "suppressed",
    ReviewClusterStatus::Dismissed => "REVIEW_CLUSTER_STATUS_DISMISSED" | "dismissed",
    ReviewClusterStatus::Escalated => "REVIEW_CLUSTER_STATUS_ESCALATED" | "escalated",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ProviderOrgStatus {
    Unspecified = 0,
    Healthy = 1,
    Attention = 2,
    Offline = 3,
}
proto_enum_codec!(ProviderOrgStatus, provider_org_status_serde, [
    ProviderOrgStatus::Unspecified => "PROVIDER_ORG_STATUS_UNSPECIFIED",
    ProviderOrgStatus::Healthy => "PROVIDER_ORG_STATUS_HEALTHY" | "healthy",
    ProviderOrgStatus::Attention => "PROVIDER_ORG_STATUS_ATTENTION" | "attention",
    ProviderOrgStatus::Offline => "PROVIDER_ORG_STATUS_OFFLINE" | "offline",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum SubjectRequestStatus {
    Unspecified = 0,
    Executed = 1,
    PendingHeld = 2,
}
proto_enum_codec!(SubjectRequestStatus, subject_request_status_serde, [
    SubjectRequestStatus::Unspecified => "SUBJECT_REQUEST_STATUS_UNSPECIFIED",
    SubjectRequestStatus::Executed => "SUBJECT_REQUEST_STATUS_EXECUTED" | "executed",
    SubjectRequestStatus::PendingHeld => "SUBJECT_REQUEST_STATUS_PENDING_HELD" | "pending_held",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ReidRequestStatus {
    Unspecified = 0,
    PendingQuorum = 1,
    Approved = 2,
    Denied = 3,
}
proto_enum_codec!(ReidRequestStatus, reid_request_status_serde, [
    ReidRequestStatus::Unspecified => "REID_REQUEST_STATUS_UNSPECIFIED",
    ReidRequestStatus::PendingQuorum => "REID_REQUEST_STATUS_PENDING_QUORUM" | "pending_quorum",
    ReidRequestStatus::Approved => "REID_REQUEST_STATUS_APPROVED" | "approved",
    ReidRequestStatus::Denied => "REID_REQUEST_STATUS_DENIED" | "denied",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ConfigRevisionLifecycle {
    Unspecified = 0,
    Draft = 1,
    Validated = 2,
    Applying = 3,
    Applied = 4,
    RolledBack = 5,
    Superseded = 6,
    Discarded = 7,
}
proto_enum_codec!(ConfigRevisionLifecycle, config_revision_lifecycle_serde, [
    ConfigRevisionLifecycle::Unspecified => "CONFIG_REVISION_LIFECYCLE_UNSPECIFIED",
    ConfigRevisionLifecycle::Draft => "CONFIG_REVISION_LIFECYCLE_DRAFT" | "draft",
    ConfigRevisionLifecycle::Validated => "CONFIG_REVISION_LIFECYCLE_VALIDATED" | "validated",
    ConfigRevisionLifecycle::Applying => "CONFIG_REVISION_LIFECYCLE_APPLYING" | "applying",
    ConfigRevisionLifecycle::Applied => "CONFIG_REVISION_LIFECYCLE_APPLIED" | "applied",
    ConfigRevisionLifecycle::RolledBack => "CONFIG_REVISION_LIFECYCLE_ROLLED_BACK" | "rolled_back",
    ConfigRevisionLifecycle::Superseded => "CONFIG_REVISION_LIFECYCLE_SUPERSEDED" | "superseded",
    ConfigRevisionLifecycle::Discarded => "CONFIG_REVISION_LIFECYCLE_DISCARDED" | "discarded",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum CompatOutcomeKind {
    Unspecified = 0,
    Compatible = 1,
    CompatibleWithWarnings = 2,
    Incompatible = 3,
}
proto_enum_codec!(CompatOutcomeKind, compat_outcome_kind_serde, [
    CompatOutcomeKind::Unspecified => "COMPAT_OUTCOME_KIND_UNSPECIFIED",
    CompatOutcomeKind::Compatible => "COMPAT_OUTCOME_KIND_COMPATIBLE" | "compatible",
    CompatOutcomeKind::CompatibleWithWarnings => "COMPAT_OUTCOME_KIND_COMPATIBLE_WITH_WARNINGS" | "compatible_with_warnings",
    CompatOutcomeKind::Incompatible => "COMPAT_OUTCOME_KIND_INCOMPATIBLE" | "incompatible",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum TargetHealthStatus {
    Unspecified = 0,
    Healthy = 1,
    Degraded = 2,
    OpenCircuit = 3,
}
proto_enum_codec!(TargetHealthStatus, target_health_status_serde, [
    TargetHealthStatus::Unspecified => "TARGET_HEALTH_STATUS_UNSPECIFIED",
    TargetHealthStatus::Healthy => "TARGET_HEALTH_STATUS_HEALTHY" | "healthy",
    TargetHealthStatus::Degraded => "TARGET_HEALTH_STATUS_DEGRADED" | "degraded",
    TargetHealthStatus::OpenCircuit => "TARGET_HEALTH_STATUS_OPEN_CIRCUIT" | "open_circuit",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum BackupDrillStatus {
    Unspecified = 0,
    Passed = 1,
    Running = 2,
    Failed = 3,
}
proto_enum_codec!(BackupDrillStatus, backup_drill_status_serde, [
    BackupDrillStatus::Unspecified => "BACKUP_DRILL_STATUS_UNSPECIFIED",
    BackupDrillStatus::Passed => "BACKUP_DRILL_STATUS_PASSED" | "passed",
    BackupDrillStatus::Running => "BACKUP_DRILL_STATUS_RUNNING" | "running",
    BackupDrillStatus::Failed => "BACKUP_DRILL_STATUS_FAILED" | "failed",
]);
