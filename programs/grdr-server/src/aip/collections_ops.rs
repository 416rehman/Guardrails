// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::{
    ActionClass, ApprovalGrade, ApprovalRequest, ApprovalState, AuditEntry, Finding, FindingClass,
    FindingLifecycle, FindingSeverity, Incident,
};

use super::filter::{FilterFieldSpec, FilterFieldType, FilterRecord, FilterValue};
use super::pagination::{KeysetItem, OrderSpec, SortKeyValue};

pub const APPROVAL_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "session_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "device_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "device_name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "agent_name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "action_class",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "rule_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "required_grade",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "status",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "requested_at",
        ty: FilterFieldType::Timestamp,
    },
];
pub const APPROVAL_SORT: &[&str] = &["id", "requested_at", "status"];
pub const APPROVAL_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "requested_at",
    desc: true,
};

pub const FINDING_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "session_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "device_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "device_name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "agent_name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "finding_class",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "severity",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "lifecycle",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "rule_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "detected_at",
        ty: FilterFieldType::Timestamp,
    },
];
pub const FINDING_SORT: &[&str] = &["id", "severity", "lifecycle", "detected_at"];
pub const FINDING_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "detected_at",
    desc: true,
};

pub const INCIDENT_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "session_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "device_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "device_name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "agent_name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "severity",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "lifecycle",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "first_seen",
        ty: FilterFieldType::Timestamp,
    },
    FilterFieldSpec {
        name: "last_seen",
        ty: FilterFieldType::Timestamp,
    },
];
pub const INCIDENT_SORT: &[&str] = &[
    "id",
    "severity",
    "lifecycle",
    "finding_count",
    "first_seen",
    "last_seen",
];
pub const INCIDENT_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "last_seen",
    desc: true,
};

pub const AUDIT_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "timestamp",
        ty: FilterFieldType::Timestamp,
    },
    FilterFieldSpec {
        name: "kind",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "actor",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "target",
        ty: FilterFieldType::Text,
    },
];
pub const AUDIT_SORT: &[&str] = &["id", "timestamp"];
pub const AUDIT_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "timestamp",
    desc: true,
};

impl FilterRecord for ApprovalRequest {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "session_id" => Some(FilterValue::Text(self.session_id.clone())),
            "device_id" => Some(FilterValue::Text(self.device_id.clone())),
            "device_name" => Some(FilterValue::Text(self.device_name.clone())),
            "agent_name" => Some(FilterValue::Text(self.agent_name.clone())),
            "action_class" => Some(FilterValue::Text(
                action_class_str(self.action_class).into(),
            )),
            "rule_id" => Some(FilterValue::Text(self.rule_id.clone())),
            "required_grade" => Some(FilterValue::Text(grade_str(self.required_grade).into())),
            "status" => Some(FilterValue::Text(approval_status_str(&self.state).into())),
            "requested_at" => Some(FilterValue::Timestamp(self.requested_at)),
            _ => None,
        }
    }
}

impl KeysetItem for ApprovalRequest {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "requested_at" => SortKeyValue::TimestampNanos(self.requested_at.as_nanosecond()),
            "status" => SortKeyValue::Text(approval_status_str(&self.state).into()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

impl FilterRecord for Finding {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "session_id" => Some(FilterValue::Text(self.session_id.clone())),
            "device_id" => Some(FilterValue::Text(self.device_id.clone())),
            "device_name" => Some(FilterValue::Text(self.device_name.clone())),
            "agent_name" => Some(FilterValue::Text(self.agent_name.clone())),
            "finding_class" => Some(FilterValue::Text(finding_class_str(self.class).into())),
            "severity" => Some(FilterValue::Text(severity_str(self.severity).into())),
            "lifecycle" => Some(FilterValue::Text(lifecycle_str(self.lifecycle).into())),
            "rule_id" => self.rule_id.clone().map(FilterValue::Text),
            "detected_at" => Some(FilterValue::Timestamp(self.detected_at)),
            _ => None,
        }
    }
}

impl KeysetItem for Finding {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "severity" => SortKeyValue::U64(severity_rank(self.severity)),
            "lifecycle" => SortKeyValue::Text(lifecycle_str(self.lifecycle).into()),
            "detected_at" => SortKeyValue::TimestampNanos(self.detected_at.as_nanosecond()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

impl FilterRecord for Incident {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "session_id" => Some(FilterValue::Text(self.session_id.clone())),
            "device_id" => Some(FilterValue::Text(self.device_id.clone())),
            "device_name" => Some(FilterValue::Text(self.device_name.clone())),
            "agent_name" => Some(FilterValue::Text(self.agent_name.clone())),
            "severity" => Some(FilterValue::Text(severity_str(self.severity).into())),
            "lifecycle" => Some(FilterValue::Text(lifecycle_str(self.lifecycle).into())),
            "first_seen" => Some(FilterValue::Timestamp(self.first_seen)),
            "last_seen" => Some(FilterValue::Timestamp(self.last_seen)),
            _ => None,
        }
    }
}

impl KeysetItem for Incident {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "severity" => SortKeyValue::U64(severity_rank(self.severity)),
            "lifecycle" => SortKeyValue::Text(lifecycle_str(self.lifecycle).into()),
            "finding_count" => {
                SortKeyValue::U64(u64::try_from(self.finding_count).unwrap_or(u64::MAX))
            }
            "first_seen" => SortKeyValue::TimestampNanos(self.first_seen.as_nanosecond()),
            "last_seen" => SortKeyValue::TimestampNanos(self.last_seen.as_nanosecond()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

impl FilterRecord for AuditEntry {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "timestamp" => Some(FilterValue::Timestamp(self.timestamp)),
            "kind" => Some(FilterValue::Text(self.kind.clone())),
            "actor" => Some(FilterValue::Text(self.actor.clone())),
            "target" => Some(FilterValue::Text(self.target.clone())),
            _ => None,
        }
    }
}

impl KeysetItem for AuditEntry {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "timestamp" => SortKeyValue::TimestampNanos(self.timestamp.as_nanosecond()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

fn action_class_str(ac: ActionClass) -> &'static str {
    match ac {
        ActionClass::Exec => "exec",
        ActionClass::FileRead => "file.read",
        ActionClass::FileWrite => "file.write",
        ActionClass::FileDelete => "file.delete",
        ActionClass::NetConnect => "net.connect",
        ActionClass::NetRequest => "net.request",
        ActionClass::LlmRequest => "llm.request",
        ActionClass::McpConnect => "mcp.connect",
        ActionClass::McpCall => "mcp.call",
        ActionClass::CredUse => "cred.use",
        ActionClass::AgentSpawn => "agent.spawn",
        ActionClass::ConfigChange => "config.change",
        ActionClass::Elevate => "elevate",
        ActionClass::UiAct => "ui.act",
        ActionClass::DataFlow => "data.flow",
    }
}

fn grade_str(g: ApprovalGrade) -> &'static str {
    match g {
        ApprovalGrade::G0 => "g0",
        ApprovalGrade::G1 => "g1",
        ApprovalGrade::G2 => "g2",
        ApprovalGrade::G3 => "g3",
    }
}

fn approval_status_str(state: &ApprovalState) -> &'static str {
    match state {
        ApprovalState::Pending { .. } => "pending",
        ApprovalState::Approved { .. } => "approved",
        ApprovalState::Denied { .. } => "denied",
        ApprovalState::Expired { .. } => "expired",
    }
}

fn finding_class_str(fc: FindingClass) -> &'static str {
    match fc {
        FindingClass::Threat => "threat",
        FindingClass::PolicyViolation => "policy_violation",
        FindingClass::Overeager => "overeager",
        FindingClass::Tamper => "tamper",
        FindingClass::CoverageGap => "coverage_gap",
        FindingClass::Other => "other",
    }
}

fn severity_str(s: FindingSeverity) -> &'static str {
    match s {
        FindingSeverity::Low => "low",
        FindingSeverity::Medium => "medium",
        FindingSeverity::High => "high",
        FindingSeverity::Critical => "critical",
    }
}

fn severity_rank(s: FindingSeverity) -> u64 {
    match s {
        FindingSeverity::Low => 1,
        FindingSeverity::Medium => 2,
        FindingSeverity::High => 3,
        FindingSeverity::Critical => 4,
    }
}

fn lifecycle_str(l: FindingLifecycle) -> &'static str {
    match l {
        FindingLifecycle::Open => "open",
        FindingLifecycle::Acknowledged => "acknowledged",
        FindingLifecycle::Contained => "contained",
        FindingLifecycle::Resolved => "resolved",
    }
}
