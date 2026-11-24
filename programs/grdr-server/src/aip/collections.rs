// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use grdr_model::{
    ArtifactEntry, AssuranceLevel, Device, DiscoveredAgent, InstallProfile, McpServerEntry,
    RiskTier, SessionSummary, UserProfile,
};

use super::filter::{FilterFieldSpec, FilterFieldType, FilterRecord, FilterValue};
use super::pagination::{KeysetItem, OrderSpec, SortKeyValue};

#[derive(Clone)]
pub struct AgentInventoryRow {
    pub composite_id: String,
    pub device_id: String,
    pub device_name: String,
    pub agent: DiscoveredAgent,
}

#[derive(Clone)]
pub struct McpInventoryRow {
    pub composite_id: String,
    pub device_id: String,
    pub device_name: String,
    pub server: McpServerEntry,
}

pub const DEVICE_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "hostname",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "os",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "arch",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "install_profile",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "daemon_version",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "online",
        ty: FilterFieldType::Bool,
    },
    FilterFieldSpec {
        name: "hook_effective",
        ty: FilterFieldType::Bool,
    },
    FilterFieldSpec {
        name: "user_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "last_seen",
        ty: FilterFieldType::Timestamp,
    },
];
pub const DEVICE_SORT: &[&str] = &["id", "hostname", "os", "last_seen"];
pub const DEVICE_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "last_seen",
    desc: true,
};

pub const AGENT_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "kind",
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
        name: "hook_installed",
        ty: FilterFieldType::Bool,
    },
    FilterFieldSpec {
        name: "assurance_level",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "detected_at",
        ty: FilterFieldType::Timestamp,
    },
];
pub const AGENT_SORT: &[&str] = &["id", "name", "mcp_count", "assurance_level", "detected_at"];
pub const AGENT_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "name",
    desc: false,
};

pub const MCP_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "transport",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "source_agent",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "pinned",
        ty: FilterFieldType::Bool,
    },
    FilterFieldSpec {
        name: "device_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "device_name",
        ty: FilterFieldType::Text,
    },
];
pub const MCP_SORT: &[&str] = &["name", "transport", "source_agent"];
pub const MCP_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "name",
    desc: false,
};

pub const ARTIFACT_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "kind",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "scope",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "source_agent",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "pinned",
        ty: FilterFieldType::Bool,
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
        name: "user_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "detected_at",
        ty: FilterFieldType::Timestamp,
    },
];
pub const ARTIFACT_SORT: &[&str] = &["id", "name", "kind", "usage_count", "detected_at"];
pub const ARTIFACT_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "detected_at",
    desc: true,
};

pub const SESSION_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
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
        name: "user_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "blocked_count",
        ty: FilterFieldType::U64,
    },
    FilterFieldSpec {
        name: "assurance_level",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "started_at",
        ty: FilterFieldType::Timestamp,
    },
    FilterFieldSpec {
        name: "last_activity",
        ty: FilterFieldType::Timestamp,
    },
];
pub const SESSION_SORT: &[&str] = &[
    "id",
    "device_name",
    "agent_name",
    "turn_count",
    "started_at",
    "last_activity",
    "total_actions",
    "blocked_count",
    "step_up_count",
    "watch_hits",
    "assurance_level",
];
pub const SESSION_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "last_activity",
    desc: true,
};

pub const USER_FILTERS: &[FilterFieldSpec] = &[
    FilterFieldSpec {
        name: "id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "display_name",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "email",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "department",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "idp_source",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "pseudonym_id",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "risk_score",
        ty: FilterFieldType::U64,
    },
    FilterFieldSpec {
        name: "risk_tier",
        ty: FilterFieldType::Text,
    },
    FilterFieldSpec {
        name: "last_active",
        ty: FilterFieldType::Timestamp,
    },
];
pub const USER_SORT: &[&str] = &[
    "id",
    "display_name",
    "artifact_count",
    "session_count",
    "blocked_count",
    "asked_count",
    "watch_count",
    "finding_count",
    "risk_score",
    "risk_tier",
    "last_active",
];
pub const USER_DEFAULT_ORDER: OrderSpec = OrderSpec {
    field: "risk_score",
    desc: true,
};

impl FilterRecord for Device {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "hostname" => Some(FilterValue::Text(self.hostname.clone())),
            "os" => Some(FilterValue::Text(self.os.clone())),
            "arch" => Some(FilterValue::Text(self.arch.clone())),
            "install_profile" => Some(FilterValue::Text(
                install_profile_str(self.install_profile).into(),
            )),
            "daemon_version" => Some(FilterValue::Text(self.daemon_version.clone())),
            "online" => Some(FilterValue::Bool(self.online)),
            "hook_effective" => Some(FilterValue::Bool(self.hook_effective)),
            "user_id" => self.user_id.clone().map(FilterValue::Text),
            "last_seen" => Some(FilterValue::Timestamp(self.last_seen)),
            _ => None,
        }
    }
}

impl KeysetItem for Device {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "hostname" => SortKeyValue::Text(self.hostname.clone()),
            "os" => SortKeyValue::Text(self.os.clone()),
            "last_seen" => SortKeyValue::TimestampNanos(self.last_seen.as_nanosecond()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

impl FilterRecord for AgentInventoryRow {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.agent.id.clone())),
            "name" => Some(FilterValue::Text(self.agent.name.clone())),
            "kind" => Some(FilterValue::Text(self.agent.kind.clone())),
            "device_id" => Some(FilterValue::Text(self.device_id.clone())),
            "device_name" => Some(FilterValue::Text(self.device_name.clone())),
            "hook_installed" => Some(FilterValue::Bool(self.agent.hook_installed)),
            "assurance_level" => Some(FilterValue::Text(
                assurance_str(self.agent.assurance_level).into(),
            )),
            "detected_at" => Some(FilterValue::Timestamp(self.agent.detected_at)),
            _ => None,
        }
    }
}

impl KeysetItem for AgentInventoryRow {
    fn item_id(&self) -> &str {
        &self.composite_id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "name" => SortKeyValue::Text(self.agent.name.clone()),
            "mcp_count" => {
                SortKeyValue::U64(u64::try_from(self.agent.mcp_count).unwrap_or(u64::MAX))
            }
            "assurance_level" => {
                SortKeyValue::Text(assurance_str(self.agent.assurance_level).into())
            }
            "detected_at" => SortKeyValue::TimestampNanos(self.agent.detected_at.as_nanosecond()),
            _ => SortKeyValue::Text(self.composite_id.clone()),
        }
    }
}

impl FilterRecord for McpInventoryRow {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "name" => Some(FilterValue::Text(self.server.name.clone())),
            "transport" => Some(FilterValue::Text(self.server.transport.clone())),
            "source_agent" => Some(FilterValue::Text(self.server.source_agent.clone())),
            "pinned" => Some(FilterValue::Bool(self.server.pinned)),
            "device_id" => Some(FilterValue::Text(self.device_id.clone())),
            "device_name" => Some(FilterValue::Text(self.device_name.clone())),
            _ => None,
        }
    }
}

impl KeysetItem for McpInventoryRow {
    fn item_id(&self) -> &str {
        &self.composite_id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "transport" => SortKeyValue::Text(self.server.transport.clone()),
            "source_agent" => SortKeyValue::Text(self.server.source_agent.clone()),
            _ => SortKeyValue::Text(self.server.name.clone()),
        }
    }
}

impl FilterRecord for ArtifactEntry {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "name" => Some(FilterValue::Text(self.name.clone())),
            "kind" => Some(FilterValue::Text(
                format!("{:?}", self.kind).to_ascii_lowercase(),
            )),
            "scope" => Some(FilterValue::Text(
                format!("{:?}", self.scope).to_ascii_lowercase(),
            )),
            "source_agent" => Some(FilterValue::Text(self.source_agent.clone())),
            "pinned" => Some(FilterValue::Bool(self.pinned)),
            "device_id" => Some(FilterValue::Text(self.device_id.clone())),
            "device_name" => Some(FilterValue::Text(self.device_name.clone())),
            "user_id" => self.user_id.clone().map(FilterValue::Text),
            "detected_at" => Some(FilterValue::Timestamp(self.detected_at)),
            _ => None,
        }
    }
}

impl KeysetItem for ArtifactEntry {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "name" => SortKeyValue::Text(self.name.clone()),
            "kind" => SortKeyValue::Text(format!("{:?}", self.kind).to_ascii_lowercase()),
            "usage_count" => SortKeyValue::U64(u64::from(self.usage_count)),
            "detected_at" => SortKeyValue::TimestampNanos(self.detected_at.as_nanosecond()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

impl FilterRecord for SessionSummary {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "device_id" => Some(FilterValue::Text(self.device_id.clone())),
            "device_name" => Some(FilterValue::Text(self.device_name.clone())),
            "agent_name" => Some(FilterValue::Text(self.agent_name.clone())),
            "user_id" => self.user_id.clone().map(FilterValue::Text),
            "blocked_count" => Some(FilterValue::U64(self.blocked_count)),
            "assurance_level" => Some(FilterValue::Text(
                assurance_str(self.assurance_level).into(),
            )),
            "started_at" => Some(FilterValue::Timestamp(self.started_at)),
            "last_activity" => Some(FilterValue::Timestamp(self.last_activity)),
            _ => None,
        }
    }
}

impl KeysetItem for SessionSummary {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "device_name" => SortKeyValue::Text(self.device_name.clone()),
            "agent_name" => SortKeyValue::Text(self.agent_name.clone()),
            "turn_count" => SortKeyValue::U64(u64::try_from(self.turn_count).unwrap_or(u64::MAX)),
            "started_at" => SortKeyValue::TimestampNanos(self.started_at.as_nanosecond()),
            "last_activity" => SortKeyValue::TimestampNanos(self.last_activity.as_nanosecond()),
            "total_actions" => SortKeyValue::U64(self.total_actions),
            "blocked_count" => SortKeyValue::U64(self.blocked_count),
            "step_up_count" => SortKeyValue::U64(self.step_up_count),
            "watch_hits" => SortKeyValue::U64(self.watch_hits),
            "assurance_level" => SortKeyValue::Text(assurance_str(self.assurance_level).into()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

impl FilterRecord for UserProfile {
    fn field_value(&self, field: &str) -> Option<FilterValue> {
        match field {
            "id" => Some(FilterValue::Text(self.id.clone())),
            "display_name" => Some(FilterValue::Text(self.display_name.clone())),
            "email" => Some(FilterValue::Text(self.email.clone())),
            "department" => Some(FilterValue::Text(self.department.clone())),
            "idp_source" => Some(FilterValue::Text(self.idp_source.clone())),
            "pseudonym_id" => Some(FilterValue::Text(self.pseudonym_id.clone())),
            "risk_score" => Some(FilterValue::U64(u64::from(self.risk_score))),
            "risk_tier" => Some(FilterValue::Text(risk_tier_str(self.risk_tier).into())),
            "last_active" => Some(FilterValue::Timestamp(self.last_active)),
            _ => None,
        }
    }
}

impl KeysetItem for UserProfile {
    fn item_id(&self) -> &str {
        &self.id
    }

    fn sort_key(&self, field: &str) -> SortKeyValue {
        match field {
            "display_name" => SortKeyValue::Text(self.display_name.clone()),
            "artifact_count" => {
                SortKeyValue::U64(u64::try_from(self.artifact_count).unwrap_or(u64::MAX))
            }
            "session_count" => {
                SortKeyValue::U64(u64::try_from(self.session_count).unwrap_or(u64::MAX))
            }
            "blocked_count" => {
                SortKeyValue::U64(u64::try_from(self.blocked_count).unwrap_or(u64::MAX))
            }
            "asked_count" => SortKeyValue::U64(u64::try_from(self.asked_count).unwrap_or(u64::MAX)),
            "watch_count" => SortKeyValue::U64(u64::try_from(self.watch_count).unwrap_or(u64::MAX)),
            "finding_count" => {
                SortKeyValue::U64(u64::try_from(self.finding_count).unwrap_or(u64::MAX))
            }
            "risk_score" => SortKeyValue::U64(u64::from(self.risk_score)),
            "risk_tier" => SortKeyValue::Text(risk_tier_str(self.risk_tier).into()),
            "last_active" => SortKeyValue::TimestampNanos(self.last_active.as_nanosecond()),
            _ => SortKeyValue::Text(self.id.clone()),
        }
    }
}

fn install_profile_str(profile: InstallProfile) -> &'static str {
    match profile {
        InstallProfile::User => "user",
        InstallProfile::Protected => "protected",
    }
}

fn assurance_str(level: AssuranceLevel) -> &'static str {
    match level {
        AssuranceLevel::Al0Inventoried => "al0",
        AssuranceLevel::Al1Observed => "al1",
        AssuranceLevel::Al2Guided => "al2",
        AssuranceLevel::Al3Contained => "al3",
        AssuranceLevel::Al4Enforced => "al4",
    }
}

fn risk_tier_str(tier: RiskTier) -> &'static str {
    match tier {
        RiskTier::Low => "low",
        RiskTier::Elevated => "elevated",
        RiskTier::High => "high",
        RiskTier::Critical => "critical",
    }
}
