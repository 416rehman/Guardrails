// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use grdr_model::{CodedError, Device, Finding, PolicyPack, SessionSummary};

use crate::tenant::{ProfileKind, SingleCtx, TenantCtx};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Device,
    Agent,
    McpServer,
    Rule,
    User,
    Finding,
    Session,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct EntitySearchHit {
    pub entity_kind: EntityKind,
    pub entity_id: String,
    pub title: String,
    pub subtitle: String,
    pub rank_score: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct TenantUserRecord {
    pub id: String,
    pub display_name: String,
    pub email: String,
    pub department: String,
    pub idp_source: String,
    pub pseudonym_id: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct MigrationRecord {
    pub version: u32,
    pub name: String,
    pub applied_at: String,
}

pub trait DeviceRepo {
    fn upsert_device(&self, ctx: &SingleCtx, device: &Device) -> Result<(), CodedError>;
    fn get_device(&self, ctx: &TenantCtx, device_id: &str) -> Result<Option<Device>, CodedError>;
    fn list_devices(&self, ctx: &TenantCtx) -> Result<Vec<Device>, CodedError>;
}

pub trait SessionSummaryRepo {
    fn upsert_session_summary(
        &self,
        ctx: &SingleCtx,
        summary: &SessionSummary,
    ) -> Result<(), CodedError>;
    fn get_session_summary(
        &self,
        ctx: &TenantCtx,
        session_id: &str,
    ) -> Result<Option<SessionSummary>, CodedError>;
    fn list_session_summaries(&self, ctx: &TenantCtx) -> Result<Vec<SessionSummary>, CodedError>;
}

pub trait FindingRepo {
    fn upsert_finding(&self, ctx: &SingleCtx, finding: &Finding) -> Result<(), CodedError>;
    fn get_finding(&self, ctx: &TenantCtx, finding_id: &str)
    -> Result<Option<Finding>, CodedError>;
    fn list_findings(&self, ctx: &TenantCtx) -> Result<Vec<Finding>, CodedError>;
}

pub trait PolicyRepo {
    fn upsert_pack(&self, ctx: &SingleCtx, pack: &PolicyPack) -> Result<(), CodedError>;
    fn get_pack(&self, ctx: &TenantCtx, pack_id: &str) -> Result<Option<PolicyPack>, CodedError>;
    fn list_packs(&self, ctx: &TenantCtx) -> Result<Vec<PolicyPack>, CodedError>;
}

pub trait UserRepo {
    fn upsert_user(&self, ctx: &SingleCtx, user: &TenantUserRecord) -> Result<(), CodedError>;
    fn get_user(
        &self,
        ctx: &TenantCtx,
        user_id: &str,
    ) -> Result<Option<TenantUserRecord>, CodedError>;
    fn list_users(&self, ctx: &TenantCtx) -> Result<Vec<TenantUserRecord>, CodedError>;
}

pub trait KvSnapshotRepo {
    fn put_kv(
        &self,
        ctx: &SingleCtx,
        namespace: &str,
        key: &str,
        value_json: &str,
    ) -> Result<(), CodedError>;
    fn get_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
        key: &str,
    ) -> Result<Option<String>, CodedError>;
    fn list_kv(
        &self,
        ctx: &TenantCtx,
        namespace: &str,
    ) -> Result<Vec<(String, String)>, CodedError>;
    fn delete_kv(&self, ctx: &SingleCtx, namespace: &str, key: &str) -> Result<(), CodedError>;
}

pub trait RelationalStorePort:
    DeviceRepo + SessionSummaryRepo + FindingRepo + PolicyRepo + UserRepo + KvSnapshotRepo
{
    fn profile(&self) -> ProfileKind;
    fn search_entities(
        &self,
        ctx: &TenantCtx,
        query: &str,
        limit: usize,
    ) -> Result<Vec<EntitySearchHit>, CodedError>;
    fn applied_migrations(&self) -> Result<Vec<MigrationRecord>, CodedError>;
}

impl EntityKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Agent => "agent",
            Self::McpServer => "mcp_server",
            Self::Rule => "rule",
            Self::User => "user",
            Self::Finding => "finding",
            Self::Session => "session",
        }
    }

    pub fn parse(raw: &str) -> Option<Self> {
        match raw {
            "device" => Some(Self::Device),
            "agent" => Some(Self::Agent),
            "mcp_server" => Some(Self::McpServer),
            "rule" => Some(Self::Rule),
            "user" => Some(Self::User),
            "finding" => Some(Self::Finding),
            "session" => Some(Self::Session),
            _ => None,
        }
    }
}
