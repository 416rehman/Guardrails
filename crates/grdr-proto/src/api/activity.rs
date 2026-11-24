// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::common::{
    ActionAttempt, DecisionReceipt, PageInfo, RevisionMeta, SessionSummary, TurnSummary,
    UserProfile, identity_mode_serde, schema_data_class_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ColumnDef {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(enumeration = "crate::common::SchemaDataClass", tag = "2")]
    #[serde(with = "schema_data_class_serde", alias = "data_class")]
    pub data_class: i32,
    #[prost(string, tag = "3")]
    pub description: String,
    #[prost(bool, tag = "4")]
    pub sensitive: bool,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntitySchema {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub description: String,
    #[prost(message, repeated, tag = "3")]
    pub columns: Vec<ColumnDef>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EntitySummaryInfo {
    #[prost(string, tag = "1")]
    pub name: String,
    #[prost(string, tag = "2")]
    pub description: String,
    #[prost(string, repeated, tag = "3")]
    #[serde(alias = "visible_columns")]
    pub visible_columns: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct UserIntentDescriptor {
    #[prost(enumeration = "crate::common::IdentityMode", tag = "1")]
    #[serde(with = "identity_mode_serde", alias = "identity_mode")]
    pub identity_mode: i32,
    #[prost(string, tag = "2")]
    #[serde(alias = "correlation_guidance")]
    pub correlation_guidance: String,
    #[prost(string, repeated, tag = "3")]
    #[serde(alias = "safe_join_keys")]
    pub safe_join_keys: Vec<String>,
    #[prost(string, repeated, tag = "4")]
    #[serde(alias = "schema_hidden_fields")]
    pub schema_hidden_fields: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct StringList {
    #[prost(string, repeated, tag = "1")]
    pub values: Vec<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Oneof, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum QueryCellKind {
    #[prost(string, tag = "1")]
    Text(String),
    #[prost(uint64, tag = "2")]
    Number(u64),
    #[prost(bool, tag = "3")]
    Boolean(bool),
    #[prost(message, tag = "4")]
    List(StringList),
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QueryCellValue {
    #[prost(oneof = "QueryCellKind", tags = "1, 2, 3, 4")]
    pub kind: Option<QueryCellKind>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QueryRow {
    #[prost(btree_map = "string, message", tag = "1")]
    pub columns: BTreeMap<String, QueryCellValue>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct QueryPlanResult {
    #[prost(string, tag = "1")]
    pub entity: String,
    #[prost(string, repeated, tag = "2")]
    #[serde(alias = "selected_columns")]
    pub selected_columns: Vec<String>,
    #[prost(uint64, tag = "3")]
    #[serde(alias = "hidden_columns_stripped")]
    pub hidden_columns_stripped: u64,
    #[prost(uint32, tag = "4")]
    #[serde(alias = "effective_limit")]
    pub effective_limit: u32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListSessionsRequest {
    #[prost(uint32, tag = "1")]
    #[serde(alias = "page_size")]
    pub page_size: u32,
    #[prost(string, tag = "2")]
    #[serde(alias = "page_token")]
    pub page_token: String,
    #[prost(string, tag = "3")]
    pub filter: String,
    #[prost(string, tag = "4")]
    #[serde(alias = "order_by")]
    pub order_by: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ListSessionsResponse {
    #[prost(message, repeated, tag = "1")]
    pub sessions: Vec<SessionSummary>,
    #[prost(message, optional, tag = "2")]
    #[serde(alias = "page_info")]
    pub page_info: Option<PageInfo>,
    #[prost(message, optional, tag = "3")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetSessionRequest {
    #[prost(string, tag = "1")]
    pub id: String,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetSessionResponse {
    #[prost(message, optional, tag = "1")]
    pub session: Option<SessionSummary>,
    #[prost(message, repeated, tag = "2")]
    pub attempts: Vec<ActionAttempt>,
    #[prost(message, repeated, tag = "3")]
    pub receipts: Vec<DecisionReceipt>,
    #[prost(message, repeated, tag = "4")]
    pub turns: Vec<TurnSummary>,
    #[prost(message, optional, tag = "5")]
    pub user: Option<UserProfile>,
    #[prost(message, optional, tag = "6")]
    pub revision: Option<RevisionMeta>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetQuerySchemaRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetQuerySchemaResponse {
    #[prost(message, repeated, tag = "1")]
    pub entities: Vec<EntitySchema>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetQueryEntitiesRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetQueryEntitiesResponse {
    #[prost(message, repeated, tag = "1")]
    pub entities: Vec<EntitySummaryInfo>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetQueryUserIntentRequest {}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct GetQueryUserIntentResponse {
    #[prost(message, optional, tag = "1")]
    pub descriptor: Option<UserIntentDescriptor>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SampleQueryRequest {
    #[prost(string, tag = "1")]
    pub entity: String,
    #[prost(string, repeated, tag = "2")]
    pub columns: Vec<String>,
    #[prost(uint32, optional, tag = "3")]
    pub limit: Option<u32>,
    #[prost(string, optional, tag = "4")]
    #[serde(alias = "filter_text")]
    pub filter_text: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct SampleQueryResponse {
    #[prost(message, optional, tag = "1")]
    pub plan: Option<QueryPlanResult>,
    #[prost(message, repeated, tag = "2")]
    pub rows: Vec<QueryRow>,
    #[prost(string, tag = "3")]
    #[serde(alias = "untrusted_warning")]
    pub untrusted_warning: String,
}
