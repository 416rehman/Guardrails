// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use std::collections::BTreeMap;

use serde::{Deserialize, Serialize};

use crate::proto_enum_codec;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum DataClass {
    Unspecified = 0,
    Public = 1,
    Metadata = 2,
    Identifier = 3,
    Pseudonym = 4,
    Content = 5,
    Secret = 6,
}
proto_enum_codec!(DataClass, data_class_serde, [
    DataClass::Unspecified => "DATA_CLASS_UNSPECIFIED",
    DataClass::Public => "DATA_CLASS_PUBLIC" | "public",
    DataClass::Metadata => "DATA_CLASS_METADATA" | "metadata",
    DataClass::Identifier => "DATA_CLASS_IDENTIFIER" | "identifier",
    DataClass::Pseudonym => "DATA_CLASS_PSEUDONYM" | "pseudonym",
    DataClass::Content => "DATA_CLASS_CONTENT" | "content",
    DataClass::Secret => "DATA_CLASS_SECRET" | "secret",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ConfirmClass {
    Unspecified = 0,
    None = 1,
    Consequence = 2,
    Typed = 3,
    Propose = 4,
    Quorum = 5,
}
proto_enum_codec!(ConfirmClass, confirm_class_serde, [
    ConfirmClass::Unspecified => "CONFIRM_CLASS_UNSPECIFIED",
    ConfirmClass::None => "CONFIRM_CLASS_NONE" | "none",
    ConfirmClass::Consequence => "CONFIRM_CLASS_CONSEQUENCE" | "consequence",
    ConfirmClass::Typed => "CONFIRM_CLASS_TYPED" | "typed",
    ConfirmClass::Propose => "CONFIRM_CLASS_PROPOSE" | "propose",
    ConfirmClass::Quorum => "CONFIRM_CLASS_QUORUM" | "quorum",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum AuditClass {
    Unspecified = 0,
    None = 1,
    Read = 2,
    SensitiveRead = 3,
    Mutation = 4,
    CriticalMutation = 5,
}
proto_enum_codec!(AuditClass, audit_class_serde, [
    AuditClass::Unspecified => "AUDIT_CLASS_UNSPECIFIED",
    AuditClass::None => "AUDIT_CLASS_NONE" | "none",
    AuditClass::Read => "AUDIT_CLASS_READ" | "read",
    AuditClass::SensitiveRead => "AUDIT_CLASS_SENSITIVE_READ" | "sensitive_read",
    AuditClass::Mutation => "AUDIT_CLASS_MUTATION" | "mutation",
    AuditClass::CriticalMutation => "AUDIT_CLASS_CRITICAL_MUTATION" | "critical_mutation",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum RateClass {
    Unspecified = 0,
    Health = 1,
    Standard = 2,
    Interactive = 3,
    Critical = 4,
    Bulk = 5,
    Ingest = 6,
}
proto_enum_codec!(RateClass, rate_class_serde, [
    RateClass::Unspecified => "RATE_CLASS_UNSPECIFIED",
    RateClass::Health => "RATE_CLASS_HEALTH" | "health",
    RateClass::Standard => "RATE_CLASS_STANDARD" | "standard",
    RateClass::Interactive => "RATE_CLASS_INTERACTIVE" | "interactive",
    RateClass::Critical => "RATE_CLASS_CRITICAL" | "critical",
    RateClass::Bulk => "RATE_CLASS_BULK" | "bulk",
    RateClass::Ingest => "RATE_CLASS_INGEST" | "ingest",
]);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, prost::Enumeration)]
#[repr(i32)]
pub enum ErrorClass {
    Unspecified = 0,
    Validation = 1,
    Auth = 2,
    Permission = 3,
    NotFound = 4,
    Conflict = 5,
    RateLimit = 6,
    Internal = 7,
}
proto_enum_codec!(ErrorClass, error_class_serde, [
    ErrorClass::Unspecified => "ERROR_CLASS_UNSPECIFIED",
    ErrorClass::Validation => "ERROR_CLASS_VALIDATION" | "validation",
    ErrorClass::Auth => "ERROR_CLASS_AUTH" | "auth",
    ErrorClass::Permission => "ERROR_CLASS_PERMISSION" | "permission",
    ErrorClass::NotFound => "ERROR_CLASS_NOT_FOUND" | "not_found",
    ErrorClass::Conflict => "ERROR_CLASS_CONFLICT" | "conflict",
    ErrorClass::RateLimit => "ERROR_CLASS_RATE_LIMIT" | "rate_limit",
    ErrorClass::Internal => "ERROR_CLASS_INTERNAL" | "internal",
]);

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ErrorInfo {
    #[prost(string, tag = "1")]
    pub reason: String,
    #[prost(string, tag = "2")]
    pub domain: String,
    #[prost(btree_map = "string, string", tag = "3")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct ErrorDetail {
    #[prost(string, tag = "1")]
    pub code: String,
    #[prost(string, tag = "2")]
    pub reason: String,
    #[prost(enumeration = "ErrorClass", tag = "3")]
    #[serde(with = "error_class_serde")]
    pub class: i32,
    #[prost(string, tag = "4")]
    pub message: String,
    #[prost(string, tag = "5")]
    #[serde(alias = "message_id")]
    pub message_id: String,
    #[prost(string, tag = "6")]
    pub fix: String,
    #[prost(string, tag = "7")]
    #[serde(alias = "docs_url")]
    pub docs_url: String,
    #[prost(string, tag = "8")]
    #[serde(alias = "request_id")]
    pub request_id: String,
    #[prost(btree_map = "string, string", tag = "9")]
    pub metadata: BTreeMap<String, String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct PageInfo {
    #[prost(string, tag = "1")]
    #[serde(alias = "next_page_token")]
    pub next_page_token: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "prev_page_token")]
    pub prev_page_token: String,
    #[prost(uint64, tag = "3")]
    #[serde(alias = "total_size_estimate")]
    pub total_size_estimate: u64,
    #[prost(bool, tag = "4")]
    #[serde(alias = "has_more")]
    pub has_more: bool,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct RevisionMeta {
    #[prost(string, tag = "1")]
    pub etag: String,
    #[prost(uint64, tag = "2")]
    #[serde(alias = "high_water_mark")]
    pub high_water_mark: u64,
}
