// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use serde::{Deserialize, Serialize};

use crate::common::{
    ActionAttempt, DecisionReceipt, action_class_serde, browser_dlp_class_serde,
    control_point_serde, verdict_serde,
};

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvaluateRequest {
    #[prost(string, optional, tag = "1")]
    #[serde(alias = "session_id")]
    pub session_id: Option<String>,
    #[prost(string, optional, tag = "2")]
    #[serde(alias = "device_id")]
    pub device_id: Option<String>,
    #[prost(string, optional, tag = "3")]
    #[serde(alias = "device_name")]
    pub device_name: Option<String>,
    #[prost(string, tag = "4")]
    #[serde(alias = "agent_name")]
    pub agent_name: String,
    #[prost(enumeration = "crate::common::ActionClass", tag = "5")]
    #[serde(with = "action_class_serde", alias = "action_class")]
    pub action_class: i32,
    #[prost(enumeration = "crate::common::ControlPoint", optional, tag = "6")]
    #[serde(with = "control_point_serde::opt", alias = "control_point")]
    pub control_point: Option<i32>,
    #[prost(string, tag = "7")]
    pub target: String,
    #[prost(string, optional, tag = "8")]
    pub summary: Option<String>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvaluateResponse {
    #[prost(message, optional, tag = "1")]
    pub receipt: Option<DecisionReceipt>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvaluateBrowserRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "app_id")]
    pub app_id: String,
    #[prost(string, tag = "2")]
    pub domain: String,
    #[prost(enumeration = "crate::common::BrowserDlpClass", tag = "3")]
    #[serde(with = "browser_dlp_class_serde", alias = "dlp_class")]
    pub dlp_class: i32,
    #[prost(string, optional, tag = "4")]
    #[serde(alias = "file_extension")]
    pub file_extension: Option<String>,
    #[prost(bool, tag = "5")]
    #[serde(alias = "has_secret_match")]
    pub has_secret_match: bool,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct EvaluateBrowserResponse {
    #[prost(string, tag = "1")]
    #[serde(alias = "app_id")]
    pub app_id: String,
    #[prost(string, tag = "2")]
    #[serde(alias = "app_name")]
    pub app_name: String,
    #[prost(enumeration = "crate::common::Verdict", tag = "3")]
    #[serde(with = "verdict_serde")]
    pub verdict: i32,
    #[prost(string, optional, tag = "4")]
    #[serde(alias = "rule_id")]
    pub rule_id: Option<String>,
    #[prost(string, tag = "5")]
    pub reason: String,
    #[prost(enumeration = "crate::common::BrowserDlpClass", tag = "6")]
    #[serde(with = "browser_dlp_class_serde", alias = "dlp_class")]
    pub dlp_class: i32,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IngestBatchRequest {
    #[prost(string, tag = "1")]
    #[serde(alias = "device_id")]
    pub device_id: String,
    #[prost(message, repeated, tag = "2")]
    pub attempts: Vec<ActionAttempt>,
    #[prost(message, repeated, tag = "3")]
    pub receipts: Vec<DecisionReceipt>,
}

#[derive(Clone, PartialEq, Eq, prost::Message, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", default)]
pub struct IngestBatchResponse {
    #[prost(uint64, tag = "1")]
    pub accepted: u64,
    #[prost(uint64, tag = "2")]
    #[serde(alias = "findings_created")]
    pub findings_created: u64,
}
