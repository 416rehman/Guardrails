// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

use jiff::Timestamp;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactKind {
    Skill,
    Rule,
    Plugin,
    Command,
    Subagent,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactScope {
    User,
    Workspace,
    Managed,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ArtifactRiskFlag {
    HasScripts,
    RequestsBroadTools,
    BidiObfuscation,
    UnpinnedDigest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactEntry {
    pub id: String,
    pub name: String,
    pub kind: ArtifactKind,
    pub scope: ArtifactScope,
    pub source_agent: String,
    pub path: String,
    pub content_digest: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub usage_count: u32,
    pub pinned: bool,
    #[serde(default)]
    pub risk_flags: Vec<ArtifactRiskFlag>,
    pub device_id: String,
    pub device_name: String,
    #[serde(default)]
    pub user_id: Option<String>,
    pub detected_at: Timestamp,
}
