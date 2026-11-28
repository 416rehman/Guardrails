// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Protocol, support contract, upgrade-path, and manifest compatibility evaluator (`D-71`, `E1.7`).

pub mod codes;
pub mod manifest_compat;
pub mod support;
mod support_parse;
pub mod upgrade_path;

use std::fmt;

use serde::{Deserialize, Serialize};

pub use codes::{
    CODE_COMPAT_FORBIDDEN_JUMP, CODE_COMPAT_INVALID_CONTRACT, CODE_COMPAT_INVALID_RANGE,
    CODE_COMPAT_INVALID_SEMVER, CODE_COMPAT_UNSUPPORTED_VERSION, CompatError,
};
pub use manifest_compat::{
    ComponentDigestDelta, ManifestCompatGraph, ManifestComponentState, ManifestContractRange,
    diff_component_digests, evaluate_manifest_compat,
};
pub use support::{
    CompatibilityMatrixContract, ContractCompatSpec, EMBEDDED_SUPPORT_TOML, PlatformBaseline,
    ReleasePolicy, SupportContract, load_embedded_support_contract, parse_support_toml,
};
pub use upgrade_path::{
    ForbiddenJumpEntry, UPGRADE_PATH_SCHEMA, UpgradePathDocument, UpgradePathEntry, UpgradePlan,
    generate_upgrade_path_doc, validate_direct_transition, validate_hop_sequence,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct SemVer {
    pub major: u32,
    pub minor: u32,
    pub patch: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProtocolCapability {
    McpToolPinning,
    SignedReceipts,
    SessionLabels,
    FastpathFloor,
    Ocsf19Export,
    StepUpApproval,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub struct VersionRange {
    pub min_inclusive: SemVer,
    pub max_exclusive: Option<SemVer>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatEntry {
    pub component: String,
    pub range: VersionRange,
    pub required_capabilities: Vec<ProtocolCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatMatrix {
    pub protocol_version: SemVer,
    pub entries: Vec<CompatEntry>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub contract_error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct NegotiationRequest {
    pub component: String,
    pub client_version: SemVer,
    pub advertised_capabilities: Vec<ProtocolCapability>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum NegotiationOutcome {
    Compatible {
        agreed_capabilities: Vec<ProtocolCapability>,
    },
    CompatibleWithWarnings {
        agreed_capabilities: Vec<ProtocolCapability>,
        warnings: Vec<String>,
    },
    Incompatible {
        code: String,
        reason: String,
    },
}

impl fmt::Display for SemVer {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)
    }
}

impl SemVer {
    #[must_use]
    pub const fn new(major: u32, minor: u32, patch: u32) -> Self {
        Self {
            major,
            minor,
            patch,
        }
    }

    pub fn parse(raw: &str) -> Result<Self, CompatError> {
        let trimmed = raw.trim();
        let trimmed = trimmed.strip_prefix('v').unwrap_or(trimmed);
        if trimmed.is_empty() || trimmed.starts_with('+') || trimmed.starts_with('-') {
            return Err(CompatError::InvalidSemVer(raw.to_owned()));
        }
        let (core, suffix) = match trimmed.find(['-', '+']) {
            Some(idx) => (
                trimmed.get(..idx).unwrap_or(""),
                Some(trimmed.get(idx.saturating_add(1)..).unwrap_or("")),
            ),
            None => (trimmed, None),
        };
        if let Some(rest) = suffix
            && rest.is_empty()
        {
            return Err(CompatError::InvalidSemVer(raw.to_owned()));
        }
        let mut parts = core.split('.');
        let major = Self::parse_part(parts.next(), raw)?;
        let minor = Self::parse_part(parts.next(), raw)?;
        let patch = Self::parse_part(parts.next(), raw)?;
        if parts.next().is_some() {
            return Err(CompatError::InvalidSemVer(raw.to_owned()));
        }
        Ok(Self::new(major, minor, patch))
    }

    fn parse_part(part: Option<&str>, raw: &str) -> Result<u32, CompatError> {
        let p = part.ok_or_else(|| CompatError::InvalidSemVer(raw.to_owned()))?;
        if p.is_empty()
            || !p.bytes().all(|b| b.is_ascii_digit())
            || (p.len() > 1 && p.starts_with('0'))
        {
            return Err(CompatError::InvalidSemVer(raw.to_owned()));
        }
        p.parse::<u32>()
            .map_err(|_| CompatError::InvalidSemVer(raw.to_owned()))
    }
}

impl VersionRange {
    #[must_use]
    pub fn contains(&self, version: SemVer) -> bool {
        if version < self.min_inclusive {
            return false;
        }
        if let Some(max_ex) = self.max_exclusive
            && version >= max_ex
        {
            return false;
        }
        true
    }
}

impl CompatMatrix {
    pub fn from_embedded_support() -> Result<Self, CompatError> {
        Ok(load_embedded_support_contract()?.to_compat_matrix())
    }

    pub fn from_support_toml(raw: &str) -> Result<Self, CompatError> {
        Ok(parse_support_toml(raw)?.to_compat_matrix())
    }

    /// Transitional wrapper for unowned callers; fails closed in `negotiate_compatibility` if embedded support contract fails to load (#133).
    #[must_use]
    pub fn default_v1() -> Self {
        match Self::from_embedded_support() {
            Ok(matrix) => matrix,
            Err(err) => Self {
                protocol_version: SemVer::new(1, 0, 0),
                entries: Vec::new(),
                contract_error: Some(err.to_string()),
            },
        }
    }
}

#[must_use]
pub fn negotiate_compatibility(
    matrix: &CompatMatrix,
    req: &NegotiationRequest,
) -> NegotiationOutcome {
    if let Some(err) = &matrix.contract_error {
        return NegotiationOutcome::Incompatible {
            code: CODE_COMPAT_INVALID_CONTRACT.into(),
            reason: err.clone(),
        };
    }
    let Some(entry) = matrix.entries.iter().find(|e| e.component == req.component) else {
        return NegotiationOutcome::Incompatible {
            code: CODE_COMPAT_UNSUPPORTED_VERSION.into(),
            reason: format!(
                "component {} is not registered in compatibility matrix",
                req.component
            ),
        };
    };

    if !entry.range.contains(req.client_version) {
        return NegotiationOutcome::Incompatible {
            code: CODE_COMPAT_UNSUPPORTED_VERSION.into(),
            reason: format!(
                "{} {} is outside supported range [{}, {:?})",
                req.component,
                req.client_version,
                entry.range.min_inclusive,
                entry.range.max_exclusive
            ),
        };
    }

    let mut agreed = Vec::new();
    let mut warnings = Vec::new();

    for cap in &entry.required_capabilities {
        if req.advertised_capabilities.contains(cap) {
            agreed.push(*cap);
        } else {
            warnings.push(format!(
                "optional degraded capability {:?} not advertised by {}",
                cap, req.component
            ));
        }
    }

    for cap in &req.advertised_capabilities {
        if !agreed.contains(cap) {
            agreed.push(*cap);
        }
    }

    if warnings.is_empty() {
        NegotiationOutcome::Compatible {
            agreed_capabilities: agreed,
        }
    } else {
        NegotiationOutcome::CompatibleWithWarnings {
            agreed_capabilities: agreed,
            warnings,
        }
    }
}
