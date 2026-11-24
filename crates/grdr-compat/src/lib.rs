// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

use std::fmt;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CompatError {
    #[error("GRDR-COMPAT-0001: invalid semantic version `{0}`")]
    InvalidSemVer(String),
    #[error("GRDR-COMPAT-0002: invalid version range for {component}")]
    InvalidRange { component: String },
    #[error("GRDR-COMPAT-0003: unsupported component or protocol version: {0}")]
    UnsupportedVersion(String),
}

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
        let trimmed = raw.trim().strip_prefix('v').unwrap_or(raw.trim());
        let core = trimmed.split(['-', '+']).next().unwrap_or(trimmed);
        let mut parts = core.split('.');
        let major = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or_else(|| CompatError::InvalidSemVer(raw.to_owned()))?;
        let minor = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or_else(|| CompatError::InvalidSemVer(raw.to_owned()))?;
        let patch = parts
            .next()
            .and_then(|p| p.parse::<u32>().ok())
            .ok_or_else(|| CompatError::InvalidSemVer(raw.to_owned()))?;
        if parts.next().is_some() {
            return Err(CompatError::InvalidSemVer(raw.to_owned()));
        }
        Ok(Self::new(major, minor, patch))
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
    #[must_use]
    pub fn default_v1() -> Self {
        Self {
            protocol_version: SemVer::new(1, 0, 0),
            entries: vec![
                CompatEntry {
                    component: "grdr-daemon".into(),
                    range: VersionRange {
                        min_inclusive: SemVer::new(0, 1, 0),
                        max_exclusive: Some(SemVer::new(2, 0, 0)),
                    },
                    required_capabilities: vec![
                        ProtocolCapability::SignedReceipts,
                        ProtocolCapability::SessionLabels,
                        ProtocolCapability::FastpathFloor,
                    ],
                },
                CompatEntry {
                    component: "grdr-mcp".into(),
                    range: VersionRange {
                        min_inclusive: SemVer::new(0, 1, 0),
                        max_exclusive: Some(SemVer::new(2, 0, 0)),
                    },
                    required_capabilities: vec![
                        ProtocolCapability::McpToolPinning,
                        ProtocolCapability::StepUpApproval,
                    ],
                },
                CompatEntry {
                    component: "grdr-desktop".into(),
                    range: VersionRange {
                        min_inclusive: SemVer::new(0, 1, 0),
                        max_exclusive: Some(SemVer::new(2, 0, 0)),
                    },
                    required_capabilities: vec![ProtocolCapability::StepUpApproval],
                },
            ],
        }
    }
}

#[must_use]
pub fn negotiate_compatibility(
    matrix: &CompatMatrix,
    req: &NegotiationRequest,
) -> NegotiationOutcome {
    let Some(entry) = matrix.entries.iter().find(|e| e.component == req.component) else {
        return NegotiationOutcome::Incompatible {
            code: "GRDR-COMPAT-0003".into(),
            reason: format!(
                "component {} is not registered in compatibility matrix",
                req.component
            ),
        };
    };

    if !entry.range.contains(req.client_version) {
        return NegotiationOutcome::Incompatible {
            code: "GRDR-COMPAT-0003".into(),
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn semver_parse_and_range_matching_work() {
        let v = SemVer::parse("v1.4.2-rc1").expect("valid semver");
        assert_eq!(v, SemVer::new(1, 4, 2));
        assert!(SemVer::parse("1.2").is_err());

        let range = VersionRange {
            min_inclusive: SemVer::new(0, 1, 0),
            max_exclusive: Some(SemVer::new(2, 0, 0)),
        };
        assert!(range.contains(v));
        assert!(!range.contains(SemVer::new(2, 0, 0)));
    }

    #[test]
    fn negotiation_handles_compatible_warnings_and_incompatible() {
        let matrix = CompatMatrix::default_v1();

        let ok = negotiate_compatibility(
            &matrix,
            &NegotiationRequest {
                component: "grdr-mcp".into(),
                client_version: SemVer::new(0, 1, 0),
                advertised_capabilities: vec![
                    ProtocolCapability::McpToolPinning,
                    ProtocolCapability::StepUpApproval,
                    ProtocolCapability::SignedReceipts,
                ],
            },
        );
        assert!(matches!(ok, NegotiationOutcome::Compatible { .. }));

        let warn = negotiate_compatibility(
            &matrix,
            &NegotiationRequest {
                component: "grdr-mcp".into(),
                client_version: SemVer::new(0, 1, 0),
                advertised_capabilities: vec![ProtocolCapability::McpToolPinning],
            },
        );
        assert!(matches!(
            warn,
            NegotiationOutcome::CompatibleWithWarnings { .. }
        ));

        let bad = negotiate_compatibility(
            &matrix,
            &NegotiationRequest {
                component: "grdr-mcp".into(),
                client_version: SemVer::new(3, 0, 0),
                advertised_capabilities: vec![ProtocolCapability::McpToolPinning],
            },
        );
        assert!(matches!(bad, NegotiationOutcome::Incompatible { .. }));
    }
}
