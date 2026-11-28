// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Support contract data model and builder backed by `contracts/support.toml` (`P14`, `D-71`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use super::codes::CompatError;
use super::support_parse::{SupportBuilder, parse_raw_support_toml};
use super::{CompatEntry, CompatMatrix, ProtocolCapability, SemVer, VersionRange};

pub const EMBEDDED_SUPPORT_TOML: &str = include_str!("../../../contracts/support.toml");
const EXPECTED_SUPPORT_SCHEMA: &str = "grdr.support.v1alpha1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReleasePolicy {
    pub cadence: String,
    pub supported_minors_behind: u32,
    pub lts_security_months: u32,
    pub first_lts_min_days_after_ga: u32,
    pub lts_interval_minors: u32,
    pub max_upgrade_minor_hop: u32,
    pub rollback_window_minors: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContractCompatSpec {
    pub name: String,
    pub version: String,
    pub frozen: bool,
    pub min_wire_major: u32,
    pub max_wire_major: u32,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CompatibilityMatrixContract {
    pub protocol_version: SemVer,
    pub wire_major: u32,
    pub schema_rev: u32,
    pub sensor_skew_behind: u32,
    pub sensor_skew_ahead: u32,
    pub pack_format_range: VersionRange,
    pub driver_interface_range: VersionRange,
    pub contracts: Vec<ContractCompatSpec>,
    pub components: Vec<CompatEntry>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PlatformBaseline {
    pub postgresql_major: u32,
    pub kubernetes_supported: Vec<String>,
    pub helm_min_v3: SemVer,
    pub helm_min_v4: SemVer,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SupportContract {
    pub schema: String,
    pub manifest_schema: String,
    pub release_policy: ReleasePolicy,
    pub platform: PlatformBaseline,
    pub compatibility_matrix: CompatibilityMatrixContract,
}

impl SupportContract {
    #[must_use]
    pub fn to_compat_matrix(&self) -> CompatMatrix {
        CompatMatrix {
            protocol_version: self.compatibility_matrix.protocol_version,
            entries: self.compatibility_matrix.components.clone(),
            contract_error: None,
        }
    }
}

pub fn load_embedded_support_contract() -> Result<SupportContract, CompatError> {
    parse_support_toml(EMBEDDED_SUPPORT_TOML)
}

pub fn parse_support_toml(raw: &str) -> Result<SupportContract, CompatError> {
    finalize_builder(parse_raw_support_toml(raw)?)
}

fn finalize_builder(b: SupportBuilder) -> Result<SupportContract, CompatError> {
    let schema = req_field(b.schema, "schema")?;
    if schema != EXPECTED_SUPPORT_SCHEMA {
        return Err(CompatError::InvalidSupportContract(format!(
            "unsupported schema `{schema}` (expected `{EXPECTED_SUPPORT_SCHEMA}`)"
        )));
    }
    let manifest_schema = req_field(b.manifest_schema, "manifest_schema")?;
    let release_policy = ReleasePolicy {
        cadence: req_field(b.cadence, "release_policy.cadence")?,
        supported_minors_behind: req_field(
            b.supported_minors_behind,
            "release_policy.supported_minors_behind",
        )?,
        lts_security_months: req_field(
            b.lts_security_months,
            "release_policy.lts_security_months",
        )?,
        first_lts_min_days_after_ga: req_field(
            b.first_lts_min_days_after_ga,
            "release_policy.first_lts_min_days_after_ga",
        )?,
        lts_interval_minors: req_field(
            b.lts_interval_minors,
            "release_policy.lts_interval_minors",
        )?,
        max_upgrade_minor_hop: req_field(
            b.max_upgrade_minor_hop,
            "release_policy.max_upgrade_minor_hop",
        )?,
        rollback_window_minors: req_field(
            b.rollback_window_minors,
            "release_policy.rollback_window_minors",
        )?,
    };
    if release_policy.max_upgrade_minor_hop == 0 || release_policy.lts_interval_minors == 0 {
        return Err(CompatError::InvalidSupportContract(
            "upgrade minor hop and LTS interval must be non-zero".into(),
        ));
    }

    let k8s_supported = req_field(
        b.kubernetes_supported,
        "platform.kubernetes.supported_versions",
    )?;
    if k8s_supported.is_empty() {
        return Err(CompatError::InvalidSupportContract(
            "platform.kubernetes.supported_versions cannot be empty".into(),
        ));
    }
    let platform = PlatformBaseline {
        postgresql_major: req_field(b.postgresql_major, "platform.databases.postgresql_major")?,
        kubernetes_supported: k8s_supported,
        helm_min_v3: SemVer::parse(&req_field(
            b.helm_min_v3,
            "platform.kubernetes.helm_min_v3",
        )?)?,
        helm_min_v4: SemVer::parse(&req_field(
            b.helm_min_v4,
            "platform.kubernetes.helm_min_v4",
        )?)?,
    };

    let protocol_version = SemVer::parse(&req_field(
        b.protocol_version,
        "compatibility_matrix.protocol_version",
    )?)?;
    let wire_major = req_field(b.wire_major, "compatibility_matrix.wire_major")?;
    let schema_rev = req_field(b.schema_rev, "compatibility_matrix.schema_rev")?;
    let sensor_skew_behind = req_field(
        b.sensor_skew_behind,
        "compatibility_matrix.sensor_skew_behind",
    )?;
    let sensor_skew_ahead = req_field(
        b.sensor_skew_ahead,
        "compatibility_matrix.sensor_skew_ahead",
    )?;

    let pack_min = SemVer::parse(&req_field(
        b.pack_format_min,
        "compatibility_matrix.pack_format_min",
    )?)?;
    let pack_max = SemVer::parse(&req_field(
        b.pack_format_max_exclusive,
        "compatibility_matrix.pack_format_max_exclusive",
    )?)?;
    if pack_max <= pack_min {
        return Err(CompatError::InvalidRange {
            component: "pack_format".into(),
        });
    }
    let drv_min = SemVer::parse(&req_field(
        b.driver_interface_min,
        "compatibility_matrix.driver_interface_min",
    )?)?;
    let drv_max = SemVer::parse(&req_field(
        b.driver_interface_max_exclusive,
        "compatibility_matrix.driver_interface_max_exclusive",
    )?)?;
    if drv_max <= drv_min {
        return Err(CompatError::InvalidRange {
            component: "driver_interface".into(),
        });
    }

    let mut seen_contracts = BTreeSet::new();
    let mut contracts = Vec::with_capacity(b.contracts.len());
    for raw_c in b.contracts {
        let name = req_field(raw_c.name, "contract.name")?;
        if !seen_contracts.insert(name.clone()) {
            return Err(CompatError::InvalidSupportContract(format!(
                "duplicate contract `{name}` in compatibility_matrix.contracts"
            )));
        }
        let min_wire_major = req_field(raw_c.min_wire_major, "contract.min_wire_major")?;
        let max_wire_major = req_field(raw_c.max_wire_major, "contract.max_wire_major")?;
        if max_wire_major < min_wire_major {
            return Err(CompatError::InvalidRange { component: name });
        }
        contracts.push(ContractCompatSpec {
            name,
            version: req_field(raw_c.version, "contract.version")?,
            frozen: raw_c.frozen.unwrap_or(false),
            min_wire_major,
            max_wire_major,
        });
    }
    if contracts.is_empty() {
        return Err(CompatError::InvalidSupportContract(
            "compatibility_matrix.contracts cannot be empty".into(),
        ));
    }

    let mut seen_components = BTreeSet::new();
    let mut components = Vec::with_capacity(b.components.len());
    for raw_comp in b.components {
        let name = req_field(raw_comp.component, "component.component")?;
        if !seen_components.insert(name.clone()) {
            return Err(CompatError::InvalidSupportContract(format!(
                "duplicate component `{name}` in compatibility_matrix.components"
            )));
        }
        let min_v = SemVer::parse(&req_field(
            raw_comp.min_inclusive,
            "component.min_inclusive",
        )?)?;
        let max_v = raw_comp
            .max_exclusive
            .as_deref()
            .map(SemVer::parse)
            .transpose()?;
        if let Some(max) = max_v
            && max <= min_v
        {
            return Err(CompatError::InvalidRange { component: name });
        }
        let raw_caps = raw_comp.required_capabilities.unwrap_or_default();
        let caps = raw_caps
            .iter()
            .map(|c| parse_capability(c))
            .collect::<Result<Vec<_>, _>>()?;
        components.push(CompatEntry {
            component: name,
            range: VersionRange {
                min_inclusive: min_v,
                max_exclusive: max_v,
            },
            required_capabilities: caps,
        });
    }
    if components.is_empty() {
        return Err(CompatError::InvalidSupportContract(
            "compatibility_matrix.components cannot be empty".into(),
        ));
    }

    Ok(SupportContract {
        schema,
        manifest_schema,
        release_policy,
        platform,
        compatibility_matrix: CompatibilityMatrixContract {
            protocol_version,
            wire_major,
            schema_rev,
            sensor_skew_behind,
            sensor_skew_ahead,
            pack_format_range: VersionRange {
                min_inclusive: pack_min,
                max_exclusive: Some(pack_max),
            },
            driver_interface_range: VersionRange {
                min_inclusive: drv_min,
                max_exclusive: Some(drv_max),
            },
            contracts,
            components,
        },
    })
}

fn parse_capability(raw: &str) -> Result<ProtocolCapability, CompatError> {
    match raw {
        "mcp_tool_pinning" => Ok(ProtocolCapability::McpToolPinning),
        "signed_receipts" => Ok(ProtocolCapability::SignedReceipts),
        "session_labels" => Ok(ProtocolCapability::SessionLabels),
        "fastpath_floor" => Ok(ProtocolCapability::FastpathFloor),
        "ocsf19_export" => Ok(ProtocolCapability::Ocsf19Export),
        "step_up_approval" => Ok(ProtocolCapability::StepUpApproval),
        other => Err(CompatError::InvalidSupportContract(format!(
            "unknown protocol capability `{other}`"
        ))),
    }
}

fn req_field<T>(opt: Option<T>, name: &str) -> Result<T, CompatError> {
    opt.ok_or_else(|| {
        CompatError::InvalidSupportContract(format!("missing required field `{name}`"))
    })
}
