// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]

//! Quote- and escape-aware TOML parser deriving runtime `CompatMatrix` entries
//! from `contracts/support.toml` and `compat-components.toml`.

use std::collections::BTreeMap;

use grdr_compat::{CompatEntry, CompatMatrix, SemVer, VersionRange};

use crate::compat_config::{compat_cfg_err, parse_capability_name, validate_compat_matrix};
use crate::error::UpdaterError;

const SUPPORT_TOML: &str = include_str!("../../../contracts/support.toml");
const COMPAT_COMPONENTS_TOML: &str = include_str!("../compat-components.toml");

#[derive(Debug, Default)]
struct ContractWireBounds {
    name: String,
    min_wire_major: Option<u32>,
    max_wire_major: Option<u32>,
}

#[derive(Debug, Default)]
struct ComponentDefaultSpec {
    name: String,
    contracts: Vec<String>,
    min_patch_floor: String,
    required_capabilities: Vec<String>,
}

#[derive(Clone, Copy, Debug)]
struct WireSpan {
    min: u32,
    max: u32,
}

struct SupportMatrixPolicy {
    proto_major: u32,
    contracts: BTreeMap<String, WireSpan>,
}

/// Build runtime `CompatMatrix` from `contracts/support.toml` + `compat-components.toml`.
pub fn load_support_toml_compat_matrix() -> Result<CompatMatrix, UpdaterError> {
    parse_support_toml_compat_matrix(SUPPORT_TOML, COMPAT_COMPONENTS_TOML)
}

fn parse_support_toml_compat_matrix(
    support_toml: &str,
    components_toml: &str,
) -> Result<CompatMatrix, UpdaterError> {
    let support = parse_support_contracts(support_toml)?;
    let component_specs = parse_component_specs(components_toml)?;
    let mut entries = Vec::with_capacity(component_specs.len());

    for spec in component_specs {
        if spec.contracts.is_empty() {
            return Err(compat_cfg_err(
                &spec.name,
                "component entry missing contracts reference",
            ));
        }
        let mut min_wire = 1u32;
        let mut max_wire = u32::MAX;
        for c_name in &spec.contracts {
            let span = support.contracts.get(c_name).copied().ok_or_else(|| {
                compat_cfg_err(
                    &spec.name,
                    &format!("contract `{c_name}` not defined in contracts/support.toml"),
                )
            })?;
            min_wire = min_wire.max(span.min);
            max_wire = max_wire.min(span.max);
        }
        if min_wire > max_wire {
            return Err(compat_cfg_err(
                &spec.name,
                "disjoint wire major contract bounds in contracts/support.toml",
            ));
        }
        let floor_ver = SemVer::parse(&spec.min_patch_floor)
            .map_err(|e| compat_cfg_err(&spec.name, &format!("invalid min_patch_floor: {e}")))?;
        let min_inclusive = if min_wire <= 1 {
            floor_ver
        } else {
            SemVer::new(min_wire, 0, 0)
        };
        let mut required_capabilities = Vec::with_capacity(spec.required_capabilities.len());
        for cap_name in &spec.required_capabilities {
            let cap = parse_capability_name(cap_name).ok_or_else(|| {
                compat_cfg_err(&spec.name, &format!("unknown capability `{cap_name}`"))
            })?;
            required_capabilities.push(cap);
        }
        entries.push(CompatEntry {
            component: spec.name,
            range: VersionRange {
                min_inclusive,
                max_exclusive: Some(SemVer::new(max_wire.saturating_add(1), 0, 0)),
            },
            required_capabilities,
        });
    }

    let matrix = CompatMatrix {
        protocol_version: SemVer::new(support.proto_major, 0, 0),
        entries,
        contract_error: None,
    };
    validate_compat_matrix(&matrix)?;
    Ok(matrix)
}

fn parse_support_contracts(toml_text: &str) -> Result<SupportMatrixPolicy, UpdaterError> {
    let mut section = String::new();
    let mut wire_major: Option<u32> = None;
    let mut contracts: Vec<ContractWireBounds> = Vec::new();
    let mut current: Option<ContractWireBounds> = None;

    for raw_line in toml_text.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if let Some(prev) = current.take() {
                contracts.push(prev);
            }
            section = parse_toml_header(line)?;
            if section == "compatibility_matrix.contracts" {
                current = Some(ContractWireBounds::default());
            }
            continue;
        }
        let Some((raw_k, raw_v)) = line.split_once('=') else {
            continue;
        };
        let key = raw_k.trim();
        let val = raw_v.trim();
        if section == "compatibility_matrix" && key == "wire_major" {
            wire_major = Some(parse_toml_u32(val, key)?);
        } else if section == "compatibility_matrix.contracts"
            && let Some(entry) = current.as_mut()
        {
            match key {
                "name" => entry.name = parse_toml_string(val, key)?,
                "min_wire_major" => entry.min_wire_major = Some(parse_toml_u32(val, key)?),
                "max_wire_major" => entry.max_wire_major = Some(parse_toml_u32(val, key)?),
                _ => {}
            }
        }
    }
    if let Some(last) = current.take() {
        contracts.push(last);
    }

    let proto_major = wire_major
        .filter(|&w| w >= 1)
        .ok_or_else(|| compat_cfg_err("compat-matrix", "support.toml missing valid wire_major"))?;
    if contracts.is_empty() {
        return Err(compat_cfg_err(
            "compat-matrix",
            "support.toml missing compatibility_matrix.contracts",
        ));
    }
    let mut map = BTreeMap::new();
    for c in contracts {
        let c_min = c
            .min_wire_major
            .filter(|&v| v >= 1)
            .ok_or_else(|| compat_cfg_err(&c.name, "missing valid min_wire_major"))?;
        let c_max = c
            .max_wire_major
            .filter(|&v| v >= c_min)
            .ok_or_else(|| compat_cfg_err(&c.name, "invalid max_wire_major < min_wire_major"))?;
        map.insert(
            c.name,
            WireSpan {
                min: c_min,
                max: c_max,
            },
        );
    }
    Ok(SupportMatrixPolicy {
        proto_major,
        contracts: map,
    })
}

fn parse_component_specs(toml_text: &str) -> Result<Vec<ComponentDefaultSpec>, UpdaterError> {
    let mut section = String::new();
    let mut specs = Vec::new();
    let mut current: Option<ComponentDefaultSpec> = None;

    for raw_line in toml_text.lines() {
        let line = strip_toml_comment(raw_line).trim();
        if line.is_empty() {
            continue;
        }
        if line.starts_with('[') {
            if let Some(prev) = current.take() {
                specs.push(prev);
            }
            section = parse_toml_header(line)?;
            if section == "components" {
                current = Some(ComponentDefaultSpec::default());
            }
            continue;
        }
        let Some((raw_k, raw_v)) = line.split_once('=') else {
            return Err(compat_cfg_err("compat-components", "expected key = value"));
        };
        let key = raw_k.trim();
        let val = raw_v.trim();
        if section == "components"
            && let Some(spec) = current.as_mut()
        {
            match key {
                "name" => spec.name = parse_toml_string(val, key)?,
                "contracts" => spec.contracts = parse_toml_string_array(val, key)?,
                "min_patch_floor" => spec.min_patch_floor = parse_toml_string(val, key)?,
                "required_capabilities" => {
                    spec.required_capabilities = parse_toml_string_array(val, key)?;
                }
                other => return Err(compat_cfg_err("compat-components", other)),
            }
        }
    }
    if let Some(last) = current.take() {
        specs.push(last);
    }
    if specs.is_empty() {
        return Err(compat_cfg_err(
            "compat-components",
            "missing [[components]] entries",
        ));
    }
    Ok(specs)
}

fn strip_toml_comment(line: &str) -> &str {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in line.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '#' if !in_double && !in_single => return line.get(..idx).unwrap_or(line),
            _ => {}
        }
    }
    line
}

fn parse_toml_header(line: &str) -> Result<String, UpdaterError> {
    let inner = if let Some(arr) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
        arr.trim()
    } else if let Some(tbl) = line.strip_prefix('[').and_then(|s| s.strip_suffix(']')) {
        tbl.trim()
    } else {
        return Err(compat_cfg_err("toml", "malformed section header"));
    };
    if inner.is_empty() || inner.contains('[') || inner.contains(']') {
        return Err(compat_cfg_err("toml", "invalid section header"));
    }
    Ok(inner.to_owned())
}

fn parse_toml_u32(val: &str, key: &str) -> Result<u32, UpdaterError> {
    val.replace('_', "")
        .parse::<u32>()
        .map_err(|_| compat_cfg_err(key, "expected positive TOML integer"))
}

fn parse_toml_string(val: &str, key: &str) -> Result<String, UpdaterError> {
    if let Some(inner) = val.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        return Ok(inner.replace("\\\"", "\"").replace("\\\\", "\\"));
    }
    if let Some(inner) = val.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')) {
        return Ok(inner.to_owned());
    }
    Err(compat_cfg_err(key, "expected quoted TOML string"))
}

fn parse_toml_string_array(val: &str, key: &str) -> Result<Vec<String>, UpdaterError> {
    let inner = val
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
        .ok_or_else(|| compat_cfg_err(key, "expected TOML array"))?;
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    for item in inner.split(',') {
        let trimmed = item.trim();
        if !trimmed.is_empty() {
            out.push(parse_toml_string(trimmed, key)?);
        }
    }
    Ok(out)
}
