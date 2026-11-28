// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strict zero-dependency TOML parser for `contracts/support.toml` (`P14`, `D-71`).

use std::collections::BTreeSet;

use super::codes::CompatError;

#[derive(Clone, Copy)]
pub(crate) enum Section {
    Root,
    ReleasePolicy,
    OsLinux,
    OsWindows,
    OsMacos,
    PlatformK8s,
    PlatformDb,
    PlatformBus,
    PlatformObjectStores,
    Agents,
    DeviceKeys,
    CompatMatrix,
    ContractItem(usize),
    ComponentItem(usize),
}

#[derive(Clone, Copy)]
enum AuxKind {
    Str,
    U32,
    StrArray,
}

#[derive(Default)]
pub(crate) struct RawComponent {
    pub(crate) component: Option<String>,
    pub(crate) min_inclusive: Option<String>,
    pub(crate) max_exclusive: Option<String>,
    pub(crate) required_capabilities: Option<Vec<String>>,
}

#[derive(Default)]
pub(crate) struct RawContract {
    pub(crate) name: Option<String>,
    pub(crate) version: Option<String>,
    pub(crate) frozen: Option<bool>,
    pub(crate) min_wire_major: Option<u32>,
    pub(crate) max_wire_major: Option<u32>,
}

#[derive(Default)]
pub(crate) struct SupportBuilder {
    pub(crate) schema: Option<String>,
    pub(crate) manifest_schema: Option<String>,
    pub(crate) cadence: Option<String>,
    pub(crate) supported_minors_behind: Option<u32>,
    pub(crate) lts_security_months: Option<u32>,
    pub(crate) first_lts_min_days_after_ga: Option<u32>,
    pub(crate) lts_interval_minors: Option<u32>,
    pub(crate) max_upgrade_minor_hop: Option<u32>,
    pub(crate) rollback_window_minors: Option<u32>,
    pub(crate) postgresql_major: Option<u32>,
    pub(crate) kubernetes_supported: Option<Vec<String>>,
    pub(crate) helm_min_v3: Option<String>,
    pub(crate) helm_min_v4: Option<String>,
    pub(crate) protocol_version: Option<String>,
    pub(crate) wire_major: Option<u32>,
    pub(crate) schema_rev: Option<u32>,
    pub(crate) sensor_skew_behind: Option<u32>,
    pub(crate) sensor_skew_ahead: Option<u32>,
    pub(crate) pack_format_min: Option<String>,
    pub(crate) pack_format_max_exclusive: Option<String>,
    pub(crate) driver_interface_min: Option<String>,
    pub(crate) driver_interface_max_exclusive: Option<String>,
    pub(crate) contracts: Vec<RawContract>,
    pub(crate) components: Vec<RawComponent>,
}

impl Section {
    fn tag(self) -> &'static str {
        match self {
            Self::Root => "",
            Self::ReleasePolicy => "release_policy",
            Self::OsLinux => "os.linux",
            Self::OsWindows => "os.windows",
            Self::OsMacos => "os.macos",
            Self::PlatformK8s => "platform.kubernetes",
            Self::PlatformDb => "platform.databases",
            Self::PlatformBus => "platform.bus",
            Self::PlatformObjectStores => "platform.object_stores",
            Self::Agents => "agents",
            Self::DeviceKeys => "device_keys",
            Self::CompatMatrix => "compatibility_matrix",
            Self::ContractItem(_) => "compatibility_matrix.contracts",
            Self::ComponentItem(_) => "compatibility_matrix.components",
        }
    }
}

fn parse_err(line_no: usize, detail: &str) -> CompatError {
    CompatError::InvalidSupportContract(format!("line {line_no}: {detail}"))
}

pub(crate) fn parse_raw_support_toml(raw: &str) -> Result<SupportBuilder, CompatError> {
    let mut b = SupportBuilder::default();
    let mut section = Section::Root;
    let mut seen_sections: BTreeSet<&'static str> = BTreeSet::new();
    let mut section_keys: BTreeSet<String> = BTreeSet::new();

    let mut lines = raw.lines().enumerate().peekable();
    while let Some((line_idx, raw_line)) = lines.next() {
        let line_no = line_idx.saturating_add(1);
        let cleaned = strip_toml_comment(raw_line).trim();
        if cleaned.is_empty() {
            continue;
        }
        if cleaned.starts_with('[') {
            section = parse_section_header(cleaned, line_no, &mut b, &mut seen_sections)?;
            section_keys.clear();
            continue;
        }
        let Some((k_raw, v_raw)) = cleaned.split_once('=') else {
            return Err(parse_err(line_no, "expected key = value"));
        };
        let key = k_raw.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(parse_err(line_no, &format!("invalid TOML key `{key}`")));
        }
        if !section_keys.insert(key.to_owned()) {
            return Err(parse_err(
                line_no,
                &format!("duplicate key `{key}` in section `{}`", section.tag()),
            ));
        }
        let mut val_buf = v_raw.trim().to_owned();
        if val_buf.starts_with('[') && !array_brackets_balanced(&val_buf) {
            for (_, next_raw) in lines.by_ref() {
                let next_clean = strip_toml_comment(next_raw).trim();
                if next_clean.is_empty() {
                    continue;
                }
                val_buf.push(' ');
                val_buf.push_str(next_clean);
                if array_brackets_balanced(&val_buf) {
                    break;
                }
            }
            if !array_brackets_balanced(&val_buf) {
                return Err(parse_err(
                    line_no,
                    &format!("unterminated array literal for `{key}`"),
                ));
            }
        }
        apply_kv(&mut b, section, key, &val_buf, line_no)?;
    }

    Ok(b)
}

fn parse_section_header(
    cleaned: &str,
    line_no: usize,
    b: &mut SupportBuilder,
    seen_sections: &mut BTreeSet<&'static str>,
) -> Result<Section, CompatError> {
    if cleaned.starts_with("[[") {
        let Some(name) = cleaned
            .strip_prefix("[[")
            .and_then(|s| s.strip_suffix("]]"))
            .map(str::trim)
        else {
            return Err(parse_err(
                line_no,
                &format!("malformed array-of-tables header `{cleaned}`"),
            ));
        };
        return match name {
            "compatibility_matrix.contracts" => {
                b.contracts.push(RawContract::default());
                Ok(Section::ContractItem(b.contracts.len().saturating_sub(1)))
            }
            "compatibility_matrix.components" => {
                b.components.push(RawComponent::default());
                Ok(Section::ComponentItem(b.components.len().saturating_sub(1)))
            }
            _ => Err(parse_err(
                line_no,
                &format!("unknown TOML table array `[[{name}]]`"),
            )),
        };
    }

    let Some(hdr) = cleaned
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
    else {
        return Err(parse_err(
            line_no,
            &format!("malformed section header `{cleaned}`"),
        ));
    };
    if hdr.is_empty() || hdr.contains('[') || hdr.contains(']') {
        return Err(parse_err(
            line_no,
            &format!("invalid section header `{cleaned}`"),
        ));
    }
    let next = match hdr {
        "release_policy" => Section::ReleasePolicy,
        "os.linux" => Section::OsLinux,
        "os.windows" => Section::OsWindows,
        "os.macos" => Section::OsMacos,
        "platform.kubernetes" => Section::PlatformK8s,
        "platform.databases" => Section::PlatformDb,
        "platform.bus" => Section::PlatformBus,
        "platform.object_stores" => Section::PlatformObjectStores,
        "agents" => Section::Agents,
        "device_keys" => Section::DeviceKeys,
        "compatibility_matrix" => Section::CompatMatrix,
        _ => return Err(parse_err(line_no, &format!("unknown section `[{hdr}]`"))),
    };
    if !seen_sections.insert(next.tag()) {
        return Err(parse_err(line_no, &format!("duplicate section `[{hdr}]`")));
    }
    Ok(next)
}

fn apply_kv(
    b: &mut SupportBuilder,
    section: Section,
    key: &str,
    val: &str,
    line_no: usize,
) -> Result<(), CompatError> {
    match section {
        Section::Root => match key {
            "schema" => b.schema = Some(parse_str(val, line_no)?),
            "manifest_schema" => b.manifest_schema = Some(parse_str(val, line_no)?),
            _ => return Err(unknown_key_err(section, key, line_no)),
        },
        Section::ReleasePolicy => match key {
            "cadence" => b.cadence = Some(parse_str(val, line_no)?),
            "supported_minors_behind" => b.supported_minors_behind = Some(parse_u32(val, line_no)?),
            "lts_security_months" => b.lts_security_months = Some(parse_u32(val, line_no)?),
            "first_lts_min_days_after_ga" => {
                b.first_lts_min_days_after_ga = Some(parse_u32(val, line_no)?)
            }
            "lts_interval_minors" => b.lts_interval_minors = Some(parse_u32(val, line_no)?),
            "max_upgrade_minor_hop" => b.max_upgrade_minor_hop = Some(parse_u32(val, line_no)?),
            "rollback_window_minors" => b.rollback_window_minors = Some(parse_u32(val, line_no)?),
            _ => return Err(unknown_key_err(section, key, line_no)),
        },
        Section::PlatformK8s => match key {
            "supported_versions" => b.kubernetes_supported = Some(parse_str_array(val, line_no)?),
            "helm_min_v3" => b.helm_min_v3 = Some(parse_str(val, line_no)?),
            "helm_min_v4" => b.helm_min_v4 = Some(parse_str(val, line_no)?),
            _ => validate_aux_key(section, key, val, line_no)?,
        },
        Section::PlatformDb => match key {
            "postgresql_major" => b.postgresql_major = Some(parse_u32(val, line_no)?),
            _ => validate_aux_key(section, key, val, line_no)?,
        },
        Section::OsLinux
        | Section::OsWindows
        | Section::OsMacos
        | Section::PlatformBus
        | Section::PlatformObjectStores
        | Section::Agents
        | Section::DeviceKeys => validate_aux_key(section, key, val, line_no)?,
        Section::CompatMatrix => match key {
            "protocol_version" => b.protocol_version = Some(parse_str(val, line_no)?),
            "wire_major" => b.wire_major = Some(parse_u32(val, line_no)?),
            "schema_rev" => b.schema_rev = Some(parse_u32(val, line_no)?),
            "sensor_skew_behind" => b.sensor_skew_behind = Some(parse_u32(val, line_no)?),
            "sensor_skew_ahead" => b.sensor_skew_ahead = Some(parse_u32(val, line_no)?),
            "pack_format_min" => b.pack_format_min = Some(parse_str(val, line_no)?),
            "pack_format_max_exclusive" => {
                b.pack_format_max_exclusive = Some(parse_str(val, line_no)?)
            }
            "driver_interface_min" => b.driver_interface_min = Some(parse_str(val, line_no)?),
            "driver_interface_max_exclusive" => {
                b.driver_interface_max_exclusive = Some(parse_str(val, line_no)?)
            }
            _ => return Err(unknown_key_err(section, key, line_no)),
        },
        Section::ContractItem(idx) => {
            let item = b
                .contracts
                .get_mut(idx)
                .ok_or_else(|| parse_err(line_no, "contract index missing"))?;
            match key {
                "name" => item.name = Some(parse_str(val, line_no)?),
                "version" => item.version = Some(parse_str(val, line_no)?),
                "frozen" => item.frozen = Some(parse_bool(val, line_no)?),
                "min_wire_major" => item.min_wire_major = Some(parse_u32(val, line_no)?),
                "max_wire_major" => item.max_wire_major = Some(parse_u32(val, line_no)?),
                _ => return Err(unknown_key_err(section, key, line_no)),
            }
        }
        Section::ComponentItem(idx) => {
            let item = b
                .components
                .get_mut(idx)
                .ok_or_else(|| parse_err(line_no, "component index missing"))?;
            match key {
                "component" => item.component = Some(parse_str(val, line_no)?),
                "min_inclusive" => item.min_inclusive = Some(parse_str(val, line_no)?),
                "max_exclusive" => item.max_exclusive = Some(parse_str(val, line_no)?),
                "required_capabilities" => {
                    item.required_capabilities = Some(parse_str_array(val, line_no)?)
                }
                _ => return Err(unknown_key_err(section, key, line_no)),
            }
        }
    }
    Ok(())
}

fn validate_aux_key(
    section: Section,
    key: &str,
    val: &str,
    line_no: usize,
) -> Result<(), CompatError> {
    let kind = match (section, key) {
        (Section::OsLinux, "tier")
        | (Section::OsWindows, "tier" | "wsl_min_major")
        | (Section::OsMacos, "tier")
        | (Section::PlatformK8s, "tier")
        | (Section::PlatformDb, "postgresql_tier")
        | (Section::Agents, "supported_minor_window") => AuxKind::U32,
        (Section::OsLinux, "architectures" | "distributions" | "container_runtime")
        | (
            Section::OsWindows,
            "architectures" | "versions" | "server_tier2" | "unsupported_skus",
        )
        | (Section::OsMacos, "architectures" | "versions")
        | (Section::PlatformK8s, "eol_versions")
        | (Section::PlatformObjectStores, "tier1" | "tier2" | "excluded")
        | (Section::Agents, "tier1") => AuxKind::StrArray,
        (Section::OsLinux, "min_kernel" | "recommended_kernel")
        | (Section::OsWindows, "optional_driver_status")
        | (Section::OsMacos, "notarisation_status" | "endpoint_security_status")
        | (Section::PlatformK8s, "server_pod_security_standard")
        | (Section::PlatformDb, "sqlite_embedded_via" | "cnpg_reference_version")
        | (Section::PlatformBus, "embedded" | "ha" | "distributed")
        | (
            Section::DeviceKeys,
            "windows_tpm"
            | "macos_secure_enclave"
            | "linux_tpm"
            | "container_ephemeral"
            | "ci_oidc",
        ) => AuxKind::Str,
        _ => return Err(unknown_key_err(section, key, line_no)),
    };
    match kind {
        AuxKind::Str => {
            let _ = parse_str(val, line_no)?;
        }
        AuxKind::U32 => {
            let _ = parse_u32(val, line_no)?;
        }
        AuxKind::StrArray => {
            let _ = parse_str_array(val, line_no)?;
        }
    }
    Ok(())
}

fn unknown_key_err(section: Section, key: &str, line_no: usize) -> CompatError {
    parse_err(
        line_no,
        &format!("unknown key `{key}` in section `{}`", section.tag()),
    )
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

fn array_brackets_balanced(val: &str) -> bool {
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    let mut depth: usize = 0;
    for ch in val.chars() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            '[' if !in_double && !in_single => depth = depth.saturating_add(1),
            ']' if !in_double && !in_single => depth = depth.saturating_sub(1),
            _ => {}
        }
    }
    !in_double && !in_single && depth == 0
}

fn parse_str(raw: &str, line_no: usize) -> Result<String, CompatError> {
    let trimmed = raw.trim();
    if let Some(inner) = trimmed.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
        let mut out = String::with_capacity(inner.len());
        let mut chars = inner.chars();
        while let Some(ch) = chars.next() {
            match ch {
                '\\' => match chars.next() {
                    Some('"') => out.push('"'),
                    Some('\\') => out.push('\\'),
                    Some('n') => out.push('\n'),
                    Some('r') => out.push('\r'),
                    Some('t') => out.push('\t'),
                    Some(other) => {
                        return Err(parse_err(
                            line_no,
                            &format!("unsupported escape `\\{other}`"),
                        ));
                    }
                    None => return Err(parse_err(line_no, "trailing backslash in string")),
                },
                '"' => return Err(parse_err(line_no, "unescaped interior quote")),
                other => out.push(other),
            }
        }
        return Ok(out);
    }
    if let Some(inner) = trimmed
        .strip_prefix('\'')
        .and_then(|s| s.strip_suffix('\''))
        && !inner.contains('\'')
    {
        return Ok(inner.to_owned());
    }
    Err(parse_err(line_no, "expected quoted string"))
}

fn parse_u32(raw: &str, line_no: usize) -> Result<u32, CompatError> {
    let t = raw.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(parse_err(line_no, "expected unsigned u32 integer"));
    }
    t.parse::<u32>()
        .map_err(|_| parse_err(line_no, "integer out of range"))
}

fn parse_bool(raw: &str, line_no: usize) -> Result<bool, CompatError> {
    match raw.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(parse_err(line_no, "expected boolean")),
    }
}

fn parse_str_array(raw: &str, line_no: usize) -> Result<Vec<String>, CompatError> {
    let trimmed = raw.trim();
    let Some(inner) = trimmed
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
    else {
        return Err(parse_err(line_no, "expected string array"));
    };
    if inner.is_empty() {
        return Ok(Vec::new());
    }
    let mut out = Vec::new();
    let mut elem_start: usize = 0;
    let mut in_double = false;
    let mut in_single = false;
    let mut escaped = false;
    for (idx, ch) in inner.char_indices() {
        if escaped {
            escaped = false;
            continue;
        }
        match ch {
            '\\' if in_double => escaped = true,
            '"' if !in_single => in_double = !in_double,
            '\'' if !in_double => in_single = !in_single,
            ',' if !in_double && !in_single => {
                let piece = inner.get(elem_start..idx).unwrap_or("").trim();
                if piece.is_empty() {
                    return Err(parse_err(line_no, "empty element in array"));
                }
                out.push(parse_str(piece, line_no)?);
                elem_start = idx.saturating_add(1);
            }
            _ => {}
        }
    }
    let tail = inner.get(elem_start..).unwrap_or("").trim();
    if !tail.is_empty() {
        out.push(parse_str(tail, line_no)?);
    }
    Ok(out)
}
