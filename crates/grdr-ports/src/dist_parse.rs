// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Strict zero-dependency TOML parser for `deploy/release/dist.toml` and `[platform.bus]`.

use std::collections::{BTreeMap, BTreeSet};

use grdr_model::CodedError;

use crate::dist::{DistManifest, cfg_err};

#[derive(Clone, Copy)]
enum Section {
    Root,
    Endpoints,
    Registries,
    Trust,
    Updates,
    UpdateSource,
    Signing,
    Links,
    Adapters,
}

#[derive(Clone, Copy)]
enum FieldKind {
    Str,
    Bool,
    U32,
    StrArray,
}

impl Section {
    fn tag(self) -> &'static str {
        match self {
            Self::Root => "",
            Self::Endpoints => "endpoints",
            Self::Registries => "registries",
            Self::Trust => "trust",
            Self::Updates => "updates",
            Self::UpdateSource => "updates.sources",
            Self::Signing => "signing",
            Self::Links => "links",
            Self::Adapters => "adapters",
        }
    }
}

pub(crate) fn parse_dist_manifest_toml(raw: &str) -> Result<DistManifest, CodedError> {
    let mut section = Section::Root;
    let mut seen_sections: BTreeSet<&'static str> = BTreeSet::new();
    let mut section_keys: BTreeSet<String> = BTreeSet::new();

    let mut schema: Option<String> = None;
    let mut brand_manifest: Option<String> = None;
    let mut channel_default: Option<String> = None;
    let mut phone_home: Option<bool> = None;
    let mut release_manifest_schema: Option<String> = None;
    let mut compatibility_matrix: Option<String> = None;
    let mut tier1_adapters: Option<Vec<String>> = None;
    let mut contrib_adapters: Option<Vec<String>> = None;

    let mut lines = raw.lines().enumerate().peekable();
    while let Some((idx, raw_line)) = lines.next() {
        let line_no = idx.saturating_add(1);
        let clean = strip_comment(raw_line).trim();
        if clean.is_empty() {
            continue;
        }
        if clean.starts_with('[') {
            section = parse_section(clean, line_no, &mut seen_sections)?;
            section_keys.clear();
            continue;
        }
        let Some((k_raw, v_raw)) = clean.split_once('=') else {
            return Err(cfg_err(format!(
                "dist.toml line {line_no}: expected `key = value` statement"
            )));
        };
        let key = k_raw.trim();
        if key.is_empty()
            || !key
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || c == '_' || c == '-')
        {
            return Err(cfg_err(format!(
                "dist.toml line {line_no}: invalid key `{key}`"
            )));
        }
        if !section_keys.insert(key.to_owned()) {
            return Err(cfg_err(format!(
                "dist.toml line {line_no}: duplicate key `{key}` in section `{}`",
                section.tag()
            )));
        }

        let mut val_buf = v_raw.trim().to_owned();
        if val_buf.starts_with('[') && !array_brackets_balanced(&val_buf) {
            for (_, next_raw) in lines.by_ref() {
                let next_clean = strip_comment(next_raw).trim();
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
                return Err(cfg_err(format!(
                    "dist.toml line {line_no}: unterminated array value for `{key}`"
                )));
            }
        }

        match (section, key) {
            (Section::Root, "schema") => schema = Some(parse_str(&val_buf, line_no)?),
            (Section::Root, "brand_manifest") => {
                brand_manifest = Some(parse_str(&val_buf, line_no)?)
            }
            (Section::Root, "channel_default") => {
                channel_default = Some(parse_str(&val_buf, line_no)?)
            }
            (Section::Root, "phone_home") => phone_home = Some(parse_bool(&val_buf, line_no)?),
            (Section::Links, "release_manifest_schema") => {
                release_manifest_schema = Some(parse_str(&val_buf, line_no)?)
            }
            (Section::Links, "compatibility_matrix") => {
                compatibility_matrix = Some(parse_str(&val_buf, line_no)?)
            }
            (Section::Adapters, "tier1") => {
                tier1_adapters = Some(parse_str_array(&val_buf, line_no)?)
            }
            (Section::Adapters, "contrib") => {
                contrib_adapters = Some(parse_str_array(&val_buf, line_no)?)
            }
            _ => validate_known_dist_field(section, key, &val_buf, line_no)?,
        }
    }

    Ok(DistManifest {
        schema: req(schema, "schema")?,
        brand_manifest: req(brand_manifest, "brand_manifest")?,
        channel_default: req(channel_default, "channel_default")?,
        phone_home: req(phone_home, "phone_home")?,
        release_manifest_schema: req(release_manifest_schema, "links.release_manifest_schema")?,
        compatibility_matrix: req(compatibility_matrix, "links.compatibility_matrix")?,
        tier1_adapters: req(tier1_adapters, "adapters.tier1")?,
        contrib_adapters: contrib_adapters.unwrap_or_default(),
    })
}

pub(crate) fn parse_support_bus_map_strict(
    raw: &str,
) -> Result<BTreeMap<String, String>, CodedError> {
    let mut map = BTreeMap::new();
    let mut in_bus = false;
    let mut seen_bus = false;

    for (idx, line) in raw.lines().enumerate() {
        let line_no = idx.saturating_add(1);
        let clean = strip_comment(line).trim();
        if clean.is_empty() {
            continue;
        }
        if clean.starts_with('[') {
            if !clean.ends_with(']') {
                return Err(cfg_err(format!(
                    "support.toml line {line_no}: malformed section header `{clean}`"
                )));
            }
            in_bus = clean == "[platform.bus]";
            if in_bus {
                if seen_bus {
                    return Err(cfg_err(
                        "support.toml contains duplicate [platform.bus] section",
                    ));
                }
                seen_bus = true;
            }
            continue;
        }
        if !in_bus {
            continue;
        }
        let Some((k, v)) = clean.split_once('=') else {
            return Err(cfg_err(format!(
                "support.toml [platform.bus] line {line_no}: expected key = value"
            )));
        };
        let key = k.trim();
        if key.is_empty() {
            return Err(cfg_err(format!(
                "support.toml [platform.bus] line {line_no}: empty key"
            )));
        }
        let parsed = parse_str(v, line_no)?;
        if parsed.trim().is_empty() {
            return Err(cfg_err(format!(
                "support.toml [platform.bus] line {line_no}: empty value for `{key}`"
            )));
        }
        if map.insert(key.to_owned(), parsed).is_some() {
            return Err(cfg_err(format!(
                "support.toml [platform.bus] line {line_no}: duplicate key `{key}`"
            )));
        }
    }
    if !seen_bus {
        return Err(cfg_err("support.toml missing [platform.bus] section"));
    }
    for req_profile in ["embedded", "ha", "distributed"] {
        if !map.contains_key(req_profile) {
            return Err(cfg_err(format!(
                "support.toml [platform.bus] missing `{req_profile}` adapter mapping"
            )));
        }
    }
    Ok(map)
}

fn parse_section(
    clean: &str,
    line_no: usize,
    seen_sections: &mut BTreeSet<&'static str>,
) -> Result<Section, CodedError> {
    if clean.starts_with("[[") {
        let Some(name) = clean
            .strip_prefix("[[")
            .and_then(|s| s.strip_suffix("]]"))
            .map(str::trim)
        else {
            return Err(cfg_err(format!(
                "dist.toml line {line_no}: malformed table array `{clean}`"
            )));
        };
        return match name {
            "updates.sources" => Ok(Section::UpdateSource),
            _ => Err(cfg_err(format!(
                "dist.toml line {line_no}: unknown table array `[[{name}]]`"
            ))),
        };
    }
    let Some(hdr) = clean
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
    else {
        return Err(cfg_err(format!(
            "dist.toml line {line_no}: malformed section `{clean}`"
        )));
    };
    let next = match hdr {
        "endpoints" => Section::Endpoints,
        "registries" => Section::Registries,
        "trust" => Section::Trust,
        "updates" => Section::Updates,
        "signing" => Section::Signing,
        "links" => Section::Links,
        "adapters" => Section::Adapters,
        _ => {
            return Err(cfg_err(format!(
                "dist.toml line {line_no}: unknown section `[{hdr}]`"
            )));
        }
    };
    if !seen_sections.insert(next.tag()) {
        return Err(cfg_err(format!(
            "dist.toml line {line_no}: duplicate section `[{hdr}]`"
        )));
    }
    Ok(next)
}

fn validate_known_dist_field(
    section: Section,
    key: &str,
    val: &str,
    line_no: usize,
) -> Result<(), CodedError> {
    let kind = match (section, key) {
        (
            Section::Endpoints,
            "release_origin"
            | "tuf_metadata_origin"
            | "mirror_cdn_origin"
            | "docs_origin"
            | "status_origin"
            | "enrol_origin"
            | "telemetry_origin",
        )
        | (
            Section::Registries,
            "container" | "helm_oci" | "crate" | "apt" | "rpm" | "winget" | "homebrew_tap",
        )
        | (Section::Trust, "mode" | "initial_root_path" | "trusted_root_path")
        | (Section::Updates, "default_authority" | "default_policy")
        | (Section::UpdateSource, "id" | "role" | "uri")
        | (
            Section::Signing,
            "sigstore_oidc_issuer" | "workflow_repository" | "dsse_payload_type",
        )
        | (Section::Links, "limits")
        | (Section::Adapters, "contrib_policy") => FieldKind::Str,
        (
            Section::Trust,
            "require_slsa_provenance" | "require_platform_signature" | "post_quantum_hybrid_ready",
        )
        | (Section::UpdateSource, "immutable_cache")
        | (Section::Links, "airgap_supported") => FieldKind::Bool,
        (Section::Updates, "mirror_lag_hours" | "timestamp_max_stale_s")
        | (Section::UpdateSource, "priority") => FieldKind::U32,
        (Section::Trust, "signature_algorithms") | (Section::Updates, "authorities") => {
            FieldKind::StrArray
        }
        _ => {
            return Err(cfg_err(format!(
                "dist.toml line {line_no}: unknown key `{key}` in section `{}`",
                section.tag()
            )));
        }
    };
    match kind {
        FieldKind::Str => {
            let _ = parse_str(val, line_no)?;
        }
        FieldKind::Bool => {
            let _ = parse_bool(val, line_no)?;
        }
        FieldKind::U32 => {
            let _ = parse_u32(val, line_no)?;
        }
        FieldKind::StrArray => {
            let _ = parse_str_array(val, line_no)?;
        }
    }
    Ok(())
}

fn req<T>(opt: Option<T>, field: &str) -> Result<T, CodedError> {
    opt.ok_or_else(|| cfg_err(format!("missing required dist.toml field `{field}`")))
}

fn strip_comment(line: &str) -> &str {
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

fn parse_str(raw: &str, line_no: usize) -> Result<String, CodedError> {
    let t = raw.trim();
    if let Some(inner) = t.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
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
                        return Err(cfg_err(format!(
                            "dist.toml line {line_no}: unsupported escape `\\{other}`"
                        )));
                    }
                    None => {
                        return Err(cfg_err(format!(
                            "dist.toml line {line_no}: trailing backslash in string"
                        )));
                    }
                },
                '"' => {
                    return Err(cfg_err(format!(
                        "dist.toml line {line_no}: unescaped interior quote"
                    )));
                }
                other => out.push(other),
            }
        }
        return Ok(out);
    }
    if let Some(inner) = t.strip_prefix('\'').and_then(|s| s.strip_suffix('\''))
        && !inner.contains('\'')
    {
        return Ok(inner.to_owned());
    }
    Err(cfg_err(format!(
        "dist.toml line {line_no}: expected quoted string"
    )))
}

fn parse_bool(raw: &str, line_no: usize) -> Result<bool, CodedError> {
    match raw.trim() {
        "true" => Ok(true),
        "false" => Ok(false),
        _ => Err(cfg_err(format!("dist.toml line {line_no}: expected bool"))),
    }
}

fn parse_u32(raw: &str, line_no: usize) -> Result<u32, CodedError> {
    let t = raw.trim();
    if t.is_empty() || !t.bytes().all(|b| b.is_ascii_digit()) {
        return Err(cfg_err(format!(
            "dist.toml line {line_no}: expected u32 integer"
        )));
    }
    t.parse::<u32>()
        .map_err(|_| cfg_err(format!("dist.toml line {line_no}: integer out of range")))
}

fn parse_str_array(raw: &str, line_no: usize) -> Result<Vec<String>, CodedError> {
    let t = raw.trim();
    let Some(inner) = t
        .strip_prefix('[')
        .and_then(|s| s.strip_suffix(']'))
        .map(str::trim)
    else {
        return Err(cfg_err(format!(
            "dist.toml line {line_no}: expected string array"
        )));
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
                let part = inner.get(elem_start..idx).unwrap_or("").trim();
                if part.is_empty() {
                    return Err(cfg_err(format!(
                        "dist.toml line {line_no}: empty element in array"
                    )));
                }
                let parsed = parse_str(part, line_no)?;
                if parsed.trim().is_empty() {
                    return Err(cfg_err(format!(
                        "dist.toml line {line_no}: empty string element in array"
                    )));
                }
                out.push(parsed);
                elem_start = idx.saturating_add(1);
            }
            _ => {}
        }
    }
    let tail = inner.get(elem_start..).unwrap_or("").trim();
    if !tail.is_empty() {
        let parsed = parse_str(tail, line_no)?;
        if parsed.trim().is_empty() {
            return Err(cfg_err(format!(
                "dist.toml line {line_no}: empty string element in array"
            )));
        }
        out.push(parsed);
    }
    Ok(out)
}
