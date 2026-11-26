// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Environment TOML parsers (`foreign_files.toml`, `surfaces.toml`) and schema context types.

use std::collections::{BTreeMap, BTreeSet};

use grdr_proto::descriptor::ResolvedOptionsExtension;

use crate::capture_toml::strip_toml_comment;
pub(crate) use crate::descriptor_env_checks::{
    check_foreign_descriptors, check_sl08_sl09_layout, check_sl10_imports, check_sl11_surfaces,
    find_and_check_options_file, is_valid_rel_proto_path, lint_err,
};
use crate::schema_compare::{EnumValueSnapshot, FieldSnapshot};
use crate::{LintError, LintSeverity};

const FOREIGN_FILES_SCHEMA: &str = "grdr.foreign_files.v1alpha1";
const SURFACES_SCHEMA: &str = "grdr.surfaces.v1alpha1";
const FOREIGN_FILES_PATH: &str = "crates/grdr-schema-lint/foreign_files.toml";

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedSchemaContext {
    pub namespace: String,
    pub options_file: String,
    pub options_package: String,
    pub options_class_wire_names: BTreeSet<String>,
    pub options_ext: ResolvedOptionsExtension,
    pub dc_wire_to_num: BTreeMap<String, i32>,
    pub ck_wire_to_num: BTreeMap<String, i32>,
    pub method_scope_tag: i32,
    pub method_mcp_tag: i32,
    pub fields: Vec<FieldSnapshot>,
    pub enums: Vec<EnumValueSnapshot>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProtoPackageRow {
    pub package: String,
    pub class: String,
}

pub fn parse_foreign_files_toml(raw: &str) -> Result<BTreeMap<String, String>, LintError> {
    let mut pins = BTreeMap::new();
    let mut schema: Option<String> = None;
    let mut in_entry = false;
    let mut cur_path: Option<String> = None;
    let mut cur_sha: Option<String> = None;

    for raw_line in raw.lines() {
        let trimmed = strip_toml_comment(raw_line).trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') {
            if !trimmed.ends_with(']') {
                return Err(foreign_err("malformed TOML section header"));
            }
            if trimmed != "[[foreign_file]]" {
                return Err(foreign_err(&format!("unexpected section `{trimmed}`")));
            }
            if in_entry {
                insert_foreign_pin(&mut pins, cur_path.take(), cur_sha.take())?;
            }
            in_entry = true;
            continue;
        }
        let Some((k_raw, v_raw)) = trimmed.split_once('=') else {
            return Err(foreign_err("expected `key = \"value\"` assignment"));
        };
        let key = k_raw.trim();
        let val = parse_quoted_toml_scalar(v_raw.trim(), FOREIGN_FILES_PATH)?;
        if !in_entry {
            if key != "schema" || schema.is_some() {
                return Err(foreign_err(&format!("unexpected top-level key `{key}`")));
            }
            schema = Some(val);
            continue;
        }
        match key {
            "path" if cur_path.is_none() => cur_path = Some(val),
            "sha256" if cur_sha.is_none() => cur_sha = Some(val),
            "path" | "sha256" => return Err(foreign_err(&format!("duplicate `{key}` key"))),
            _ => {
                return Err(foreign_err(&format!(
                    "unknown key `{key}` in [[foreign_file]]"
                )));
            }
        }
    }
    if in_entry {
        insert_foreign_pin(&mut pins, cur_path, cur_sha)?;
    }
    if schema.as_deref() != Some(FOREIGN_FILES_SCHEMA) {
        return Err(foreign_err(&format!(
            "missing or invalid schema (expected `{FOREIGN_FILES_SCHEMA}`)"
        )));
    }
    Ok(pins)
}

pub fn parse_surfaces_proto_packages(raw: &str) -> Result<Vec<ProtoPackageRow>, LintError> {
    let mut rows = Vec::new();
    let mut schema: Option<String> = None;
    let mut in_header = true;
    let mut in_proto_pkg = false;
    let mut cur_pkg: Option<String> = None;
    let mut cur_class: Option<String> = None;

    for raw_line in raw.lines() {
        let trimmed = strip_toml_comment(raw_line).trim();
        if trimmed.is_empty() {
            continue;
        }
        if trimmed.starts_with('[') {
            if !trimmed.ends_with(']') {
                return Err(surfaces_err("malformed TOML section header"));
            }
            in_header = false;
            if in_proto_pkg {
                rows.push(flush_proto_pkg_row(cur_pkg.take(), cur_class.take())?);
            }
            in_proto_pkg = trimmed == "[[proto_package]]";
            continue;
        }
        if in_header {
            let Some((k_raw, v_raw)) = trimmed.split_once('=') else {
                continue;
            };
            if k_raw.trim() == "schema" {
                if schema.is_some() {
                    return Err(surfaces_err("duplicate top-level schema key"));
                }
                schema = Some(parse_quoted_toml_scalar(
                    v_raw.trim(),
                    "contracts/surfaces.toml",
                )?);
            }
            continue;
        }
        if !in_proto_pkg {
            continue;
        }
        let Some((k_raw, v_raw)) = trimmed.split_once('=') else {
            return Err(surfaces_err(
                "expected key = value inside [[proto_package]]",
            ));
        };
        let key = k_raw.trim();
        let val = parse_quoted_toml_scalar(v_raw.trim(), "contracts/surfaces.toml")?;
        match key {
            "package" if cur_pkg.is_none() => cur_pkg = Some(val),
            "class" if cur_class.is_none() => cur_class = Some(val),
            "package" | "class" => return Err(surfaces_err(&format!("duplicate `{key}` key"))),
            _ => {
                return Err(surfaces_err(&format!(
                    "unknown key `{key}` in [[proto_package]]"
                )));
            }
        }
    }
    if in_proto_pkg {
        rows.push(flush_proto_pkg_row(cur_pkg, cur_class)?);
    }
    if schema.as_deref() != Some(SURFACES_SCHEMA) {
        return Err(surfaces_err(&format!(
            "missing or invalid schema (expected `{SURFACES_SCHEMA}`)"
        )));
    }
    Ok(rows)
}

fn parse_quoted_toml_scalar(raw: &str, file: &str) -> Result<String, LintError> {
    if let Some(inner) = raw.strip_prefix('"').and_then(|s| s.strip_suffix('"'))
        && !inner.contains('"')
    {
        return Ok(inner.to_owned());
    }
    if let Some(inner) = raw.strip_prefix('\'').and_then(|s| s.strip_suffix('\''))
        && !inner.contains('\'')
    {
        return Ok(inner.to_owned());
    }
    Err(LintError::ForeignDescriptorViolation {
        file: file.into(),
        detail: "invalid or unclosed string literal".into(),
    })
}

fn flush_proto_pkg_row(
    pkg: Option<String>,
    class: Option<String>,
) -> Result<ProtoPackageRow, LintError> {
    let (Some(package), Some(class)) = (pkg, class) else {
        return Err(surfaces_err(
            "[[proto_package]] requires both `package` and `class`",
        ));
    };
    if package.is_empty() || class.is_empty() {
        return Err(surfaces_err("[[proto_package]] values must be non-empty"));
    }
    Ok(ProtoPackageRow { package, class })
}

fn insert_foreign_pin(
    pins: &mut BTreeMap<String, String>,
    path_opt: Option<String>,
    sha_opt: Option<String>,
) -> Result<(), LintError> {
    let (Some(path), Some(sha256)) = (path_opt, sha_opt) else {
        return Err(foreign_err(
            "[[foreign_file]] requires both `path` and `sha256`",
        ));
    };
    if !is_valid_rel_proto_path(&path)
        || sha256.len() != 64
        || !sha256
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
    {
        return Err(foreign_err(&format!(
            "invalid foreign_file entry `{path}` sha256 `{sha256}`"
        )));
    }
    if pins.insert(path.clone(), sha256).is_some() {
        return Err(foreign_err(&format!("duplicate foreign_file pin `{path}`")));
    }
    Ok(())
}

fn foreign_err(detail: &str) -> LintError {
    LintError::ForeignDescriptorViolation {
        file: FOREIGN_FILES_PATH.into(),
        detail: detail.into(),
    }
}

fn surfaces_err(detail: &str) -> LintError {
    let _ = LintSeverity::Error;
    LintError::ForeignDescriptorViolation {
        file: "contracts/surfaces.toml".into(),
        detail: detail.into(),
    }
}
