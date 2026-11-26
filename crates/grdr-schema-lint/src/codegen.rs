// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Deterministic `fields.json`, `registry.rs`, and `capture.rs` codegen and `--check` drift gate.

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::LintError;
use crate::capture_toml::{CaptureConfig, CaptureLevelRow, ReclassKind, ReclassificationEntry};
use crate::descriptor_env::ResolvedSchemaContext;
use crate::io_safe::sync_selected_targets;
use crate::schema_compare::FieldSnapshot;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedRegistryDoc {
    pub schema_version: String,
    pub namespace: String,
    pub options_package: String,
    pub fields: Vec<GeneratedFieldRow>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct GeneratedFieldRow {
    pub path: String,
    pub package: String,
    pub message: String,
    pub field: String,
    pub number: i32,
    pub data_class: String,
    pub content_kind: Option<String>,
    pub commitment_class: String,
    pub policy_readable: bool,
    pub sealable: bool,
}

fn check_safe_ident(val: &str, label: &str) -> Result<(), LintError> {
    let valid = !val.is_empty()
        && val
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b':'));
    if valid {
        Ok(())
    } else {
        Err(LintError::CaptureOrCodegenViolation {
            target: label.into(),
            detail: format!("unsafe character in codegen identifier `{val}`"),
        })
    }
}

pub fn generate_fields_json(ctx: &ResolvedSchemaContext) -> Result<String, LintError> {
    let mut rows: Vec<GeneratedFieldRow> = ctx.fields.iter().map(snapshot_to_row).collect();
    rows.sort_by(|a, b| a.path.cmp(&b.path));
    let mut seen_paths = BTreeSet::new();
    for r in &rows {
        if !seen_paths.insert(r.path.as_str()) {
            return Err(LintError::CaptureOrCodegenViolation {
                target: r.path.clone(),
                detail: format!("duplicate field path `{}` in schema registry", r.path),
            });
        }
    }
    let doc = GeneratedRegistryDoc {
        schema_version: "grdr.fields.v1alpha1".into(),
        namespace: ctx.namespace.clone(),
        options_package: ctx.options_package.clone(),
        fields: rows,
    };
    let mut out =
        serde_json::to_string_pretty(&doc).map_err(|e| LintError::CaptureOrCodegenViolation {
            target: "crates/grdr-schema/registry/fields.json".into(),
            detail: e.to_string(),
        })?;
    out.push('\n');
    Ok(out)
}

pub fn generate_registry_rs(ctx: &ResolvedSchemaContext) -> Result<String, LintError> {
    check_safe_ident(&ctx.options_package, "OPTIONS_PACKAGE")?;
    let mut fields: Vec<&FieldSnapshot> = ctx.fields.iter().collect();
    fields.sort_by(|a, b| a.path.cmp(&b.path));

    let mut seen_paths = BTreeSet::new();
    let mut out = String::new();
    write_generated_header(&mut out);
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "use crate::{{CommitmentClass, ContentKind, DataClass}};"
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "pub const OPTIONS_PACKAGE: &str = {:?};",
        ctx.options_package
    );
    let _ = writeln!(out);
    let _ = writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]");
    let _ = writeln!(out, "pub struct RegistryFieldSpec {{");
    let _ = writeln!(out, "    pub path: &'static str,");
    let _ = writeln!(out, "    pub package: &'static str,");
    let _ = writeln!(out, "    pub message: &'static str,");
    let _ = writeln!(out, "    pub field: &'static str,");
    let _ = writeln!(out, "    pub number: i32,");
    let _ = writeln!(out, "    pub data_class: DataClass,");
    let _ = writeln!(out, "    pub content_kind: Option<ContentKind>,");
    let _ = writeln!(out, "    pub commitment_class: CommitmentClass,");
    let _ = writeln!(out, "    pub policy_readable: bool,");
    let _ = writeln!(out, "    pub sealable: bool,");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "pub const REGISTERED_FIELDS: &[RegistryFieldSpec] = &["
    );
    for f in fields {
        let row = snapshot_to_row(f);
        if !seen_paths.insert(row.path.clone()) {
            return Err(LintError::CaptureOrCodegenViolation {
                target: row.path,
                detail: "duplicate field path in registry codegen".into(),
            });
        }
        check_safe_ident(&row.path, "field.path")?;
        check_safe_ident(&row.package, "field.package")?;
        check_safe_ident(&row.message, "field.message")?;
        check_safe_ident(&row.field, "field.field")?;
        let dc_expr = match row.data_class.as_str() {
            "identifier" => "DataClass::Identifier",
            "structural" => "DataClass::Structural",
            "derived" => "DataClass::Derived",
            "content" => "DataClass::Content",
            other => {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: row.path,
                    detail: format!("unknown data_class `{other}` in registry codegen"),
                });
            }
        };
        let ck_expr = match row.content_kind.as_deref() {
            Some("argument") => "Some(ContentKind::Argument)",
            Some("body") => "Some(ContentKind::Body)",
            None => "None",
            Some(other) => {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: row.path,
                    detail: format!("unknown content_kind `{other}` in registry codegen"),
                });
            }
        };
        let cc_expr = match row.commitment_class.as_str() {
            "structural" => "CommitmentClass::Structural",
            "derived" => "CommitmentClass::Derived",
            "identifier" => "CommitmentClass::Identifier",
            "content.argument" => "CommitmentClass::ContentArgument",
            "content.body" => "CommitmentClass::ContentBody",
            other => {
                return Err(LintError::CaptureOrCodegenViolation {
                    target: row.path,
                    detail: format!("unknown commitment_class `{other}` in registry codegen"),
                });
            }
        };
        let _ = writeln!(out, "    RegistryFieldSpec {{");
        let _ = writeln!(out, "        path: {:?},", row.path);
        let _ = writeln!(out, "        package: {:?},", row.package);
        let _ = writeln!(out, "        message: {:?},", row.message);
        let _ = writeln!(out, "        field: {:?},", row.field);
        let _ = writeln!(out, "        number: {},", row.number);
        let _ = writeln!(out, "        data_class: {dc_expr},");
        let _ = writeln!(out, "        content_kind: {ck_expr},");
        let _ = writeln!(out, "        commitment_class: {cc_expr},");
        let _ = writeln!(out, "        policy_readable: {},", row.policy_readable);
        let _ = writeln!(out, "        sealable: {},", row.sealable);
        let _ = writeln!(out, "    }},");
    }
    let _ = writeln!(out, "];");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "pub fn find_field(path: &str) -> Option<&'static RegistryFieldSpec> {{"
    );
    let _ = writeln!(
        out,
        "    REGISTERED_FIELDS.iter().find(|entry| entry.path == path)"
    );
    let _ = writeln!(out, "}}");
    Ok(out)
}

pub fn generate_capture_rs(
    capture: &CaptureConfig,
    reclass: &[ReclassificationEntry],
) -> Result<String, LintError> {
    if capture.levels.is_empty() {
        return Err(LintError::CaptureOrCodegenViolation {
            target: "crates/grdr-schema/capture.toml".into(),
            detail: "cannot generate capture.rs from empty capture levels".into(),
        });
    }
    check_safe_ident(&capture.schema, "CAPTURE_SCHEMA_VERSION")?;
    check_safe_ident(&capture.default_level, "DEFAULT_CAPTURE_LEVEL")?;
    for lvl in &capture.levels {
        check_safe_ident(&lvl.name, "capture.level.name")?;
    }
    for entry in reclass {
        check_safe_ident(&entry.rfc, "reclass.rfc")?;
        check_safe_ident(&entry.target, "reclass.target")?;
        check_safe_ident(&entry.from, "reclass.from")?;
        check_safe_ident(&entry.to, "reclass.to")?;
        if let Some(ref succ) = entry.successor {
            check_safe_ident(succ, "reclass.successor")?;
        }
    }
    let default_spec = capture
        .levels
        .iter()
        .find(|lvl| lvl.name == capture.default_level)
        .ok_or_else(|| LintError::CaptureOrCodegenViolation {
            target: "crates/grdr-schema/capture.toml".into(),
            detail: format!(
                "default capture level `{}` not found",
                capture.default_level
            ),
        })?;

    let mut out = String::new();
    write_generated_header(&mut out);
    let _ = writeln!(out);
    let _ = writeln!(out, "use crate::CommitmentClass;");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "pub const CAPTURE_SCHEMA_VERSION: &str = {:?};",
        capture.schema
    );
    let _ = writeln!(
        out,
        "pub const DEFAULT_CAPTURE_LEVEL: &str = {:?};",
        capture.default_level
    );
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]"
    );
    let _ = writeln!(out, "pub enum CaptureDisposition {{");
    let _ = writeln!(out, "    Withheld,");
    let _ = writeln!(out, "    Redacted,");
    let _ = writeln!(out, "    DigestOnly,");
    let _ = writeln!(out, "    Pseudonymous,");
    let _ = writeln!(out, "    Full,");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]");
    let _ = writeln!(out, "pub enum ReclassHoldKind {{");
    let _ = writeln!(out, "    Field,");
    let _ = writeln!(out, "    Level,");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]");
    let _ = writeln!(out, "pub struct CaptureLevelSpec {{");
    let _ = writeln!(out, "    pub name: &'static str,");
    let _ = writeln!(out, "    pub rank: u8,");
    let _ = writeln!(out, "    pub structural: CaptureDisposition,");
    let _ = writeln!(out, "    pub derived: CaptureDisposition,");
    let _ = writeln!(out, "    pub identifier: CaptureDisposition,");
    let _ = writeln!(out, "    pub content_argument: CaptureDisposition,");
    let _ = writeln!(out, "    pub content_body: CaptureDisposition,");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(out, "#[derive(Clone, Copy, Debug, PartialEq, Eq)]");
    let _ = writeln!(out, "pub struct PendingReclassificationHold {{");
    let _ = writeln!(out, "    pub kind: ReclassHoldKind,");
    let _ = writeln!(out, "    pub rfc: &'static str,");
    let _ = writeln!(out, "    pub target: &'static str,");
    let _ = writeln!(out, "    pub successor: Option<&'static str>,");
    let _ = writeln!(out, "    pub from_disposition: &'static str,");
    let _ = writeln!(out, "    pub to_disposition: &'static str,");
    let _ = writeln!(out, "    pub from_sealable: Option<bool>,");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(out, "pub const CAPTURE_LEVELS: &[CaptureLevelSpec] = &[");
    for lvl in &capture.levels {
        write_capture_level_spec(&mut out, lvl, "    ")?;
        let _ = writeln!(out, ",");
    }
    let _ = writeln!(out, "];");
    let _ = writeln!(out);
    let holds: Vec<&ReclassificationEntry> = reclass
        .iter()
        .filter(|r| matches!(r.kind, ReclassKind::Field | ReclassKind::Level))
        .collect();
    if holds.is_empty() {
        let _ = writeln!(
            out,
            "pub const RECLASSIFICATION_HOLDS: &[PendingReclassificationHold] = &[];"
        );
    } else {
        let _ = writeln!(
            out,
            "pub const RECLASSIFICATION_HOLDS: &[PendingReclassificationHold] = &["
        );
        for entry in holds {
            let kind_expr = match entry.kind {
                ReclassKind::Field => "ReclassHoldKind::Field",
                _ => "ReclassHoldKind::Level",
            };
            let _ = writeln!(out, "    PendingReclassificationHold {{");
            let _ = writeln!(out, "        kind: {kind_expr},");
            let _ = writeln!(out, "        rfc: {:?},", entry.rfc);
            let _ = writeln!(out, "        target: {:?},", entry.target);
            match entry.successor {
                Some(ref s) => {
                    let _ = writeln!(out, "        successor: Some({:?}),", s);
                }
                None => {
                    let _ = writeln!(out, "        successor: None,");
                }
            }
            let _ = writeln!(out, "        from_disposition: {:?},", entry.from);
            let _ = writeln!(out, "        to_disposition: {:?},", entry.to);
            let _ = writeln!(out, "        from_sealable: {:?},", entry.from_sealable);
            let _ = writeln!(out, "    }},");
        }
        let _ = writeln!(out, "];");
    }
    let _ = writeln!(out);
    let _ = writeln!(out, "impl CaptureLevelSpec {{");
    let _ = writeln!(
        out,
        "    pub const fn for_class(&self, class: CommitmentClass) -> CaptureDisposition {{"
    );
    let _ = writeln!(out, "        match class {{");
    let _ = writeln!(
        out,
        "            CommitmentClass::Structural => self.structural,"
    );
    let _ = writeln!(out, "            CommitmentClass::Derived => self.derived,");
    let _ = writeln!(
        out,
        "            CommitmentClass::Identifier => self.identifier,"
    );
    let _ = writeln!(
        out,
        "            CommitmentClass::ContentArgument => self.content_argument,"
    );
    let _ = writeln!(
        out,
        "            CommitmentClass::ContentBody => self.content_body,"
    );
    let _ = writeln!(out, "        }}");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "pub fn find_capture_level(name: &str) -> Option<&'static CaptureLevelSpec> {{"
    );
    let _ = writeln!(
        out,
        "    CAPTURE_LEVELS.iter().find(|lvl| lvl.name == name)"
    );
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "pub fn has_reclassification_hold(target: &str) -> bool {{"
    );
    let _ = writeln!(out, "    RECLASSIFICATION_HOLDS");
    let _ = writeln!(out, "        .iter()");
    let _ = writeln!(
        out,
        "        .any(|hold| hold.target == target || hold.successor == Some(target))"
    );
    let _ = writeln!(out, "}}");
    let _ = writeln!(out);
    let _ = write!(
        out,
        "pub const DEFAULT_CAPTURE_LEVEL_SPEC: CaptureLevelSpec = "
    );
    write_capture_level_spec(&mut out, default_spec, "")?;
    let _ = writeln!(out, ";");
    let _ = writeln!(out);
    let _ = writeln!(
        out,
        "pub fn default_capture_level() -> &'static CaptureLevelSpec {{"
    );
    let _ = writeln!(
        out,
        "    match find_capture_level(DEFAULT_CAPTURE_LEVEL) {{"
    );
    let _ = writeln!(out, "        Some(spec) => spec,");
    let _ = writeln!(out, "        None => &DEFAULT_CAPTURE_LEVEL_SPEC,");
    let _ = writeln!(out, "    }}");
    let _ = writeln!(out, "}}");
    Ok(out)
}

fn write_capture_level_spec(
    out: &mut String,
    lvl: &CaptureLevelRow,
    indent: &str,
) -> Result<(), LintError> {
    let disp = |cls: &str| -> Result<&'static str, LintError> {
        match lvl.dispositions.get(cls).map(String::as_str) {
            Some("full") => Ok("CaptureDisposition::Full"),
            Some("pseudonymous") => Ok("CaptureDisposition::Pseudonymous"),
            Some("digest_only") => Ok("CaptureDisposition::DigestOnly"),
            Some("redacted") => Ok("CaptureDisposition::Redacted"),
            Some("withheld") => Ok("CaptureDisposition::Withheld"),
            other => Err(LintError::CaptureOrCodegenViolation {
                target: "crates/grdr-schema/capture.toml".into(),
                detail: format!(
                    "level `{}` class `{cls}` has invalid disposition `{other:?}`",
                    lvl.name
                ),
            }),
        }
    };
    let structural = disp("structural")?;
    let derived = disp("derived")?;
    let identifier = disp("identifier")?;
    let content_argument = disp("content.argument")?;
    let content_body = disp("content.body")?;
    let _ = writeln!(out, "{indent}CaptureLevelSpec {{");
    let _ = writeln!(out, "{indent}    name: {:?},", lvl.name);
    let _ = writeln!(out, "{indent}    rank: {},", lvl.rank);
    let _ = writeln!(out, "{indent}    structural: {structural},");
    let _ = writeln!(out, "{indent}    derived: {derived},");
    let _ = writeln!(out, "{indent}    identifier: {identifier},");
    let _ = writeln!(out, "{indent}    content_argument: {content_argument},");
    let _ = writeln!(out, "{indent}    content_body: {content_body},");
    let _ = write!(out, "{indent}}}");
    Ok(())
}

pub fn sync_or_check_generated_artifacts(
    root: &Path,
    ctx: &ResolvedSchemaContext,
    capture: &CaptureConfig,
    reclass: &[ReclassificationEntry],
    check_only: bool,
) -> Result<(), LintError> {
    let fields_json = generate_fields_json(ctx)?;
    let registry_rs = generate_registry_rs(ctx)?;
    let capture_rs = generate_capture_rs(capture, reclass)?;

    let targets = [
        ("crates/grdr-schema/registry/fields.json", fields_json),
        ("crates/grdr-schema/src/registry.rs", registry_rs),
        ("crates/grdr-schema/src/capture.rs", capture_rs),
    ];
    sync_selected_targets(root, &targets, check_only)
}

pub(crate) fn check_registry_artifacts(
    root: &Path,
    ctx: &ResolvedSchemaContext,
) -> Result<(), LintError> {
    let targets = [
        (
            "crates/grdr-schema/registry/fields.json",
            generate_fields_json(ctx)?,
        ),
        (
            "crates/grdr-schema/src/registry.rs",
            generate_registry_rs(ctx)?,
        ),
    ];
    sync_selected_targets(root, &targets, true)
}

pub(crate) fn check_capture_artifact(
    root: &Path,
    capture: &CaptureConfig,
    reclass: &[ReclassificationEntry],
) -> Result<(), LintError> {
    let targets = [(
        "crates/grdr-schema/src/capture.rs",
        generate_capture_rs(capture, reclass)?,
    )];
    sync_selected_targets(root, &targets, true)
}

fn write_generated_header(out: &mut String) {
    out.push_str(concat!(
        "// SPDX-",
        "License-Identifier: Apache-2.0\n",
        "// SPDX-",
        "FileCopyrightText: The Guardrails ADR Authors\n",
        "// @generated by grdr-schema-lint; do not edit.\n",
    ));
}

fn snapshot_to_row(f: &FieldSnapshot) -> GeneratedFieldRow {
    GeneratedFieldRow {
        path: f.path.clone(),
        package: f.package.clone(),
        message: f.message.clone(),
        field: f.field.clone(),
        number: f.number,
        data_class: f.data_class.clone(),
        content_kind: f.content_kind.clone(),
        commitment_class: f.commitment_class.clone(),
        policy_readable: f.policy_readable,
        sealable: f.sealable,
    }
}
