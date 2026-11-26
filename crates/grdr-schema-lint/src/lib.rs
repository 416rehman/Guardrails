// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Schema, Cedar, vocabulary, and P7 pack manifest linter (`docs/design/04`, `12`, `03`).
#![deny(clippy::arithmetic_side_effects)]

pub mod capture_toml;
pub mod cedar_lint;
pub mod codegen;
pub mod descriptor_env;
pub(crate) mod descriptor_env_checks;
pub mod descriptor_lint;
pub mod descriptor_rules;
mod descriptor_rules_enum;
pub(crate) mod io_safe;
mod io_safe_fs;
mod manifest_lint;
mod manifest_toml;
pub mod pack_lint;
pub mod proto_lint;
mod proto_option_lex;
mod proto_source_parity;
mod proto_source_parse;
mod proto_source_rpc;
pub mod reclass_toml;
pub mod schema_compare;
pub mod vocab_lint;

use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

pub(crate) use io_safe::{
    canonicalize_real_dir, is_symlink_or_reparse, read_bounded_regular_file, reject_symlinks_under,
    run_descriptor_and_capture_checks,
};
use serde::{Deserialize, Serialize};

pub use capture_toml::{
    CANONICAL_CLASSES, CaptureConfig, CaptureLevelRow, Openness, ReclassKind,
    ReclassificationEntry, parse_capture_toml, parse_reclassifications_toml, validate_capture_sl13,
};
pub use cedar_lint::{lint_cedar_dir, lint_cedar_policy_in_mode, lint_cedar_schema_file};
pub use codegen::{
    generate_capture_rs, generate_fields_json, generate_registry_rs,
    sync_or_check_generated_artifacts,
};
pub use descriptor_env::{
    ProtoPackageRow, ResolvedSchemaContext, parse_foreign_files_toml, parse_surfaces_proto_packages,
};
pub use descriptor_lint::check_descriptor_set;
pub use pack_lint::{
    EvidenceQueryDecl, FieldReadDecl, PackDataClass, PackKind, PackManifest,
    first_forbidden_execution_pattern, lint_pack_manifest,
};
pub use proto_lint::{
    lint_proto_dir, lint_proto_dir_with_namespace, lint_proto_source,
    lint_proto_source_with_namespace,
};
pub use schema_compare::{
    EnumValueSnapshot, FieldSnapshot, SchemaCompareReport, compare_schemas_sl12,
    validate_reclassifications_entries,
};
pub use vocab_lint::{
    VocabularyEntry, VocabularyForbidden, VocabularyRegistry, lint_text_against_vocabulary,
    lint_vocabulary_toml, parse_vocabulary_toml,
};

pub(crate) const MAX_LINT_FILE_BYTES: u64 = 2 * 1024 * 1024;
pub(crate) const MAX_DESCRIPTOR_BINPB_BYTES: u64 = 16 * 1024 * 1024;
pub(crate) const MAX_LINT_DIR_DEPTH: usize = 16;

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LintError {
    #[error("GRDR-LINT-0001: I/O failure reading `{path}`: {detail}")]
    Io { path: String, detail: String },
    #[error("GRDR-LINT-0002: proto schema violation in `{file}`: {detail}")]
    ProtoViolation { file: String, detail: String },
    #[error("GRDR-LINT-0003: Cedar schema violation in `{file}`: {detail}")]
    CedarViolation { file: String, detail: String },
    #[error("GRDR-LINT-0004: vocabulary violation: {detail}")]
    VocabularyViolation { detail: String },
    #[error("GRDR-LINT-0005: P7 pack manifest violation in `{pack_id}`: {detail}")]
    PackViolation { pack_id: String, detail: String },
    #[error("GRDR-LINT-0006: foreign descriptor or options violation in `{file}`: {detail}")]
    ForeignDescriptorViolation { file: String, detail: String },
    #[error("GRDR-LINT-0007: surfaces stability authority violation on `{package}`: {detail}")]
    SurfacesViolation { package: String, detail: String },
    #[error("GRDR-LINT-0008: schema compatibility violation on `{target}`: {detail}")]
    CompareViolation { target: String, detail: String },
    #[error("GRDR-LINT-0009: capture matrix or generated registry drift on `{target}`: {detail}")]
    CaptureOrCodegenViolation { target: String, detail: String },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintSeverity {
    Error,
    Warning,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LintDomain {
    Proto,
    Cedar,
    Vocabulary,
    PackManifest,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LintFinding {
    pub code: String,
    pub domain: LintDomain,
    pub severity: LintSeverity,
    pub target: String,
    pub message: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LintReport {
    pub proto_files_checked: usize,
    pub cedar_files_checked: usize,
    pub vocab_terms_checked: usize,
    pub findings: Vec<LintFinding>,
}

impl LintReport {
    pub fn is_clean(&self) -> bool {
        !self
            .findings
            .iter()
            .any(|f| f.severity == LintSeverity::Error)
    }
}

fn validate_brand_manifest(brand_raw: &str) -> Result<grdr_schema::BrandIdentity, LintError> {
    let brand = grdr_schema::parse_brand_identity_toml(brand_raw);
    if !grdr_schema::is_valid_brand_identity(&brand) {
        return Err(LintError::ForeignDescriptorViolation {
            file: "contracts/interface/brand/brand.toml".into(),
            detail: "invalid or missing [identity].namespace or [identity].domain".into(),
        });
    }
    Ok(brand)
}

pub fn lint_repo_root(root: &Path) -> Result<LintReport, LintError> {
    let mut findings = Vec::new();
    let canon_root = canonicalize_real_dir(root, "repository root")?;
    let brand_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("contracts/interface/brand/brand.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let brand = validate_brand_manifest(&brand_raw)?;

    let contracts_dir = canon_root.join("contracts");
    let proto_dir = contracts_dir.join("proto");
    let proto_files_checked =
        proto_lint::lint_proto_dir_under(&canon_root, &proto_dir, &brand.namespace, &mut findings)?;
    let cedar_dir = contracts_dir.join("cedar");
    let cedar_files_checked =
        cedar_lint::lint_cedar_dir_under(&canon_root, &cedar_dir, &mut findings)?;
    let vocab_path = contracts_dir.join("interface").join("vocabulary.toml");
    let vocab_terms_checked =
        vocab_lint::lint_vocabulary_toml_under(&canon_root, &vocab_path, &mut findings)?;

    let (ctx, capture_cfg, reclass) =
        run_descriptor_and_capture_checks(&canon_root, &proto_dir, &brand_raw, &mut findings)?;
    if let Err(drift) =
        sync_or_check_generated_artifacts(&canon_root, &ctx, &capture_cfg, &reclass, true)
    {
        findings.push(LintFinding {
            code: "GRDR-LINT-0009".into(),
            domain: LintDomain::Proto,
            severity: LintSeverity::Error,
            target: "crates/grdr-schema".into(),
            message: drift.to_string(),
        });
    }

    Ok(LintReport {
        proto_files_checked,
        cedar_files_checked,
        vocab_terms_checked,
        findings,
    })
}

pub fn regenerate_schema_artifacts(root: &Path) -> Result<ResolvedSchemaContext, LintError> {
    let mut findings = Vec::new();
    let canon_root = canonicalize_real_dir(root, "repository root")?;
    let brand_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("contracts/interface/brand/brand.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let _ = validate_brand_manifest(&brand_raw)?;
    let proto_dir = canon_root.join("contracts").join("proto");
    let (ctx, capture_cfg, reclass) =
        run_descriptor_and_capture_checks(&canon_root, &proto_dir, &brand_raw, &mut findings)?;
    if findings.iter().any(|f| f.severity == LintSeverity::Error) {
        return Err(LintError::CaptureOrCodegenViolation {
            target: "contracts/proto".into(),
            detail: format!("descriptor lint failed before codegen: {findings:?}"),
        });
    }
    sync_or_check_generated_artifacts(&canon_root, &ctx, &capture_cfg, &reclass, false)?;
    Ok(ctx)
}

pub fn check_capture_only(root: &Path) -> Result<LintReport, LintError> {
    let canon_root = canonicalize_real_dir(root, "repository root")?;
    let brand_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("contracts/interface/brand/brand.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let _ = validate_brand_manifest(&brand_raw)?;
    let mut findings = Vec::new();
    let (_, capture_cfg, reclass) = run_descriptor_and_capture_checks(
        &canon_root,
        &canon_root.join("contracts/proto"),
        &brand_raw,
        &mut findings,
    )?;
    if let Err(drift) = codegen::check_capture_artifact(&canon_root, &capture_cfg, &reclass) {
        findings.push(LintFinding {
            code: "GRDR-LINT-0009".into(),
            domain: LintDomain::Proto,
            severity: LintSeverity::Error,
            target: "crates/grdr-schema/src/capture.rs".into(),
            message: drift.to_string(),
        });
    }
    Ok(LintReport {
        proto_files_checked: 0,
        cedar_files_checked: 0,
        vocab_terms_checked: 0,
        findings,
    })
}

pub fn check_registry_only(root: &Path) -> Result<LintReport, LintError> {
    let canon_root = canonicalize_real_dir(root, "repository root")?;
    let brand_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("contracts/interface/brand/brand.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let _ = validate_brand_manifest(&brand_raw)?;
    let mut findings = Vec::new();
    let (ctx, _, _) = run_descriptor_and_capture_checks(
        &canon_root,
        &canon_root.join("contracts/proto"),
        &brand_raw,
        &mut findings,
    )?;
    if let Err(drift) = codegen::check_registry_artifacts(&canon_root, &ctx) {
        findings.push(LintFinding {
            code: "GRDR-LINT-0009".into(),
            domain: LintDomain::Proto,
            severity: LintSeverity::Error,
            target: "crates/grdr-schema/registry/fields.json".into(),
            message: drift.to_string(),
        });
    }
    Ok(LintReport {
        proto_files_checked: 0,
        cedar_files_checked: 0,
        vocab_terms_checked: 0,
        findings,
    })
}

pub fn compare_roots(
    base_root: &Path,
    head_root: &Path,
    accepted_rfcs: &BTreeSet<String>,
) -> Result<SchemaCompareReport, LintError> {
    let mut findings = Vec::new();
    let canon_base = canonicalize_real_dir(base_root, "base repository root")?;
    let canon_head = canonicalize_real_dir(head_root, "head repository root")?;
    let base_brand = read_bounded_regular_file(
        &canon_base,
        &canon_base.join("contracts/interface/brand/brand.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let head_brand = read_bounded_regular_file(
        &canon_head,
        &canon_head.join("contracts/interface/brand/brand.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let _ = validate_brand_manifest(&base_brand)?;
    let _ = validate_brand_manifest(&head_brand)?;
    let (base_ctx, base_cap, base_rec) = run_descriptor_and_capture_checks(
        &canon_base,
        &canon_base.join("contracts/proto"),
        &base_brand,
        &mut findings,
    )?;
    let (head_ctx, head_cap, head_rec) = run_descriptor_and_capture_checks(
        &canon_head,
        &canon_head.join("contracts/proto"),
        &head_brand,
        &mut findings,
    )?;
    let mut report = compare_schemas_sl12(
        &base_ctx.fields,
        &head_ctx.fields,
        &base_ctx.enums,
        &head_ctx.enums,
        &base_cap,
        &head_cap,
        &base_rec,
        &head_rec,
        accepted_rfcs,
    );
    report.findings.extend(findings);
    Ok(report)
}

pub fn check_manifests(root: &Path) -> Result<BTreeMap<String, String>, LintError> {
    let canon_root = canonicalize_real_dir(root, "repository root")?;
    let brand_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("contracts/interface/brand/brand.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let _ = validate_brand_manifest(&brand_raw)?;
    let foreign_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("crates/grdr-schema-lint/foreign_files.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let surfaces_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("contracts/surfaces.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let capture_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("crates/grdr-schema/capture.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let reclass_raw = read_bounded_regular_file(
        &canon_root,
        &canon_root.join("crates/grdr-schema/reclassifications.toml"),
        MAX_LINT_FILE_BYTES,
    )?;
    let pins = parse_foreign_files_toml(&foreign_raw)?;
    let mut findings = Vec::new();
    descriptor_env_checks::validate_surfaces_rows_only(&surfaces_raw, &mut findings)?;
    let capture_cfg = parse_capture_toml(&capture_raw)?;
    let expected_classes: BTreeSet<String> =
        CANONICAL_CLASSES.iter().map(|s| (*s).to_owned()).collect();
    validate_capture_sl13(&capture_cfg, &expected_classes, &mut findings);
    let reclass = parse_reclassifications_toml(&reclass_raw)?;
    validate_reclassifications_entries(&reclass, &mut findings);
    if let Some(first_err) = findings.iter().find(|f| f.severity == LintSeverity::Error) {
        return Err(LintError::CaptureOrCodegenViolation {
            target: first_err.target.clone(),
            detail: first_err.message.clone(),
        });
    }
    manifest_lint::verify_workspace_manifests(&canon_root)?;
    Ok(pins)
}
