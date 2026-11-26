// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
#![forbid(unsafe_code)]
#![deny(clippy::arithmetic_side_effects)]
//! Schema, Cedar, vocabulary, and P7 pack manifest linter (`docs/design/04`, `12`, `03`).

pub mod cedar_lint;
pub mod pack_lint;
pub mod proto_lint;
pub mod vocab_lint;

use std::fs;
use std::io::Read;
use std::path::Path;

use serde::{Deserialize, Serialize};

pub use cedar_lint::{lint_cedar_dir, lint_cedar_policy_in_mode, lint_cedar_schema_file};
pub use pack_lint::{
    EvidenceQueryDecl, FieldReadDecl, PackDataClass, PackKind, PackManifest,
    first_forbidden_execution_pattern, lint_pack_manifest,
};
pub use proto_lint::{lint_proto_dir, lint_proto_source};
pub use vocab_lint::{
    VocabularyEntry, VocabularyForbidden, VocabularyRegistry, lint_text_against_vocabulary,
    lint_vocabulary_toml, parse_vocabulary_toml,
};

pub(crate) const MAX_LINT_FILE_BYTES: u64 = 2 * 1024 * 1024;
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

pub fn lint_repo_root(root: &Path) -> Result<LintReport, LintError> {
    let mut findings = Vec::new();

    let contracts_dir = root.join("contracts");
    let proto_dir = contracts_dir.join("proto");
    let proto_files_checked = lint_proto_dir(&proto_dir, &mut findings)?;

    let cedar_dir = contracts_dir.join("cedar");
    let cedar_files_checked = lint_cedar_dir(&cedar_dir, &mut findings)?;

    let vocab_path = contracts_dir.join("interface").join("vocabulary.toml");
    let vocab_terms_checked = lint_vocabulary_toml(&vocab_path, &mut findings)?;

    Ok(LintReport {
        proto_files_checked,
        cedar_files_checked,
        vocab_terms_checked,
        findings,
    })
}

pub(crate) fn read_bounded_regular_file(
    canon_root: &Path,
    path: &Path,
    max_bytes: u64,
) -> Result<String, LintError> {
    let meta = fs::symlink_metadata(path).map_err(|e| LintError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    if meta.file_type().is_symlink() || !meta.is_file() {
        return Err(LintError::Io {
            path: path.display().to_string(),
            detail: "refusing to read symlink or non-regular file".into(),
        });
    }
    if meta.len() > max_bytes {
        return Err(LintError::Io {
            path: path.display().to_string(),
            detail: format!("file size {} exceeds cap {max_bytes}", meta.len()),
        });
    }
    let canon_path = fs::canonicalize(path).map_err(|e| LintError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    if !canon_path.starts_with(canon_root) {
        return Err(LintError::Io {
            path: path.display().to_string(),
            detail: "resolved path escapes allowed schema root".into(),
        });
    }
    let file = fs::File::open(&canon_path).map_err(|e| LintError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    let mut out = String::new();
    let mut reader = file.take(max_bytes.saturating_add(1));
    reader.read_to_string(&mut out).map_err(|e| LintError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    if (out.len() as u64) > max_bytes {
        return Err(LintError::Io {
            path: path.display().to_string(),
            detail: format!("file content exceeds cap {max_bytes}"),
        });
    }
    Ok(out)
}
