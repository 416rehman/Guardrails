// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Fail-closed TOML AST validation for compliance `pack.toml` and `trust-roots.toml`.

use std::collections::{BTreeMap, BTreeSet};

use crate::ComplyError;
use crate::evidence::{EvidenceDataClass, EvidenceQuery, FieldRead, validate_evidence_query};
use crate::pack_trust_roots::parse_semver_triple;
pub(crate) use crate::pack_trust_roots::{
    SignerTrustStatus, TrustedRootEntry, compare_semver, parse_trust_roots_toml,
};
use crate::toml_ast::{TomlVal, parse_toml_document};

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CompliancePackManifest {
    pub id: String,
    pub version: String,
    pub kind: String,
    pub per_person_scoring: bool,
    pub evidence_queries: Vec<EvidenceQuery>,
}

pub(crate) fn parse_compliance_pack_toml(raw: &str) -> Result<CompliancePackManifest, ComplyError> {
    reject_unsafe_toml_text(raw, "pack.toml")?;
    let root = parse_toml_document(raw)?;
    reject_hostile_toml_table(&root)?;

    for key in root.keys() {
        if !matches!(
            key.as_str(),
            "id" | "version"
                | "kind"
                | "per_person_scoring"
                | "reads"
                | "evidence_queries"
                | "commands"
                | "executables"
                | "urls"
                | "env_vars_to_set"
                | "mcp_servers_to_start"
        ) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("unknown top-level key `{key}` in compliance pack.toml"),
            });
        }
    }

    let id = req_safe_str(&root, "id", "pack.toml")?;
    let version = req_safe_str(&root, "version", "pack.toml")?;
    parse_semver_triple(&version)?;
    let kind = req_safe_str(&root, "kind", "pack.toml")?;
    if kind != "compliance" {
        return Err(ComplyError::VerificationFailed {
            detail: format!("pack.toml kind `{kind}` != \"compliance\""),
        });
    }
    let per_person_scoring = match root.get("per_person_scoring") {
        None => false,
        Some(TomlVal::Bool(false)) => false,
        Some(TomlVal::Bool(true)) => {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: id,
                detail: "per_person_scoring cannot be enabled in compliance pack".into(),
            });
        }
        Some(_) => {
            return Err(ComplyError::VerificationFailed {
                detail: "invalid non-boolean per_person_scoring in pack.toml".into(),
            });
        }
    };

    let declared_reads = parse_top_reads(root.get("reads"))?;
    let evidence_queries = parse_queries(root.get("evidence_queries"), &declared_reads)?;
    for q in &evidence_queries {
        validate_evidence_query(q)?;
    }

    Ok(CompliancePackManifest {
        id,
        version,
        kind,
        per_person_scoring,
        evidence_queries,
    })
}

pub(crate) fn is_safe_manifest_token(val: &str) -> bool {
    !val.is_empty()
        && !val
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '\u{2014}')
}

pub(crate) fn reject_unsafe_toml_text(raw: &str, label: &str) -> Result<(), ComplyError> {
    if raw.contains('\u{2014}') {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{label}` contains forbidden em dash"),
        });
    }
    if raw
        .chars()
        .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
    {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{label}` contains forbidden ASCII control characters"),
        });
    }
    Ok(())
}

fn reject_hostile_toml_table(tbl: &BTreeMap<String, TomlVal>) -> Result<(), ComplyError> {
    for (k, v) in tbl {
        let lower = k.to_ascii_lowercase();
        if matches!(
            lower.as_str(),
            "command"
                | "commands"
                | "executable"
                | "executables"
                | "url"
                | "urls"
                | "env_var"
                | "env_vars_to_set"
                | "mcp_server"
                | "mcp_servers_to_start"
                | "rule_snippet"
                | "rule_snippets"
                | "snippet"
                | "cedar"
                | "script"
                | "expr"
        ) && !is_empty_toml_list(v)
        {
            return Err(ComplyError::VerificationFailed {
                detail: format!("P7 rejects execution/URL/script field `{k}` in compliance pack"),
            });
        }
        reject_hostile_toml_value(v)?;
    }
    Ok(())
}

fn reject_hostile_toml_value(v: &TomlVal) -> Result<(), ComplyError> {
    match v {
        TomlVal::Table(sub) => reject_hostile_toml_table(sub),
        TomlVal::Array(items) => {
            for item in items {
                reject_hostile_toml_value(item)?;
            }
            Ok(())
        }
        TomlVal::Str(_) | TomlVal::Bool(_) | TomlVal::Int(_) => Ok(()),
    }
}

fn is_empty_toml_list(v: &TomlVal) -> bool {
    matches!(v, TomlVal::Array(items) if items.is_empty())
}

fn parse_top_reads(
    val: Option<&TomlVal>,
) -> Result<BTreeMap<String, EvidenceDataClass>, ComplyError> {
    let mut map = BTreeMap::new();
    let Some(v) = val else {
        return Ok(map);
    };
    let TomlVal::Array(items) = v else {
        return Err(ComplyError::VerificationFailed {
            detail: "`reads` in pack.toml must be an array of tables".into(),
        });
    };
    for item in items {
        let read = parse_read_table(item, "pack.reads")?;
        if read.data_class > EvidenceDataClass::Derived {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: "pack.reads".into(),
                detail: "pack manifest read class exceeds derived".into(),
            });
        }
        if map
            .insert(read.field_path.clone(), read.data_class)
            .is_some()
        {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate declared read path `{}`", read.field_path),
            });
        }
    }
    Ok(map)
}

fn parse_queries(
    val: Option<&TomlVal>,
    declared_reads: &BTreeMap<String, EvidenceDataClass>,
) -> Result<Vec<EvidenceQuery>, ComplyError> {
    let Some(v) = val else {
        return Ok(Vec::new());
    };
    let TomlVal::Array(items) = v else {
        return Err(ComplyError::VerificationFailed {
            detail: "`evidence_queries` must be an array of tables".into(),
        });
    };
    let mut queries = Vec::with_capacity(items.len());
    let mut seen_ids = BTreeSet::new();
    for item in items {
        let TomlVal::Table(tbl) = item else {
            return Err(ComplyError::VerificationFailed {
                detail: "`evidence_queries` entries must be tables".into(),
            });
        };
        for key in tbl.keys() {
            if !matches!(
                key.as_str(),
                "id" | "version" | "max_class" | "group_by" | "reads"
            ) {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("unknown key `{key}` in `[[evidence_queries]]`"),
                });
            }
        }
        let id = req_safe_str(tbl, "id", "evidence_queries")?;
        if !seen_ids.insert(id.clone()) {
            return Err(ComplyError::VerificationFailed {
                detail: format!("duplicate evidence query `{id}`"),
            });
        }
        let version = opt_safe_str(tbl, "version")?.unwrap_or_else(|| "1.0.0".to_owned());
        let max_class_raw = req_safe_str(tbl, "max_class", &id)?;
        let max_class = parse_data_class(&max_class_raw)?;
        let group_by = parse_string_list(tbl.get("group_by"), &id, "group_by")?;

        let Some(TomlVal::Array(read_vals)) = tbl.get("reads") else {
            return Err(ComplyError::InvalidEvidenceQuery {
                query_id: id,
                detail: "evidence query missing `reads` array".into(),
            });
        };
        let mut reads = Vec::with_capacity(read_vals.len());
        for rv in read_vals {
            let fr = parse_read_table(rv, &id)?;
            let declared_class = declared_reads.get(&fr.field_path).ok_or_else(|| {
                ComplyError::InvalidEvidenceQuery {
                    query_id: id.clone(),
                    detail: format!(
                        "query read path `{}` is not declared in pack `[[reads]]`",
                        fr.field_path
                    ),
                }
            })?;
            if fr.data_class > *declared_class {
                return Err(ComplyError::InvalidEvidenceQuery {
                    query_id: id.clone(),
                    detail: format!(
                        "query read path `{}` exceeds declared top-level class",
                        fr.field_path
                    ),
                });
            }
            reads.push(fr);
        }

        let capability = id
            .strip_prefix("q.")
            .map_or_else(|| id.clone(), |suffix| format!("cap.{suffix}"));
        queries.push(EvidenceQuery {
            id,
            version,
            capability,
            reads,
            max_class,
            group_by,
        });
    }
    Ok(queries)
}

fn parse_read_table(val: &TomlVal, ctx: &str) -> Result<FieldRead, ComplyError> {
    let TomlVal::Table(tbl) = val else {
        return Err(ComplyError::VerificationFailed {
            detail: format!("read entry in `{ctx}` must be a table"),
        });
    };
    for key in tbl.keys() {
        if !matches!(key.as_str(), "path" | "data_class") {
            return Err(ComplyError::VerificationFailed {
                detail: format!("unknown key `{key}` in read entry for `{ctx}`"),
            });
        }
    }
    let path = req_safe_str(tbl, "path", ctx)?;
    let class_raw = req_safe_str(tbl, "data_class", &path)?;
    Ok(FieldRead {
        field_path: path,
        data_class: parse_data_class(&class_raw)?,
    })
}

pub(crate) fn req_safe_str(
    tbl: &BTreeMap<String, TomlVal>,
    key: &str,
    ctx: &str,
) -> Result<String, ComplyError> {
    match tbl.get(key) {
        Some(TomlVal::Str(s)) => {
            let trimmed = s.trim();
            if !is_safe_manifest_token(trimmed) {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("invalid or empty `{key}` in `{ctx}`"),
                });
            }
            Ok(trimmed.to_owned())
        }
        _ => Err(ComplyError::VerificationFailed {
            detail: format!("missing string `{key}` in `{ctx}`"),
        }),
    }
}

pub(crate) fn opt_safe_str(
    tbl: &BTreeMap<String, TomlVal>,
    key: &str,
) -> Result<Option<String>, ComplyError> {
    match tbl.get(key) {
        None => Ok(None),
        Some(TomlVal::Str(s)) => {
            let trimmed = s.trim();
            if !is_safe_manifest_token(trimmed) {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("invalid value for optional key `{key}`"),
                });
            }
            Ok(Some(trimmed.to_owned()))
        }
        _ => Err(ComplyError::VerificationFailed {
            detail: format!("expected string for optional key `{key}`"),
        }),
    }
}

fn parse_string_list(
    val: Option<&TomlVal>,
    ctx: &str,
    field: &str,
) -> Result<Vec<String>, ComplyError> {
    let Some(v) = val else {
        return Ok(Vec::new());
    };
    let TomlVal::Array(items) = v else {
        return Err(ComplyError::VerificationFailed {
            detail: format!("`{field}` in `{ctx}` must be an array"),
        });
    };
    let mut out = Vec::with_capacity(items.len());
    for item in items {
        match item {
            TomlVal::Str(s) => {
                let trimmed = s.trim();
                if !is_safe_manifest_token(trimmed) {
                    return Err(ComplyError::VerificationFailed {
                        detail: format!("invalid entry in `{field}` for `{ctx}`"),
                    });
                }
                out.push(trimmed.to_owned());
            }
            _ => {
                return Err(ComplyError::VerificationFailed {
                    detail: format!("non-string entry in `{field}` for `{ctx}`"),
                });
            }
        }
    }
    Ok(out)
}

fn parse_data_class(raw: &str) -> Result<EvidenceDataClass, ComplyError> {
    match raw.trim().to_ascii_lowercase().as_str() {
        "structural" => Ok(EvidenceDataClass::Structural),
        "derived" => Ok(EvidenceDataClass::Derived),
        "identifier" => Ok(EvidenceDataClass::Identifier),
        "content" => Ok(EvidenceDataClass::Content),
        other => Err(ComplyError::InvalidEvidenceQuery {
            query_id: "pack.toml".into(),
            detail: format!("unknown P8 data_class `{other}`"),
        }),
    }
}
