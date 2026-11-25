// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Pack TOML manifest parsing, bounded file reading, and vocabulary/prose checks.

use std::fs;
use std::path::Path;

use grdr_schema_lint::{
    EvidenceQueryDecl, FieldReadDecl, LintFinding, PackDataClass, PackKind, PackManifest,
    lint_text_against_vocabulary,
};

use crate::ConformanceError;

pub const MAX_PACK_FILE_BYTES: u64 = 2 * 1024 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TomlBlock {
    Top,
    Reads,
    Query,
    QueryReads,
}

pub fn check_no_em_dash_or_vocab(
    path: &Path,
    text: &str,
    vocab: &grdr_schema_lint::VocabularyRegistry,
) -> Result<(), ConformanceError> {
    if text.contains('\u{2014}') {
        return Err(conf_err(
            "pack-prose",
            &format!("em dash found in `{}`", path.display()),
        ));
    }
    let mut findings: Vec<LintFinding> = Vec::new();
    lint_text_against_vocabulary(vocab, &path.display().to_string(), text, &mut findings);
    if !findings.is_empty() {
        return Err(conf_err(
            "pack-vocab",
            &format!("forbidden term in `{}`: {:?}", path.display(), findings),
        ));
    }
    Ok(())
}

pub fn parse_pack_manifest_toml(raw: &str) -> Result<PackManifest, ConformanceError> {
    let mut id = String::new();
    let mut version = String::new();
    let mut kind: Option<PackKind> = None;
    let mut per_person_scoring = false;
    let mut reads = Vec::new();
    let mut queries: Vec<EvidenceQueryDecl> = Vec::new();
    let mut block = TomlBlock::Top;
    let mut cur_read_path = String::new();
    let mut cur_read_class = None;
    let mut cur_q: Option<EvidenceQueryDecl> = None;

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[[reads]]" {
            flush_read(
                &mut block,
                &mut reads,
                &mut cur_q,
                &mut cur_read_path,
                &mut cur_read_class,
            )?;
            block = TomlBlock::Reads;
            continue;
        }
        if line == "[[evidence_queries]]" {
            flush_read(
                &mut block,
                &mut reads,
                &mut cur_q,
                &mut cur_read_path,
                &mut cur_read_class,
            )?;
            if let Some(q) = cur_q.take() {
                queries.push(q);
            }
            cur_q = Some(EvidenceQueryDecl {
                id: String::new(),
                reads: Vec::new(),
                max_class: PackDataClass::Derived,
                group_by: Vec::new(),
            });
            block = TomlBlock::Query;
            continue;
        }
        if line == "[[evidence_queries.reads]]" {
            flush_read(
                &mut block,
                &mut reads,
                &mut cur_q,
                &mut cur_read_path,
                &mut cur_read_class,
            )?;
            block = TomlBlock::QueryReads;
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = v.trim();
        match block {
            TomlBlock::Top => match key {
                "id" => id = unquote(val),
                "version" => version = unquote(val),
                "kind" => kind = Some(parse_kind(&unquote(val))?),
                "per_person_scoring" => per_person_scoring = val == "true",
                _ => {}
            },
            TomlBlock::Reads | TomlBlock::QueryReads => match key {
                "path" => cur_read_path = unquote(val),
                "data_class" => cur_read_class = Some(parse_class(&unquote(val))?),
                _ => {}
            },
            TomlBlock::Query => {
                if let Some(q) = cur_q.as_mut() {
                    match key {
                        "id" => q.id = unquote(val),
                        "max_class" => q.max_class = parse_class(&unquote(val))?,
                        "group_by" => q.group_by = parse_str_array(val),
                        _ => {}
                    }
                }
            }
        }
    }
    flush_read(
        &mut block,
        &mut reads,
        &mut cur_q,
        &mut cur_read_path,
        &mut cur_read_class,
    )?;
    if let Some(q) = cur_q.take() {
        queries.push(q);
    }
    let resolved_kind = kind.ok_or_else(|| conf_err("pack-toml", "missing pack kind"))?;
    Ok(PackManifest {
        id,
        version,
        kind: resolved_kind,
        reads,
        commands: Vec::new(),
        executables: Vec::new(),
        urls: Vec::new(),
        env_vars_to_set: Vec::new(),
        mcp_servers_to_start: Vec::new(),
        evidence_queries: queries,
        rule_snippets: Vec::new(),
        per_person_scoring,
    })
}

pub fn read_regular_text(path: &Path) -> Result<String, ConformanceError> {
    let meta = fs::symlink_metadata(path).map_err(|e| conf_err("pack-io", &e.to_string()))?;
    if meta.file_type().is_symlink() || !meta.is_file() || meta.len() > MAX_PACK_FILE_BYTES {
        return Err(conf_err(
            "pack-io",
            &format!("invalid regular file `{}`", path.display()),
        ));
    }
    fs::read_to_string(path).map_err(|e| conf_err("pack-io", &e.to_string()))
}

pub fn unquote(raw: &str) -> String {
    raw.trim().trim_matches('"').trim_matches('\'').to_owned()
}

pub fn conf_err(scenario_id: &str, detail: &str) -> ConformanceError {
    ConformanceError::ScenarioFailed {
        scenario_id: scenario_id.to_owned(),
        detail: detail.to_owned(),
    }
}

fn flush_read(
    block: &mut TomlBlock,
    top_reads: &mut Vec<FieldReadDecl>,
    cur_q: &mut Option<EvidenceQueryDecl>,
    path: &mut String,
    cls: &mut Option<PackDataClass>,
) -> Result<(), ConformanceError> {
    if path.is_empty() && cls.is_none() {
        return Ok(());
    }
    let p = std::mem::take(path);
    let c = cls
        .take()
        .ok_or_else(|| conf_err("pack-toml", "read missing data_class"))?;
    let decl = FieldReadDecl {
        path: p,
        data_class: c,
    };
    match block {
        TomlBlock::Reads => top_reads.push(decl),
        TomlBlock::QueryReads => {
            if let Some(q) = cur_q.as_mut() {
                q.reads.push(decl);
            }
        }
        _ => {}
    }
    Ok(())
}

fn parse_kind(raw: &str) -> Result<PackKind, ConformanceError> {
    match raw {
        "policy" => Ok(PackKind::Policy),
        "detection" => Ok(PackKind::Detection),
        "compliance" => Ok(PackKind::Compliance),
        "intel" => Ok(PackKind::Intel),
        other => Err(conf_err(
            "pack-toml",
            &format!("unknown pack kind `{other}`"),
        )),
    }
}

fn parse_class(raw: &str) -> Result<PackDataClass, ConformanceError> {
    match raw {
        "public" => Ok(PackDataClass::Public),
        "identifier" => Ok(PackDataClass::Identifier),
        "structural" => Ok(PackDataClass::Structural),
        "derived" => Ok(PackDataClass::Derived),
        "content" => Ok(PackDataClass::Content),
        "secret" => Ok(PackDataClass::Secret),
        other => Err(conf_err(
            "pack-toml",
            &format!("unknown data class `{other}`"),
        )),
    }
}

fn parse_str_array(raw: &str) -> Vec<String> {
    raw.trim()
        .trim_start_matches('[')
        .trim_end_matches(']')
        .split(',')
        .map(unquote)
        .filter(|s| !s.is_empty())
        .collect()
}
