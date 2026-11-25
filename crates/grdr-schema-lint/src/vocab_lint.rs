// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Vocabulary registry parser and terminology consistency linter (`contracts/interface/vocabulary.toml`).

use std::fs;
use std::path::Path;

use serde::{Deserialize, Serialize};

use crate::{
    LintDomain, LintError, LintFinding, LintSeverity, MAX_LINT_FILE_BYTES,
    read_bounded_regular_file,
};

const REQUIRED_TERM_KEYS: &[&str] = &[
    "mode",
    "verdict",
    "assurance_level",
    "grant",
    "receipt",
    "finding",
    "incident",
    "sponsor",
];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VocabularyEntry {
    pub key: String,
    pub term: String,
    pub translate: bool,
    pub desc: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VocabularyForbidden {
    pub word: String,
    pub replacement: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VocabularyRegistry {
    pub brand_name: String,
    pub short_name: String,
    pub terms: Vec<VocabularyEntry>,
    pub forbidden: Vec<VocabularyForbidden>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum TomlSection {
    None,
    Brand,
    Term,
    Forbidden,
}

#[derive(Default)]
struct VocabParserState {
    brand_name: String,
    short_name: String,
    cur_key: String,
    cur_term: String,
    cur_translate: bool,
    cur_desc: String,
    cur_word: String,
    cur_replacement: String,
    terms: Vec<VocabularyEntry>,
    forbidden: Vec<VocabularyForbidden>,
}

impl VocabParserState {
    fn flush(&mut self, section: TomlSection) {
        let key = std::mem::take(&mut self.cur_key);
        let term = std::mem::take(&mut self.cur_term);
        let translate = std::mem::take(&mut self.cur_translate);
        let desc = std::mem::take(&mut self.cur_desc);
        let word = std::mem::take(&mut self.cur_word);
        let replacement = std::mem::take(&mut self.cur_replacement);

        match section {
            TomlSection::Term if !key.is_empty() => {
                self.terms.push(VocabularyEntry {
                    key,
                    term,
                    translate,
                    desc,
                });
            }
            TomlSection::Forbidden if !word.is_empty() => {
                self.forbidden
                    .push(VocabularyForbidden { word, replacement });
            }
            _ => {}
        }
    }
}

pub fn lint_vocabulary_toml(
    path: &Path,
    findings: &mut Vec<LintFinding>,
) -> Result<usize, LintError> {
    let parent = path.parent().unwrap_or(path);
    let canon_root = fs::canonicalize(parent).map_err(|e| LintError::Io {
        path: path.display().to_string(),
        detail: e.to_string(),
    })?;
    let raw = read_bounded_regular_file(&canon_root, path, MAX_LINT_FILE_BYTES)?;
    let registry = parse_vocabulary_toml(&raw)?;

    for req_key in REQUIRED_TERM_KEYS {
        if !registry.terms.iter().any(|t| t.key == *req_key) {
            findings.push(LintFinding {
                code: "GRDR-LINT-0004".into(),
                domain: LintDomain::Vocabulary,
                severity: LintSeverity::Error,
                target: path.display().to_string(),
                message: format!("missing canonical vocabulary term `{req_key}`"),
            });
        }
    }

    if registry.forbidden.is_empty() {
        findings.push(LintFinding {
            code: "GRDR-LINT-0004".into(),
            domain: LintDomain::Vocabulary,
            severity: LintSeverity::Error,
            target: path.display().to_string(),
            message: "vocabulary registry must declare forbidden synonyms".into(),
        });
    }

    for term in &registry.terms {
        for forbidden in &registry.forbidden {
            if contains_standalone_word(&term.desc, &forbidden.word) {
                findings.push(LintFinding {
                    code: "GRDR-LINT-0004".into(),
                    domain: LintDomain::Vocabulary,
                    severity: LintSeverity::Error,
                    target: format!("term.{}", term.key),
                    message: format!(
                        "forbidden synonym `{}` in term description; use `{}`",
                        forbidden.word, forbidden.replacement
                    ),
                });
            }
        }
    }

    Ok(registry.terms.len())
}

pub fn lint_text_against_vocabulary(
    registry: &VocabularyRegistry,
    target_label: &str,
    text: &str,
    findings: &mut Vec<LintFinding>,
) {
    for forbidden in &registry.forbidden {
        if contains_standalone_word(text, &forbidden.word) {
            findings.push(LintFinding {
                code: "GRDR-LINT-0004".into(),
                domain: LintDomain::Vocabulary,
                severity: LintSeverity::Error,
                target: target_label.into(),
                message: format!(
                    "forbidden Guardrails synonym `{}` found; use `{}`",
                    forbidden.word, forbidden.replacement
                ),
            });
        }
    }
}

pub fn parse_vocabulary_toml(raw: &str) -> Result<VocabularyRegistry, LintError> {
    let mut state = VocabParserState::default();
    let mut section = TomlSection::None;

    for raw_line in raw.lines() {
        let line = raw_line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == "[brand]" {
            state.flush(section);
            section = TomlSection::Brand;
            continue;
        }
        if line == "[[term]]" {
            state.flush(section);
            section = TomlSection::Term;
            continue;
        }
        if line == "[[forbidden]]" {
            state.flush(section);
            section = TomlSection::Forbidden;
            continue;
        }

        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let key = k.trim();
        let val = unquote(v.trim());
        match section {
            TomlSection::Brand => match key {
                "name" => state.brand_name = val,
                "short_name" => state.short_name = val,
                _ => {}
            },
            TomlSection::Term => match key {
                "key" => state.cur_key = val,
                "term" => state.cur_term = val,
                "translate" => state.cur_translate = val == "true",
                "desc" => state.cur_desc = val,
                _ => {}
            },
            TomlSection::Forbidden => match key {
                "word" => state.cur_word = val,
                "replacement" => state.cur_replacement = val,
                _ => {}
            },
            TomlSection::None => {}
        }
    }

    state.flush(section);

    if state.brand_name.is_empty() {
        return Err(LintError::VocabularyViolation {
            detail: "missing `[brand].name` in vocabulary.toml".into(),
        });
    }

    Ok(VocabularyRegistry {
        brand_name: state.brand_name,
        short_name: state.short_name,
        terms: state.terms,
        forbidden: state.forbidden,
    })
}

fn unquote(raw: &str) -> String {
    let trimmed = raw.trim();
    if trimmed.starts_with('"') && trimmed.ends_with('"') && trimmed.len() >= 2 {
        trimmed
            .get(1..trimmed.len().saturating_sub(1))
            .unwrap_or("")
            .to_owned()
    } else {
        trimmed.to_owned()
    }
}

fn contains_standalone_word(haystack: &str, word: &str) -> bool {
    let lower_hay = haystack.to_ascii_lowercase();
    let lower_word = word.to_ascii_lowercase();
    let bytes = lower_hay.as_bytes();
    let wlen = lower_word.len();
    if wlen == 0 {
        return false;
    }

    let mut search_from: usize = 0;
    while let Some(rel_idx) = lower_hay
        .get(search_from..)
        .and_then(|s| s.find(&lower_word))
    {
        let start = search_from.saturating_add(rel_idx);
        let end = start.saturating_add(wlen);
        let prev_ok = start == 0
            || bytes
                .get(start.saturating_sub(1))
                .is_some_and(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        let next_ok = end >= bytes.len()
            || bytes
                .get(end)
                .is_some_and(|b| !b.is_ascii_alphanumeric() && *b != b'_');
        if prev_ok && next_ok {
            return true;
        }
        search_from = start.saturating_add(1);
    }
    false
}
