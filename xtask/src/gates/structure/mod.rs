//! Checks S1 to S7 of the `grdr-structure` skill (owner instructions 4, 15 and 26), and the
//! interface checks UX1 to UX8 of [`crate::gates::interface`], which read the same sources.
//! `post-edit` and `stop-gate` call [`check_files`] for both families; verify gate V20 calls
//! [`check_changed`] for the structure family and V26 for the interface family. S5 warns; every
//! other check blocks.

mod comments;
#[cfg(test)]
mod corpus_tests;
mod hardcoded;
mod items;
pub(crate) mod lexer;
mod nesting;
mod panics;
pub(crate) mod patterns;
mod policy;
mod rust;
pub(crate) mod syntax;
mod typescript;

pub use hardcoded::{BRAND_PATH, Names, VENDORS_PATH};
pub(crate) use hardcoded::{NameKind, visible, visual};
pub(crate) use policy::read as policy_read;
pub use policy::{
    EXEMPTIONS_PATH, Exemption, FILE_SIZE_PATH, FileSizeEntry, FileSizeRatchet,
    HARDCODED_EXEMPTIONS_PATH, HardcodedExemption, Pattern, Policy,
};

use std::fmt;
use std::process::ExitCode;

use anyhow::Result;
use serde::Serialize;

use crate::cli::{self, Spec};
use crate::config::limits::{Limits, StructureLimits};
use crate::gates::interface;
use crate::git::{self, AddedLines, Base};
use crate::globs::{Case, GlobList};
use crate::paths::{Located, RepoPath};
use crate::repo::Repo;

/// The line `post-edit` and the gate print so the model loads the skill before fixing the file.
pub const SKILL_HINT: &str = "load the grdr-structure skill";
const NOT_CHECKED: &[&str] = &[
    "third_party/**",
    "**/fixtures/**",
    "**/node_modules/**",
    "target/**",
    "**/vendor/**",
    ".claude/**",
];
/// Test code, where S6 and S7 do not apply: unwrapping and literal fixtures are fine there.
const TEST_PATHS: &[&str] = &[
    "**/tests/**",
    "**/benches/**",
    "**/tests.rs",
    "**/*_tests.rs",
    "**/testkit.rs",
    "**/*.test.*",
    "**/*.spec.*",
    "**/__tests__/**",
    "**/test/**",
    "**/e2e/**",
];
const RUST_EXTENSIONS: &[&str] = &["rs"];
const SCRIPT_EXTENSIONS: &[&str] = &["ts", "mts", "cts", "js", "mjs", "cjs"];
const MARKUP_EXTENSIONS: &[&str] = &["tsx", "jsx"];
const STYLE_EXTENSIONS: &[&str] = &["css"];

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize)]
pub enum Check {
    S1,
    S2,
    S3,
    S4,
    S5,
    S6,
    S7,
    UX1,
    UX2,
    UX3,
    UX4,
    UX5,
    UX6,
    UX7,
    UX8,
}

/// The skill a check belongs to, which decides the gate that runs it and the hint it prints.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Family {
    Structure,
    Interface,
}

/// The kind of file a check reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Language {
    Rust,
    Script,
    Markup,
    Style,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct Finding {
    pub check: Check,
    pub path: String,
    pub line: usize,
    pub message: String,
}

#[derive(Debug, Clone, Default, Serialize)]
pub struct Report {
    pub findings: Vec<Finding>,
}

/// One finding before it gets its path, with what an exemption would name.
#[derive(Debug, Clone)]
pub(crate) struct Raw {
    pub(crate) check: Check,
    pub(crate) line: usize,
    pub(crate) message: String,
    pub(crate) key: Option<Key>,
}

/// What an exemption entry names for a finding.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Key {
    /// S4: the type and the rule it broke, in `quality/state-machine-exemptions.toml`.
    State { type_name: String, pattern: Pattern },
    /// S6 and S7: the construct or literal, in `quality/hardcoded-exemptions.toml`.
    Value(String),
}

struct Analysis {
    code_lines: usize,
    findings: Vec<Raw>,
}

/// One file as every check reads it.
pub(crate) struct Source<'a> {
    pub(crate) path: &'a RepoPath,
    pub(crate) text: &'a str,
    pub(crate) language: Language,
    /// `None` for a stylesheet, which the token checks do not read.
    pub(crate) lexed: Option<lexer::Lexed>,
    pub(crate) added: &'a AddedLines,
    test_file: bool,
    test_lines: Vec<(usize, usize)>,
}

/// Where text on a source line sits, for checks that read code only or comments only.
pub struct SourceMap {
    lexed: lexer::Lexed,
    test_lines: Vec<(usize, usize)>,
}

impl Check {
    pub fn family(self) -> Family {
        match self {
            Check::S1 | Check::S2 | Check::S3 | Check::S4 | Check::S5 | Check::S6 | Check::S7 => {
                Family::Structure
            }
            Check::UX1
            | Check::UX2
            | Check::UX3
            | Check::UX4
            | Check::UX5
            | Check::UX6
            | Check::UX7
            | Check::UX8 => Family::Interface,
        }
    }

    /// S5 is a warning; every other check blocks the stop and the gate.
    pub fn blocks(self) -> bool {
        self != Check::S5
    }
}

impl Family {
    pub fn hint(self) -> &'static str {
        match self {
            Family::Structure => SKILL_HINT,
            Family::Interface => interface::HINT,
        }
    }
}

impl Language {
    fn of(path: &RepoPath) -> Option<Language> {
        let extension = path.extension()?;
        let table = [
            (RUST_EXTENSIONS, Language::Rust),
            (SCRIPT_EXTENSIONS, Language::Script),
            (MARKUP_EXTENSIONS, Language::Markup),
            (STYLE_EXTENSIONS, Language::Style),
        ];
        table
            .iter()
            .find(|(extensions, _)| extensions.contains(&extension))
            .map(|(_, language)| *language)
    }

    fn lexer(self) -> Option<lexer::Language> {
        match self {
            Language::Rust => Some(lexer::Language::Rust),
            Language::Script => Some(lexer::Language::Script),
            Language::Markup => Some(lexer::Language::Markup),
            Language::Style => None,
        }
    }
}

impl fmt::Display for Check {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{self:?}")
    }
}

impl fmt::Display for Finding {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {}:{}: {}",
            self.check, self.path, self.line, self.message
        )
    }
}

impl Report {
    pub fn blocking(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|finding| finding.check.blocks())
    }

    pub fn warnings(&self) -> impl Iterator<Item = &Finding> {
        self.findings
            .iter()
            .filter(|finding| !finding.check.blocks())
    }

    pub fn blocks(&self) -> bool {
        self.blocking().next().is_some()
    }

    /// The skill hint of each family with a blocking finding, structure first.
    pub fn hints(&self) -> Vec<&'static str> {
        let mut families: Vec<Family> = self
            .blocking()
            .map(|finding| finding.check.family())
            .collect();
        families.sort();
        families.dedup();
        families.into_iter().map(Family::hint).collect()
    }

    fn only(mut self, family: Family) -> Report {
        self.findings
            .retain(|finding| finding.check.family() == family);
        self
    }
}

impl Raw {
    pub(crate) fn new(check: Check, line: usize, message: String) -> Raw {
        Raw {
            check,
            line,
            message,
            key: None,
        }
    }

    /// An S4 finding on `type_name`, which an exemption for that type and pattern silences.
    fn state(line: usize, message: String, type_name: &str, pattern: Pattern) -> Raw {
        Raw {
            check: Check::S4,
            line,
            message,
            key: Some(Key::State {
                type_name: type_name.to_owned(),
                pattern,
            }),
        }
    }

    /// An S6 or S7 finding on `value`, which an exemption for that value in the file silences.
    pub(crate) fn valued(check: Check, line: usize, message: String, value: &str) -> Raw {
        Raw {
            check,
            line,
            message,
            key: Some(Key::Value(value.to_owned())),
        }
    }
}

impl<'a> Source<'a> {
    fn read(path: &'a RepoPath, text: &'a str, added: &'a AddedLines) -> Option<Source<'a>> {
        let language = Language::of(path)?;
        let lexed = language.lexer().map(|lexer| lexer::lex(text, lexer));
        let test_lines = match (&lexed, language) {
            (Some(lexed), Language::Rust) => rust::test_lines(lexed),
            _ => Vec::new(),
        };
        let test_file = GlobList::new(TEST_PATHS, Case::Sensitive)
            .is_ok_and(|globs| globs.is_match(path.as_str()));
        Some(Source {
            path,
            text,
            language,
            lexed,
            added,
            test_file,
            test_lines,
        })
    }

    /// Whether 1-based `line` is test code: a test file, or inside a `#[cfg(test)]` item.
    pub(crate) fn in_test(&self, line: usize) -> bool {
        self.test_file || within(&self.test_lines, line)
    }

    pub(crate) fn tokens(&self) -> &[lexer::Token] {
        self.lexed
            .as_ref()
            .map_or(&[], |lexed| lexed.tokens.as_slice())
    }
}

impl SourceMap {
    /// The map of a Rust or script source the structure checks apply to; `None` for any other file.
    pub fn of(path: &RepoPath, source: &str) -> Option<SourceMap> {
        if !applies_to(path) {
            return None;
        }
        let language = Language::of(path)?;
        let lexed = lexer::lex(source, language.lexer()?);
        let test_lines = match language {
            Language::Rust => rust::test_lines(&lexed),
            _ => Vec::new(),
        };
        Some(SourceMap { lexed, test_lines })
    }

    /// Whether 1-based `line` is inside a `#[cfg(test)]` item.
    pub fn in_test(&self, line: usize) -> bool {
        within(&self.test_lines, line)
    }

    /// Whether `text` on 1-based `line` is part of a string literal, markup text or a comment.
    pub fn outside_code(&self, line: usize, text: &str) -> bool {
        let in_literal = self.lexed.tokens.iter().any(|token| {
            token.line == line
                && matches!(
                    token.kind,
                    lexer::TokenKind::Literal | lexer::TokenKind::Text
                )
                && token.value.contains(text)
        });
        in_literal || self.in_comment(line, text)
    }

    /// Whether `text` on 1-based `line` is inside a comment.
    pub fn in_comment(&self, line: usize, text: &str) -> bool {
        self.lexed
            .lines
            .get(line.saturating_sub(1))
            .is_some_and(|found| {
                found
                    .comments
                    .iter()
                    .any(|comment| comment.text.contains(text))
            })
    }
}

/// Whether `line` falls in one of the inclusive `(first, last)` ranges.
fn within(ranges: &[(usize, usize)], line: usize) -> bool {
    ranges
        .iter()
        .any(|(first, last)| (*first..=*last).contains(&line))
}

/// Whether the structure or interface checks read this path at all.
pub fn applies_to(path: &RepoPath) -> bool {
    Language::of(path).is_some()
        && GlobList::new(NOT_CHECKED, Case::Sensitive)
            .is_ok_and(|globs| !globs.is_match(path.as_str()))
}

/// Checks one file's text. `added` limits S3 and S6 to new lines; the other checks read the file.
pub fn analyse(path: &RepoPath, source: &str, added: &AddedLines, policy: &Policy) -> Vec<Finding> {
    let Some(source) = Source::read(path, source, added) else {
        return Vec::new();
    };
    let mut raw = Vec::new();
    if let Some(lexed) = &source.lexed {
        let analysis = match source.language {
            Language::Rust => rust::analyse(lexed, &policy.limits),
            _ => typescript::analyse(lexed, &policy.limits),
        };
        raw.extend(size_finding(path, analysis.code_lines, policy));
        raw.extend(comment_findings(lexed, added, &policy.limits));
        raw.extend(analysis.findings);
        raw.extend(panics::findings(&source));
    }
    raw.extend(hardcoded::findings(&source, policy));
    raw.extend(interface::findings(&source, policy));
    let mut findings: Vec<Finding> = raw
        .into_iter()
        .filter(|raw| {
            !raw.key
                .as_ref()
                .is_some_and(|key| policy.exempt(path.as_str(), raw.check, key))
        })
        .map(|raw| Finding {
            check: raw.check,
            path: path.to_string(),
            line: raw.line,
            message: raw.message,
        })
        .collect();
    findings.sort_by_key(|finding| (finding.check, finding.line));
    findings.dedup();
    findings
}

/// Checks files on disk against `base`, both families: the policy files and the added lines of
/// S3 and S6 come from there.
pub fn check_files(repo: &Repo, base: &Base, paths: &[RepoPath]) -> Result<Report> {
    let paths: Vec<RepoPath> = paths
        .iter()
        .filter(|path| applies_to(path))
        .cloned()
        .collect();
    let policy = Policy::load(repo, base)?;
    let added = git::added_lines(repo, base, &paths)?;
    let mut report = Report::default();
    for path in &paths {
        let Ok(source) = std::fs::read_to_string(repo.path(path.as_str())) else {
            continue;
        };
        let lines = added.get(path).cloned().unwrap_or(AddedLines::All);
        report
            .findings
            .extend(analyse(path, &source, &lines, &policy));
    }
    Ok(report)
}

/// Every changed source file against `base` for one family; for the structure family also the S1
/// ratchet, which may only shrink.
pub fn check_changed(repo: &Repo, base: &Base, family: Family) -> Result<Report> {
    let changed = git::changed_files(repo, base)?;
    let mut report = check_files(repo, base, &changed)?.only(family);
    let ratchet_changed = changed.iter().any(|path| path.as_str() == FILE_SIZE_PATH);
    if let (Family::Structure, true, Some(commit)) = (family, ratchet_changed, base.commit()) {
        let before = git::show(repo, commit, FILE_SIZE_PATH)?
            .map(|text| crate::config::parse_toml::<FileSizeRatchet>(&text, FILE_SIZE_PATH))
            .transpose()?
            .unwrap_or_default();
        let now = FileSizeRatchet::from_working_tree(repo)?.unwrap_or_default();
        report.findings.extend(
            now.loosened_since(&before)
                .into_iter()
                .map(|message| Finding {
                    check: Check::S1,
                    path: FILE_SIZE_PATH.to_owned(),
                    line: 1,
                    message,
                }),
        );
    }
    Ok(report)
}

/// `cargo xtask structure [--base <ref>] [<path>...]`: the given files, or every changed one.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(
        args,
        &Spec {
            flags: &[],
            options: &["--base"],
        },
    )?;
    let repo = Repo::discover()?;
    let base = git::base_for(&repo, parsed.value("--base"))?;
    let printed = Limits::load(&repo, &base)?.gates.structure.printed_findings;
    let report = if parsed.positional.is_empty() {
        let mut report = check_changed(&repo, &base, Family::Structure)?;
        report
            .findings
            .extend(check_changed(&repo, &base, Family::Interface)?.findings);
        report
    } else {
        let cwd = std::env::current_dir()?;
        let mut paths = Vec::new();
        for raw in &parsed.positional {
            match repo.locate(raw, Some(&cwd)) {
                Located::Inside(path) => paths.push(path),
                Located::Outside(path) => anyhow::bail!("{path} is outside the repository"),
            }
        }
        check_files(&repo, &base, &paths)?
    };
    for finding in report.findings.iter().take(printed) {
        let label = if finding.check.blocks() {
            "ERROR"
        } else {
            "warning"
        };
        println!("{label} {finding}");
    }
    if let Some(more) = report
        .findings
        .len()
        .checked_sub(printed)
        .filter(|n| *n > 0)
    {
        println!("... and {more} more");
    }
    if report.blocks() {
        for hint in report.hints() {
            println!("{hint}");
        }
        return Ok(ExitCode::from(2));
    }
    Ok(ExitCode::SUCCESS)
}

fn size_finding(path: &RepoPath, code_lines: usize, policy: &Policy) -> Option<Raw> {
    let limit = policy.limits.max_code_lines;
    if code_lines <= limit {
        return None;
    }
    let message = match policy.allowed_lines(path.as_str()) {
        Some(allowed) if code_lines <= allowed => return None,
        Some(allowed) => format!(
            "{code_lines} code lines, above its ratchet of {allowed} in {FILE_SIZE_PATH}; split it by responsibility"
        ),
        None => format!(
            "{code_lines} code lines (limit {limit}; blank lines, comments and tests excluded); split it by responsibility"
        ),
    };
    Some(Raw::new(Check::S1, 1, message))
}

fn comment_findings(
    lexed: &lexer::Lexed,
    added: &AddedLines,
    limits: &StructureLimits,
) -> Vec<Raw> {
    let mut found = Vec::new();
    for (index, line) in lexed.lines.iter().enumerate() {
        let number = index + 1;
        if !added.contains(number) {
            continue;
        }
        for comment in &line.comments {
            if let Some(reason) = comments::classify(&comment.text, comment.doc) {
                let quoted = excerpt(&comment.text, limits.excerpt_chars);
                found.push(Raw::new(Check::S3, number, format!("{reason}: `{quoted}`")));
            }
        }
    }
    found
}

pub(crate) fn excerpt(text: &str, width: usize) -> String {
    let mut out: String = text.chars().take(width).collect();
    if text.chars().count() > width {
        out.push_str("...");
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(p: &str) -> RepoPath {
        RepoPath::new(p).unwrap()
    }

    #[test]
    fn s1_counts_against_the_limit_and_the_ratchet() {
        let source: String = (0..510).map(|i| format!("const C{i}: u8 = 0;\n")).collect();
        let findings = analyse(
            &path("src/big.rs"),
            &source,
            &AddedLines::All,
            &Policy::for_tests(),
        );
        assert_eq!(
            findings.iter().map(|f| f.check).collect::<Vec<_>>(),
            vec![Check::S1]
        );
        let mut policy = Policy::for_tests();
        policy.ratchet.files = vec![FileSizeEntry {
            path: "src/big.rs".into(),
            code_lines: 520,
        }];
        assert!(analyse(&path("src/big.rs"), &source, &AddedLines::All, &policy).is_empty());
        policy.ratchet.files = vec![FileSizeEntry {
            path: "src/big.rs".into(),
            code_lines: 505,
        }];
        assert_eq!(
            analyse(&path("src/big.rs"), &source, &AddedLines::All, &policy).len(),
            1
        );
    }

    #[test]
    fn s3_only_judges_added_lines() {
        let source = "// Create the client\nfn a() {}\n// Loop over all items\nfn b() {}\n";
        let only_third = AddedLines::Only([3].into_iter().collect());
        let findings = analyse(&path("src/a.rs"), source, &only_third, &Policy::for_tests());
        assert_eq!(
            findings
                .iter()
                .map(|f| (f.check, f.line))
                .collect::<Vec<_>>(),
            vec![(Check::S3, 3)]
        );
        assert_eq!(
            analyse(
                &path("src/a.rs"),
                source,
                &AddedLines::All,
                &Policy::for_tests()
            )
            .len(),
            2
        );
    }

    #[test]
    fn s4_exemption_silences_only_its_type() {
        let source = "struct Flags {\n    a: bool,\n    b: bool,\n    c: bool,\n}\nstruct Job {\n    x: bool,\n    y: bool,\n    z: bool,\n}\n";
        let mut policy = Policy::for_tests();
        policy.exemptions = vec![Exemption {
            path: "src/a.rs".into(),
            type_name: "Flags".into(),
            pattern: Pattern::BoolFields,
            reason: "switches".into(),
            requested_in: "#12".into(),
            added_by: "lead-agent-kit".into(),
        }];
        let findings = analyse(&path("src/a.rs"), source, &AddedLines::All, &policy);
        assert_eq!(findings.len(), 1);
        assert!(findings[0].message.contains("`Job`"));
    }

    #[test]
    fn s5_is_a_warning_and_other_files_are_skipped() {
        let deep = "fn f() { if a { if b { if c { if d { if e { g() } } } } } }\n";
        let report = Report {
            findings: analyse(
                &path("src/a.rs"),
                deep,
                &AddedLines::All,
                &Policy::for_tests(),
            ),
        };
        assert_eq!(report.warnings().count(), 1);
        assert!(!report.blocks());
        assert!(
            analyse(
                &path("README.md"),
                "# Create the client",
                &AddedLines::All,
                &Policy::for_tests()
            )
            .is_empty()
        );
        assert!(!applies_to(&path("xtask/fixtures/hooks/bad.rs")));
        assert!(applies_to(&path("web/src/app.tsx")));
        assert!(applies_to(&path("web/src/app.css")));
    }

    #[test]
    fn hints_name_each_blocking_family_once() {
        let finding = |check| Finding {
            check,
            path: "a".into(),
            line: 1,
            message: String::new(),
        };
        let report = Report {
            findings: vec![finding(Check::UX3), finding(Check::S6), finding(Check::UX1)],
        };
        assert_eq!(report.hints(), vec![SKILL_HINT, interface::HINT]);
        let only = report.only(Family::Interface);
        assert_eq!(only.findings.len(), 2);
    }

    #[test]
    fn test_files_are_known_by_path() {
        let added = AddedLines::All;
        let unit = path("crates/a/src/dispatch/tests.rs");
        assert!(Source::read(&unit, "", &added).unwrap().in_test(1));
        let spec = path("web/apps/console/src/a.spec.tsx");
        assert!(Source::read(&spec, "", &added).unwrap().in_test(1));
        let code = path("crates/a/src/lib.rs");
        let source = "fn a() {}\n#[cfg(test)]\nmod tests {\n    fn t() {}\n}\n";
        let read = Source::read(&code, source, &added).unwrap();
        assert!(!read.in_test(1));
        assert!(read.in_test(4));
    }
}
