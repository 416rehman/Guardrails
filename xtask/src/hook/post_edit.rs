//! `PostToolUse` on the file tools (team/03 section 4.1, owner instructions 4, 15, 19 and 26):
//! rustfmt on a `.rs` file, then the structure checks S1 to S7 and, on the interface paths, the
//! interface checks UX1 to UX8 on the edited file (S3 and S6 on its new lines only), and new
//! suppressions without a reason. Every blocking finding comes back as `decision: block` with the
//! hint of each family that found something ("load the grdr-structure skill", "load the
//! ui-architect skill, then grdr-interface"); S5 is feedback only.

use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::LazyLock;

use anyhow::Result;

use super::context::{Context, tool_path};
use super::outcome::{Outcome, capped};
use crate::config::limits::{Limits, PostEditLimits};
use crate::gates::structure::patterns::{Compiled, compile, find};
use crate::gates::structure::{self, SourceMap};
use crate::git::{self, AddedLines};
use crate::paths::RepoPath;
use crate::process;
use crate::repo::Repo;

const DEFAULT_EDITION: &str = "2024";
const MANIFEST: &str = "Cargo.toml";
const LINT: &str = "a lint suppression";
const IGNORE: &str = "#[ignore]";
const DIRECTIVE: &str = "a lint directive";

static RUST_LINT: Compiled = LazyLock::new(|| compile(r"#!?\[\s*(allow|expect)\s*\("));
static RUST_IGNORE: Compiled = LazyLock::new(|| compile(r"#\[\s*ignore\s*\]"));
static SCRIPT_DIRECTIVE: Compiled = LazyLock::new(|| {
    compile(r"@ts-(ignore|expect-error|nocheck)|eslint-disable(-next-line|-line)?|biome-ignore\S*")
});

pub fn run(context: &Context) -> Result<Outcome> {
    let Some(raw) = tool_path(&context.input) else {
        return Ok(Outcome::Allow);
    };
    let Some(path) = context.locate_inside(raw) else {
        return Ok(Outcome::Allow);
    };
    let file = context.repo.path(path.as_str());
    if !file.is_file() {
        return Ok(Outcome::Allow);
    }
    let base = git::resolve_base(&context.repo)?;
    let limits = Limits::load(&context.repo, &base)?.hook.post_edit;
    if path.extension() == Some("rs") {
        format_rust(context, &file, &limits);
    }
    let report = structure::check_files(&context.repo, &base, std::slice::from_ref(&path))?;
    let mut blocking: Vec<String> = report.blocking().map(ToString::to_string).collect();
    let hints = report.hints();
    blocking.extend(new_suppressions(
        &context.repo,
        &base,
        std::slice::from_ref(&path),
    )?);
    let warnings: Vec<String> = report
        .warnings()
        .map(|finding| format!("warning {finding}"))
        .collect();
    for line in blocking.iter().chain(&warnings) {
        context.note(line.clone());
    }
    if !blocking.is_empty() {
        let mut lines = capped(&blocking, limits.printed_findings);
        lines.extend(hints.into_iter().map(str::to_owned));
        return Ok(Outcome::Block(lines.join("\n")));
    }
    if !warnings.is_empty() {
        let mut lines = capped(&warnings, limits.printed_findings);
        lines.push(
            "S5 is feedback only; return early or extract a function when you next touch it"
                .to_owned(),
        );
        return Ok(Outcome::Context(lines.join("\n")));
    }
    Ok(Outcome::Allow)
}

/// Suppressions on the lines `paths` add against `base` that carry no reason, in the Rust and
/// script sources the structure checks read: a lint suppression in code outside the test module,
/// `#[ignore]` in code, and a script directive in a comment. Prose, data files and string
/// literals that only mention a suppression are not suppressions. Panic macros are S6's.
pub fn new_suppressions(repo: &Repo, base: &git::Base, paths: &[RepoPath]) -> Result<Vec<String>> {
    let min_reason = Limits::load(repo, base)?.hook.post_edit.min_reason_chars;
    let sources: Vec<RepoPath> = paths
        .iter()
        .filter(|path| structure::applies_to(path))
        .cloned()
        .collect();
    let added = git::added_lines(repo, base, &sources)?;
    let mut problems = Vec::new();
    for path in &sources {
        let Ok(text) = std::fs::read_to_string(repo.path(path.as_str())) else {
            continue;
        };
        let Some(map) = SourceMap::of(path, &text) else {
            continue;
        };
        let lines: Vec<&str> = text.lines().collect();
        let only = added.get(path).cloned().unwrap_or(AddedLines::All);
        for (index, line) in lines.iter().enumerate() {
            let number = index + 1;
            if !only.contains(number) {
                continue;
            }
            let previous = index.checked_sub(1).and_then(|i| lines.get(i)).copied();
            let found =
                unexplained_match(line, previous, min_reason).filter(
                    |(kind, matched)| match *kind {
                        IGNORE => !map.outside_code(number, matched),
                        DIRECTIVE => map.in_comment(number, matched),
                        _ => !map.in_test(number) && !map.outside_code(number, matched),
                    },
                );
            if let Some((kind, _)) = found {
                problems.push(format!(
                    "{path}:{number}: {kind} without a reason; say why, or fix the cause"
                ));
            }
        }
    }
    Ok(problems)
}

/// The suppression on `line` that has no reason of at least `min_reason` characters beside it or
/// on the comment line above it: its kind and the text that matched.
fn unexplained_match(
    line: &str,
    previous: Option<&str>,
    min_reason: usize,
) -> Option<(&'static str, String)> {
    let long_enough = |reason: &str| reason.trim().chars().count() >= min_reason;
    let commented_above = previous.is_some_and(|above| {
        let above = above.trim_start();
        above.starts_with("//")
            && !above.starts_with("///")
            && long_enough(above.trim_start_matches('/'))
    });
    let trailing = line
        .split_once("//")
        .is_some_and(|(_, comment)| long_enough(comment));
    let explained = commented_above || trailing;
    if let Some(found) = find(&RUST_LINT, line)
        && !line.contains("reason")
        && !explained
    {
        return Some((LINT, found.as_str().to_owned()));
    }
    if let Some(found) = find(&RUST_IGNORE, line).filter(|_| !explained) {
        return Some((IGNORE, found.as_str().to_owned()));
    }
    let directive = find(&SCRIPT_DIRECTIVE, line)?;
    let after = line.get(directive.end()..).unwrap_or_default();
    let reason = if directive.as_str().starts_with("eslint") {
        after
            .split_once("--")
            .is_some_and(|(_, why)| long_enough(why))
    } else {
        long_enough(
            after
                .trim_start_matches([':', ' ', '-'])
                .trim()
                .trim_end_matches("*/"),
        )
    };
    (!reason).then(|| (DIRECTIVE, directive.as_str().to_owned()))
}

fn format_rust(context: &Context, file: &Path, limits: &PostEditLimits) {
    let edition = edition_for(&context.repo, file);
    let mut command = Command::new(rustfmt());
    command
        .args(["--edition", &edition])
        .arg(file)
        .current_dir(context.repo.root());
    let timeout = limits
        .format_timeout()
        .min(context.remaining().saturating_sub(limits.format_margin()));
    match process::run(&mut command, None, timeout) {
        Ok(ran) if ran.success() => {}
        Ok(ran) => context.note(format!(
            "rustfmt {}: {}",
            ran.describe(),
            ran.stderr().lines().next().unwrap_or_default()
        )),
        Err(error) => context.note(format!("rustfmt did not start: {error}")),
    }
}

/// rustfmt beside the cargo that `process::cargo` finds, else from `PATH`.
fn rustfmt() -> PathBuf {
    let name = format!("rustfmt{}", std::env::consts::EXE_SUFFIX);
    process::cargo()
        .parent()
        .map(|dir| dir.join(&name))
        .filter(|path| path.is_file())
        .unwrap_or_else(|| PathBuf::from(name))
}

/// The edition of the package that holds `file`, or of the workspace it inherits from.
fn edition_for(repo: &Repo, file: &Path) -> String {
    for dir in file.ancestors().skip(1) {
        let table = std::fs::read_to_string(dir.join(MANIFEST))
            .ok()
            .and_then(|text| toml::from_str::<toml::Table>(&text).ok());
        let edition = table
            .as_ref()
            .and_then(|table| table.get("package")?.get("edition"));
        match edition {
            Some(toml::Value::String(edition)) => return edition.clone(),
            Some(_) => break,
            None if dir == repo.root() => break,
            None => {}
        }
    }
    workspace_edition(repo).unwrap_or_else(|| DEFAULT_EDITION.to_owned())
}

/// `[workspace.package] edition` of the root manifest.
fn workspace_edition(repo: &Repo) -> Option<String> {
    let text = repo.read_optional(MANIFEST).ok().flatten()?;
    let table: toml::Table = toml::from_str(&text).ok()?;
    table
        .get("workspace")?
        .get("package")?
        .get("edition")?
        .as_str()
        .map(str::to_owned)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn unexplained(line: &str, previous: Option<&str>) -> Option<&'static str> {
        let min_reason = Limits::built_with()
            .unwrap()
            .hook
            .post_edit
            .min_reason_chars;
        unexplained_match(line, previous, min_reason).map(|(kind, _)| kind)
    }

    #[test]
    fn every_pattern_compiles() {
        assert!(structure::patterns::all_compile(&[
            &RUST_LINT,
            &RUST_IGNORE,
            &SCRIPT_DIRECTIVE
        ]));
    }

    #[test]
    fn suppressions_need_a_reason() {
        assert!(unexplained("#[allow(dead_code)]", None).is_some());
        assert!(unexplained("#[allow(dead_code, reason = \"wired in WI-0012\")]", None).is_none());
        assert!(
            unexplained(
                "#[allow(dead_code)]",
                Some("// kept for the ABI, see design/07")
            )
            .is_none()
        );
        assert!(unexplained("#[ignore]", None).is_some());
        assert!(unexplained("#[ignore = \"needs a TPM\"]", None).is_none());
        assert!(unexplained("    todo!()", None).is_none());
        assert!(unexplained("// @ts-ignore", None).is_some());
        assert!(unexplained("// @ts-expect-error the SDK types lag the API", None).is_none());
        assert!(unexplained("// eslint-disable-next-line no-console", None).is_some());
        assert!(
            unexplained(
                "// eslint-disable-next-line no-console -- the CLI prints",
                None
            )
            .is_none()
        );
        assert!(unexplained("let allowed = true;", None).is_none());
    }

    #[test]
    fn prose_literals_and_tests_are_not_suppressions() {
        let temp = crate::testkit::TempRepo::create();
        temp.write(
            "docs/notes.md",
            "A `#[ignore]` without a reason, and todo!() too.\n",
        );
        temp.write(
            "crates/a/src/lib.rs",
            "// a #[allow(x)] mentioned in prose\nconst DIRECTIVE: &str = \"eslint-disable\";\npub fn a() {}\n#[cfg(test)]\nmod tests {\n    #[allow(clippy::unwrap_used)]\n    fn t() { todo!() }\n    #[ignore]\n    #[test]\n    fn slow() {}\n}\n",
        );
        temp.write(
            "web/src/a.ts",
            "// eslint-disable-next-line\nexport const a = 1;\n",
        );
        let paths: Vec<RepoPath> = ["docs/notes.md", "crates/a/src/lib.rs", "web/src/a.ts"]
            .iter()
            .filter_map(|path| RepoPath::new(path))
            .collect();
        let found = new_suppressions(&temp.repo(), &git::Base::Unborn, &paths).unwrap();
        assert_eq!(
            found,
            vec![
                "crates/a/src/lib.rs:8: #[ignore] without a reason; say why, or fix the cause",
                "web/src/a.ts:1: a lint directive without a reason; say why, or fix the cause",
            ]
        );
    }
}
