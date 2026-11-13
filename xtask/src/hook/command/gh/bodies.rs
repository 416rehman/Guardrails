//! What a `gh` call posts: only to the repository of harness.toml `[github]`, only text the guard
//! can read (a named file, or stdin from a quoted here-document, the form the kit workflows use),
//! and never a kit record (`ready.v1`, `lease.v1`, `state.v1`, `handoff.v1`, `meta.v1`,
//! `lane.v1`), which only `kit ready`, `kit handoff`, `risk --raise` and the dispatcher post.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::super::{Rules, join};
use super::Call;
use crate::hook::shell::Word;
use crate::orchestrate::records::KIT_RECORDS;
use crate::paths::Located;

const BODY_TEXT_FLAGS: &[&str] = &["-b", "--body"];

const BODY_FILE_FLAGS: &[&str] = &["-F", "--body-file"];

const API_TEXT_FLAGS: &[&str] = &["-f", "--field", "--raw-field", "-F"];

const API_FILE_FLAGS: &[&str] = &["--input"];

/// `gh api`'s typed-field flags, which read a file when their value starts with `@` (`@-` reads
/// stdin), unlike `-f`/`--raw-field`, whose value is always a literal string.
const FIELD_FILE_FLAGS: &[&str] = &["-F", "--field"];

const REPO_FLAGS: &[&str] = &["-R", "--repo"];

/// The subcommands that post text a reader of the issue may take for a kit record.
const POSTING: &[&str] = &["comment", "create", "edit", "review"];

static KIT_RECORD: LazyLock<Option<Regex>> = LazyLock::new(|| {
    let schemas: Vec<String> = KIT_RECORDS
        .iter()
        .map(|schema| regex::escape(schema))
        .collect();
    Regex::new(&format!(
        r#"(?i)("schema"\s*:\s*"|<summary>\s*)({})"#,
        schemas.join("|")
    ))
    .ok()
});

/// Whether a `gh api` typed-field value (`key=@path`, or `@path` with no key) reads a file: the
/// part after the first `=`, or the whole value, starts with `@`.
fn field_reads_file(value: &str) -> bool {
    let rest = value.split_once('=').map_or(value, |(_, rest)| rest);
    rest.starts_with('@')
}

/// `-R` and `--repo` name the one repository of owner instruction 5.
pub(super) fn repository(call: &Call, repository: &str) -> Result<(), String> {
    for word in call.raw_values(REPO_FLAGS) {
        if word.opaque || !word.value.eq_ignore_ascii_case(repository) {
            return Err(format!(
                "`{}` works only on {repository}, not `{}`",
                call.command(),
                word.raw
            ));
        }
    }
    Ok(())
}

/// Text that carries a kit record, or text the guard cannot read, in a call that posts it. `stdin`
/// is the here-document the command reads, which is what a file flag of `-` posts. For an agent a
/// call never reads a local file into the body it posts: a typed `gh api` field whose value starts
/// with `@`, an `--input` that is not a here-document on stdin, and a `--body-file` outside the
/// worktree are refused, so the Read deny list and the worktree edge hold for what is published.
pub(super) fn records(
    rules: &Rules,
    call: &Call,
    cwd: Option<&Path>,
    stdin: Option<&Word>,
) -> Result<(), String> {
    if call.group != "api" && !POSTING.contains(&call.sub) {
        return Ok(());
    }
    let agent = rules.identity.is_agent();
    if agent && call.group == "api" {
        for word in call.raw_values(FIELD_FILE_FLAGS) {
            if !word.opaque && field_reads_file(&word.value) {
                return Err(format!(
                    "`{} {}` reads a local file into the posted body; give field values literally, not with `@`",
                    call.command(),
                    word.raw
                ));
            }
        }
    }
    let (text_flags, file_flags) = if call.group == "api" {
        (API_TEXT_FLAGS, API_FILE_FLAGS)
    } else {
        (BODY_TEXT_FLAGS, BODY_FILE_FLAGS)
    };
    let mut texts: Vec<String> = Vec::new();
    for word in call.raw_values(text_flags) {
        if word.opaque {
            return Err(format!(
                "`{}` posts text built from an expansion; write it literally so the guard can read it",
                call.command()
            ));
        }
        texts.push(word.value);
    }
    for word in call.raw_values(file_flags) {
        let literal_stdin = stdin.filter(|body| !body.opaque);
        match (word.value.as_str(), literal_stdin) {
            ("-", Some(body)) if !word.opaque => {
                texts.push(body.value.clone());
                continue;
            }
            ("-", _) => {
                return Err(format!(
                    "`{}` posts stdin the guard cannot read; give it as a quoted here-document, or name a file literally",
                    call.command()
                ));
            }
            _ if word.opaque => {
                return Err(format!(
                    "`{}` posts a file named by an expansion; name it literally",
                    call.command()
                ));
            }
            _ if agent && call.group == "api" => {
                return Err(format!(
                    "`{} --input {}` reads a local file; an agent gives the JSON as a quoted here-document on `--input -`",
                    call.command(),
                    word.raw
                ));
            }
            _ if agent
                && matches!(
                    rules.context.repo.locate(&word.value, cwd),
                    Located::Outside(_)
                ) =>
            {
                return Err(format!(
                    "`{}` posts {}, which is outside this worktree; name a file inside it",
                    call.command(),
                    word.raw
                ));
            }
            _ => {}
        }
        match std::fs::read_to_string(join(cwd, &word.value)) {
            Ok(text) => texts.push(text),
            Err(error) => {
                return Err(format!(
                    "`{}` posts {}, which the guard cannot read ({error})",
                    call.command(),
                    word.value
                ));
            }
        }
    }
    let pattern = KIT_RECORD
        .as_ref()
        .ok_or("guard-command's kit record pattern does not compile")?;
    match texts.iter().find_map(|text| pattern.find(text)) {
        Some(found) => Err(format!(
            "`{}` would post a kit record (`{}`); only kit ready, kit handoff and the dispatcher post them",
            call.command(),
            found.as_str().trim()
        )),
        None => Ok(()),
    }
}
