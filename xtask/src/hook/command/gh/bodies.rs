//! What a `gh` call posts: only to the repository of harness.toml `[github]`, only text the guard
//! can read, and never a kit record (`ready.v1`, `lease.v1`, `state.v1`, `handoff.v1`, `meta.v1`,
//! `lane.v1`), which only `kit ready`, `kit handoff`, `risk --raise` and the dispatcher post.

use std::path::Path;
use std::sync::LazyLock;

use regex::Regex;

use super::super::join;
use super::Call;

const BODY_TEXT_FLAGS: &[&str] = &["-b", "--body"];

const BODY_FILE_FLAGS: &[&str] = &["-F", "--body-file"];

const API_TEXT_FLAGS: &[&str] = &["-f", "--field", "--raw-field"];

const API_FILE_FLAGS: &[&str] = &["--input"];

const REPO_FLAGS: &[&str] = &["-R", "--repo"];

/// The subcommands that post text a reader of the issue may take for a kit record.
const POSTING: &[&str] = &["comment", "create", "edit", "review"];

static KIT_RECORD: LazyLock<Option<Regex>> = LazyLock::new(|| {
    Regex::new(r#"(?i)("schema"\s*:\s*"|<summary>\s*)(ready|lease|state|handoff|meta|lane)\.v1"#)
        .ok()
});

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

/// Text that carries a kit record, or text the guard cannot read, in a call that posts it.
pub(super) fn records(call: &Call, cwd: Option<&Path>) -> Result<(), String> {
    if call.group != "api" && !POSTING.contains(&call.sub) {
        return Ok(());
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
        if word.opaque || word.value == "-" {
            return Err(format!(
                "`{}` posts a file the guard cannot read; name it literally, never stdin",
                call.command()
            ));
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
