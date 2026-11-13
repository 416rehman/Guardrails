//! Gate `rfc-required` (D-61, design/30 section 3), in the CI form of verify because it reads the
//! pull request, as Q01 reads the issue: a diff that touches a path `governance/rfc-required.toml`
//! lists fails unless the pull request body has a line `RFC: <nnnn>` naming an RFC file under
//! `rfcs/` at the comparison base. The rules are read at the base too. A body that cannot be read
//! fails with the reason, so the gate never passes unread.

use std::collections::BTreeSet;
use std::fs;
use std::io::ErrorKind;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;

use super::{Context, Outcome};
use crate::git::{self, Base};
use crate::github::{Gh, Mode};
use crate::globs::{Case, GlobList};
use crate::orchestrate::tracker::{GhTracker, Tracker};
use crate::paths::RepoPath;
use crate::repo::Repo;

pub const RULES_PATH: &str = "governance/rfc-required.toml";
/// The pull request's branch in a GitHub Actions `pull_request` run, where `HEAD` is detached.
const PULL_REQUEST_BRANCH_VARIABLE: &str = "GITHUB_HEAD_REF";
const RFC_EXTENSION: &str = ".md";
const NUMBER_SEPARATOR: char = '-';

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RfcRules {
    paths: Vec<String>,
    directory: String,
    marker: String,
    digits: usize,
    reserved: Vec<String>,
}

/// The pull request body as the gate found it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Body {
    Read(String),
    Unreadable(String),
}

/// One body line that starts with the marker.
enum Named<'a> {
    Rfc(&'a str),
    Malformed(&'a str),
}

impl RfcRules {
    pub fn at(repo: &Repo, base: &Base) -> Result<RfcRules> {
        let (text, label) = git::read_at(repo, base, RULES_PATH)?;
        let Some(text) = text else {
            bail!("{RULES_PATH} is missing; it lists the paths whose change needs an RFC");
        };
        crate::config::parse_toml(&text, &label)
    }

    fn named<'a>(&self, body: &'a str) -> Vec<Named<'a>> {
        body.lines()
            .filter_map(|line| {
                let line = line.trim();
                let number = line.strip_prefix(&self.marker)?.trim();
                let well_formed =
                    number.len() == self.digits && number.chars().all(|c| c.is_ascii_digit());
                Some(if well_formed {
                    Named::Rfc(number)
                } else {
                    Named::Malformed(line)
                })
            })
            .collect()
    }

    fn rfc_problem(&self, number: &str, files: &BTreeSet<String>) -> Option<String> {
        let directory = &self.directory;
        if self.reserved.iter().any(|reserved| reserved == number) {
            return Some(format!(
                "{} {number} is reserved and names no RFC",
                self.marker
            ));
        }
        let prefix = format!("{number}{NUMBER_SEPARATOR}");
        let exists = files
            .iter()
            .any(|name| name.starts_with(&prefix) && name.ends_with(RFC_EXTENSION));
        (!exists).then(|| {
            format!(
                "{} {number} names no file {directory}/{prefix}<title>{RFC_EXTENSION} at the base",
                self.marker
            )
        })
    }
}

pub fn gate(context: &Context) -> Result<Outcome> {
    let rules = RfcRules::at(&context.repo, &context.base)?;
    let found = check(
        &rules,
        &context.changed,
        || pull_request_body(&context.repo),
        || rfc_files(&context.repo, &context.base, &rules.directory),
    )?;
    Ok(Outcome::from_problems(found))
}

/// The problems of a diff touching `changed`. `body` and `rfc_files` are read only when a
/// changed path needs an RFC; `rfc_files` gives the file names in the RFC directory at the base.
pub fn check(
    rules: &RfcRules,
    changed: &[RepoPath],
    body: impl FnOnce() -> Body,
    rfc_files: impl FnOnce() -> Result<BTreeSet<String>>,
) -> Result<Vec<String>> {
    let globs = GlobList::new(&rules.paths, Case::Sensitive)?;
    let gated: Vec<&str> = changed
        .iter()
        .map(RepoPath::as_str)
        .filter(|path| globs.is_match(path))
        .collect();
    let Some(first) = gated.first() else {
        return Ok(Vec::new());
    };
    let touched = format!(
        "{} changed path(s) under {RULES_PATH}, {first} among them,",
        gated.len()
    );
    let text = match body() {
        Body::Read(text) => text,
        Body::Unreadable(reason) => {
            return Ok(vec![format!(
                "{touched} need an RFC, and the pull request body cannot be read: {reason}"
            )]);
        }
    };
    let named = rules.named(&text);
    if named.is_empty() {
        return Ok(vec![format!(
            "{touched} need an RFC: add a line `{} <{}-digit number>` to the pull request body (GOVERNANCE.md, RFCs)",
            rules.marker, rules.digits
        )]);
    }
    let files = rfc_files()?;
    Ok(named
        .iter()
        .filter_map(|named| match named {
            Named::Rfc(number) => rules.rfc_problem(number, &files),
            Named::Malformed(line) => Some(format!(
                "`{line}` is not `{} <{}-digit number>`",
                rules.marker, rules.digits
            )),
        })
        .collect())
}

/// The body of the open pull request from the checked-out branch, or from the pull request's
/// branch in CI.
fn pull_request_body(repo: &Repo) -> Body {
    let branch = match git::current_branch(repo) {
        Ok(branch) => branch.or_else(|| {
            std::env::var(PULL_REQUEST_BRANCH_VARIABLE)
                .ok()
                .filter(|branch| !branch.is_empty())
        }),
        Err(error) => return Body::Unreadable(format!("{error:#}")),
    };
    let Some(branch) = branch else {
        return Body::Unreadable("no branch is checked out, so no pull request is known".into());
    };
    match Gh::for_repo(repo, Mode::Live) {
        Ok(gh) => body_of(&GhTracker::new(gh), &branch),
        Err(error) => Body::Unreadable(format!("{error:#}")),
    }
}

fn body_of(tracker: &dyn Tracker, branch: &str) -> Body {
    match tracker.open_pull_request(branch) {
        Ok(Some(request)) => Body::Read(request.body),
        Ok(None) => Body::Unreadable(format!("no open pull request from {branch}")),
        Err(error) => Body::Unreadable(format!("{error:#}")),
    }
}

/// The file names in `directory` at the base, or in the working tree when nothing is committed.
fn rfc_files(repo: &Repo, base: &Base, directory: &str) -> Result<BTreeSet<String>> {
    let Some(commit) = base.commit() else {
        let entries = match fs::read_dir(repo.path(directory)) {
            Ok(entries) => entries,
            Err(error) if error.kind() == ErrorKind::NotFound => return Ok(BTreeSet::new()),
            Err(error) => return Err(error).with_context(|| format!("reading {directory}")),
        };
        return entries
            .map(|entry| Ok(entry?.file_name().to_string_lossy().into_owned()))
            .collect();
    };
    let listed = git::output(
        repo,
        &[
            "ls-tree",
            "--name-only",
            commit,
            "--",
            &format!("{directory}/"),
        ],
    )?;
    Ok(listed
        .lines()
        .filter_map(|path| path.rsplit('/').next())
        .map(str::to_owned)
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrate::testkit::{MemoryTracker, init_git};
    use crate::orchestrate::tracker::PullRequest;
    use crate::testkit::TempRepo;

    fn rules() -> RfcRules {
        let text = std::fs::read_to_string(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("..")
                .join(RULES_PATH),
        )
        .unwrap();
        crate::config::parse_toml(&text, RULES_PATH).unwrap()
    }

    fn diff(paths: &[&str]) -> Vec<RepoPath> {
        paths
            .iter()
            .map(|path| RepoPath::new(path).unwrap())
            .collect()
    }

    fn rfcs() -> Result<BTreeSet<String>> {
        Ok(["0000-template.md", "0001-adopt-the-spine.md"]
            .map(str::to_owned)
            .into())
    }

    fn run(paths: &[&str], body: &str) -> Vec<String> {
        let body = Body::Read(body.to_owned());
        check(&rules(), &diff(paths), || body, rfcs).unwrap()
    }

    const NO_RFC: &str =
        "Closes #12\n\n<details><summary>meta.v1</summary>\n\nharness: claude-code\n</details>\n";

    #[test]
    fn rfc_required_fails_a_proto_change_without_an_rfc_line() {
        let found = run(&["proto/grdr/event/v1/event.proto", "README.md"], NO_RFC);
        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("1 changed path(s)"), "{found:?}");
        assert!(found[0].contains("proto/grdr/event/v1/event.proto"));
        assert!(found[0].contains("add a line `RFC: <4-digit number>`"));
    }

    #[test]
    fn rfc_required_fails_a_schema_change_without_an_rfc_line() {
        let found = run(&["schema/cedar/grdr.cedarschema"], NO_RFC);
        assert_eq!(found.len(), 1);
        assert!(found[0].contains("schema/cedar/grdr.cedarschema"));
    }

    #[test]
    fn rfc_required_passes_a_body_naming_an_existing_rfc() {
        let body = format!("{NO_RFC}RFC: 0001\n");
        assert_eq!(
            run(&["proto/grdr/a.proto", "schema/b.toml"], &body),
            Vec::<String>::new()
        );
        let indented = format!("{NO_RFC}  RFC:0001  \n");
        assert_eq!(
            run(&["proto/grdr/a.proto"], &indented),
            Vec::<String>::new()
        );
    }

    #[test]
    fn rfc_required_passes_a_change_outside_the_gated_paths_unread() {
        let found = check(
            &rules(),
            &diff(&["crates/grdr-core/src/lib.rs", "docs/proto/notes.md"]),
            || panic!("the body is read only when a gated path changed"),
            || panic!("the RFC directory is read only when a body names an RFC"),
        )
        .unwrap();
        assert_eq!(found, Vec::<String>::new());
    }

    #[test]
    fn rfc_required_fails_when_the_body_cannot_be_read() {
        let unreadable = Body::Unreadable("gh: HTTP 401".into());
        let found = check(&rules(), &diff(&["proto/a.proto"]), || unreadable, rfcs).unwrap();
        assert_eq!(found.len(), 1);
        assert!(found[0].ends_with("the pull request body cannot be read: gh: HTTP 401"));
        let tracker = MemoryTracker::default();
        assert_eq!(
            body_of(&tracker, "agent/12/a1"),
            Body::Unreadable("no open pull request from agent/12/a1".into())
        );
        tracker.set_pull_request(
            "agent/12/a1",
            PullRequest {
                number: 40,
                body: "RFC: 0001\n".into(),
                ..PullRequest::default()
            },
        );
        assert_eq!(
            body_of(&tracker, "agent/12/a1"),
            Body::Read("RFC: 0001\n".into())
        );
    }

    #[test]
    fn rfc_required_fails_a_missing_reserved_or_malformed_rfc() {
        assert_eq!(
            run(
                &["proto/a.proto"],
                "RFC: 0042\nRFC: 0000\nRFC: 12\nRFC: 0001\n"
            ),
            vec![
                "RFC: 0042 names no file rfcs/0042-<title>.md at the base",
                "RFC: 0000 is reserved and names no RFC",
                "`RFC: 12` is not `RFC: <4-digit number>`",
            ]
        );
    }

    #[test]
    fn rfc_required_reads_the_rfc_directory_at_the_base() {
        let temp = TempRepo::create();
        temp.write("rfcs/0001-adopt-the-spine.md", "# RFC 0001\n");
        init_git(temp.root());
        temp.write("rfcs/0002-later.md", "# RFC 0002\n");
        let repo = temp.repo();
        let base = git::base_for(&repo, Some("HEAD")).unwrap();
        assert_eq!(
            rfc_files(&repo, &base, "rfcs").unwrap(),
            BTreeSet::from(["0001-adopt-the-spine.md".to_owned()])
        );
        let unborn = rfc_files(&repo, &Base::Unborn, "rfcs").unwrap();
        assert!(unborn.contains("0002-later.md"));
    }
}
