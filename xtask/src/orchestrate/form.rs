//! The commit and pull-request form of owner instruction 27, from `.agents/harness.toml`
//! `[commit]`, `[pull_request]` and `[launch] harness`: a pull-request title is one Conventional
//! Commit subject under gate V24's rule ([`check_message`]), and so is the merge queue's squash
//! subject, the title with the pull-request number; the pull request targets the base, and its
//! body closes its own issue and no other and carries the writer's `meta.v1` block.

use anyhow::{Context, Result};
use regex::Regex;
use serde::Deserialize;

use super::launch::HARNESS_FILE;
use super::records::{self, META_SCHEMA, Meta};
use super::tracker::PullRequest;
use crate::gates::commits::{CommitForm, check_message};
use crate::repo::Repo;

/// GitHub's closing keywords followed by an issue reference: `#<n>`, `owner/name#<n>` or an
/// issue URL.
const CLOSING_REFERENCE: &str = r"(?i)\b(?:close[sd]?|fix(?:e[sd])?|resolve[sd]?):?\s+((?:[\w.-]+/[\w.-]+)?#\d+|https?://\S+/issues/\d+)";

#[derive(Debug, Clone, Deserialize)]
struct FormFile {
    commit: CommitForm,
    pull_request: PullRequestRules,
    launch: LaunchName,
}

#[derive(Debug, Clone, Deserialize)]
struct PullRequestRules {
    base: String,
    remote: String,
    closes: String,
    squash_subject: String,
}

#[derive(Debug, Clone, Deserialize)]
struct LaunchName {
    harness: String,
}

/// The form, ready to check subjects and bodies.
#[derive(Debug, Clone)]
pub struct Form {
    commit: CommitForm,
    closing: Regex,
    closes: String,
    squash_subject: String,
    /// The branch pull requests target.
    pub base: String,
    /// The remote agent branches are pushed to and the base is fetched from.
    pub remote: String,
    /// The harness name every `meta.v1` block carries.
    pub harness: String,
}

/// What a pull-request body must say for its issue and attempt.
#[derive(Debug, Clone, Copy)]
pub struct Expected<'a> {
    pub item: u64,
    pub attempt: u32,
    pub model_ids: &'a [&'a str],
}

impl Form {
    pub fn load(repo: &Repo) -> Result<Form> {
        let text = repo
            .read_optional(HARNESS_FILE)?
            .with_context(|| format!("{HARNESS_FILE} is missing"))?;
        Form::parse(&text)
    }

    pub fn parse(text: &str) -> Result<Form> {
        let file: FormFile = crate::config::parse_toml(text, HARNESS_FILE).with_context(|| {
            format!("reading [commit], [pull_request] and [launch] harness in {HARNESS_FILE}")
        })?;
        let closing =
            Regex::new(CLOSING_REFERENCE).context("building the closing-reference pattern")?;
        Ok(Form {
            commit: file.commit,
            closing,
            closes: file.pull_request.closes,
            squash_subject: file.pull_request.squash_subject,
            base: file.pull_request.base,
            remote: file.pull_request.remote,
            harness: file.launch.harness,
        })
    }

    /// Why `subject` is not one Conventional Commit line; empty when it is.
    pub fn subject_problems(&self, subject: &str) -> Vec<String> {
        check_message(subject, &self.commit)
    }

    /// Why `title` does not land as a valid squash subject on pull request `pr`; empty when it
    /// does.
    pub fn landing_problems(&self, title: &str, pr: u64) -> Vec<String> {
        let problems = self.subject_problems(title);
        if !problems.is_empty() {
            return problems;
        }
        let squash = self.squash_subject(title, pr);
        check_message(&squash, &self.commit)
            .into_iter()
            .map(|problem| format!("it lands as `{squash}`, and {problem}"))
            .collect()
    }

    /// The line that closes `issue` when the pull request merges.
    pub fn closes(&self, issue: u64) -> String {
        self.closes.replace("{issue}", &issue.to_string())
    }

    /// The squash commit's subject, the form release-please reads.
    pub fn squash_subject(&self, title: &str, pr: u64) -> String {
        self.squash_subject
            .replace("{title}", title)
            .replace("{pr}", &pr.to_string())
    }

    /// The writer's `meta.v1` for a body this form writes.
    pub fn meta(&self, item: u64, model: &str, attempt: u32) -> Meta {
        Meta {
            schema: META_SCHEMA.to_owned(),
            item,
            harness: self.harness.clone(),
            model: model.to_owned(),
            attempt,
        }
    }

    /// Closing references in `body` to anything but `item`, which the squash merge would close.
    pub fn foreign_closes(&self, body: &str, item: u64) -> Vec<String> {
        let own = format!("#{item}");
        self.closing
            .captures_iter(body)
            .filter(|found| found.get(1).is_some_and(|target| target.as_str() != own))
            .filter_map(|found| found.get(0))
            .map(|found| {
                format!(
                    "body: `{}` would close another issue; only `{}` closes one",
                    found.as_str(),
                    self.closes(item)
                )
            })
            .collect()
    }

    /// Why a pull request is not what the merge queue lands; empty when valid.
    pub fn pull_request_problems(&self, request: &PullRequest, expected: Expected) -> Vec<String> {
        let mut problems: Vec<String> = self
            .landing_problems(&request.title, request.number)
            .into_iter()
            .map(|problem| format!("title: {problem}"))
            .collect();
        if request.base != self.base {
            problems.push(format!(
                "base: the pull request targets `{}`, not `{}`",
                request.base, self.base
            ));
        }
        let body = request.body.as_str();
        let closes = self.closes(expected.item);
        if !body.lines().any(|line| line.trim() == closes) {
            problems.push(format!("body: no `{closes}` line"));
        }
        problems.extend(self.foreign_closes(body, expected.item));
        let Some(meta) = records::meta_in(body) else {
            problems.push(format!("body: no {META_SCHEMA} block"));
            return problems;
        };
        if meta.item != expected.item {
            problems.push(format!(
                "body: {META_SCHEMA} names #{}, not #{}",
                meta.item, expected.item
            ));
        }
        if meta.attempt != expected.attempt {
            problems.push(format!(
                "body: {META_SCHEMA} names attempt {}, not {}",
                meta.attempt, expected.attempt
            ));
        }
        if meta.harness != self.harness {
            problems.push(format!(
                "body: {META_SCHEMA} names harness `{}`, not `{}`",
                meta.harness, self.harness
            ));
        }
        if !expected.model_ids.contains(&meta.model.as_str()) {
            problems.push(format!(
                "body: {META_SCHEMA} names model `{}`, which .agents/models.toml does not bind",
                meta.model
            ));
        }
        problems
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;

    pub(crate) const FORM: &str = "[commit]\ntypes = [\"feat\", \"fix\", \"docs\", \"chore\"]\nmax_subject_chars = 72\n[pull_request]\nbase = \"main\"\nremote = \"origin\"\ncloses = \"Closes #{issue}\"\nsquash_subject = \"{title} (#{pr})\"\n[launch]\nharness = \"claude-code\"\n";

    pub(crate) fn form() -> Form {
        Form::parse(FORM).unwrap()
    }

    #[test]
    fn subjects_are_one_conventional_line_within_the_limit() {
        let form = form();
        assert!(
            form.subject_problems("feat(core): add the parser")
                .is_empty()
        );
        assert!(form.subject_problems("fix!: drop the flag").is_empty());
        assert_eq!(form.subject_problems("Add the parser").len(), 1);
        assert_eq!(form.subject_problems("perf: faster").len(), 1);
        assert_eq!(form.subject_problems("feat: a\nWork-Item: #7").len(), 1);
        let long = format!("feat: {}", "x".repeat(70));
        assert_eq!(form.subject_problems(&long).len(), 1);
        assert_eq!(
            form.squash_subject("feat(core): add the parser", 12),
            "feat(core): add the parser (#12)"
        );
        assert_eq!(form.closes(7), "Closes #7");
    }

    #[test]
    fn titles_follow_the_commit_gate_rule() {
        let form = form();
        assert_eq!(form.subject_problems("fix: handle (a").len(), 1);
        assert_eq!(form.subject_problems("fix: a (b (c))").len(), 1);
        assert!(form.subject_problems("fix: handle (a) once").is_empty());
    }

    #[test]
    fn the_squash_subject_must_fit_the_limit() {
        let form = form();
        let title = format!("feat: {}", "x".repeat(60));
        assert!(form.subject_problems(&title).is_empty());
        assert_eq!(form.landing_problems(&title, 123).len(), 1);
        assert!(form.landing_problems(&title, 12).is_empty());
    }

    fn request(title: &str, body: &str) -> PullRequest {
        PullRequest {
            number: 12,
            title: title.to_owned(),
            body: body.to_owned(),
            base: "main".to_owned(),
            ..PullRequest::default()
        }
    }

    #[test]
    fn bodies_close_their_issue_and_name_the_writer() {
        let form = form();
        let ids = ["claude-sonnet-5-5", "claude-opus-5-5"];
        let expected = Expected {
            item: 7,
            attempt: 1,
            model_ids: &ids,
        };
        let block = records::meta_block(&form.meta(7, "claude-sonnet-5-5", 1)).unwrap();
        let body = format!("Work item: #7\nCloses #7\n\n{block}");
        let valid = request("feat(a): add a", &body);
        assert!(form.pull_request_problems(&valid, expected).is_empty());
        let problems = form.pull_request_problems(&request("Add a", "Work item: #7"), expected);
        assert_eq!(problems.len(), 3, "{problems:?}");
        let stale = records::meta_block(&form.meta(7, "claude-haiku-4", 2)).unwrap();
        let problems = form.pull_request_problems(
            &request("feat(a): add a", &format!("Closes #7\n{stale}")),
            expected,
        );
        assert_eq!(problems.len(), 2, "{problems:?}");
        let elsewhere = PullRequest {
            base: "release/1.0".to_owned(),
            ..valid
        };
        let problems = form.pull_request_problems(&elsewhere, expected);
        assert_eq!(problems.len(), 1, "{problems:?}");
        assert!(problems[0].contains("release/1.0"), "{problems:?}");
        assert!(Form::parse("[commit]\ntypes = [\"feat\"]\n").is_err());
    }

    #[test]
    fn a_body_closes_only_its_item() {
        let form = form();
        let ids = ["claude-sonnet-5-5"];
        let expected = Expected {
            item: 7,
            attempt: 1,
            model_ids: &ids,
        };
        let block = records::meta_block(&form.meta(7, "claude-sonnet-5-5", 1)).unwrap();
        let body = format!("Closes #7\nFixes #12\nresolves: someone/else#3\nFixes #7\n{block}");
        let problems = form.pull_request_problems(&request("feat(a): add a", &body), expected);
        assert_eq!(problems.len(), 2, "{problems:?}");
        assert!(problems[0].contains("Fixes #12"), "{problems:?}");
        assert!(problems[1].contains("someone/else#3"), "{problems:?}");
    }
}
