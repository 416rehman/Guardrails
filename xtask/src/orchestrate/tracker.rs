//! What the kit commands and the dispatcher ask of GitHub, behind one trait so their logic is
//! tested against an in-memory tracker. [`GhTracker`] is the real one: every call goes through
//! [`Gh`], the one door to GitHub, so `GRDR_GH` and `--dry-run` hold everywhere.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use super::issue::{Issue, IssueState, Login};
use crate::github::{Gh, GhError};

const ISSUE_FIELDS: &str = "number,title,body,labels,state,createdAt,updatedAt,assignees,comments";
const LIST_FIELDS: &str = "number,title,body,labels,state,createdAt,updatedAt,assignees";
const PULL_REQUEST_FIELDS: &str =
    "number,url,title,body,headRefOid,baseRefName,isDraft,isCrossRepository,statusCheckRollup";
const SOURCE_FIELDS: &str = "headRefName,headRepository,isCrossRepository,closingIssuesReferences";
const LIST_LIMIT: &str = "1000";
const LABEL_LIMIT: &str = "500";
const SQUASH: &str = "squash";
/// The conclusions of a finished check run that count as green; GitHub's own values.
const GREEN_CONCLUSIONS: &[&str] = &["SUCCESS", "NEUTRAL", "SKIPPED"];
const COMPLETED: &str = "COMPLETED";
const STATUS_SUCCESS: &str = "SUCCESS";
const STATUS_WAITING: &[&str] = &["PENDING", "EXPECTED"];

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct Dependency {
    pub number: u64,
    #[serde(default)]
    pub state: IssueState,
}

/// An open pull request with what the review pass and the merge queue read of it.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PullRequest {
    pub number: u64,
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
    #[serde(default, rename = "headRefOid")]
    pub head: String,
    #[serde(default, rename = "baseRefName")]
    pub base: String,
    #[serde(default, rename = "isDraft")]
    pub draft: bool,
    /// The head branch lives in a fork, whose branch names anyone can copy.
    #[serde(default, rename = "isCrossRepository")]
    pub cross_repository: bool,
    #[serde(default, rename = "statusCheckRollup")]
    pub checks: Vec<CheckRollup>,
}

/// Where a pull request's head lives and which issues it closes.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct PullRequestSource {
    #[serde(rename = "headRefName")]
    pub head_branch: String,
    /// Absent when the head repository was deleted.
    #[serde(default, rename = "headRepository")]
    pub head_repository: Option<HeadRepository>,
    #[serde(default, rename = "isCrossRepository")]
    pub cross_repository: bool,
    #[serde(default, rename = "closingIssuesReferences")]
    pub closes: Vec<ClosingReference>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct HeadRepository {
    #[serde(default, rename = "nameWithOwner")]
    pub name_with_owner: String,
}

/// An issue the pull request closes when it merges, in whichever repository it lives.
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ClosingReference {
    pub number: u64,
    #[serde(default)]
    pub repository: Option<ReferencedRepository>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct ReferencedRepository {
    pub name: String,
    #[serde(default)]
    pub owner: Login,
}

/// One entry of `statusCheckRollup`: a check run (`name`, `status`, `conclusion`) or a commit
/// status (`context`, `state`).
#[derive(Debug, Clone, Default, PartialEq, Eq, Deserialize)]
pub struct CheckRollup {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub context: String,
    #[serde(default)]
    pub status: String,
    #[serde(default)]
    pub conclusion: String,
    #[serde(default)]
    pub state: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckState {
    Green,
    Waiting,
    Failed,
}

/// A squash merge of `number` whose head must still be `head`, with a one-line message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Squash<'a> {
    pub number: u64,
    pub subject: &'a str,
    pub head: &'a str,
}

#[derive(Serialize)]
struct MergeRequest<'a> {
    merge_method: &'a str,
    commit_title: &'a str,
    commit_message: &'a str,
    sha: &'a str,
}

#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct RemoteLabel {
    pub name: String,
    #[serde(default)]
    pub color: String,
    #[serde(default)]
    pub description: String,
}

/// One `gh issue edit`: labels to add and remove, and whether to assign the caller.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct IssueEdit {
    pub add: Vec<String>,
    pub remove: Vec<String>,
    pub assign_self: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewPullRequest<'a> {
    pub branch: &'a str,
    pub base: &'a str,
    pub title: &'a str,
    pub body: &'a str,
}

pub trait Tracker {
    /// The issue with its labels, body and comments.
    fn issue(&self, number: u64) -> Result<Issue>;
    /// Open issues carrying `label`, without comments.
    fn open_with_label(&self, label: &str) -> Result<Vec<Issue>>;
    fn blocked_by(&self, number: u64) -> Result<Vec<Dependency>>;
    fn blocking(&self, number: u64) -> Result<Vec<Dependency>>;
    fn edit(&self, number: u64, edit: &IssueEdit) -> Result<()>;
    fn comment(&self, number: u64, body: &str) -> Result<()>;
    /// The open pull request from `branch` of this repository; a fork's branch of the same name
    /// is someone else's.
    fn open_pull_request(&self, branch: &str) -> Result<Option<PullRequest>>;
    fn create_pull_request(&self, request: &NewPullRequest) -> Result<()>;
    fn update_pull_request(&self, number: u64, title: &str, body: &str) -> Result<()>;
    fn squash_merge(&self, squash: &Squash) -> Result<()>;
    fn close_issue(&self, number: u64) -> Result<()>;
    fn labels(&self) -> Result<Vec<RemoteLabel>>;
    fn save_label(&self, label: &RemoteLabel, exists: bool) -> Result<()>;
}

pub struct GhTracker {
    gh: Gh,
}

impl GhTracker {
    pub fn new(gh: Gh) -> GhTracker {
        GhTracker { gh }
    }

    pub fn gh(&self) -> &Gh {
        &self.gh
    }

    /// Pull request `number`'s head branch and repository and the issues it closes.
    pub fn pull_request_source(&self, number: u64) -> Result<PullRequestSource> {
        self.read_json(&["pr", "view", &number.to_string(), "--json", SOURCE_FIELDS])
    }

    fn read_json<T: for<'de> Deserialize<'de>>(&self, args: &[&str]) -> Result<T> {
        let text = self.gh.read(args)?;
        serde_json::from_str(&text).with_context(|| format!("parsing gh {}", args.join(" ")))
    }

    fn dependencies(&self, number: u64, relation: &str) -> Result<Vec<Dependency>> {
        let path = format!(
            "repos/{}/issues/{number}/dependencies/{relation}",
            self.gh.repository()
        );
        let text = self.gh.read(&["api", "--paginate", &path])?;
        let mut all = Vec::new();
        for page in serde_json::Deserializer::from_str(&text).into_iter::<Vec<Dependency>>() {
            all.extend(page.with_context(|| format!("parsing gh api {path}"))?);
        }
        Ok(all)
    }
}

impl Tracker for GhTracker {
    fn issue(&self, number: u64) -> Result<Issue> {
        self.read_json(&["issue", "view", &number.to_string(), "--json", ISSUE_FIELDS])
    }

    fn open_with_label(&self, label: &str) -> Result<Vec<Issue>> {
        self.read_json(&[
            "issue",
            "list",
            "--state",
            "open",
            "--label",
            label,
            "--limit",
            LIST_LIMIT,
            "--json",
            LIST_FIELDS,
        ])
    }

    fn blocked_by(&self, number: u64) -> Result<Vec<Dependency>> {
        self.dependencies(number, "blocked_by")
    }

    fn blocking(&self, number: u64) -> Result<Vec<Dependency>> {
        self.dependencies(number, "blocking")
    }

    fn edit(&self, number: u64, edit: &IssueEdit) -> Result<()> {
        let number = number.to_string();
        let mut args = vec!["issue", "edit", number.as_str()];
        for label in &edit.add {
            args.extend(["--add-label", label.as_str()]);
        }
        for label in &edit.remove {
            args.extend(["--remove-label", label.as_str()]);
        }
        if edit.assign_self {
            args.extend(["--add-assignee", "@me"]);
        }
        self.gh.write(&args, None)?;
        Ok(())
    }

    fn comment(&self, number: u64, body: &str) -> Result<()> {
        self.gh.write(
            &["issue", "comment", &number.to_string(), "--body-file", "-"],
            Some(body),
        )?;
        Ok(())
    }

    fn open_pull_request(&self, branch: &str) -> Result<Option<PullRequest>> {
        let found: Vec<PullRequest> = self.read_json(&[
            "pr",
            "list",
            "--head",
            branch,
            "--state",
            "open",
            "--limit",
            LIST_LIMIT,
            "--json",
            PULL_REQUEST_FIELDS,
        ])?;
        Ok(found.into_iter().find(|request| !request.cross_repository))
    }

    fn create_pull_request(&self, request: &NewPullRequest) -> Result<()> {
        self.gh.write(
            &[
                "pr",
                "create",
                "--head",
                request.branch,
                "--base",
                request.base,
                "--title",
                request.title,
                "--body-file",
                "-",
            ],
            Some(request.body),
        )?;
        Ok(())
    }

    fn update_pull_request(&self, number: u64, title: &str, body: &str) -> Result<()> {
        self.gh.write(
            &[
                "pr",
                "edit",
                &number.to_string(),
                "--title",
                title,
                "--body-file",
                "-",
            ],
            Some(body),
        )?;
        Ok(())
    }

    fn squash_merge(&self, squash: &Squash) -> Result<()> {
        let path = format!(
            "repos/{}/pulls/{}/merge",
            self.gh.repository(),
            squash.number
        );
        let request = MergeRequest {
            merge_method: SQUASH,
            commit_title: squash.subject,
            commit_message: "",
            sha: squash.head,
        };
        let body = serde_json::to_string(&request)?;
        self.gh.write(
            &["api", "--method", "PUT", &path, "--input", "-"],
            Some(&body),
        )?;
        Ok(())
    }

    fn close_issue(&self, number: u64) -> Result<()> {
        self.gh.write(
            &[
                "issue",
                "close",
                &number.to_string(),
                "--reason",
                "completed",
            ],
            None,
        )?;
        Ok(())
    }

    fn labels(&self) -> Result<Vec<RemoteLabel>> {
        self.read_json(&[
            "label",
            "list",
            "--limit",
            LABEL_LIMIT,
            "--json",
            "name,color,description",
        ])
    }

    fn save_label(&self, label: &RemoteLabel, exists: bool) -> Result<()> {
        let verb = if exists { "edit" } else { "create" };
        self.gh.write(
            &[
                "label",
                verb,
                &label.name,
                "--color",
                &label.color,
                "--description",
                &label.description,
            ],
            None,
        )?;
        Ok(())
    }
}

impl PullRequestSource {
    /// Whether the head is in another repository than `repository`, the base.
    pub fn from_fork(&self, repository: &str) -> bool {
        self.cross_repository
            || self
                .head_repository
                .as_ref()
                .is_none_or(|head| !head.name_with_owner.eq_ignore_ascii_case(repository))
    }

    /// The issues of `repository` it closes.
    pub fn closed_issues(&self, repository: &str) -> Vec<u64> {
        self.closes
            .iter()
            .filter(|reference| {
                reference.repository.as_ref().is_some_and(|found| {
                    format!("{}/{}", found.owner.login, found.name).eq_ignore_ascii_case(repository)
                })
            })
            .map(|reference| reference.number)
            .collect()
    }
}

impl CheckRollup {
    pub fn label(&self) -> &str {
        if self.name.is_empty() {
            &self.context
        } else {
            &self.name
        }
    }

    pub fn state(&self) -> CheckState {
        if !self.state.is_empty() {
            return match self.state.as_str() {
                STATUS_SUCCESS => CheckState::Green,
                waiting if STATUS_WAITING.contains(&waiting) => CheckState::Waiting,
                _ => CheckState::Failed,
            };
        }
        if self.status != COMPLETED {
            return CheckState::Waiting;
        }
        if GREEN_CONCLUSIONS.contains(&self.conclusion.as_str()) {
            CheckState::Green
        } else {
            CheckState::Failed
        }
    }
}

/// The owner step a GitHub error carries, when it is that kind of error.
pub fn missing_step(error: &anyhow::Error) -> Option<&str> {
    match error.downcast_ref::<GhError>() {
        Some(GhError::Missing { step, .. }) => Some(step),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::github::Mode;
    use crate::github::tests::identity;
    use crate::orchestrate::testkit::FakeProgram;

    fn tracker(fake: &FakeProgram, mode: Mode) -> GhTracker {
        GhTracker::new(Gh::new(fake.program().to_path_buf(), identity(), mode))
    }

    #[test]
    fn reads_parse_and_writes_send_bodies_on_stdin() {
        let fake = FakeProgram::new("tracker-gh");
        fake.respond(
            1,
            r#"{"number": 4, "title": "t", "labels": [{"name": "status:ready"}], "comments": []}"#,
            0,
        );
        fake.respond(
            2,
            "[{\"number\": 3, \"state\": \"closed\"}][{\"number\": 5, \"state\": \"open\"}]",
            0,
        );
        let tracker = tracker(&fake, Mode::Live);
        let issue = tracker.issue(4).unwrap();
        assert!(issue.has_label("status:ready"));
        let deps = tracker.blocked_by(4).unwrap();
        assert_eq!(deps.len(), 2);
        assert_eq!(deps[1].state, IssueState::Open);
        tracker.comment(4, "a body\n").unwrap();
        tracker
            .edit(
                4,
                &IssueEdit {
                    add: vec!["status:leased".into()],
                    remove: vec!["status:ready".into()],
                    assign_self: true,
                },
            )
            .unwrap();
        let calls = fake.calls();
        assert!(
            calls[0].contains("issue view 4 --json number,title,body"),
            "{calls:?}"
        );
        assert!(calls[1].contains(
            "api --paginate repos/416rehman/Guardrails/issues/4/dependencies/blocked_by"
        ));
        assert!(calls[2].contains("issue comment 4 --body-file -"));
        assert!(fake.stdin(3).contains("a body"));
        assert!(
            calls[3].contains(
                "--add-label status:leased --remove-label status:ready --add-assignee @me"
            )
        );
    }

    #[test]
    fn a_fork_with_the_same_branch_name_is_not_the_pull_request() {
        let fake = FakeProgram::new("tracker-fork");
        fake.respond(
            1,
            r#"[{"number": 71, "isCrossRepository": true, "headRefOid": "f0"}, {"number": 70, "isCrossRepository": false, "headRefOid": "a1"}]"#,
            0,
        );
        fake.respond(2, r#"[{"number": 72, "isCrossRepository": true}]"#, 0);
        let tracker = tracker(&fake, Mode::Live);
        let own = tracker.open_pull_request("agent/7/a1").unwrap().unwrap();
        assert_eq!((own.number, own.head.as_str()), (70, "a1"));
        assert_eq!(tracker.open_pull_request("agent/7/a1").unwrap(), None);
        let calls = fake.calls();
        assert!(
            calls[0].contains("pr list --head agent/7/a1 --state open --limit 1000 --json number,")
                && calls[0].contains("isCrossRepository"),
            "{calls:?}"
        );
    }

    #[test]
    fn dry_runs_change_nothing_and_missing_repositories_name_the_step() {
        let fake = FakeProgram::new("tracker-dry");
        let dry = tracker(&fake, Mode::DryRun);
        dry.comment(4, "x").unwrap();
        assert!(fake.calls().is_empty());
        fake.respond_err(
            1,
            "GraphQL: Could not resolve to a Repository with the name '416rehman/Guardrails'.",
            1,
        );
        let error = tracker(&fake, Mode::Live).issue(4).unwrap_err();
        assert!(missing_step(&error).is_some_and(|step| step.contains("gh repo create")));
    }

    #[test]
    fn squash_merges_carry_the_subject_and_the_head_on_stdin() {
        let fake = FakeProgram::new("tracker-merge");
        fake.respond(1, "{\"merged\": true}", 0);
        let squash = Squash {
            number: 12,
            subject: "feat(core): add the parser (#12)",
            head: "abc123",
        };
        tracker(&fake, Mode::Live).squash_merge(&squash).unwrap();
        let calls = fake.calls();
        assert!(
            calls[0]
                .contains("api --method PUT repos/416rehman/Guardrails/pulls/12/merge --input -"),
            "{calls:?}"
        );
        let sent: serde_json::Value = serde_json::from_str(fake.stdin(1).trim()).unwrap();
        assert_eq!(sent["merge_method"], "squash");
        assert_eq!(sent["commit_title"], "feat(core): add the parser (#12)");
        assert_eq!(sent["commit_message"], "");
        assert_eq!(sent["sha"], "abc123");
    }

    #[test]
    fn check_rollups_read_runs_and_statuses() {
        let run = |status: &str, conclusion: &str| CheckRollup {
            name: "verify".into(),
            status: status.into(),
            conclusion: conclusion.into(),
            ..CheckRollup::default()
        };
        let status = |state: &str| CheckRollup {
            context: "grdr-evaluator/eval-diff".into(),
            state: state.into(),
            ..CheckRollup::default()
        };
        assert_eq!(run("COMPLETED", "SUCCESS").state(), CheckState::Green);
        assert_eq!(run("COMPLETED", "SKIPPED").state(), CheckState::Green);
        assert_eq!(run("IN_PROGRESS", "").state(), CheckState::Waiting);
        assert_eq!(run("COMPLETED", "FAILURE").state(), CheckState::Failed);
        assert_eq!(status("SUCCESS").state(), CheckState::Green);
        assert_eq!(status("PENDING").state(), CheckState::Waiting);
        assert_eq!(status("ERROR").state(), CheckState::Failed);
        assert_eq!(status("ERROR").label(), "grdr-evaluator/eval-diff");
        assert_eq!(run("COMPLETED", "SUCCESS").label(), "verify");
    }
}
