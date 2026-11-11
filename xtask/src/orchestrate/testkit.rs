//! Test doubles: a scripted executable that stands in for `gh` or `claude`, and an in-memory
//! tracker. No test reaches the real GitHub API or starts a real Claude session.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicUsize, Ordering};

use anyhow::{Result, bail};

use super::issue::{Comment, Issue, IssueState, Login, Named};
use super::records::{READY_SCHEMA, Ready};
use super::tracker::{
    Dependency, IssueEdit, NewPullRequest, PullRequest, RemoteLabel, Squash, Tracker,
};

static NEXT: AtomicUsize = AtomicUsize::new(0);

const FAKE_CMD: &str = "@echo off\r\nsetlocal EnableExtensions\r\nset \"dir=%~dp0\"\r\nset n=0\r\nif exist \"%dir%count\" set /p n=<\"%dir%count\"\r\nset /a n=n+1\r\n>\"%dir%count\" echo %n%\r\n>>\"%dir%calls.log\" echo %*\r\n>\"%dir%env%n%.txt\" echo agent=%GRDR_AGENT% item=%GRDR_WORK_ITEM% model=%GRDR_MODEL% scope=%GRDR_SCOPE%\r\nfindstr \"^\" > \"%dir%stdin%n%.txt\"\r\nset s=0\r\nif exist \"%dir%sleep%n%.txt\" set /p s=<\"%dir%sleep%n%.txt\"\r\nif not \"%s%\"==\"0\" ping -n %s% 127.0.0.1 >NUL\r\nset target=\r\nif exist \"%dir%target%n%.txt\" set /p target=<\"%dir%target%n%.txt\"\r\nif defined target copy /Y \"%dir%write%n%.txt\" \"%target%\" >NUL\r\nif exist \"%dir%out%n%.txt\" type \"%dir%out%n%.txt\"\r\nif exist \"%dir%err%n%.txt\" type \"%dir%err%n%.txt\" 1>&2\r\nset code=0\r\nif exist \"%dir%code%n%.txt\" set /p code=<\"%dir%code%n%.txt\"\r\nexit /b %code%\r\n";
const FAKE_SH: &str = "#!/bin/sh\ndir=$(dirname \"$0\")\nn=0\n[ -f \"$dir/count\" ] && n=$(cat \"$dir/count\")\nn=$((n+1))\necho \"$n\" > \"$dir/count\"\necho \"$*\" >> \"$dir/calls.log\"\necho \"agent=$GRDR_AGENT item=$GRDR_WORK_ITEM model=$GRDR_MODEL scope=$GRDR_SCOPE\" > \"$dir/env$n.txt\"\ncat > \"$dir/stdin$n.txt\"\n[ -f \"$dir/sleep$n.txt\" ] && sleep \"$(cat \"$dir/sleep$n.txt\")\"\n[ -f \"$dir/target$n.txt\" ] && cp \"$dir/write$n.txt\" \"$(cat \"$dir/target$n.txt\")\"\n[ -f \"$dir/out$n.txt\" ] && cat \"$dir/out$n.txt\"\n[ -f \"$dir/err$n.txt\" ] && cat \"$dir/err$n.txt\" >&2\ncode=0\n[ -f \"$dir/code$n.txt\" ] && code=$(cat \"$dir/code$n.txt\")\nexit \"$code\"\n";

/// A scripted executable in a scratch directory: call `n` records its arguments, its `GRDR_*`
/// environment and its stdin, sleeps `sleep<n>.txt` seconds, copies `write<n>.txt` to the path in
/// `target<n>.txt`, prints `out<n>.txt` and `err<n>.txt` and exits with `code<n>.txt`.
pub struct FakeProgram {
    dir: PathBuf,
    program: PathBuf,
}

#[derive(Default)]
struct Memory {
    issues: BTreeMap<u64, Issue>,
    blocked_by: BTreeMap<u64, Vec<Dependency>>,
    blocking: BTreeMap<u64, Vec<Dependency>>,
    pull_requests: BTreeMap<String, PullRequest>,
    labels: Vec<RemoteLabel>,
    calls: Vec<String>,
    /// Bumped by every change, so `updatedAt` moves as it does on GitHub.
    revision: u64,
}

/// An in-memory tracker that applies edits and comments to its issues and records every call.
#[derive(Default)]
pub struct MemoryTracker {
    memory: RefCell<Memory>,
}

impl FakeProgram {
    pub fn new(name: &str) -> FakeProgram {
        let id = NEXT.fetch_add(1, Ordering::SeqCst);
        let dir =
            std::env::temp_dir().join(format!("xtask-fake-{name}-{}-{id}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let (file, script) = if cfg!(windows) {
            ("fake.cmd", FAKE_CMD)
        } else {
            ("fake", FAKE_SH)
        };
        let program = dir.join(file);
        fs::write(&program, script).unwrap();
        make_executable(&program);
        FakeProgram { dir, program }
    }

    pub fn program(&self) -> &Path {
        &self.program
    }

    pub fn respond(&self, call: usize, out: &str, code: i32) -> &FakeProgram {
        self.file(&format!("out{call}.txt"), out);
        self.file(&format!("code{call}.txt"), &code.to_string());
        self
    }

    pub fn respond_err(&self, call: usize, err: &str, code: i32) -> &FakeProgram {
        self.file(&format!("err{call}.txt"), err);
        self.file(&format!("code{call}.txt"), &code.to_string());
        self
    }

    /// Call `n` copies `content` to `relative`, a path under its working directory.
    pub fn writes(&self, call: usize, relative: &str, content: &str) -> &FakeProgram {
        let native = relative.replace('/', std::path::MAIN_SEPARATOR_STR);
        self.file(&format!("target{call}.txt"), &native);
        self.file(&format!("write{call}.txt"), content);
        self
    }

    pub fn sleep(&self, call: usize, seconds: u32) -> &FakeProgram {
        self.file(&format!("sleep{call}.txt"), &seconds.to_string());
        self
    }

    pub fn calls(&self) -> Vec<String> {
        fs::read_to_string(self.dir.join("calls.log"))
            .unwrap_or_default()
            .lines()
            .map(|line| line.replace('"', ""))
            .collect()
    }

    pub fn stdin(&self, call: usize) -> String {
        fs::read_to_string(self.dir.join(format!("stdin{call}.txt"))).unwrap_or_default()
    }

    pub fn env(&self, call: usize) -> String {
        fs::read_to_string(self.dir.join(format!("env{call}.txt"))).unwrap_or_default()
    }

    fn file(&self, name: &str, text: &str) {
        fs::write(self.dir.join(name), text).unwrap();
    }
}

impl Drop for FakeProgram {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

impl MemoryTracker {
    pub fn add(&self, issue: Issue) {
        self.memory.borrow_mut().issues.insert(issue.number, issue);
    }

    pub fn block(&self, number: u64, by: u64, state: IssueState) {
        let dependency = Dependency { number: by, state };
        self.memory
            .borrow_mut()
            .blocked_by
            .entry(number)
            .or_default()
            .push(dependency);
    }

    pub fn blocks(&self, number: u64, other: u64) {
        let dependency = Dependency {
            number: other,
            state: IssueState::Open,
        };
        self.memory
            .borrow_mut()
            .blocking
            .entry(number)
            .or_default()
            .push(dependency);
    }

    pub fn open_pull_request_for(&self, branch: &str, number: u64) {
        let request = PullRequest {
            number,
            url: format!("https://github.com/416rehman/Guardrails/pull/{number}"),
            ..PullRequest::default()
        };
        self.set_pull_request(branch, request);
    }

    pub fn set_pull_request(&self, branch: &str, request: PullRequest) {
        self.memory
            .borrow_mut()
            .pull_requests
            .insert(branch.to_owned(), request);
    }

    pub fn set_labels(&self, labels: Vec<RemoteLabel>) {
        self.memory.borrow_mut().labels = labels;
    }

    pub fn snapshot(&self, number: u64) -> Issue {
        self.memory
            .borrow()
            .issues
            .get(&number)
            .cloned()
            .unwrap_or_default()
    }

    pub fn calls(&self) -> Vec<String> {
        self.memory.borrow().calls.clone()
    }

    fn record(&self, call: String) {
        self.memory.borrow_mut().calls.push(call);
    }
}

impl Memory {
    fn touch(&mut self, number: u64) {
        self.revision = self.revision.saturating_add(1);
        let stamp = format!(
            "2026-11-11T12:{:02}:{:02}Z",
            self.revision / 60 % 60,
            self.revision % 60
        );
        if let Some(issue) = self.issues.get_mut(&number) {
            issue.updated_at = stamp;
        }
    }
}

impl Tracker for MemoryTracker {
    fn issue(&self, number: u64) -> Result<Issue> {
        self.record(format!("issue {number}"));
        match self.memory.borrow().issues.get(&number) {
            Some(issue) => Ok(issue.clone()),
            None => bail!("no issue #{number}"),
        }
    }

    fn open_with_label(&self, label: &str) -> Result<Vec<Issue>> {
        self.record(format!("list {label}"));
        Ok(self
            .memory
            .borrow()
            .issues
            .values()
            .filter(|issue| issue.is_open() && issue.has_label(label))
            .map(|issue| Issue {
                comments: Vec::new(),
                ..issue.clone()
            })
            .collect())
    }

    fn blocked_by(&self, number: u64) -> Result<Vec<Dependency>> {
        Ok(self
            .memory
            .borrow()
            .blocked_by
            .get(&number)
            .cloned()
            .unwrap_or_default())
    }

    fn blocking(&self, number: u64) -> Result<Vec<Dependency>> {
        Ok(self
            .memory
            .borrow()
            .blocking
            .get(&number)
            .cloned()
            .unwrap_or_default())
    }

    fn edit(&self, number: u64, edit: &IssueEdit) -> Result<()> {
        self.record(format!(
            "edit {number} +{} -{}",
            edit.add.join(","),
            edit.remove.join(",")
        ));
        let mut memory = self.memory.borrow_mut();
        let Some(issue) = memory.issues.get_mut(&number) else {
            bail!("no issue #{number}");
        };
        issue
            .labels
            .retain(|label| !edit.remove.contains(&label.name));
        for name in &edit.add {
            if !issue.has_label(name) {
                issue.labels.push(Named { name: name.clone() });
            }
        }
        if edit.assign_self {
            issue.assignees = vec![Login {
                login: "416rehman".into(),
            }];
        }
        memory.touch(number);
        Ok(())
    }

    fn comment(&self, number: u64, body: &str) -> Result<()> {
        self.record(format!("comment {number}"));
        let mut memory = self.memory.borrow_mut();
        let Some(issue) = memory.issues.get_mut(&number) else {
            bail!("no issue #{number}");
        };
        issue.comments.push(Comment {
            body: body.to_owned(),
            ..Comment::default()
        });
        memory.touch(number);
        Ok(())
    }

    fn open_pull_request(&self, branch: &str) -> Result<Option<PullRequest>> {
        Ok(self.memory.borrow().pull_requests.get(branch).cloned())
    }

    fn create_pull_request(&self, request: &NewPullRequest) -> Result<()> {
        self.record(format!("pr create {} {}", request.branch, request.title));
        let number = 1000 + self.memory.borrow().pull_requests.len() as u64;
        self.set_pull_request(
            request.branch,
            PullRequest {
                number,
                title: request.title.to_owned(),
                body: request.body.to_owned(),
                base: request.base.to_owned(),
                ..PullRequest::default()
            },
        );
        Ok(())
    }

    fn update_pull_request(&self, number: u64, title: &str, body: &str) -> Result<()> {
        self.record(format!("pr edit {number} {title}"));
        let mut memory = self.memory.borrow_mut();
        if let Some(request) = memory
            .pull_requests
            .values_mut()
            .find(|request| request.number == number)
        {
            request.title = title.to_owned();
            request.body = body.to_owned();
        }
        Ok(())
    }

    fn squash_merge(&self, squash: &Squash) -> Result<()> {
        self.record(format!(
            "merge {} {} at {}",
            squash.number, squash.subject, squash.head
        ));
        self.memory
            .borrow_mut()
            .pull_requests
            .retain(|_, request| request.number != squash.number);
        Ok(())
    }

    fn close_issue(&self, number: u64) -> Result<()> {
        self.record(format!("close {number}"));
        let mut memory = self.memory.borrow_mut();
        let Some(issue) = memory.issues.get_mut(&number) else {
            bail!("no issue #{number}");
        };
        issue.state = IssueState::Closed;
        memory.touch(number);
        Ok(())
    }

    fn labels(&self) -> Result<Vec<RemoteLabel>> {
        Ok(self.memory.borrow().labels.clone())
    }

    fn save_label(&self, label: &RemoteLabel, exists: bool) -> Result<()> {
        self.record(format!(
            "label {} {}",
            if exists { "edit" } else { "create" },
            label.name
        ));
        Ok(())
    }
}

/// An issue with the given labels and body.
pub fn issue(number: u64, labels: &[&str], body: &str) -> Issue {
    let stamp = format!("2026-11-{:02}T10:00:00Z", 1 + number % 28);
    Issue {
        number,
        title: format!("Item {number}"),
        body: body.to_owned(),
        labels: labels
            .iter()
            .map(|name| Named {
                name: (*name).to_owned(),
            })
            .collect(),
        created_at: stamp.clone(),
        updated_at: stamp,
        ..Issue::default()
    }
}

/// The `ready.v1` that `by` posts for issue `number` with `body`, carrying both its digests.
pub fn ready_for(number: u64, by: &str, body: &str) -> Ready {
    let item = issue(number, &[], body).work_item();
    Ready {
        schema: READY_SCHEMA.to_owned(),
        item: number,
        by: by.to_owned(),
        write_set_sha256: item.write_set_sha256(),
        acceptance_sha256: item
            .acceptance
            .map(|found| found.sha256)
            .unwrap_or_default(),
    }
}

/// A work-item body in the form's section order.
pub fn body(agent: &str, write_set: &[&str], acceptance: &str) -> String {
    format!(
        "### Kind\n\nfeature\n\n### Squad\n\ncore\n\n### Agent\n\n{agent}\n\n### Size\n\nS\n\n### Write set\n\n```text\n{}\n```\n\n### Spec\n\nDo the thing.\n\n### Acceptance criteria\n\n{acceptance}\n\n### Risk tier\n\nmedium\n\n### Trust core\n\nno\n",
        write_set.join("\n")
    )
}

/// Runs git in `root` as a test identity; panics when it fails.
pub fn git(root: &Path, args: &[&str]) -> String {
    let output = std::process::Command::new("git")
        .arg("-C")
        .arg(root)
        .args([
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "-c",
            "commit.gpgsign=false",
        ])
        .args(args)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "git {args:?}: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    String::from_utf8_lossy(&output.stdout).into_owned()
}

/// Makes `root` a repository on `main` with everything committed.
pub fn init_git(root: &Path) {
    git(root, &["init", "--quiet", "--initial-branch=main"]);
    git(root, &["add", "-A"]);
    git(root, &["commit", "--quiet", "-m", "chore: seed"]);
}

#[cfg(unix)]
fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    fs::set_permissions(path, fs::Permissions::from_mode(0o755)).unwrap();
}

#[cfg(not(unix))]
fn make_executable(_path: &Path) {}
