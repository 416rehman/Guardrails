//! Git queries the kit and the gates share: the comparison base, the branch diff, added lines and
//! the tree digest that evidence records.

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::PathBuf;
use std::process::Command;

use anyhow::{Context, Result, bail};

use crate::config::limits::Limits;
use crate::paths::RepoPath;
use crate::process;
use crate::repo::Repo;

const MERGE_BASE_REFERENCES: [&str; 2] = ["origin/main", "main"];
/// The name of the directory a main checkout keeps its repository in.
const GIT_DIR: &str = ".git";

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Base {
    Commit {
        commit: String,
        origin: BaseOrigin,
    },
    /// No commit exists yet, so every file in the working tree is new.
    Unborn,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum BaseOrigin {
    MergeBase(String),
    Head,
    Given(String),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AddedLines {
    All,
    Only(BTreeSet<usize>),
}

#[derive(Debug, Clone)]
pub struct Commit {
    pub sha: String,
    pub message: String,
}

impl Base {
    pub fn commit(&self) -> Option<&str> {
        match self {
            Base::Commit { commit, .. } => Some(commit),
            Base::Unborn => None,
        }
    }

    pub fn describe(&self) -> String {
        match self {
            Base::Commit { commit, origin } => match origin {
                BaseOrigin::MergeBase(reference) => {
                    format!("merge base with {reference} ({commit})")
                }
                BaseOrigin::Head => format!("HEAD ({commit})"),
                BaseOrigin::Given(reference) => format!("{reference} ({commit})"),
            },
            Base::Unborn => "no commits yet (the whole tree is new)".to_owned(),
        }
    }
}

impl AddedLines {
    pub fn contains(&self, line: usize) -> bool {
        match self {
            AddedLines::All => true,
            AddedLines::Only(lines) => lines.contains(&line),
        }
    }
}

/// Runs git in the repository and returns stdout; a non-zero exit is an error naming the command.
pub fn output(repo: &Repo, args: &[&str]) -> Result<String> {
    try_output(repo, args)?.with_context(|| format!("git {} failed", args.join(" ")))
}

/// Like [`output`], but a non-zero exit is `None`.
pub fn try_output(repo: &Repo, args: &[&str]) -> Result<Option<String>> {
    run(repo, args, &[])
}

pub fn head(repo: &Repo) -> Result<Option<String>> {
    try_trimmed(repo, &["rev-parse", "--verify", "--quiet", "HEAD^{commit}"])
}

/// The merge base with `origin/main`, else with `main`, else `HEAD`, else no commit at all.
pub fn resolve_base(repo: &Repo) -> Result<Base> {
    let Some(head) = head(repo)? else {
        return Ok(Base::Unborn);
    };
    for reference in MERGE_BASE_REFERENCES {
        if let Some(commit) = try_trimmed(repo, &["merge-base", "HEAD", reference])? {
            return Ok(Base::Commit {
                commit,
                origin: BaseOrigin::MergeBase(reference.to_owned()),
            });
        }
    }
    Ok(Base::Commit {
        commit: head,
        origin: BaseOrigin::Head,
    })
}

/// `--base <ref>` when given, otherwise [`resolve_base`].
pub fn base_for(repo: &Repo, reference: Option<&str>) -> Result<Base> {
    let Some(reference) = reference else {
        return resolve_base(repo);
    };
    let spec = format!("{reference}^{{commit}}");
    let Some(commit) = try_trimmed(repo, &["rev-parse", "--verify", "--quiet", &spec])? else {
        bail!("--base {reference} does not name a commit");
    };
    Ok(Base::Commit {
        commit,
        origin: BaseOrigin::Given(reference.to_owned()),
    })
}

/// Paths that differ from `base` in the working tree, deleted ones included, plus untracked
/// files that are not ignored. With no base, every tracked and untracked file.
pub fn changed_files(repo: &Repo, base: &Base) -> Result<Vec<RepoPath>> {
    let paths = match base {
        Base::Commit { commit, .. } => {
            let diff = output(
                repo,
                &["diff", "--name-only", "-z", "--no-renames", commit, "--"],
            )?;
            let mut paths = listed_paths(&diff);
            paths.extend(untracked_files(repo)?);
            paths
        }
        Base::Unborn => listed_paths(&output(
            repo,
            &[
                "ls-files",
                "-z",
                "--cached",
                "--others",
                "--exclude-standard",
            ],
        )?),
    };
    Ok(paths.into_iter().collect())
}

pub fn untracked_files(repo: &Repo) -> Result<BTreeSet<RepoPath>> {
    let listing = output(repo, &["ls-files", "-z", "--others", "--exclude-standard"])?;
    Ok(listed_paths(&listing))
}

/// The lines each of `paths` adds against `base`; untracked files and an unborn base add every line.
pub fn added_lines(
    repo: &Repo,
    base: &Base,
    paths: &[RepoPath],
) -> Result<BTreeMap<RepoPath, AddedLines>> {
    let mut added: BTreeMap<RepoPath, AddedLines> =
        paths.iter().map(|p| (p.clone(), AddedLines::All)).collect();
    let Base::Commit { commit, .. } = base else {
        return Ok(added);
    };
    let untracked = untracked_files(repo)?;
    let diff = output(
        repo,
        &[
            "-c",
            "core.quotepath=off",
            "diff",
            "-U0",
            "--no-color",
            "--no-ext-diff",
            "--no-renames",
            commit,
            "--",
        ],
    )?;
    for (path, lines) in parse_added(&diff) {
        if let Some(entry) = added.get_mut(&path)
            && !untracked.contains(&path)
        {
            *entry = AddedLines::Only(lines);
        }
    }
    Ok(added)
}

/// The git tree id of the working tree as `git add -A` would record it, ignored files left out.
/// It changes whenever any tracked or untracked file changes, and it ignores CRLF conversion.
pub fn tree_digest(repo: &Repo) -> Result<String> {
    let index = output(repo, &["rev-parse", "--git-path", "index"])?;
    let index = repo.root().join(index.trim());
    let scratch = std::env::temp_dir().join(format!(
        "xtask-index-{}-{}",
        std::process::id(),
        unique_suffix()
    ));
    if index.is_file() {
        fs::copy(&index, &scratch).context("copying the git index")?;
    }
    let scratch_text = scratch.to_string_lossy().into_owned();
    let env = [("GIT_INDEX_FILE", scratch_text.as_str())];
    let result = run(repo, &["add", "-A", "--", "."], &env)
        .and_then(|added| added.context("git add -A into a scratch index failed"))
        .and_then(|_| run(repo, &["write-tree"], &env))
        .and_then(|tree| tree.context("git write-tree failed"));
    let _ = fs::remove_file(&scratch);
    Ok(result?.trim().to_owned())
}

pub fn current_branch(repo: &Repo) -> Result<Option<String>> {
    try_trimmed(repo, &["symbolic-ref", "--quiet", "--short", "HEAD"])
}

/// The main checkout of `repo`'s repository: `repo`'s own root, and for a linked worktree the
/// folder that holds the shared `.git` directory, as git resolves it.
pub fn main_checkout(repo: &Repo) -> Result<PathBuf> {
    let common = PathBuf::from(
        output(
            repo,
            &["rev-parse", "--path-format=absolute", "--git-common-dir"],
        )?
        .trim(),
    );
    match common.parent() {
        Some(main) if common.file_name().is_some_and(|name| name == GIT_DIR) => {
            Ok(main.to_path_buf())
        }
        _ => Ok(repo.root().to_path_buf()),
    }
}

/// Whether `repo` is a linked worktree rather than the main checkout.
pub fn is_linked_worktree(repo: &Repo) -> Result<bool> {
    let own = output(repo, &["rev-parse", "--path-format=absolute", "--git-dir"])?;
    let common = output(
        repo,
        &["rev-parse", "--path-format=absolute", "--git-common-dir"],
    )?;
    Ok(own.trim() != common.trim())
}

/// Commits reachable from `HEAD` and not from `base`, oldest first. Merge commits are left out:
/// a pull request's CI checks out the test merge GitHub makes, whose message is GitHub's, and the
/// queue squashes every change into one commit.
pub fn commits_since(repo: &Repo, base: &Base) -> Result<Vec<Commit>> {
    let Base::Commit { commit, .. } = base else {
        return Ok(Vec::new());
    };
    if head(repo)?.as_deref() == Some(commit.as_str()) {
        return Ok(Vec::new());
    }
    let range = format!("{commit}..HEAD");
    let log = output(
        repo,
        &[
            "log",
            "--reverse",
            "--no-merges",
            "--format=%H%x1f%B%x1e",
            &range,
        ],
    )?;
    Ok(log
        .split('\u{1e}')
        .filter_map(|record| {
            let (sha, message) = record.trim_start_matches('\n').split_once('\u{1f}')?;
            Some(Commit {
                sha: sha.to_owned(),
                message: message.trim_end().to_owned(),
            })
        })
        .collect())
}

/// The content of `path` at `commit`, or `None` when the commit has no such file.
pub fn show(repo: &Repo, commit: &str, path: &str) -> Result<Option<String>> {
    try_output(repo, &["show", &format!("{commit}:{path}")])
}

/// A file at the base commit, or in the working tree when the base is unborn or lacks it, with a
/// label naming where it came from.
pub fn read_at(repo: &Repo, base: &Base, path: &str) -> Result<(Option<String>, String)> {
    if let Some(commit) = base.commit()
        && let Some(text) = show(repo, commit, path)?
    {
        return Ok((Some(text), format!("{path} at {commit}")));
    }
    let text = repo
        .read_optional(path)
        .with_context(|| format!("reading {path}"))?;
    Ok((text, format!("{path} in the working tree")))
}

/// The git tree id of directory `path` at `commit`.
pub fn tree_id(repo: &Repo, commit: &str, path: &str) -> Result<Option<String>> {
    let spec = format!("{commit}:{path}");
    try_trimmed(repo, &["rev-parse", "--verify", "--quiet", &spec])
}

fn run(repo: &Repo, args: &[&str], env: &[(&str, &str)]) -> Result<Option<String>> {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repo.root())
        .args(args)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .envs(env.iter().copied());
    let timeout = Limits::built_with()?.kit.git.timeout();
    let ran = process::run(&mut command, None, timeout).context("starting git")?;
    Ok(ran.success().then(|| ran.stdout()))
}

/// Like [`try_output`], with the surrounding whitespace trimmed.
fn try_trimmed(repo: &Repo, args: &[&str]) -> Result<Option<String>> {
    Ok(try_output(repo, args)?.map(|text| text.trim().to_owned()))
}

/// The paths of a `-z` listing, without duplicates or the root.
fn listed_paths(listing: &str) -> BTreeSet<RepoPath> {
    listing
        .split('\0')
        .filter_map(RepoPath::new)
        .filter(|path| !path.is_root())
        .collect()
}

fn parse_added(diff: &str) -> BTreeMap<RepoPath, BTreeSet<usize>> {
    let mut added: BTreeMap<RepoPath, BTreeSet<usize>> = BTreeMap::new();
    let mut current: Option<RepoPath> = None;
    for line in diff.lines() {
        if let Some(path) = line.strip_prefix("+++ ") {
            current = path.strip_prefix("b/").and_then(RepoPath::new);
            if let Some(path) = &current {
                added.entry(path.clone()).or_default();
            }
            continue;
        }
        let (Some(path), Some(range)) = (&current, hunk_range(line)) else {
            continue;
        };
        added.entry(path.clone()).or_default().extend(range);
    }
    added
}

/// `@@ -3,2 +5,4 @@` adds lines 5 to 8.
fn hunk_range(line: &str) -> Option<std::ops::Range<usize>> {
    let rest = line.strip_prefix("@@ ")?;
    let new = rest
        .split_whitespace()
        .find_map(|part| part.strip_prefix('+'))?;
    let (start, count) = match new.split_once(',') {
        Some((start, count)) => (start.parse().ok()?, count.parse().ok()?),
        None => (new.parse().ok()?, 1usize),
    };
    Some(start..start.checked_add(count)?)
}

fn unique_suffix() -> u128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_nanos())
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn added_lines_from_zero_context_diff() {
        let diff = "diff --git a/src/a.rs b/src/a.rs\n--- a/src/a.rs\n+++ b/src/a.rs\n@@ -1,0 +2,3 @@\n+x\n+y\n+z\n@@ -9 +12 @@\n-old\n+new\ndiff --git a/gone.rs b/gone.rs\n--- a/gone.rs\n+++ /dev/null\n@@ -1 +0,0 @@\n-x\n";
        let added = parse_added(diff);
        let lines: Vec<usize> = added[&RepoPath::new("src/a.rs").unwrap()]
            .iter()
            .copied()
            .collect();
        assert_eq!(lines, vec![2, 3, 4, 12]);
        assert_eq!(added.len(), 1);
    }

    #[test]
    fn hunk_without_added_lines() {
        assert_eq!(hunk_range("@@ -4,2 +3,0 @@"), Some(3..3));
        assert_eq!(hunk_range("not a hunk"), None);
    }

    #[test]
    fn a_test_merge_is_not_a_commit_of_the_change() {
        use crate::orchestrate::testkit::{git, init_git};
        let temp = crate::testkit::TempRepo::create();
        init_git(temp.root());
        let repo = temp.repo();
        let base = head(&repo).unwrap().unwrap();
        git(temp.root(), &["switch", "--quiet", "-c", "agent/seed"]);
        temp.write("docs/plan.md", "The plan.\n");
        git(temp.root(), &["add", "-A"]);
        git(
            temp.root(),
            &["commit", "--quiet", "-m", "docs(plan): seed the agent team"],
        );
        git(temp.root(), &["switch", "--quiet", "--detach", &base]);
        git(
            temp.root(),
            &[
                "merge",
                "--quiet",
                "--no-ff",
                "-m",
                "Merge abc into def",
                "agent/seed",
            ],
        );
        let since = base_for(&repo, Some(&base)).unwrap();
        let messages: Vec<String> = commits_since(&repo, &since)
            .unwrap()
            .into_iter()
            .map(|commit| commit.message)
            .collect();
        assert_eq!(messages, vec!["docs(plan): seed the agent team"]);
    }

    #[test]
    fn a_worktree_knows_its_main_checkout() {
        use crate::orchestrate::testkit::{git, init_git};
        let temp = crate::testkit::TempRepo::create();
        init_git(temp.root());
        let worktree = temp.root().join(".agent/worktrees/7-a1");
        git(
            temp.root(),
            &[
                "worktree",
                "add",
                "--quiet",
                "--detach",
                &worktree.to_string_lossy(),
            ],
        );
        let main = main_checkout(&temp.repo()).unwrap();
        assert_eq!(main_checkout(&Repo::at(&worktree)).unwrap(), main);
        assert_eq!(
            fs::canonicalize(&main).unwrap(),
            fs::canonicalize(temp.root()).unwrap()
        );
        assert!(!is_linked_worktree(&temp.repo()).unwrap());
        assert!(is_linked_worktree(&Repo::at(&worktree)).unwrap());
    }
}
