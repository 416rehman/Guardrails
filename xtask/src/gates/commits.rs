//! Gate V24: every commit message is one Conventional Commit line, `type(scope): summary`, with
//! the type from the allowed list and the length limit of `.agents/harness.toml [commit]`; no
//! body, no trailer and no credit line (owner instruction 27). The model that wrote a change is
//! in the pull request's metadata block, not in its commits. `guard-command` calls
//! [`check_message`] on agent commits before they are made.

use anyhow::{Result, bail};
use serde::Deserialize;

use super::{Context, Outcome};
use crate::git;
use crate::repo::Repo;

const HARNESS_FILE: &str = "harness.toml";

/// `.agents/harness.toml [commit]`.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CommitForm {
    pub types: Vec<String>,
    pub max_subject_chars: usize,
}

#[derive(Debug, Deserialize)]
struct HarnessCommit {
    commit: Option<CommitForm>,
}

impl CommitForm {
    pub fn load(repo: &Repo) -> Result<CommitForm> {
        let (label, path) = crate::config::agents_file(repo, HARNESS_FILE);
        let file: HarnessCommit = crate::config::read_toml(&path, &label)?;
        match file.commit {
            Some(form) if !form.types.is_empty() && form.max_subject_chars > 0 => Ok(form),
            Some(_) => bail!("{label} [commit] needs a non-empty `types` and `max_subject_chars`"),
            None => bail!(
                "{label} has no [commit] table with the commit form (`types`, `max_subject_chars`)"
            ),
        }
    }
}

pub fn gate(context: &Context) -> Result<Outcome> {
    let commits = git::commits_since(&context.repo, &context.base)?;
    if commits.is_empty() {
        return Ok(Outcome::skip("no commits since the base"));
    }
    let form = CommitForm::load(&context.repo)?;
    let problems = commits
        .iter()
        .flat_map(|commit| {
            check_message(&commit.message, &form)
                .into_iter()
                .map(|problem| format!("{}: {problem}", commit.sha))
        })
        .collect();
    Ok(Outcome::from_problems(problems))
}

/// Every way `message` is not one valid commit line under `form`.
pub fn check_message(message: &str, form: &CommitForm) -> Vec<String> {
    let message = message.trim_end();
    let mut problems = Vec::new();
    if message.lines().nth(1).is_some() {
        problems.push(
            "the message has more than one line; a commit is one subject line with no body, trailer or credit line"
                .to_owned(),
        );
    }
    let subject = message.lines().next().unwrap_or_default();
    problems.extend(subject_problem(subject, form));
    let length = subject.chars().count();
    if length > form.max_subject_chars {
        problems.push(format!(
            "the subject is {length} characters, over the limit of {}",
            form.max_subject_chars
        ));
    }
    problems
}

/// Why `subject` is not `type(scope)!: summary`, if it is not.
fn subject_problem(subject: &str, form: &CommitForm) -> Option<String> {
    let shape = || {
        format!(
            "`{subject}` is not a Conventional Commit `type(scope): summary` with type one of {}",
            form.types.join(", ")
        )
    };
    let Some((head, summary)) = subject.split_once(": ") else {
        return Some(shape());
    };
    let head = head.strip_suffix('!').unwrap_or(head);
    let (kind, scope) = match head.split_once('(') {
        Some((kind, rest)) => match rest.strip_suffix(')') {
            Some(scope) => (kind, Some(scope)),
            None => return Some(shape()),
        },
        None => (head, None),
    };
    if !form.types.iter().any(|allowed| allowed == kind) {
        return Some(shape());
    }
    if scope.is_some_and(|scope| !valid_scope(scope)) {
        return Some(format!(
            "the scope of `{subject}` is not lower-case letters, digits, `.`, `_`, `/` or `-`"
        ));
    }
    if summary.is_empty() || summary.starts_with(char::is_whitespace) {
        return Some(shape());
    }
    (!balanced(summary)).then(|| {
        format!("the summary of `{subject}` has unbalanced or nested parentheses, which release-please cannot parse")
    })
}

fn valid_scope(scope: &str) -> bool {
    scope
        .chars()
        .next()
        .is_some_and(|first| first.is_ascii_lowercase() || first.is_ascii_digit())
        && scope.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | '-')
        })
}

/// Parentheses that open and close in order, one level deep.
fn balanced(text: &str) -> bool {
    let mut open = false;
    for c in text.chars() {
        match (c, open) {
            ('(', false) => open = true,
            (')', true) => open = false,
            ('(', true) | (')', false) => return false,
            _ => {}
        }
    }
    !open
}

#[cfg(test)]
mod tests {
    use super::*;

    fn form() -> CommitForm {
        CommitForm {
            types: ["feat", "fix", "docs", "chore"].map(str::to_owned).to_vec(),
            max_subject_chars: 72,
        }
    }

    #[test]
    fn one_valid_line_passes() {
        for message in [
            "feat(kit): render managed settings",
            "fix: handle the empty case\n",
            "feat(grdr-core)!: drop the v0 wire format",
            "docs(plan): name the operator plane (D-70)",
        ] {
            assert!(check_message(message, &form()).is_empty(), "{message}");
        }
    }

    #[test]
    fn bodies_trailers_and_bad_subjects_fail() {
        let with_trailer =
            "fix(kit): x\n\nWork-Item: #7\nAssisted-by: claude-code:claude-sonnet-5-5";
        assert_eq!(check_message(with_trailer, &form()).len(), 1);
        assert_eq!(check_message("Render managed settings", &form()).len(), 1);
        assert_eq!(check_message("style: x", &form()).len(), 1);
        assert_eq!(check_message("fix(Kit): x", &form()).len(), 1);
        assert_eq!(check_message("fix(kit: x", &form()).len(), 1);
        assert_eq!(check_message("fix:  x", &form()).len(), 1);
        assert_eq!(check_message("fix: a (b (c))", &form()).len(), 1);
        assert_eq!(check_message("fix: a (b", &form()).len(), 1);
        let long = format!("fix: {}", "x".repeat(70));
        assert_eq!(check_message(&long, &form()).len(), 1);
    }

    #[test]
    fn the_form_comes_from_the_harness_file() {
        let temp = crate::testkit::TempRepo::create();
        temp.write(
            ".agents/harness.toml",
            "[dispatch]\nmax_writers = 3\n[commit]\ntypes = [\"fix\"]\nmax_subject_chars = 50\n",
        );
        let loaded = CommitForm::load(&temp.repo()).unwrap();
        assert_eq!(loaded.types, vec!["fix".to_owned()]);
        assert_eq!(loaded.max_subject_chars, 50);
        temp.write(".agents/harness.toml", "[dispatch]\nmax_writers = 3\n");
        assert!(CommitForm::load(&temp.repo()).is_err());
    }
}
