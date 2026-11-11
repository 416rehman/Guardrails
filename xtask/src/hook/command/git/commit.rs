//! `git commit` (owner instructions 7 and 27): `--no-verify` for no one, and for an agent one
//! `-m` whose text [`check_message`] accepts against `.agents/harness.toml [commit]`. Anything
//! that adds a line to the message or hides it from the hook is refused: `-F`, `--file`,
//! `--template`, a second `-m`, `--trailer`, sign-off and fixup commits, under any prefix git
//! takes for them, and any long option that resolves to none. A reused or amended message is read
//! from the log and checked the same way.

use std::path::Path;

use anyhow::Result;

use super::super::Rules;
use super::options::{LongOption, Subcommand};
use crate::gates::commits::{CommitForm, check_message};
use crate::hook::shell::Word;
use crate::repo::Repo;

const COMMIT_VALUED: &[&str] = &["--author", "--date", "--cleanup", "--pathspec-from-file"];

const COMMIT_SHORT_VALUED: &[char] = &['m', 'F', 'C', 'c', 't'];

/// Long options an agent's commit may not carry, each followed by the value it takes.
const REFUSED_VALUED: &[(&str, Refused)] = &[
    ("--file", Refused::File),
    ("--template", Refused::Template),
    ("--trailer", Refused::Trailer),
    ("--fixup", Refused::Fixup),
    ("--squash", Refused::Fixup),
];

/// What a `git commit` command line says about its message.
#[derive(Debug, Default)]
struct CommitLine {
    messages: Vec<Word>,
    reuse: Option<Word>,
    refused: Vec<Refused>,
    flags: Vec<CommitFlag>,
    /// Long options git would refuse as unknown or ambiguous, as written.
    unresolved: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum CommitFlag {
    Amend,
    NoVerify,
    DryRun,
}

/// Options an agent's commit may not carry, because each adds a line or hides the message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Refused {
    File,
    Template,
    Trailer,
    SignOff,
    Fixup,
}

impl Refused {
    fn reason(self) -> &'static str {
        match self {
            Refused::File => {
                "commit: -F and --file are refused; give the message as one -m on the command line"
            }
            Refused::Template => {
                "commit: --template is refused; give the message as one -m on the command line"
            }
            Refused::Trailer => "commit: commits carry no trailers; drop --trailer",
            Refused::SignOff => {
                "commit: commits carry no Signed-off-by or other credit line; drop -s"
            }
            Refused::Fixup => {
                "commit: fixup and squash commits are not one Conventional Commit line; amend locally instead"
            }
        }
    }
}

pub(super) fn commit(rules: &Rules, args: &[Word], dir: Option<&Path>) -> Result<Vec<String>> {
    let line = parse_commit(args);
    let mut reasons = Vec::new();
    if line.flags.contains(&CommitFlag::NoVerify) {
        reasons
            .push("`git commit -n` skips the git hooks; fix what they report instead".to_owned());
    }
    if !rules.is_agent() || line.flags.contains(&CommitFlag::DryRun) {
        return Ok(reasons);
    }
    reasons.extend(
        line.refused
            .iter()
            .map(|refused| refused.reason().to_owned()),
    );
    reasons.extend(line.unresolved.iter().map(|option| {
        format!("commit: `{option}` is not one git commit option; write the option out in full")
    }));
    if line.messages.len() > 1 {
        reasons.push(
            "commit: a second -m adds a body; a commit is one line given in one -m".to_owned(),
        );
    }
    match message(&line, dir) {
        Ok(message) => {
            let form = CommitForm::load(&rules.context.repo)?;
            reasons.extend(
                check_message(&message, &form)
                    .into_iter()
                    .map(|problem| format!("commit: {problem}")),
            );
        }
        Err(reason) => reasons.push(format!("commit: {reason}")),
    }
    Ok(reasons)
}

fn parse_commit(args: &[Word]) -> CommitLine {
    let mut line = CommitLine::default();
    let mut index = 0;
    while let Some(word) = args.get(index) {
        index += 1;
        let value = word.value.as_str();
        if value == "--" {
            break;
        }
        if !value.starts_with('-') {
            continue;
        }
        let (name, attached) = match value.split_once('=') {
            Some((name, attached)) if value.starts_with("--") => {
                (name, Some(word.with_value(attached)))
            }
            _ => (value, None),
        };
        let name = if name.starts_with("--") {
            match Subcommand::Commit.resolve(name) {
                LongOption::Known(full) => full,
                LongOption::Unresolved => {
                    line.unresolved.push(name.to_owned());
                    continue;
                }
            }
        } else {
            name
        };
        let take = |index: &mut usize| {
            attached.clone().or_else(|| {
                let next = args.get(*index).cloned();
                *index += 1;
                next
            })
        };
        if let Some((_, refused)) = REFUSED_VALUED.iter().find(|(option, _)| *option == name) {
            let _ = take(&mut index);
            line.refused.push(*refused);
            continue;
        }
        match name {
            "--message" => line.messages.extend(take(&mut index)),
            "--reuse-message" | "--reedit-message" => line.reuse = take(&mut index),
            "--amend" => line.flags.push(CommitFlag::Amend),
            "--signoff" => line.refused.push(Refused::SignOff),
            "--no-signoff" => line.refused.retain(|refused| *refused != Refused::SignOff),
            "--dry-run" => line.flags.push(CommitFlag::DryRun),
            _ if COMMIT_VALUED.contains(&name) => {
                let _ = take(&mut index);
            }
            _ if !name.starts_with("--") => index = short_cluster(&mut line, word, args, index),
            _ => {}
        }
    }
    line
}

/// `-am <msg>`, `-sm<msg>`, `-n`: flags until one that takes a value.
fn short_cluster(line: &mut CommitLine, word: &Word, args: &[Word], mut index: usize) -> usize {
    let flags: Vec<char> = word.value.chars().skip(1).collect();
    for (position, flag) in flags.iter().enumerate() {
        match flag {
            'n' => line.flags.push(CommitFlag::NoVerify),
            's' => line.refused.push(Refused::SignOff),
            'S' | 'u' => return index,
            flag if COMMIT_SHORT_VALUED.contains(flag) => {
                let rest: String = flags.iter().skip(position + 1).collect();
                let value = if rest.is_empty() {
                    index += 1;
                    args.get(index - 1).cloned()
                } else {
                    Some(word.with_value(&rest))
                };
                match flag {
                    'm' => line.messages.extend(value),
                    'F' => line.refused.push(Refused::File),
                    't' => line.refused.push(Refused::Template),
                    'C' | 'c' => line.reuse = value,
                    _ => {}
                }
                return index;
            }
            _ => {}
        }
    }
    index
}

/// The message the commit will have, or why it cannot be known before it runs.
fn message(line: &CommitLine, dir: Option<&Path>) -> Result<String, String> {
    if let Some(first) = line.messages.first() {
        if first.opaque {
            return Err(
                "the message depends on an expansion; write it literally in one -m".to_owned(),
            );
        }
        return Ok(first.value.clone());
    }
    if let Some(reuse) = &line.reuse {
        if reuse.opaque {
            return Err("the reused commit depends on an expansion".to_owned());
        }
        return logged_message(dir, &reuse.value);
    }
    if line.flags.contains(&CommitFlag::Amend) {
        return logged_message(dir, "HEAD");
    }
    if !line.refused.is_empty() {
        return Err("give the message as one -m".to_owned());
    }
    Err(
        "a commit without -m opens an editor no agent can use; give the message as one -m"
            .to_owned(),
    )
}

fn logged_message(dir: Option<&Path>, commit: &str) -> Result<String, String> {
    let dir = dir.ok_or("the commit runs in an unknown directory")?;
    crate::git::try_output(&Repo::at(dir), &["log", "-1", "--format=%B", commit])
        .ok()
        .flatten()
        .map(|text| text.trim_end().to_owned())
        .ok_or_else(|| format!("cannot read the message of {commit}"))
}
