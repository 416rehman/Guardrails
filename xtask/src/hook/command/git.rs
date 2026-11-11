//! git (team/03 section 4.1, owner instructions 7 and 27): force pushes; pushes to the base and
//! release branches of `.agents/harness.toml [pull_request]`; `--no-verify` and `core.hooksPath`;
//! pushes and tags an agent's role does not allow; and an agent commit whose message is not one
//! Conventional Commit line (`commit.rs`). git takes any unambiguous prefix of a long option, so
//! options are matched by what they resolve to (`options.rs`).

mod commit;
mod options;

use std::path::Path;

use anyhow::Result;

use self::options::{LongOption, Subcommand};
use super::{Rules, join};
use crate::hook::identity::Role;
use crate::hook::shell::{Invocation, Word};

const GLOBAL_VALUED: &[&str] = &[
    "--git-dir",
    "--work-tree",
    "--namespace",
    "--super-prefix",
    "--exec-path",
];
const PUSH_VALUED: &[&str] = &["--repo", "-o", "--push-option", "--receive-pack", "--exec"];
const TAG_LISTING: &[&str] = &[
    "-l",
    "--list",
    "--contains",
    "--no-contains",
    "--points-at",
    "--merged",
    "--no-merged",
    "-n",
];
/// Configuration that moves where a push lands, so the refspec on the command line no longer says.
const PUSH_CONFIG: &[&str] = &["remote.", "push.default", "branch.", "url."];
const PUSH_CONFIG_SUFFIXES: &[&str] = &[
    ".push",
    ".pushurl",
    ".merge",
    ".remote",
    ".pushremote",
    ".insteadof",
    ".pushinsteadof",
];
const CONFIG_READS: &[&str] = &[
    "--get",
    "--get-all",
    "--get-regexp",
    "-l",
    "--list",
    "--show-origin",
];

pub fn check(rules: &Rules, invocation: &Invocation, cwd: Option<&Path>) -> Result<Vec<String>> {
    let args = &invocation.args;
    let mut reasons = Vec::new();
    let mut dir = cwd.map(Path::to_path_buf);
    let mut index = 0;
    while let Some(word) = args.get(index).filter(|word| word.value.starts_with('-')) {
        let value = word.value.as_str();
        let next = args.get(index + 1);
        let config = match value {
            "-c" => next,
            _ if value.starts_with("--config-env") => Some(word),
            _ => None,
        };
        if config.is_some_and(|config| {
            config.opaque || config.value.to_ascii_lowercase().contains("core.hookspath")
        }) {
            reasons.push(
                "`git -c core.hooksPath` moves the hooks; git hooks stay where the kit put them"
                    .to_owned(),
            );
        }
        if rules.is_agent()
            && let Some(config) = config.filter(|config| moves_push(&config.value))
        {
            reasons.push(format!(
                "`git -c {}` changes where a push lands; push with an explicit refspec to your own branch",
                config.value
            ));
        }
        if value == "-C" {
            dir = next.and_then(|next| (!next.opaque).then(|| join(cwd, &next.value)));
        }
        let valued = matches!(value, "-C" | "-c")
            || (GLOBAL_VALUED.contains(&value) && !value.contains('='));
        index += if valued { 2 } else { 1 };
    }
    let Some(sub) = args.get(index) else {
        return Ok(reasons);
    };
    if sub.opaque {
        reasons.push(format!(
            "`git {}` hides its subcommand; write it literally",
            sub.raw
        ));
        return Ok(reasons);
    }
    let rest = args.get(index + 1..).unwrap_or_default();
    let subcommand = Subcommand::of(&sub.value);
    let skips_hooks = rest.iter().any(|word| match subcommand {
        Some(subcommand) if word.value.starts_with("--") => {
            subcommand.resolve(&word.value) == LongOption::Known("--no-verify")
        }
        _ => word.value == "--no-verify",
    });
    if skips_hooks {
        reasons.push("`--no-verify` skips the git hooks; fix what they report instead".to_owned());
    }
    let dir = dir.as_deref();
    match sub.value.as_str() {
        "push" => reasons.extend(push(rules, rest, dir)),
        "commit" => reasons.extend(commit::commit(rules, rest, dir)?),
        "config" if config_moves_hooks(rest) => {
            reasons.push("`git config core.hooksPath` moves the hooks; git hooks stay where the kit put them".to_owned());
        }
        "config" if rules.is_agent() && config_moves_push(rest) => {
            reasons.push("`git config` of a push, remote or branch key changes where a push lands; agents push with an explicit refspec".to_owned());
        }
        "tag" if rules.is_agent() && creates_tag(rest) => {
            reasons.push("release tags are made by release-please, never by a session".to_owned());
        }
        _ => {}
    }
    Ok(reasons)
}

fn push(rules: &Rules, args: &[Word], dir: Option<&Path>) -> Vec<String> {
    let mut reasons = Vec::new();
    let mut positional: Vec<&Word> = Vec::new();
    let mut index = 0;
    let mut options_done = false;
    while let Some(word) = args.get(index) {
        index += 1;
        let value = word.value.as_str();
        if options_done || !value.starts_with('-') {
            positional.push(word);
            continue;
        }
        let long = value.starts_with("--") && value != "--";
        let value = match Subcommand::Push.resolve(value) {
            LongOption::Known(full) if long => full,
            LongOption::Unresolved if long && rules.is_agent() => {
                reasons.push(format!(
                    "`git push {value}` is not one git push option; write the option out in full"
                ));
                continue;
            }
            _ => value,
        };
        let short_force = !value.starts_with("--")
            && value.len() > 1
            && value.chars().skip(1).all(|c| c.is_ascii_alphabetic())
            && value.contains('f');
        match value {
            "--" => options_done = true,
            _ if short_force || value.starts_with("--force") || value == "--mirror" => {
                reasons.push(format!(
                    "`git push {value}` rewrites history on the remote; push new commits instead"
                ));
            }
            "--all" | "--branches" => {
                reasons.push("`git push --all` pushes every branch, main included".to_owned())
            }
            "--tags" | "--follow-tags" if rules.is_agent() => {
                reasons.push(
                    "tags are made and pushed by release-please, never by a session".to_owned(),
                );
            }
            "--prune" if rules.is_agent() => {
                reasons.push("`git push --prune` deletes remote branches".to_owned())
            }
            _ if PUSH_VALUED.contains(&value) && !word.value.contains('=') => index += 1,
            _ => {}
        }
    }
    let destinations: Vec<Result<String, String>> = if positional.len() > 1 {
        positional
            .iter()
            .skip(1)
            .map(|refspec| destination(rules, refspec, dir))
            .collect()
    } else {
        vec![dir.and_then(|dir| rules.branch(dir)).ok_or_else(|| {
            "`git push` from a detached HEAD has no branch to check; name the refspec".to_owned()
        })]
    };
    for destination in destinations {
        match destination {
            Ok(branch) => reasons.extend(branch_problem(rules, &branch)),
            Err(reason) => reasons.push(reason),
        }
    }
    reasons
}

/// The remote branch a refspec updates; force refspecs and expansions are reasons.
fn destination(rules: &Rules, refspec: &Word, dir: Option<&Path>) -> Result<String, String> {
    if refspec.opaque {
        return Err(format!(
            "the push refspec `{}` depends on an expansion; write the branch literally",
            refspec.raw
        ));
    }
    let value = refspec.value.as_str();
    if let Some(forced) = value.strip_prefix('+') {
        return Err(format!(
            "`+{forced}` force-pushes; push new commits instead"
        ));
    }
    let target = value.rsplit_once(':').map_or(value, |(_, target)| target);
    let target = if target == "HEAD" || target.is_empty() && !value.contains(':') {
        dir.and_then(|dir| rules.branch(dir))
            .unwrap_or_else(|| "HEAD".to_owned())
    } else {
        target.to_owned()
    };
    if target.starts_with("refs/tags/") && rules.is_agent() {
        return Err("tags are made and pushed by release-please, never by a session".to_owned());
    }
    Ok(target
        .strip_prefix("refs/heads/")
        .unwrap_or(&target)
        .to_owned())
}

fn branch_problem(rules: &Rules, branch: &str) -> Option<String> {
    if rules.github.is_protected_branch(branch) {
        return Some(format!(
            "pushing to `{branch}` is the merge queue's job; push your {} branch",
            rules.github.any_item_branch()
        ));
    }
    match rules.role {
        Role::Person => return None,
        Role::Implementer | Role::Gardener => {}
        _ => {
            return Some(format!(
                "{} pushes no branches; its output is issue comments",
                rules.agent_name()
            ));
        }
    }
    (!rules.is_own_branch(branch)).then(|| {
        format!(
            "{} may push only `{}`, not `{branch}`",
            rules.agent_name(),
            rules.own_branch_pattern()
        )
    })
}

/// `remote.<name>.push`, `push.default`, `branch.<name>.merge` and the like.
fn moves_push(setting: &str) -> bool {
    let key = setting
        .split('=')
        .next()
        .unwrap_or_default()
        .trim()
        .to_ascii_lowercase();
    key == "push.default"
        || (PUSH_CONFIG.iter().any(|prefix| key.starts_with(prefix))
            && PUSH_CONFIG_SUFFIXES
                .iter()
                .any(|suffix| key.ends_with(suffix)))
}

/// `git config <key> <value>` that sets a key `moves_push` names; reads are left alone.
fn config_moves_push(args: &[Word]) -> bool {
    if args
        .iter()
        .any(|word| CONFIG_READS.contains(&word.value.as_str()))
    {
        return false;
    }
    args.iter()
        .find(|word| !word.value.starts_with('-'))
        .is_some_and(|key| key.opaque || moves_push(&key.value))
}

fn config_moves_hooks(args: &[Word]) -> bool {
    let reads = args
        .iter()
        .any(|word| CONFIG_READS.contains(&word.value.as_str()));
    let names_hooks = args
        .iter()
        .any(|word| word.opaque || word.value.to_ascii_lowercase().contains("core.hookspath"));
    names_hooks && !reads
}

fn creates_tag(args: &[Word]) -> bool {
    let lists = args
        .iter()
        .any(|word| TAG_LISTING.contains(&word.value.as_str()));
    let named = args.iter().any(|word| !word.value.starts_with('-'));
    named && !lists
}
