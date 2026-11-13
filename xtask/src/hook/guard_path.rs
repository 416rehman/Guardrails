//! `PreToolUse` on the file tools (team/03 section 4.1): protected paths always, the kit's own
//! state always, and for an agent the paths outside its scope: the item's write set with a
//! snapshot of its own item, the seed paths in the seed session, and the roster's `write` globs
//! otherwise, so a planner or evaluator launched on another agent's item never gets its write
//! set. The
//! seed and protected scopes widen what a session may write. A path is judged where it lands once
//! the links on its way are followed. Outside the repository, no session writes inside a git
//! directory or the main checkout a worktree belongs to, and an agent never writes the files that
//! configure Claude Code, git, gh or cargo for every later session, through this tool or the shell
//! ([`outside_refusal`]). An edit it allows on a path of `.agents/kit/path-skills.toml` names that
//! entry's skills the first time the session edits there (owner instruction 18).
//!
//! The project settings carry no Edit allow rule, so an agent's write inside its scope runs in
//! `dontAsk` only because this handler approves it. A person's session gets no approval and
//! prompts as before. Every protected path is an Edit deny rule (kit render), which no approval
//! overrides, so a widened session puts a protected path in place with `cargo xtask kit place`
//! instead.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result};

use super::context::{Context, expand_home, tool_path};
use super::identity::{Identity, Who};
use super::model;
use super::outcome::Outcome;
use super::path_skills::{self, PATH_SKILLS_FILE, PathSkills};
use super::state::SkillsState;
use crate::config::protected::ProtectedPaths;
use crate::config::session::Scope;
use crate::gates::protected::allowance;
use crate::git::{self, Base};
use crate::globs::{Case, GlobList};
use crate::kit::{claude_config, gh_config};
use crate::paths::{self, Located};
use crate::repo::resolve_existing;

/// Written by xtask and the hooks only: the kit binary, evidence and session state.
pub const KIT_STATE: &[&str] = &[
    ".git/**",
    ".agent/kit/**",
    ".agent/evidence/**",
    ".agent/state/**",
];
/// What an agent writes itself under `.agent/`: its hand-off, the bodies of issues and comments it
/// posts, its predictions (skill grdr-start-item), the run records an audit keeps without its
/// runner (audit.js), the evaluator's expectation log until the evidence writer of WI-0002 owns
/// it (skill grdr-evaluate), and the files a widened session stages for `kit place`.
const AGENT_DRAFTS: &[&str] = &[
    ".agent/state/handoff-*",
    ".agent/state/proposed-*",
    ".agent/state/audit-run-*",
    ".agent/state/research-*",
    ".agent/state/threat-model-*",
    ".agent/state/*.AGENTS.draft.md",
    ".agent/state/expect-*",
    ".agent/evidence/expectations-*.jsonl",
    ".agent/state/place/**",
];
/// Where a widened session stages the protected files `cargo xtask kit place` puts in place.
const PLACE_DIR: &str = ".agent/state/place";
/// Ends a staged copy's name, so no `**/` protected glob (`**/AGENTS.md`, `**/*.snap`) denies
/// the copy to the file tools.
const PLACE_SUFFIX: &str = ".staged";
/// Ends a refusal of a scratch file under `.agent/`: an agent asking for one usually wants a body
/// for gh, which a draft holds, since an inline body with `#` lines is refused in `dontAsk`.
const DRAFT_HINT: &str = "; an issue or comment body is a draft at .agent/state/proposed-<slug>.md, passed with --body-file";

/// Files under the home directory that configure every later session: Claude Code's settings
/// and the configuration of git and cargo. Claude Code's and gh's own directories are wherever
/// [`claude_config`] and [`gh_config`] find them.
const HOME_CONFIGURATION: &[&str] = &[
    ".claude/",
    ".claude.json",
    ".gitconfig",
    ".config/git/",
    ".cargo/config",
];
/// The directory component of a git repository's own files.
const GIT_DIR: &str = ".git";

/// What the handler decides about one write.
enum Verdict {
    Refused(String),
    /// Inside the repository and inside the agent's scope.
    Approved,
    /// No decision: a person's session, or a path outside the repository nothing refuses.
    Undecided,
}

/// [`KIT_STATE`] with [`AGENT_DRAFTS`] carved out, compiled once for every path a handler checks.
pub struct KitState {
    state: GlobList,
    drafts: GlobList,
}

impl KitState {
    pub fn compile() -> Result<KitState> {
        KitState::from_lists(KIT_STATE, AGENT_DRAFTS)
    }

    /// A list that does not compile is an error naming its glob, so the handler fails closed
    /// instead of allowing the write.
    fn from_lists(state: &[&str], drafts: &[&str]) -> Result<KitState> {
        Ok(KitState {
            state: GlobList::new(state, Case::Insensitive).context("the kit-state globs")?,
            drafts: GlobList::new(drafts, Case::Insensitive).context("the agent-draft globs")?,
        })
    }

    /// An agent's own draft under `.agent/`.
    pub fn is_draft(&self, path: &str) -> bool {
        self.drafts.is_match(path)
    }

    /// Written by xtask and the hooks only.
    pub fn is_kit_written(&self, path: &str) -> bool {
        self.state.is_match(path) && !self.is_draft(path)
    }
}

/// Where a widened session writes its copy of `path` for `cargo xtask kit place`.
pub fn staged_path(path: &str) -> String {
    format!("{PLACE_DIR}/{path}{PLACE_SUFFIX}")
}

pub fn run(context: &Context) -> Result<Outcome> {
    let identity = Identity::load(context)?;
    if let Some(message) = model::violation(context, &identity)? {
        return Ok(Outcome::Block(message));
    }
    let Some(raw) = tool_path(&context.input) else {
        return Ok(Outcome::Allow);
    };
    let verdict = verdict(context, &identity, raw)?;
    if let Verdict::Refused(reason) = verdict {
        return Ok(Outcome::Block(reason));
    }
    let skills = first_skills(context, raw)?;
    Ok(match (verdict, skills) {
        (Verdict::Approved, context) => Outcome::Approve {
            reason: format!(
                "{raw} is inside what {} writes",
                identity.agent().unwrap_or("this session")
            ),
            context,
        },
        (_, Some(skills)) => Outcome::Context(skills),
        (_, None) => Outcome::Allow,
    })
}

/// The skills of every path-skill entry `raw` matches that this session has not been told yet.
/// A state file that cannot be written is logged, so the edit is never blocked for it.
fn first_skills(context: &Context, raw: &str) -> Result<Option<String>> {
    let Some(path) = context.locate_inside(raw) else {
        return Ok(None);
    };
    let mapping = PathSkills::load(&context.repo)?;
    let matching = mapping.matching(&context.repo, path.as_str());
    let session = context.input.session_id();
    let mut state = match session {
        Some(session) => SkillsState::load(&context.repo, session)?,
        None => SkillsState::default(),
    };
    let fresh: Vec<_> = matching
        .into_iter()
        .filter(|entry| !state.announced.contains(&entry.name))
        .collect();
    if fresh.is_empty() {
        return Ok(None);
    }
    state
        .announced
        .extend(fresh.iter().map(|entry| entry.name.clone()));
    if let Some(session) = session
        && let Err(error) = state.save(&context.repo, session)
    {
        context.note(format!("could not save the path-skill state: {error:#}"));
    }
    let names: Vec<&str> = fresh.iter().map(|entry| entry.name.as_str()).collect();
    Ok(Some(format!(
        "Before editing {path}, load these skills with the Skill tool, in order: {} ({PATH_SKILLS_FILE}: {}).",
        path_skills::skills_of(&fresh).join(", "),
        names.join(", ")
    )))
}

/// Whether `identity` may write `raw`, and whether this handler approves it.
fn verdict(context: &Context, identity: &Identity, raw: &str) -> Result<Verdict> {
    let expanded = if raw.starts_with('~') {
        expand_home(raw, &context.env)
            .to_string_lossy()
            .into_owned()
    } else {
        raw.to_owned()
    };
    let cwd = context.input.cwd();
    let located = match context.repo.locate_through_links(&expanded, cwd.as_deref()) {
        Ok(located) => located,
        Err(error) => {
            return Ok(Verdict::Refused(format!(
                "{raw} goes through a link the guard cannot follow ({error:#}); write the path it leads to"
            )));
        }
    };
    let path = match located {
        Located::Inside(path) => path,
        Located::Outside(absolute) => {
            let refused = outside_refusal(context, identity, &absolute).or_else(|| {
                identity.snapshot().map(|snapshot| {
                    format!(
                        "{absolute} is outside the repository, so outside the write set of issue #{}",
                        snapshot.number
                    )
                })
            });
            return Ok(refused.map_or(Verdict::Undecided, Verdict::Refused));
        }
    };
    let text = path.as_str();
    let in_own_scope = match &identity.who {
        Who::Agent { .. } => Verdict::Approved,
        Who::Person | Who::Unknown(_) => Verdict::Undecided,
    };
    let kit_state = KitState::compile()?;
    if kit_state.is_draft(text) {
        return Ok(in_own_scope);
    }
    if kit_state.is_kit_written(text) {
        return Ok(Verdict::Refused(format!(
            "{path} is the kit's own state, written by xtask and the hooks only"
        )));
    }
    let widened = match identity.agent() {
        Some(agent) => allowance(&context.repo, &Base::Unborn, &identity.session, agent)?,
        None => None,
    };
    let in_scope = |text: &str| widened.as_ref().is_some_and(|globs| globs.is_match(text));
    let protected = ProtectedPaths::load(&context.repo)?.globs()?;
    if protected.is_match(text) {
        let reason = if in_scope(text) {
            format!(
                "{path} is a protected path in this session's scope, and the project's permission rules deny every protected path to the file tools. Stage it instead: `cargo xtask kit place --stage {path}` copies the current file to {} (skip that for a new file); edit or write that copy, then run `cargo xtask kit place {path}`. When the tree does not build, run both through the installed kit, `.agent/kit/bin/xtask kit place`, which compiles nothing",
                staged_path(path.as_str())
            )
        } else {
            format!(
                "{path} is a protected path (.agents/kit/protected-paths.toml); ask for the change in the hand-off's protected_change_requests"
            )
        };
        return Ok(Verdict::Refused(reason));
    }
    let own_item = identity
        .snapshot()
        .filter(|snapshot| identity.agent() == Some(snapshot.agent.as_str()));
    if let Some(snapshot) = own_item {
        if !snapshot.write_set_globs()?.is_match(text) && !in_scope(text) {
            return Ok(Verdict::Refused(format!(
                "{path} is outside the write set of issue #{} ({}); file a status:proposed issue for it and name it in the hand-off's next field",
                snapshot.number,
                snapshot.write_set.join(", ")
            )));
        }
        return Ok(in_own_scope);
    }
    if identity.scope() == Some(Scope::Seed) && widened.is_some() {
        if !in_scope(text) {
            return Ok(Verdict::Refused(format!(
                "{path} is outside the seed scope (.agents/kit/seed-scope.toml paths); the seed session writes those paths only{}",
                draft_hint(text)
            )));
        }
        return Ok(in_own_scope);
    }
    if let Who::Agent { name, agent } = &identity.who
        && !agent.write_globs()?.is_match(text)
        && !in_scope(text)
    {
        let globs = if agent.write.is_empty() {
            "none".to_owned()
        } else {
            agent.write.join(", ")
        };
        return Ok(Verdict::Refused(format!(
            "{path} is outside what {name} writes ({globs}, .agents/roster.toml); file a status:proposed issue for it instead{}",
            draft_hint(text)
        )));
    }
    Ok(in_own_scope)
}

fn draft_hint(path: &str) -> &'static str {
    if path.starts_with(".agent/") {
        DRAFT_HINT
    } else {
        ""
    }
}

/// Why no tool may write `absolute`, a path outside the repository, for `identity`: a path inside
/// a git directory or inside the main checkout a worktree session belongs to, for any session, and
/// for an agent a file that configures every later session. The main checkout holds the kit binary
/// every hook there runs, its state, its protected paths and the worktrees of every other session.
/// guard-command asks the same of shell writes, since on native Windows there is no sandbox
/// behind it.
pub fn outside_refusal(context: &Context, identity: &Identity, absolute: &str) -> Option<String> {
    if in_git_dir(absolute) {
        return Some(format!(
            "{absolute} is inside a git directory, which only git writes; its hooks are kit configuration"
        ));
    }
    let target = spellings(Path::new(absolute));
    match git::main_checkout(&context.repo) {
        Ok(main) if rest_below(&target, &main).is_some() => {
            return Some(format!(
                "{absolute} is in the main checkout {}, which the dispatcher and the kit run from; a session writes only inside its own worktree",
                main.display()
            ));
        }
        Ok(_) => {}
        Err(error) => {
            return Some(format!(
                "cannot tell whether {absolute} is in this repository's main checkout ({error:#}); write inside the repository"
            ));
        }
    }
    if identity.is_agent() && configures_sessions(&target, context) {
        return Some(format!(
            "{absolute} configures every later session; an agent never writes Claude Code's or gh's configuration directory or these paths in the home directory: {}",
            HOME_CONFIGURATION.join(", ")
        ));
    }
    None
}

/// A path in Claude Code's or gh's configuration directory, or one `HOME_CONFIGURATION` names
/// under a home directory: the one Claude Code reads and the one `HOME` names for git and cargo.
/// The directory itself counts, since a link to it lets a later write reach into it.
fn configures_sessions(target: &[String], context: &Context) -> bool {
    let lookup = context.env.lookup();
    let homes: Vec<PathBuf> = [claude_config::home(&lookup), context.env.home()]
        .into_iter()
        .flatten()
        .collect();
    let in_config_dir = claude_config::config_dir(&lookup)
        .into_iter()
        .chain(gh_config::config_dirs(&lookup, &homes))
        .any(|dir| rest_below(target, &dir).is_some());
    in_config_dir
        || homes.iter().any(|home| {
            rest_below(target, home).is_some_and(|rest| {
                HOME_CONFIGURATION.iter().any(|entry| {
                    rest.starts_with(entry) || Some(rest.as_str()) == entry.strip_suffix('/')
                })
            })
        })
}

/// `path` as written and as the file system resolves it, both [`normal`]: a link, a junction or
/// a Windows short name gives one file two spellings.
fn spellings(path: &Path) -> Vec<String> {
    let written = normal(&path.to_string_lossy());
    match resolve_existing(path).map(|real| normal(&real.to_string_lossy())) {
        Ok(real) if real != written => vec![written, real],
        _ => vec![written],
    }
}

/// The part of `target`, in one of its [`spellings`], at or below `dir` in one of its own: empty
/// for `dir` itself.
fn rest_below(target: &[String], dir: &Path) -> Option<String> {
    let dirs = spellings(dir);
    target.iter().find_map(|path| {
        dirs.iter().find_map(|dir| {
            let rest = path.strip_prefix(dir.trim_end_matches('/'))?;
            match rest.strip_prefix('/') {
                Some(below) => Some(below.to_owned()),
                None => rest.is_empty().then(String::new),
            }
        })
    })
}

/// Forward slashes, no verbatim prefix and one case, so spellings of a path compare equal.
fn normal(text: &str) -> String {
    paths::forward_slashes(text).to_ascii_lowercase()
}

/// A path inside some repository's `.git` directory, such as the main checkout's hooks from a
/// worktree.
pub fn in_git_dir(path: &str) -> bool {
    normal(path)
        .split('/')
        .any(|component| component == GIT_DIR)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn git_directories_anywhere() {
        assert!(in_git_dir(r"D:\src\grdr\.git\hooks\pre-commit"));
        assert!(in_git_dir("/home/dev/grdr/.git/hooks"));
        assert!(in_git_dir("/home/dev/grdr/.GIT/config"));
        assert!(!in_git_dir("/home/dev/grdr/.github/hooks.md"));
        assert!(!in_git_dir("/home/dev/grdr/x.git/config"));
    }

    #[test]
    fn a_path_is_below_a_directory_in_either_spelling() {
        let home = crate::testkit::TempRepo::create();
        let alias = crate::testkit::TempRepo::create();
        let linked = alias.root().join("home");
        crate::testkit::link_dir(&linked, home.root());
        let through_link = spellings(&linked.join(".claude").join("settings.json"));
        assert_eq!(
            rest_below(&through_link, home.root()).as_deref(),
            Some(".claude/settings.json")
        );
        let written = spellings(&home.root().join(".gitconfig"));
        assert_eq!(rest_below(&written, &linked).as_deref(), Some(".gitconfig"));
        assert_eq!(
            rest_below(&written, home.root()).as_deref(),
            Some(".gitconfig")
        );
        assert_eq!(
            rest_below(&spellings(home.root()), home.root()).as_deref(),
            Some("")
        );
        assert_eq!(rest_below(&written, alias.root()), None);
    }

    #[test]
    fn drafts_are_carved_out_of_kit_state() {
        let kit_state = KitState::compile().unwrap();
        assert!(kit_state.is_draft(".agent/state/handoff-7-impl-rust.json"));
        assert!(!kit_state.is_kit_written(".agent/state/handoff-7-impl-rust.json"));
        assert!(!kit_state.is_draft(".agent/state/item-7.json"));
        assert!(kit_state.is_kit_written(".agent/state/item-7.json"));
        assert!(kit_state.is_kit_written(".agent/kit/bin/xtask.exe"));
        for draft in [
            ".agent/state/expect-7.jsonl",
            ".agent/state/research-7.md",
            ".agent/state/grdr-core.AGENTS.draft.md",
            ".agent/evidence/expectations-7.jsonl",
            ".agent/state/place/AGENTS.md.staged",
        ] {
            assert!(kit_state.is_draft(draft), "{draft}");
        }
        assert!(kit_state.is_kit_written(".agent/evidence/chain.jsonl"));
        assert!(kit_state.is_kit_written(".agent/state/session-1.md"));
    }

    #[test]
    fn a_glob_that_does_not_compile_is_named() {
        let error = KitState::from_lists(&[".agent/state/[x"], AGENT_DRAFTS)
            .err()
            .unwrap();
        assert!(
            format!("{error:#}").contains(".agent/state/[x"),
            "{error:#}"
        );
    }
}
