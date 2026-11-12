//! Gate V05 for agent sessions: no protected path in the branch diff (team/05 section 5). The two
//! widened scopes are the chief architect's seed session (`.agents/kit/seed-scope.toml`) and a
//! protected-change lease, whose own write set is allowed (owner instruction 7). The gate reads the
//! protected paths, the seed scope and `[dispatch] protected_change_agents` at the comparison base,
//! so a change never sets the rules that judge it; the hooks read the working tree, which their
//! session cannot write. A session that holds another agent's item, an evaluator's, judges that
//! item's branch as its writer would be judged: with the seed scope on the seed's branch and with
//! the item's write set for a protected-change agent, as the merge queue does. Only the gate does
//! this; the hooks still hold such a session to its own scope.

use anyhow::Result;

use super::{Context, Outcome};
use crate::config::protected::{ProtectedPaths, SeedScope};
use crate::config::session::{ItemSnapshot, Scope, Session};
use crate::git::{self, Base};
use crate::globs::GlobList;
use crate::orchestrate::launch::protected_change_agents;
use crate::paths::RepoPath;
use crate::repo::Repo;

pub fn gate(context: &Context) -> Result<Outcome> {
    let Some(agent) = context.session.agent.as_deref() else {
        return Ok(Outcome::skip(
            "GRDR_AGENT is unset, so this is a person's session",
        ));
    };
    let protected = ProtectedPaths::at(&context.repo, &context.base)?.globs()?;
    let writer = writer_of(&context.repo, &context.base, &context.session, agent)?;
    let (agent, session) = writer
        .as_ref()
        .map_or((agent, &context.session), |(name, session)| {
            (name.as_str(), session)
        });
    let allowed = allowance(&context.repo, &context.base, session, agent)?;
    Ok(Outcome::from_problems(violations(
        &context.changed,
        &protected,
        allowed.as_ref(),
    )))
}

/// For a session holding the snapshot of an item another agent writes, that writer and the scope
/// its change is judged in: the seed scope when the checkout is on the seed's branch, otherwise
/// the protected scope, which [`allowance`] grants only to a protected-change agent's own item.
fn writer_of(
    repo: &Repo,
    rules_at: &Base,
    session: &Session,
    agent: &str,
) -> Result<Option<(String, Session)>> {
    let Some(item) = session.item(repo)? else {
        return Ok(None);
    };
    if item.agent == agent {
        return Ok(None);
    }
    let branch = git::current_branch(repo)?.unwrap_or_default();
    let on_seed_branch =
        SeedScope::at(repo, rules_at)?.is_some_and(|seed| seed.is_session(&item.agent, &branch));
    let scope = if on_seed_branch {
        Scope::Seed
    } else {
        Scope::Protected
    };
    let judged = Session {
        agent: Some(item.agent.clone()),
        work_item: session.work_item,
        scope: Some(scope),
    };
    Ok(Some((item.agent, judged)))
}

/// Protected paths in `changed` that the session's scope does not cover.
pub fn violations(
    changed: &[RepoPath],
    protected: &GlobList,
    allowed: Option<&GlobList>,
) -> Vec<String> {
    changed
        .iter()
        .filter(|path| protected.is_match(path.as_str()))
        .filter(|path| !allowed.is_some_and(|globs| globs.is_match(path.as_str())))
        .map(|path| format!("{path} is protected; stop with status blocked and a protected_change_requests entry"))
        .collect()
}

/// The protected globs this session may write, if its scope widens anything. `rules_at` is where
/// the scope data is read: the comparison base in the gate, `Base::Unborn` (the working tree)
/// in the hooks.
pub fn allowance(
    repo: &Repo,
    rules_at: &Base,
    session: &Session,
    agent: &str,
) -> Result<Option<GlobList>> {
    match session.scope {
        None => Ok(None),
        Some(Scope::Seed) => {
            let Some(seed) = SeedScope::at(repo, rules_at)? else {
                return Ok(None);
            };
            if seed.agent != agent || seed.scope != "seed" {
                return Ok(None);
            }
            seed.globs().map(Some)
        }
        Some(Scope::Protected) => match protected_lease(repo, rules_at, session, agent)? {
            Some(item) => item.write_set_globs().map(Some),
            None => Ok(None),
        },
    }
}

/// The item of a protected-change lease (owner instruction 7): `GRDR_SCOPE=protected`, an agent
/// that `[dispatch] protected_change_agents` at `rules_at` names, and a snapshot of an issue
/// leased to that agent. Anything less widens nothing.
pub fn protected_lease(
    repo: &Repo,
    rules_at: &Base,
    session: &Session,
    agent: &str,
) -> Result<Option<ItemSnapshot>> {
    if session.scope != Some(Scope::Protected)
        || !protected_change_agents(repo, rules_at)?
            .iter()
            .any(|name| name == agent)
    {
        return Ok(None);
    }
    Ok(session.item(repo)?.filter(|item| item.agent == agent))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::limits::Limits;
    use crate::gates::Form;
    use crate::git;
    use crate::globs::Case;
    use crate::orchestrate::testkit::init_git;
    use crate::testkit::TempRepo;

    const SNAPSHOT: &str = r#"{"schema": "item-snapshot.v1", "number": 7, "title": "[WI-0003] Gates",
        "agent": "impl-rust", "kind": "gate", "squad": null, "size": null, "risk_tier": "high",
        "trust_core": false, "write_set": [".agents/**"], "status": "leased",
        "acceptance_sha256": "ab", "attempt": 1, "fetched_at": "2026-11-11T10:00:00Z"}"#;

    fn paths(list: &[&str]) -> Vec<RepoPath> {
        list.iter().map(|p| RepoPath::new(p).unwrap()).collect()
    }

    /// The gate over `changed` in `temp`, judged against its first commit, as `session`.
    fn judged(temp: &TempRepo, changed: &[&str], session: Session) -> Outcome {
        let repo = temp.repo();
        let context = Context {
            base: git::base_for(&repo, Some("HEAD")).unwrap(),
            limits: Limits::working_tree(&repo).unwrap(),
            repo,
            form: Form::Fast,
            changed: paths(changed),
            session,
        };
        gate(&context).unwrap()
    }

    fn problems(outcome: Outcome) -> Vec<String> {
        match outcome {
            Outcome::Fail { problems } => problems,
            other => panic!("V05 passed a protected change: {other:?}"),
        }
    }

    #[test]
    fn a_change_that_drops_its_paths_from_the_list_is_judged_by_the_base_list() {
        let temp = TempRepo::create();
        temp.write(
            ".agents/kit/protected-paths.toml",
            "paths = [\"Cargo.toml\", \".agents/**\"]\n",
        );
        init_git(temp.root());
        temp.write(".agents/kit/protected-paths.toml", "paths = []\n");
        let session = Session {
            agent: Some("impl-rust".into()),
            work_item: None,
            scope: None,
        };
        let found = problems(judged(
            &temp,
            &[".agents/kit/protected-paths.toml"],
            session,
        ));
        assert!(
            found[0].starts_with(".agents/kit/protected-paths.toml is protected"),
            "{found:?}"
        );
    }

    #[test]
    fn a_change_that_names_its_agent_a_protected_writer_widens_nothing() {
        let temp = TempRepo::create();
        temp.write(
            ".agents/kit/protected-paths.toml",
            "paths = [\".agents/**\"]\n",
        );
        init_git(temp.root());
        let harness = temp.repo().read(".agents/harness.toml").unwrap();
        temp.write(
            ".agents/harness.toml",
            &harness.replace(
                "protected_change_agents = [\"lead-agent-kit\", \"chief-architect\"]",
                "protected_change_agents = [\"impl-rust\"]",
            ),
        );
        temp.write(".agent/state/item-7.json", SNAPSHOT);
        assert_eq!(
            protected_change_agents(&temp.repo(), &Base::Unborn).unwrap(),
            vec!["impl-rust"]
        );
        let session = Session {
            agent: Some("impl-rust".into()),
            work_item: Some(7),
            scope: Some(Scope::Protected),
        };
        let found = problems(judged(&temp, &[".agents/harness.toml"], session));
        assert!(
            found[0].starts_with(".agents/harness.toml is protected"),
            "{found:?}"
        );
    }

    #[test]
    fn an_evaluator_judges_a_protected_change_by_its_writers_write_set() {
        let temp = TempRepo::create();
        temp.write(
            ".agents/kit/protected-paths.toml",
            "paths = [\".agents/**\", \"AGENTS.md\"]\n",
        );
        init_git(temp.root());
        temp.write(
            ".agent/state/item-7.json",
            &SNAPSHOT.replace("\"impl-rust\"", "\"lead-agent-kit\""),
        );
        let evaluator = || Session {
            agent: Some("eval-acceptance".into()),
            work_item: Some(7),
            scope: None,
        };
        let changed = [".agents/kit/hooks.toml"];
        assert!(matches!(
            judged(&temp, &changed, evaluator()),
            Outcome::Pass { .. }
        ));
        let found = problems(judged(
            &temp,
            &[".agents/kit/hooks.toml", "AGENTS.md"],
            evaluator(),
        ));
        assert_eq!(found.len(), 1, "{found:?}");
        assert!(found[0].starts_with("AGENTS.md is protected"), "{found:?}");
    }

    #[test]
    fn an_evaluator_of_an_ordinary_item_widens_nothing() {
        let temp = TempRepo::create();
        temp.write(
            ".agents/kit/protected-paths.toml",
            "paths = [\".agents/**\"]\n",
        );
        init_git(temp.root());
        temp.write(".agent/state/item-7.json", SNAPSHOT);
        let evaluator = Session {
            agent: Some("eval-acceptance".into()),
            work_item: Some(7),
            scope: None,
        };
        let found = problems(judged(&temp, &[".agents/kit/hooks.toml"], evaluator));
        assert!(
            found[0].starts_with(".agents/kit/hooks.toml is protected"),
            "{found:?}"
        );
    }

    #[test]
    fn protected_paths_fail_unless_the_scope_allows_them() {
        let protected = GlobList::new(
            &["Cargo.toml", ".agents/**", "**/AGENTS.md"],
            Case::Insensitive,
        )
        .unwrap();
        let changed = paths(&[
            "crates/a/src/lib.rs",
            "Cargo.toml",
            "crates/a/AGENTS.md",
            ".agents/kit/hooks.toml",
        ]);
        assert_eq!(violations(&changed, &protected, None).len(), 3);
        let seed = GlobList::new(&["**/AGENTS.md"], Case::Sensitive).unwrap();
        let left = violations(&changed, &protected, Some(&seed));
        assert_eq!(left.len(), 2);
        assert!(left[0].starts_with("Cargo.toml is protected"));
    }
}
