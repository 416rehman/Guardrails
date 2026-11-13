//! The chief architect's seed session hands off like an implementer: its `agent/seed` pull request
//! enters review as a leased item's does, and a blocked or impossible end escalates its issue,
//! since nobody readies the seed's issue.

use serde_json::json;

use super::tests::{caller, draft, temp_repo};
use super::*;
use crate::config::session::Scope;
use crate::orchestrate::records::{LEASE_SCHEMA, Lease, lease_comment, records};
use crate::orchestrate::testkit::{MemoryTracker, body, git, init_git, issue};
use crate::testkit::TempRepo;

#[test]
fn the_seed_sessions_blocked_or_impossible_handoff_escalates_its_issue() {
    for status in ["blocked", "impossible"] {
        let temp = temp_repo();
        temp.write(
            ".agents/kit/seed-scope.toml",
            "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\npaths = [\"AGENTS.md\"]\n",
        );
        let tracker = MemoryTracker::default();
        tracker.add(issue(
            7,
            &["status:leased", "agent:chief-architect"],
            &body("chief-architect", &["AGENTS.md"], "AC-1"),
        ));
        let lease = Lease {
            schema: LEASE_SCHEMA.into(),
            item: 7,
            attempt: 2,
            agent: "chief-architect".into(),
            model: "claude-sonnet-5-5".into(),
            acceptance_sha256: "x".into(),
            branch: "agent/seed".into(),
            session: Some("6b1c0f4e-1111-4222-8333-944455556607".into()),
        };
        tracker.comment(7, &lease_comment(&lease).unwrap()).unwrap();
        let mut ended = draft(status);
        ended["agent"] = json!("chief-architect");
        temp.write(
            ".agent/state/handoff-7-chief-architect.json",
            &ended.to_string(),
        );
        let seeding = Caller {
            session: Session {
                agent: Some("chief-architect".to_owned()),
                work_item: Some(7),
                scope: Some(Scope::Seed),
            },
            model: None,
        };
        let code = publish(&temp.repo(), &tracker, 7, &seeding, Mode::Live).unwrap();
        assert_eq!(code, ExitCode::SUCCESS);
        assert_eq!(
            tracker.snapshot(7).status(),
            Some(ItemStatus::Escalated),
            "{status}"
        );
    }
}

#[test]
fn the_seed_session_ships_agent_seed_into_review() {
    let temp = temp_repo();
    temp.write(".gitignore", ".agent/\n");
    temp.write(
        ".agents/kit/seed-scope.toml",
        "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\npaths = [\"AGENTS.md\"]\n",
    );
    init_git(temp.root());
    let origin = TempRepo::create();
    git(
        origin.root(),
        &["init", "--quiet", "--bare", "--initial-branch=main"],
    );
    let url = origin.root().to_string_lossy().into_owned();
    git(temp.root(), &["remote", "add", "origin", &url]);
    git(temp.root(), &["push", "--quiet", "origin", "main"]);
    let form = Form::load(&temp.repo()).unwrap();
    crate::orchestrate::launch::check_out_seed_branch(&temp.repo(), &form, "agent/seed").unwrap();
    temp.write("AGENTS.md", "# Agents\n");
    git(temp.root(), &["add", "-A"]);
    git(
        temp.root(),
        &["commit", "--quiet", "-m", "docs(plan): seed the agent team"],
    );
    let tracker = MemoryTracker::default();
    tracker.add(issue(
        7,
        &["status:proposed", "agent:chief-architect"],
        &body("chief-architect", &["AGENTS.md"], "AC-1"),
    ));
    let mut seed = draft("done");
    seed["agent"] = json!("chief-architect");
    temp.write(
        ".agent/state/handoff-7-chief-architect.json",
        &seed.to_string(),
    );
    let ordinary = caller("chief-architect");
    let seeding = Caller {
        session: Session {
            scope: Some(Scope::Seed),
            ..ordinary.session.clone()
        },
        ..ordinary
    };
    let code = publish(&temp.repo(), &tracker, 7, &seeding, Mode::Live).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let calls = tracker.calls();
    assert!(
        calls
            .iter()
            .any(|call| call == "pr create agent/seed docs(plan): seed the agent team"),
        "{calls:?}"
    );
    assert!(git(origin.root(), &["branch", "--list"]).contains("agent/seed"));
    let after = tracker.snapshot(7);
    assert_eq!(after.status(), Some(ItemStatus::InReview));
    let found = records(&after);
    let lease = crate::orchestrate::records::current_lease(&found, 7).unwrap();
    assert_eq!(lease.branch, "agent/seed");
    assert_eq!(
        crate::orchestrate::records::lane_floor(&found, 7),
        Some(crate::orchestrate::risk::Lane::Full)
    );
    assert_eq!(crate::git::current_branch(&temp.repo()).unwrap(), None);
    let worktree = temp.root().join(".agent/worktrees/7-a1");
    git(
        temp.root(),
        &[
            "worktree",
            "add",
            "--quiet",
            &worktree.to_string_lossy(),
            "agent/seed",
        ],
    );
    let fix = Repo::at(&worktree);
    assert_eq!(
        crate::git::current_branch(&fix).unwrap().as_deref(),
        Some("agent/seed")
    );
    release_seed_branch(&fix, "agent/seed").unwrap();
    assert_eq!(
        crate::git::current_branch(&fix).unwrap().as_deref(),
        Some("agent/seed")
    );
}

#[test]
fn the_seed_branch_is_checked_out_from_the_base() {
    let temp = temp_repo();
    temp.write(".gitignore", ".agent/\n");
    init_git(temp.root());
    let repo = temp.repo();
    let form = Form::load(&repo).unwrap();
    crate::orchestrate::launch::check_out_seed_branch(&repo, &form, "agent/seed").unwrap();
    assert_eq!(
        crate::git::current_branch(&repo).unwrap().as_deref(),
        Some("agent/seed")
    );
    crate::orchestrate::launch::check_out_seed_branch(&repo, &form, "agent/seed").unwrap();
    git(temp.root(), &["checkout", "--quiet", "main"]);
    temp.write(".gitignore", ".agent/\ntarget/\n");
    let error =
        crate::orchestrate::launch::check_out_seed_branch(&repo, &form, "agent/seed").unwrap_err();
    assert!(
        format!("{error:#}").contains("uncommitted changes"),
        "{error:#}"
    );
}
