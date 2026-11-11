//! Gate Q01 `acceptance-digest` (team/05 section 5, owner instruction 5), in the CI form only
//! because it reads the issue and `verify` uses no network: the pull request's issue, from
//! `GRDR_WORK_ITEM` or the item branch `.agents/harness.toml [github] branch` names, must carry
//! a `ready.v1` from an agent that may ready it and does not implement it, and its acceptance
//! section and write set must still match the digests that `ready.v1` holds, the acceptance
//! section also the current lease's. Any edit of either after readying, the implementer's
//! included, fails it. The seed session's `[WI-0000]` issue is never readied: its lease, which
//! `kit handoff` posts, holds its acceptance digest alone. Who may ready and the seed scope are read
//! at the comparison base, as V05 reads its rules, so a change never decides who readied it.

use anyhow::{Context as _, Result};

use super::{Context, Outcome};
use crate::config::protected::SeedScope;
use crate::config::runtime::Harness;
use crate::git;
use crate::github::{Gh, Mode};
use crate::orchestrate::issue::Issue;
use crate::orchestrate::labels::LabelsFile;
use crate::orchestrate::records;
use crate::orchestrate::tracker::{GhTracker, Tracker};

const ISSUE_PLACEHOLDER: &str = "{issue}";
const ATTEMPT_PLACEHOLDER: &str = "{attempt}";
/// The pull request's branch in a GitHub Actions `pull_request` run, where `HEAD` is detached.
const PULL_REQUEST_BRANCH_VARIABLE: &str = "GITHUB_HEAD_REF";

pub fn gate(context: &Context) -> Result<Outcome> {
    let Some(item) = work_item(context)? else {
        return Ok(Outcome::skip(
            "not an item branch, so there is no issue to check",
        ));
    };
    let tracker = GhTracker::new(Gh::for_repo(&context.repo, Mode::Live)?);
    let issue = tracker.issue(item)?;
    let seed = SeedScope::at(&context.repo, &context.base)?;
    let labels = LabelsFile::at(&context.repo, &context.base)?;
    Ok(Outcome::from_problems(problems(
        &issue,
        seed.as_ref(),
        &labels,
    )?))
}

/// `GRDR_WORK_ITEM`, else the issue the current branch, or the pull request's branch in CI, is
/// the item branch of.
fn work_item(context: &Context) -> Result<Option<u64>> {
    if let Some(number) = context.session.work_item {
        return Ok(Some(number));
    }
    let checked_out = git::current_branch(&context.repo)?;
    let Some(branch) = checked_out.or_else(|| {
        std::env::var(PULL_REQUEST_BRANCH_VARIABLE)
            .ok()
            .filter(|branch| !branch.is_empty())
    }) else {
        return Ok(None);
    };
    let template = Harness::load(&context.repo)?
        .github
        .branch
        .context(".agents/harness.toml [github] has no `branch`, the item branch template")?;
    Ok(item_of(&branch, &template))
}

/// The issue number in `branch` when it fills `template`, whose `{issue}` comes before its
/// `{attempt}`, with digits.
fn item_of(branch: &str, template: &str) -> Option<u64> {
    let (prefix, rest) = template.split_once(ISSUE_PLACEHOLDER)?;
    let (between, suffix) = rest.split_once(ATTEMPT_PLACEHOLDER)?;
    let filled = branch.strip_prefix(prefix)?.strip_suffix(suffix)?;
    let (number, attempt) = filled.split_once(between)?;
    let is_number = |text: &str| !text.is_empty() && text.chars().all(|c| c.is_ascii_digit());
    if !is_number(attempt) || !is_number(number) {
        return None;
    }
    number.parse().ok()
}

/// Every reason the issue's acceptance section and write set are not the ones its item was
/// readied and leased on.
pub fn problems(
    issue: &Issue,
    seed: Option<&SeedScope>,
    labels: &LabelsFile,
) -> Result<Vec<String>> {
    let number = issue.number;
    let found = records::records(issue);
    let item = issue.work_item();
    let current = item.acceptance.as_ref().map(|a| a.sha256.as_str());
    let lease = records::current_lease(&found, number);
    let matches_lease = lease.is_none_or(|lease| Some(lease.acceptance_sha256.as_str()) == current);
    let changed = format!(
        "acceptance section of #{number} does not match the ready.v1 digest; the item returns to status:proposed"
    );
    let seed_item = lease
        .is_some_and(|lease| seed.is_some_and(|seed| seed.is_session(&lease.agent, &lease.branch)));
    if seed_item {
        return Ok(if matches_lease {
            Vec::new()
        } else {
            vec![changed]
        });
    }
    let Some((_, ready)) = records::latest_ready(&found, number) else {
        return Ok(vec![format!(
            "#{number} has no ready.v1; a lead, the product lead or the programme manager readies it with cargo xtask kit ready"
        )]);
    };
    let mut problems = Vec::new();
    let acting_as = seed.map_or(&[][..], |seed| seed.roles_of(&ready.by));
    if item.agent.as_deref() == Some(ready.by.as_str()) {
        problems.push(format!(
            "#{number} was readied by its own implementer {}; the agent that readies an item never implements it",
            ready.by
        ));
    } else if !labels.may_ready(&ready.by, acting_as)? {
        problems.push(format!(
            "#{number} was readied by {}, which .github/labels.toml does not let ready items",
            ready.by
        ));
    }
    if current != Some(ready.acceptance_sha256.as_str()) || !matches_lease {
        problems.push(changed);
    }
    if !records::write_set_readied(&found, &item) {
        problems.push(format!(
            "write set of #{number} does not match the ready.v1 digest; the item returns to status:proposed"
        ));
    }
    Ok(problems)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrate::records::{LEASE_SCHEMA, Lease, lease_comment, ready_comment};
    use crate::orchestrate::testkit::{MemoryTracker, body, issue, ready_for};
    use crate::testkit::TempRepo;

    const LABELS: &str = "[[transition]]\nfrom = \"proposed\"\nto = \"ready\"\nby = [\"kit\"]\nrun_by = [\"lead-*\"]\n";
    const SEED: &str = "agent = \"chief-architect\"\nscope = \"seed\"\nbranch = \"agent/seed\"\npaths = [\"AGENTS.md\"]\nacts_as = [\"lead-core\"]\n";

    fn readied(by: &str, criteria: &str) -> Issue {
        let text = body("impl-rust", &["crates/a/**"], criteria);
        let tracker = MemoryTracker::default();
        tracker.add(issue(5, &["status:in-review", "agent:impl-rust"], &text));
        tracker
            .comment(5, &ready_comment(&ready_for(5, by, &text)).unwrap())
            .unwrap();
        tracker.snapshot(5)
    }

    fn labels() -> LabelsFile {
        let temp = TempRepo::create();
        temp.write(".github/labels.toml", LABELS);
        LabelsFile::load(&temp.repo()).unwrap()
    }

    fn seed() -> SeedScope {
        let temp = TempRepo::create();
        temp.write(".agents/kit/seed-scope.toml", SEED);
        SeedScope::load(&temp.repo()).unwrap().unwrap()
    }

    /// The `[WI-0000]` issue with the one lease `kit handoff` posts for the seed session.
    fn seed_item(branch: &str) -> Issue {
        let text = body(
            "chief-architect",
            &["AGENTS.md"],
            "AC-1 | true | exit 0 | oracle: sh",
        );
        let tracker = MemoryTracker::default();
        tracker.add(issue(
            1,
            &["status:in-review", "agent:chief-architect"],
            &text,
        ));
        let lease = Lease {
            schema: LEASE_SCHEMA.into(),
            item: 1,
            attempt: 1,
            agent: "chief-architect".into(),
            model: "claude-fable-5-2".into(),
            acceptance_sha256: ready_for(1, "kit", &text).acceptance_sha256,
            branch: branch.into(),
            session: None,
        };
        tracker.comment(1, &lease_comment(&lease).unwrap()).unwrap();
        tracker.snapshot(1)
    }

    #[test]
    fn the_item_comes_from_a_branch_that_fills_the_template() {
        let template = "agent/{issue}/a{attempt}";
        assert_eq!(item_of("agent/42/a2", template), Some(42));
        assert_eq!(item_of("agent/seed", template), None);
        assert_eq!(item_of("agent/42/a", template), None);
        assert_eq!(item_of("agent/x/a1", template), None);
        assert_eq!(item_of("main", template), None);
    }

    #[test]
    fn a_changed_section_or_a_self_readying_fails() {
        let labels = labels();
        let good = readied("lead-core", "AC-1 | true | exit 0 | oracle: sh");
        assert!(problems(&good, None, &labels).unwrap().is_empty());
        let mut edited = good.clone();
        edited.body = body(
            "impl-rust",
            &["crates/a/**"],
            "AC-1 | true | exit 1 | oracle: sh",
        );
        let found = problems(&edited, None, &labels).unwrap();
        assert_eq!(
            found,
            vec![
                "acceptance section of #5 does not match the ready.v1 digest; the item returns to status:proposed"
            ]
        );
        let own = readied("impl-rust", "AC-1 | true | exit 0 | oracle: sh");
        assert!(problems(&own, None, &labels).unwrap()[0].contains("own implementer"));
    }

    #[test]
    fn a_write_set_edited_after_readying_fails() {
        let labels = labels();
        let mut widened = readied("lead-core", "AC-1 | true | exit 0 | oracle: sh");
        widened.body = body(
            "impl-rust",
            &["crates/a/**", ".github/**"],
            "AC-1 | true | exit 0 | oracle: sh",
        );
        assert_eq!(
            problems(&widened, None, &labels).unwrap(),
            vec![
                "write set of #5 does not match the ready.v1 digest; the item returns to status:proposed"
            ]
        );
    }

    #[test]
    fn the_seed_item_is_judged_by_its_lease_alone() {
        let labels = labels();
        let seed = seed();
        let item = seed_item("agent/seed");
        assert!(problems(&item, Some(&seed), &labels).unwrap().is_empty());
        let mut edited = item.clone();
        edited.body = edited.body.replace("exit 0", "exit 1");
        assert!(
            problems(&edited, Some(&seed), &labels).unwrap()[0]
                .starts_with("acceptance section of #1")
        );
        let elsewhere = seed_item("agent/1/a1");
        assert!(problems(&elsewhere, Some(&seed), &labels).unwrap()[0].contains("has no ready.v1"));
        assert!(problems(&item, None, &labels).unwrap()[0].contains("has no ready.v1"));
    }

    #[test]
    fn the_seed_scope_lets_its_agent_ready_as_the_roles_it_plays() {
        let labels = labels();
        let seed = seed();
        let text = body(
            "impl-rust",
            &["crates/a/**"],
            "AC-1 | true | exit 0 | oracle: sh",
        );
        let tracker = MemoryTracker::default();
        tracker.add(issue(5, &["status:in-review", "agent:impl-rust"], &text));
        tracker
            .comment(
                5,
                &ready_comment(&ready_for(5, "chief-architect", &text)).unwrap(),
            )
            .unwrap();
        let by_seed = tracker.snapshot(5);
        assert!(problems(&by_seed, Some(&seed), &labels).unwrap().is_empty());
        assert!(problems(&by_seed, None, &labels).unwrap()[0].contains("does not let ready items"));
    }

    #[test]
    fn the_rules_are_read_at_the_base() {
        let temp = TempRepo::create();
        let plain_seed = SEED.replace("acts_as = [\"lead-core\"]\n", "");
        temp.write(".github/labels.toml", LABELS);
        temp.write(".agents/kit/seed-scope.toml", &plain_seed);
        crate::orchestrate::testkit::init_git(temp.root());
        temp.write(".github/labels.toml", &LABELS.replace("lead-*", "impl-*"));
        temp.write(".agents/kit/seed-scope.toml", SEED);
        let repo = temp.repo();
        let base = git::base_for(&repo, Some("HEAD")).unwrap();
        let labels = LabelsFile::at(&repo, &base).unwrap();
        assert!(labels.may_ready("lead-core", &[]).unwrap());
        assert!(!labels.may_ready("impl-other", &[]).unwrap());
        let seed = SeedScope::at(&repo, &base).unwrap().unwrap();
        assert!(seed.roles_of("chief-architect").is_empty());
    }
}
