//! Cases built from the kit's workflow scripts by `workflows.js`, which node runs: `review.js` end
//! to end with its agents answered, and the audit and persona-council scripts' own builders, on
//! findings that quote every kit record in each form guard-command refuses. Each command a
//! publisher is given must pass guard-command as `eval-diff` with the kit's own roster, labels
//! and repository; a new issue's title must read without the record escape; and the review's
//! hand-off, with or without an audit child, must be one the Stop gate and `kit handoff` accept.
//! A forced re-review must cite the round's newest verdict comment and that comment must show its
//! verdict, though the posted hand-offs quote the lookup and the run returns to a verdict the
//! round had before; only a run that reaches the newest verdict posts nothing. The next round
//! must read only the newest record of the round before, in whatever order the markers are
//! listed. A comment gh reads back only on the second try is cited once, and one that is never
//! read back is no evidence: the review is incomplete, hands back the comment and its hash
//! command, says why, and names the digest of no input as one never to cite. None posts the
//! comment again.

use std::collections::BTreeMap;
use std::process::Command;

use anyhow::{Context as _, Result, bail};
use serde::Deserialize;
use serde_json::{Value, json};

use super::harness::{Case, Expect, Report, run_case};
use crate::config::limits::HookLimits;
use crate::config::models::Models;
use crate::config::runtime::{Harness, Usage};
use crate::hook::Handler;
use crate::hook::handoff::{Expectation, Kind, validate};
use crate::hook::limits;
use crate::orchestrate::records::KIT_RECORDS;
use crate::process;
use crate::repo::Repo;

const SCRIPT: &str = "xtask/src/hook/selftest/workflows.js";
const AGENT: &str = "eval-diff";
const ITEM: u64 = 7;
const KIT_FILES: &[&str] = &[
    ".agents/harness.toml",
    ".agents/models.toml",
    ".agents/roster.toml",
    ".github/labels.toml",
];
/// What the workflows write for the dot of a record name; an issue title is plain text, so it
/// shows there as written.
const RECORD_ESCAPE: &str = "&#46;";

/// What the scripts built: each publisher command, the review's hand-off by how it ran, what each
/// forced re-review cites, the findings the next round lists, what a review cites when gh reads
/// its comment back late, and what it returns when the comment is never read back.
#[derive(Deserialize)]
struct Built {
    commands: Vec<Published>,
    handoffs: BTreeMap<String, Value>,
    reruns: BTreeMap<String, Citation>,
    prior: Prior,
    reread: Citation,
    unread: BTreeMap<String, Unread>,
}

#[derive(Deserialize)]
struct Published {
    name: String,
    command: String,
}

/// A review's verdict, evidence and read-back prompts, beside the newest verdict comment on the
/// item for its round, the verdict that comment shows, and how many comments the run posted
/// against how many it should.
#[derive(Deserialize)]
struct Citation {
    status: String,
    evidence: Vec<Cited>,
    read_backs: Vec<String>,
    newest: Cited,
    shows: String,
    posted: usize,
    posts: usize,
}

/// An evidence entry by what it points at.
#[derive(Debug, Deserialize, PartialEq)]
struct Cited {
    log: String,
    sha256: String,
}

/// The round after the re-reviewed one, the earlier findings its finders are shown, and the
/// findings of that round's newest verdict.
#[derive(Deserialize)]
struct Prior {
    round: u64,
    after: u64,
    listed: Vec<String>,
    expected: Vec<String>,
}

/// A review whose comment is never read back: its status, evidence and read-back prompts, the
/// comment and hash command it returns beside the ones it posted and gave its publisher, and its
/// reason beside the cause that reason must name and the digest of no input.
#[derive(Deserialize)]
struct Unread {
    status: String,
    evidence: Vec<Cited>,
    read_backs: Vec<String>,
    returned: Comment,
    posted: Comment,
    reason: String,
    cause: String,
    empty_digest: String,
}

/// A verdict comment's URL and the command that hashes it.
#[derive(Debug, Deserialize, PartialEq)]
struct Comment {
    comment: String,
    hash: String,
}

/// Runs the cases into `report`: the commands under guard-command, the hand-offs as the Stop
/// gate reads them.
pub fn record(report: &mut Report, only: Option<&str>, verbose: bool) -> Result<()> {
    let wanted = |handler: Handler| only.is_none_or(|only| only == handler.name());
    if !wanted(Handler::GuardCommand) && !wanted(Handler::StopGate) {
        return Ok(());
    }
    let kit = Repo::discover()?;
    let limits = limits::load(&kit)?;
    let built = match build(&kit, &limits) {
        Ok(built) => built,
        Err(error) => {
            report.record("guard-command/workflow-scripts", Err(error), verbose);
            return Ok(());
        }
    };
    if wanted(Handler::GuardCommand) {
        for case in cases(&kit, &built)? {
            let label = format!("guard-command/{}", case.name);
            let result = run_case(Handler::GuardCommand, "evaluator", &case, &limits);
            report.record(&label, result, verbose);
        }
        report.record(
            "guard-command/workflow-issue-titles",
            titles(&built),
            verbose,
        );
    }
    if wanted(Handler::StopGate) {
        let accepted = handoffs(&kit, &built);
        report.record("stop-gate/workflow-review-handoff", accepted, verbose);
        let rerun = rerun_evidence(&built.reruns);
        report.record("stop-gate/workflow-review-rerun", rerun, verbose);
        let prior = prior_findings(&built.prior);
        report.record("stop-gate/workflow-review-prior", prior, verbose);
        let reread = cites_its_verdict("a review read back on the second try", &built.reread);
        report.record("stop-gate/workflow-review-reread", reread, verbose);
        let unread = unread_evidence(&built.unread);
        report.record("stop-gate/workflow-review-unread", unread, verbose);
    }
    Ok(())
}

fn build(kit: &Repo, limits: &HookLimits) -> Result<Built> {
    let repository = Harness::load(kit)?
        .github
        .repository
        .context(".agents/harness.toml [github] has no repository")?;
    let max_rounds = Usage::load(kit)?
        .item
        .max_review_rounds
        .context(".agents/kit/usage.toml [item] has no max_review_rounds")?;
    let request = json!({
        "root": kit.root(),
        "repository": repository,
        "records": KIT_RECORDS,
        "item": ITEM,
        "maxRounds": max_rounds,
    });
    let mut node = Command::new("node");
    node.arg(kit.path(SCRIPT)).current_dir(kit.root());
    let ran = process::run(
        &mut node,
        Some(request.to_string().as_bytes()),
        limits.selftest.process(),
    )
    .context("starting node, which runs the kit's workflow scripts for these cases")?;
    if !ran.success() {
        bail!("{SCRIPT} failed ({}): {}", ran.describe(), ran.stderr());
    }
    serde_json::from_str(&ran.stdout()).with_context(|| format!("reading what {SCRIPT} printed"))
}

/// One guard-command case per publisher command, as `eval-diff` on the kit's own data.
fn cases(kit: &Repo, built: &Built) -> Result<Vec<Case>> {
    let mut files = BTreeMap::new();
    for path in KIT_FILES {
        files.insert((*path).to_owned(), kit.read(path)?);
    }
    let env = BTreeMap::from([
        ("GRDR_AGENT".to_owned(), AGENT.to_owned()),
        ("GRDR_WORK_ITEM".to_owned(), ITEM.to_string()),
    ]);
    Ok(built
        .commands
        .iter()
        .map(|published| Case {
            name: format!("workflow-{}", published.name),
            preset: None,
            env: env.clone(),
            input: json!({"tool_name": "Bash", "tool_input": {"command": published.command}}),
            expect: Expect::Allow,
            contains: None,
            files: files.clone(),
            sign_off: false,
        })
        .collect())
}

fn titles(built: &Built) -> Result<()> {
    let escaped: Vec<&str> = built
        .commands
        .iter()
        .filter_map(|published| published.command.lines().next())
        .filter(|line| line.starts_with("gh issue create") && line.contains(RECORD_ESCAPE))
        .collect();
    if !escaped.is_empty() {
        bail!(
            "an issue title shows {RECORD_ESCAPE} as text: {}",
            escaped.join("; ")
        );
    }
    Ok(())
}

fn handoffs(kit: &Repo, built: &Built) -> Result<()> {
    let ids: Vec<String> = Models::load(kit)?.ids().map(str::to_owned).collect();
    let expect = Expectation {
        item: ITEM,
        agent: AGENT,
        model_ids: &ids,
        launcher_model: None,
        kind: Kind::Evaluator,
    };
    let refused: Vec<String> = built
        .handoffs
        .iter()
        .filter_map(|(run, handoff)| {
            let problems = validate(handoff, &expect);
            (!problems.is_empty()).then(|| format!("{run}: {}", problems.join("; ")))
        })
        .collect();
    if !refused.is_empty() {
        bail!(
            "kit handoff refuses the review's hand-off {}",
            refused.join("; ")
        );
    }
    Ok(())
}

fn rerun_evidence(reruns: &BTreeMap<String, Citation>) -> Result<()> {
    for (run, citation) in reruns {
        cites_its_verdict(&format!("a forced re-review {run}"), citation)?;
    }
    Ok(())
}

/// The review posts as many verdict comments as it should, the round's newest one shows its
/// verdict, the review cites that comment alone, and no read-back could post another.
fn cites_its_verdict(run: &str, citation: &Citation) -> Result<()> {
    if citation.posted != citation.posts {
        bail!(
            "{run} posts {} verdict comments, not {}",
            citation.posted,
            citation.posts
        );
    }
    if citation.shows != citation.status {
        bail!(
            "{run} ends {} while the round's newest verdict comment {:?} shows {}",
            citation.status,
            citation.newest,
            citation.shows
        );
    }
    if citation.evidence.as_slice() != std::slice::from_ref(&citation.newest) {
        bail!(
            "{run} cites {:?}, not the round's newest verdict comment {:?}",
            citation.evidence,
            citation.newest
        );
    }
    read_backs_post_nothing(run, &citation.read_backs)
}

fn read_backs_post_nothing(run: &str, prompts: &[String]) -> Result<()> {
    if let Some(posting) = prompts
        .iter()
        .find(|prompt| prompt.contains("gh issue comment") || prompt.contains("<<'"))
    {
        bail!("{run} gives a read-back that can post: {posting}");
    }
    Ok(())
}

fn prior_findings(prior: &Prior) -> Result<()> {
    if prior.round != prior.after + 1 {
        bail!(
            "the review after round {} reviews round {}",
            prior.after,
            prior.round
        );
    }
    if prior.listed != prior.expected {
        bail!(
            "round {} lists the earlier findings {:?}, not {:?} from round {}'s newest verdict",
            prior.round,
            prior.listed,
            prior.expected,
            prior.after
        );
    }
    Ok(())
}

fn unread_evidence(unread: &BTreeMap<String, Unread>) -> Result<()> {
    for (run, unread) in unread {
        returns_its_comment(&format!("a review never read back {run}"), unread)?;
    }
    Ok(())
}

fn returns_its_comment(run: &str, unread: &Unread) -> Result<()> {
    if !unread.evidence.is_empty() {
        bail!("{run} cites {:?}", unread.evidence);
    }
    if unread.status != "incomplete" {
        bail!("{run} ends {}", unread.status);
    }
    if unread.returned != unread.posted {
        bail!(
            "{run} returns {:?}, not the comment and hash command it gave its publisher {:?}",
            unread.returned,
            unread.posted
        );
    }
    if !unread.reason.contains(&unread.cause) {
        bail!(
            "{run} gives the reason {:?}, which does not say {:?}",
            unread.reason,
            unread.cause
        );
    }
    if !unread.reason.contains(&unread.empty_digest) {
        bail!(
            "{run} gives the reason {:?}, which does not name {}, the digest of no input, as one never to cite",
            unread.reason,
            unread.empty_digest
        );
    }
    read_backs_post_nothing(run, &unread.read_backs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gates::plan::{VERIFY_TOML, parse_plan};

    /// Where `KIT_RECORDS` and each schema name it lists are defined.
    const RECORDS_SOURCE: &str = "xtask/src/orchestrate/records.rs";
    const RECORDS_LIST: &str = "pub const KIT_RECORDS: &[&str] = &[";

    /// The value of each constant `KIT_RECORDS` lists, from its definition in `source`, so a list
    /// or a name defined in another file is missed.
    fn records_defined_in(source: &str) -> Vec<String> {
        let (_, after) = source
            .split_once(RECORDS_LIST)
            .unwrap_or_else(|| panic!("{RECORDS_SOURCE} no longer defines KIT_RECORDS"));
        let (list, _) = after.split_once("];").unwrap();
        list.split(',')
            .map(str::trim)
            .filter(|name| !name.is_empty())
            .map(|name| {
                let definition = format!("pub const {name}: &str = \"");
                let (_, value) = source.split_once(&definition).unwrap_or_else(|| {
                    panic!("{name}, which KIT_RECORDS lists, is not defined in {RECORDS_SOURCE}")
                });
                value.split_once('"').unwrap().0.to_owned()
            })
            .collect()
    }

    #[test]
    fn the_self_test_runs_when_a_file_these_cases_read_changes() {
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .parent()
            .unwrap();
        let plan = std::fs::read_to_string(root.join(VERIFY_TOML)).unwrap();
        let triggers = parse_plan(&plan)
            .unwrap()
            .into_iter()
            .find(|step| step.id == "V18")
            .and_then(|step| step.changed)
            .unwrap();
        let unwatched: Vec<&str> = KIT_FILES
            .iter()
            .copied()
            .chain([SCRIPT, RECORDS_SOURCE])
            .filter(|path| !triggers.is_match(path))
            .collect();
        assert!(unwatched.is_empty(), "V18 skips a change to {unwatched:?}");
        let records = std::fs::read_to_string(root.join(RECORDS_SOURCE)).unwrap();
        assert_eq!(records_defined_in(&records), KIT_RECORDS);
    }
}
