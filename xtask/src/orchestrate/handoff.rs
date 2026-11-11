//! `cargo xtask kit handoff [--item <n>] [--draft <json> | --draft -] [--dry-run]` (team/02
//! section 1.4, skill `grdr-handoff`): validate the session's `handoff.v1` draft, post it on the
//! issue as a collapsed comment, and for a worker push `agent/<n>/a<attempt>` and open or update
//! its pull request in the form of owner instruction 27: a Conventional Commit title, and a body
//! with the evidence template, `Closes #<n>` and the `meta.v1` block that the hand-off comment
//! repeats. `--draft` takes the JSON inline or on stdin and writes the draft file first, so a
//! read-only role (an evaluator, a lead, the programme manager) that has no Write tool still
//! leaves the draft the Stop gate checks. A session ships code when its role writes code or it
//! holds a protected-change lease, whose lead or chief architect is the item's implementer (owner
//! instruction 7), and so does the chief architect's seed session, whose `agent/seed` pull request
//! for the `[WI-0000]` issue then enters review like a leased item's: the kit posts the lease that
//! names its branch, raises its lane to full and moves the issue to `status:in-review`, so the
//! review pass and the merge queue take it (team/06 section 13 step 5). In the main checkout the
//! seed session then leaves `agent/seed` for a detached `HEAD` at the same commit, because git
//! checks a branch out in one working tree at a time and the dispatcher checks the seed branch
//! out in the worktrees of its evaluators and fix sessions. The draft names the model
//! the launcher started the session on (`GRDR_MODEL`),
//! since a verdict counts only from the model it was asked on. Status changes follow the
//! `by = ["kit"]` transitions of
//! `.github/labels.toml`: a blocked hand-off goes to `status:blocked`, or to `status:escalated`
//! when it carries an escalation packet, and an impossible one returns to `status:proposed`.

mod pull_request;

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use serde_json::Value;

use self::pull_request::{Branch, Ship, Shipment, Writer};
use super::form::Form;
use super::issue::{Issue, status_label};
use super::launch::{LaunchKit, owner_step_or};
use super::records::{
    self, HANDOFF_SCHEMA, LANE_SCHEMA, LEASE_SCHEMA, LaneRaise, Lease, Reason, comment_body,
    lane_comment, lease_comment, meta_block,
};
use super::risk::Lane;
use super::tracker::{GhTracker, IssueEdit, Tracker};
use crate::cli::{self, Spec};
use crate::config::limits::Limits;
use crate::config::protected::SeedScope;
use crate::config::roster::Group;
use crate::config::session::{ItemSnapshot, ItemStatus, LAUNCHER_MODEL_VARIABLE, Scope, Session};
use crate::gates::protected::protected_lease;
use crate::git::{self, Base};
use crate::github::{Gh, Mode};
use crate::hook::handoff::{Expectation, Kind};
use crate::repo::Repo;

pub use self::pull_request::{Writer as PullRequestWriter, pull_request_body};

const SPEC: Spec = Spec {
    flags: &["--dry-run"],
    options: &["--item", "--draft"],
};
/// `--draft -` reads the JSON from stdin.
const STDIN: &str = "-";
const BUG_KIND: &str = "bug";
/// The name the kit's own `lane.v1` comments carry, as `.github/labels.toml` names it.
const KIT: &str = "kit";

/// The session that publishes a hand-off: who it is, its scope, and the model id the launcher
/// started it on.
#[derive(Debug, Clone, Default)]
pub struct Caller {
    pub session: Session,
    pub model: Option<String>,
}

/// What a session's work is.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Output {
    /// Commits on its item branch, shipped as a pull request.
    Code,
    /// Issue comments only.
    Comments,
}

/// What a hand-off asks of GitHub beyond the comment.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Follow {
    PullRequest,
    PushOnly,
    Status(ItemStatus),
    Nothing,
}

/// `kit handoff`.
pub fn command(args: &[String]) -> Result<ExitCode> {
    let parsed = cli::parse(args, &SPEC)?;
    let repo = Repo::discover()?;
    let session = Session::from_env()?;
    let item = match parsed.value("--item") {
        Some(raw) => crate::config::session::parse_item_number(raw)?,
        None => session
            .work_item
            .context("no item: pass --item <n> or launch with cargo xtask kit launch --item <n>")?,
    };
    let mode = if parsed.has("--dry-run") {
        Mode::DryRun
    } else {
        Mode::Live
    };
    let tracker = GhTracker::new(Gh::for_repo(&repo, mode)?);
    if let Some(given) = parsed.value("--draft") {
        let name = session
            .agent
            .as_deref()
            .context("GRDR_AGENT is unset: kit handoff --draft writes an agent session's draft")?;
        let text = if given == STDIN {
            std::io::read_to_string(std::io::stdin())
                .context("reading the hand-off draft from stdin")?
        } else {
            given.to_owned()
        };
        write_draft(&repo, item, name, &text)?;
    }
    let caller = Caller {
        session,
        model: std::env::var(LAUNCHER_MODEL_VARIABLE)
            .ok()
            .filter(|model| !model.trim().is_empty()),
    };
    match publish(&repo, &tracker, item, &caller, mode) {
        Ok(code) => Ok(code),
        Err(error) => owner_step_or(error),
    }
}

/// Validates and publishes the draft for `item`.
pub fn publish(
    repo: &Repo,
    tracker: &dyn Tracker,
    item: u64,
    caller: &Caller,
    mode: Mode,
) -> Result<ExitCode> {
    let kit = LaunchKit::load(repo)?;
    let form = Form::load(repo)?;
    let name = caller
        .session
        .agent
        .clone()
        .context("GRDR_AGENT is unset: kit handoff publishes an agent session's draft")?;
    let (path, draft) = read_draft(repo, item, &name)?;
    let group = kit.agent(&name)?.group;
    let seed = seed_session(repo, &caller.session, &name)?;
    let output = match &seed {
        Some(_) => Output::Code,
        None => output(repo, &caller.session, &name, group)?,
    };
    let issue = tracker.issue(item)?;
    let snapshot = ItemSnapshot::load(repo, item)?;
    let bug = snapshot.as_ref().is_some_and(|s| s.kind == BUG_KIND)
        || issue.work_item().kind.as_deref() == Some(BUG_KIND);
    let ids: Vec<String> = kit.models.ids().map(str::to_owned).collect();
    let expect = Expectation {
        item,
        agent: &name,
        model_ids: &ids,
        launcher_model: caller.model.as_deref(),
        kind: kind(group, bug),
    };
    let mut problems = crate::hook::handoff::validate(&draft, &expect);
    if seed.is_some() && issue.work_item().acceptance.is_none() {
        problems.push(format!(
            "#{item} has no acceptance criteria section, which the seed's evaluators judge it against"
        ));
    }
    if !problems.is_empty() {
        let printed = Limits::built_with()?.hook.stop_gate.handoff_problems;
        for problem in problems.iter().take(printed) {
            eprintln!("ERROR kit handoff: {path}: {problem}");
        }
        return Ok(ExitCode::from(2));
    }
    let status = draft
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let found = records::records(&issue);
    let attempt = records::current_lease(&found, item).map_or(1, |lease| lease.attempt);
    let packet = repo.read_optional(&format!(".agent/state/escalation-{item}.md"))?;
    let model = draft
        .get("model")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let writer = Writer {
        model: &model,
        attempt,
    };
    let follow = follow(&status, output, packet.is_some());
    let ships_code = matches!(follow, Follow::PullRequest | Follow::PushOnly);
    let mut comment = handoff_comment(&draft, &name, attempt, packet.as_deref())?;
    if ships_code {
        comment.push('\n');
        comment.push_str(&meta_block(&form.meta(item, writer.model, attempt))?);
    }
    tracker.comment(item, &comment)?;
    println!("kit handoff: posted the {status} hand-off on #{item}");
    let ship = match follow {
        Follow::Status(next) => return move_status(tracker, &issue, next),
        Follow::Nothing => return Ok(ExitCode::SUCCESS),
        Follow::PullRequest => Ship::PullRequest,
        Follow::PushOnly => Ship::PushOnly,
    };
    let shipment = Shipment {
        form: &form,
        issue: &issue,
        draft: &draft,
        writer,
        mode,
        ship,
        branch: seed
            .as_ref()
            .map_or(Branch::Item, |scope| Branch::Named(&scope.branch)),
    };
    let code = pull_request::ship(repo, tracker, &shipment)?;
    match &seed {
        Some(scope) if ship == Ship::PullRequest && code == ExitCode::SUCCESS => {
            seed_into_review(tracker, &issue, &name, &model, scope)?;
            if mode == Mode::Live {
                release_seed_branch(repo, &scope.branch)?;
            }
        }
        _ => {}
    }
    Ok(code)
}

/// Detaches the main checkout from the seed branch at its tip, files unchanged, so the dispatcher
/// can check the branch out for the seed pull request's evaluators and fix sessions. A fix
/// session's own worktree keeps the branch it commits on.
fn release_seed_branch(repo: &Repo, branch: &str) -> Result<()> {
    if git::is_linked_worktree(repo)? {
        return Ok(());
    }
    git::output(repo, &["switch", "--quiet", "--detach"])?;
    println!(
        "kit handoff: this checkout left {branch} for its tip, so the dispatcher can check {branch} out"
    );
    Ok(())
}

/// The seed scope, when this is the chief architect's seed session: `GRDR_SCOPE=seed` and the
/// agent `.agents/kit/seed-scope.toml` names.
fn seed_session(repo: &Repo, session: &Session, agent: &str) -> Result<Option<SeedScope>> {
    if session.scope != Some(Scope::Seed) {
        return Ok(None);
    }
    Ok(SeedScope::load(repo)?.filter(|scope| scope.agent == agent))
}

/// The seed's pull request enters review as a leased item's does: a lease names its branch, its
/// lane is raised to full (its paths are gate configuration and the plan), and the issue moves to
/// `status:in-review`, where the review pass starts its evaluators.
fn seed_into_review(
    tracker: &dyn Tracker,
    issue: &Issue,
    agent: &str,
    model: &str,
    scope: &SeedScope,
) -> Result<()> {
    let number = issue.number;
    if records::current_lease(&records::records(issue), number).is_none() {
        let lease = Lease {
            schema: LEASE_SCHEMA.to_owned(),
            item: number,
            attempt: 1,
            agent: agent.to_owned(),
            model: model.to_owned(),
            acceptance_sha256: issue
                .work_item()
                .acceptance
                .map(|acceptance| acceptance.sha256)
                .unwrap_or_default(),
            branch: scope.branch.clone(),
            session: None,
        };
        tracker.comment(number, &lease_comment(&lease)?)?;
        let raise = LaneRaise {
            schema: LANE_SCHEMA.to_owned(),
            item: number,
            lane: Lane::Full,
            by: KIT.to_owned(),
            reason: "the seed session writes gate configuration and the plan".to_owned(),
        };
        tracker.comment(number, &lane_comment(&raise)?)?;
    }
    match issue.status() {
        Some(from @ ItemStatus::Proposed) => crate::dispatch::lease::transition(
            tracker,
            number,
            1,
            from,
            ItemStatus::InReview,
            Reason::PullRequestOpen,
        ),
        _ => Ok(()),
    }
}

/// Implementers, gardeners and operations agents ship code, and so does any session on a
/// protected-change lease (owner instruction 7).
fn output(repo: &Repo, session: &Session, agent: &str, group: Group) -> Result<Output> {
    let writer = matches!(
        group,
        Group::Implementer | Group::Gardener | Group::Operations
    );
    if writer || protected_lease(repo, &Base::Unborn, session, agent)?.is_some() {
        return Ok(Output::Code);
    }
    Ok(Output::Comments)
}

/// What follows the comment for a status and what the session's work is.
pub fn follow(status: &str, output: Output, has_packet: bool) -> Follow {
    let writes_code = output == Output::Code;
    match status {
        "done" if writes_code => Follow::PullRequest,
        "partial" if writes_code => Follow::PushOnly,
        "blocked" if has_packet => Follow::Status(ItemStatus::Escalated),
        "blocked" => Follow::Status(ItemStatus::Blocked),
        "impossible" => Follow::Status(ItemStatus::Proposed),
        _ => Follow::Nothing,
    }
}

/// The draft the Stop gate's check (`hook::handoff`) expects of this role.
pub fn kind(group: Group, bug: bool) -> Kind {
    match (group, bug) {
        (Group::Evaluator, _) => Kind::Evaluator,
        (_, true) => Kind::BugFix,
        (_, false) => Kind::Worker,
    }
}

/// Writes `text`, which must be one JSON object, as the session's draft.
pub fn write_draft(repo: &Repo, item: u64, agent: &str, text: &str) -> Result<()> {
    let value: Value = serde_json::from_str(text).context("the --draft value is not JSON")?;
    if !value.is_object() {
        bail!("the --draft value is not a JSON object");
    }
    let mut json = serde_json::to_string_pretty(&value)?;
    json.push('\n');
    let path = repo.path(&crate::hook::handoff::path(item, agent));
    crate::repo::write_if_changed(&path, json.as_bytes())?;
    Ok(())
}

/// `.agent/state/handoff-<n>-<agent>.json`, the draft the Stop hook checked.
fn read_draft(repo: &Repo, item: u64, agent: &str) -> Result<(String, Value)> {
    let path = crate::hook::handoff::path(item, agent);
    let Some(text) = repo.read_optional(&path)? else {
        bail!("no hand-off draft at {path}; write the handoff.v1 JSON there (skill grdr-handoff)")
    };
    let value = serde_json::from_str(&text).with_context(|| format!("{path} is not JSON"))?;
    Ok((path, value))
}

fn handoff_comment(
    draft: &Value,
    agent: &str,
    attempt: u32,
    packet: Option<&str>,
) -> Result<String> {
    let status = draft
        .get("status")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let round = draft.get("round").and_then(Value::as_u64).unwrap_or(1);
    let summary = draft
        .get("summary")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let mut line =
        format!("Hand-off from {agent}, attempt {attempt}, round {round}: **{status}**. {summary}");
    if let Some(packet) = packet {
        line.push_str("\n\n");
        line.push_str(packet.trim());
    }
    Ok(comment_body(
        &line,
        HANDOFF_SCHEMA,
        &serde_json::to_string_pretty(draft)?,
    ))
}

fn move_status(tracker: &dyn Tracker, issue: &Issue, next: ItemStatus) -> Result<ExitCode> {
    if issue.status() != Some(ItemStatus::Leased) {
        println!(
            "kit handoff: #{} is not leased, so its status stays as it is",
            issue.number
        );
        return Ok(ExitCode::SUCCESS);
    }
    let edit = IssueEdit {
        add: status_label(next).into_iter().collect(),
        remove: status_label(ItemStatus::Leased).into_iter().collect(),
        assign_self: false,
    };
    tracker.edit(issue.number, &edit)?;
    println!(
        "kit handoff: #{} moved to {}",
        issue.number,
        edit.add.join("")
    );
    Ok(ExitCode::SUCCESS)
}

#[cfg(test)]
mod tests;
