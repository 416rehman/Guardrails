//! `Stop` (team/03 section 4.1, owner instruction 8): the definition of done, checked by code and
//! never by a model. A session that writes runs `verify --fast` on its tree (unless evidence for
//! that tree is already green), the structure checks S1 to S7 and, on the interface paths, the
//! interface checks UX1 to UX8 on its changed files, the cleanup sign-off, the three-arm proof for
//! a bug item and the claims in its last message; an agent with an item leaves a valid
//! `handoff.v1` draft. `[hook.stop_gate] blocks` blocks on one diff digest allow the stop and mark
//! the draft `gate: failed`, so the lead re-plans instead of the agent looping. Every stop records
//! the skills the session loaded beside the path-skill entries guard-path named (owner
//! instruction 18).

use std::process::Command;
use std::sync::{LazyLock, Mutex};

use anyhow::Result;
use regex::Regex;
use serde_json::Value;

use super::context::{Context, Progress};
use super::handoff::{self, Expectation, Kind};
use super::identity::{Identity, Role, Who};
use super::outcome::{Outcome, capped};
use super::path_skills::{self, PathSkills};
use super::post_edit;
use super::signoff;
use super::state::{SessionState, SkillsState, StopCounter};
use super::transcript;
use crate::config::limits::HookLimits;
use crate::config::models::Models;
use crate::config::session::{
    AGENT_VARIABLE, LAUNCHER_MODEL_VARIABLE, WORK_ITEM_VARIABLE, parse_item_number,
};
use crate::gates::Form;
use crate::gates::evidence::{EVIDENCE_DIR, Evidence, summary_lines};
use crate::gates::structure;
use crate::git;
use crate::process::{self, Finished};
use crate::repo::{Repo, walk_files};

const VERIFY_JSON: &str = ".agent/state/verify.json";
const SKILL_TOOL: &str = "Skill";

static EVIDENCE_ID: LazyLock<Option<Regex>> =
    LazyLock::new(|| regex(r"\b(?:verify|prove|evidence)-\d{8}T\d{6}Z(?:-\d+)?\b"));
static SUCCESS: LazyLock<Option<Regex>> = LazyLock::new(|| {
    regex(
        r"(?i)\b(all (tests|checks|gates) (pass|passed|are green)|tests? pass(es|ed)?|verify (is |was )?green|(is|are) (now )?(done|complete|fixed|working)|works now|successfully)\b",
    )
});
static EXCUSE: LazyLock<Option<Regex>> = LazyLock::new(|| {
    regex(r"(?i)\b(pre-?existing|flaky|out of scope|unrelated (failure|test)s?)\b")
});
static ISSUE: LazyLock<Option<Regex>> = LazyLock::new(|| regex(r"#\d+\b"));

pub fn run(context: &Context) -> Result<Outcome> {
    let waiting = context
        .input
        .at("/background_tasks")
        .and_then(Value::as_array)
        .is_some_and(|tasks| !tasks.is_empty());
    if waiting {
        return Ok(Outcome::Allow);
    }
    let identity = Identity::load(context)?;
    if let Err(error) = record_skills(context, &identity) {
        context.note(format!("could not record the loaded skills: {error:#}"));
    }
    let digest = git::tree_digest(&context.repo)?;
    context.record_digest(&digest);
    let problems = definition_of_done(context, &identity, &digest)?;
    let session = context.input.session_id().unwrap_or("unknown");
    Ok(decide(
        &context.repo,
        session,
        &digest,
        problems,
        Some(context.limits.stop_gate.blocks),
        &|reason| {
            context.note(format!("stop allowed with problems open: {reason}"));
            mark_draft(context, &identity, reason);
        },
    ))
}

/// The Stop decision after a panic or a missed deadline, under the same round counter. Without
/// the limits there is no counter to keep, so the stop is allowed and the draft marked failed.
/// `progress` takes the lines for the handler's log.
pub fn after_failure(
    repo: &Repo,
    session: Option<&str>,
    digest: Option<&str>,
    reason: &str,
    limits: Option<&HookLimits>,
    progress: &Mutex<Progress>,
) -> Outcome {
    let problems = vec![format!("the stop gate {reason}")];
    let digest = digest.unwrap_or("unknown-tree");
    let note = |line: String| {
        if let Ok(mut shared) = progress.lock() {
            shared.detail.push(line);
        }
    };
    decide(
        repo,
        session.unwrap_or("unknown"),
        digest,
        problems,
        limits.map(|limits| limits.stop_gate.blocks),
        &|reason| {
            note(format!("stop allowed with problems open: {reason}"));
            let agent = std::env::var(AGENT_VARIABLE).ok();
            let item = std::env::var(WORK_ITEM_VARIABLE)
                .ok()
                .and_then(|raw| parse_item_number(&raw).ok());
            if let (Some(agent), Some(item)) = (agent, item) {
                note(draft_mark_line(handoff::mark_failed(
                    repo, item, &agent, None, reason,
                )));
            }
        },
    )
}

/// Blocks on a failing tree until `max_blocks` blocks on its digest, then allows the stop and
/// gives up. A round counter it cannot save would hold every stop at block one, so a failed save
/// allows the stop the same way and says why on stderr.
fn decide(
    repo: &Repo,
    session: &str,
    digest: &str,
    problems: Vec<String>,
    max_blocks: Option<u32>,
    give_up: &dyn Fn(&str),
) -> Outcome {
    if problems.is_empty() {
        return Outcome::Allow;
    }
    let counter = StopCounter::load(repo, session);
    let blocks = counter.blocks_on(digest);
    let Some(max_blocks) = max_blocks.filter(|max| blocks < *max) else {
        give_up(&problems.join("; "));
        return Outcome::Allow;
    };
    let next = StopCounter {
        digest: digest.to_owned(),
        blocks: blocks.saturating_add(1),
    };
    if let Err(error) = next.save(repo, session) {
        let unsaved = format!(
            "the stop gate could not save its round counter {} ({error:#}), so it cannot count its blocks and allows the stop",
            StopCounter::path(session)
        );
        eprintln!("{unsaved}");
        give_up(&format!("{unsaved}; {}", problems.join("; ")));
        return Outcome::Allow;
    }
    let mut lines = vec![format!(
        "stop gate: not done (block {} of {max_blocks} on this diff; then the stop is allowed and the hand-off says gate: failed)",
        next.blocks
    )];
    lines.extend(problems);
    Outcome::Block(lines.join("\n"))
}

fn definition_of_done(context: &Context, identity: &Identity, digest: &str) -> Result<Vec<String>> {
    let repo = &context.repo;
    let limits = &context.limits;
    let state = match context.input.session_id() {
        Some(session) => SessionState::load(repo, session)?,
        None => None,
    };
    let changed = state.as_ref().and_then(|state| state.start_tree.as_deref()) != Some(digest);
    let code_checks = changed || (identity.is_agent() && identity.writes());
    let mut problems = Vec::new();
    if code_checks {
        let base = git::resolve_base(repo)?;
        let files = git::changed_files(repo, &base)?;
        let report = structure::check_files(repo, &base, &files)?;
        let blocking: Vec<String> = report.blocking().map(ToString::to_string).collect();
        for unprinted in blocking.iter().skip(limits.stop_gate.printed_findings) {
            context.note(unprinted.clone());
        }
        problems.extend(capped(&blocking, limits.stop_gate.printed_findings));
        problems.extend(report.hints().into_iter().map(str::to_owned));
        problems.extend(post_edit::new_suppressions(repo, &base, &files)?);
        problems.extend(signoff::problem(repo, &base)?);
        problems.extend(claims(
            repo,
            context
                .input
                .str("last_assistant_message")
                .unwrap_or_default(),
        ));
        if identity.snapshot().is_some_and(|item| item.kind == "bug") {
            problems.extend(proof(repo, digest, limits.stop_gate.evidence_files)?);
        }
        if !green_evidence(repo, digest, base.commit(), limits.stop_gate.evidence_files)? {
            problems.extend(verify(context)?);
        }
    }
    if identity.is_agent()
        && !identity.workflow_subagent
        && let (Some(item), Some(agent)) = (identity.item_number(), identity.agent())
    {
        let ids: Vec<String> = Models::load(repo)?.ids().map(str::to_owned).collect();
        let kind = match (identity.role(), identity.snapshot()) {
            (Role::Evaluator, _) => Kind::Evaluator,
            (_, Some(snapshot)) if snapshot.kind == "bug" => Kind::BugFix,
            _ => Kind::Worker,
        };
        let expect = Expectation {
            item,
            agent,
            model_ids: &ids,
            launcher_model: context.env.get(LAUNCHER_MODEL_VARIABLE),
            kind,
        };
        problems.extend(handoff::check(
            repo,
            &expect,
            limits.stop_gate.handoff_problems,
        )?);
    }
    for problem in &problems {
        context.note(problem.clone());
    }
    Ok(problems)
}

/// Adds to the session's skills state the skills it loaded: its roster agent's preloaded skills
/// and every Skill call in its transcript. The log names each skill of an entry guard-path named
/// that is not among them.
fn record_skills(context: &Context, identity: &Identity) -> Result<()> {
    let Some(session) = context.input.session_id() else {
        return Ok(());
    };
    let mut state = SkillsState::load(&context.repo, session)?;
    if let Who::Agent { agent, .. } = &identity.who {
        state.loaded.extend(agent.skills.iter().cloned());
    }
    let uses = context
        .input
        .path("transcript_path", &context.env)
        .filter(|path| path.is_file())
        .and_then(|path| transcript::tail(&path, context.limits.stop_gate.transcript_bytes).ok())
        .map(|entries| transcript::tool_uses(&entries))
        .unwrap_or_default();
    state.loaded.extend(
        uses.iter()
            .filter(|tool| tool.name == SKILL_TOOL)
            .filter_map(|tool| tool.input.get("skill").and_then(Value::as_str))
            .map(str::to_owned),
    );
    let mapping = PathSkills::load(&context.repo)?;
    let named = mapping.named(&state.announced);
    let missing: Vec<String> = path_skills::skills_of(&named)
        .into_iter()
        .filter(|skill| !state.loaded.contains(skill))
        .collect();
    if !missing.is_empty() {
        context.note(format!(
            "path skills named but not loaded: {}",
            missing.join(", ")
        ));
    }
    state.save(&context.repo, session)
}

/// Success claims without an evidence id, cited ids that do not exist, and failures called
/// pre-existing, flaky or out of scope without the issue filed for them.
pub fn claims(repo: &Repo, message: &str) -> Vec<String> {
    let (Some(evidence_id), Some(success), Some(excuse), Some(issue)) = (
        EVIDENCE_ID.as_ref(),
        SUCCESS.as_ref(),
        EXCUSE.as_ref(),
        ISSUE.as_ref(),
    ) else {
        return vec!["the stop gate's claim patterns do not compile".to_owned()];
    };
    let mut problems = Vec::new();
    let ids: Vec<&str> = evidence_id
        .find_iter(message)
        .map(|found| found.as_str())
        .collect();
    if success.is_match(message) && ids.is_empty() {
        problems.push(
            "the last message claims success without naming an evidence id from .agent/evidence"
                .to_owned(),
        );
    }
    for id in &ids {
        if !repo.path(&format!("{EVIDENCE_DIR}/{id}.json")).is_file() {
            problems.push(format!(
                "the last message cites evidence {id}, which .agent/evidence does not hold"
            ));
        }
    }
    if let Some(found) = excuse.find(message)
        && !issue.is_match(message)
    {
        problems.push(format!(
            "the last message calls a failure `{}` without the issue filed for it (#<n>); file it as a proposed issue",
            found.as_str()
        ));
    }
    problems
}

/// A `prove*.json` for this tree whose before and revert arms fail and whose after arm passes.
fn proof(repo: &Repo, digest: &str, limit: usize) -> Result<Option<String>> {
    let proven = recent_evidence(repo, "prove", limit)?.iter().any(|value| {
        value.get("tree_digest").and_then(Value::as_str) == Some(digest) && arms_hold(value)
    });
    Ok((!proven).then(|| {
        "a bug item needs the three-arm proof for this tree: run cargo xtask prove (.agent/evidence/prove-*.json)".to_owned()
    }))
}

fn arms_hold(value: &Value) -> bool {
    let arms = value
        .get("arms")
        .or_else(|| value.get("three_arm"))
        .unwrap_or(value);
    let exit = |arm: &str| {
        let entry = arms.get(arm)?;
        entry.get("exit").unwrap_or(entry).as_i64()
    };
    matches!(
        (exit("fails_before"), exit("passes_after"), exit("fails_on_revert")),
        (Some(before), Some(0), Some(revert)) if before != 0 && revert != 0
    )
}

/// Green verify evidence for this tree, run against the base the gate itself resolves: a run
/// with `--base` at the branch's own tip has an empty diff, so it proves nothing.
fn green_evidence(repo: &Repo, digest: &str, base: Option<&str>, limit: usize) -> Result<bool> {
    Ok(recent_evidence(repo, "verify", limit)?
        .into_iter()
        .any(|value| {
            serde_json::from_value::<Evidence>(value).is_ok_and(|evidence| {
                evidence.tree_digest == digest
                    && evidence.exit_code == 0
                    && evidence.base.as_deref() == base
                    && matches!(evidence.form, Form::Fast | Form::Full)
            })
        }))
}

/// The newest `limit` evidence files whose name starts with `prefix`.
fn recent_evidence(repo: &Repo, prefix: &str, limit: usize) -> Result<Vec<Value>> {
    let mut files: Vec<_> = walk_files(&repo.path(EVIDENCE_DIR))?
        .into_iter()
        .filter(|path| {
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().into_owned())
                .unwrap_or_default();
            name.starts_with(prefix) && name.ends_with(".json")
        })
        .collect();
    files.sort();
    files.reverse();
    Ok(files
        .into_iter()
        .take(limit)
        .filter_map(|path| std::fs::read_to_string(path).ok())
        .filter_map(|text| serde_json::from_str(&text).ok())
        .collect())
}

/// `verify --fast` from this kit binary, so the gate is the base branch's, never the worktree's.
fn verify(context: &Context) -> Result<Vec<String>> {
    let repo = &context.repo;
    let json = repo.path(VERIFY_JSON);
    let _ = std::fs::remove_file(&json);
    let mut command = Command::new(std::env::current_exe()?);
    command
        .args(["verify", "--fast", "--json"])
        .arg(&json)
        .current_dir(repo.root())
        .env("CLAUDE_PROJECT_DIR", repo.root())
        .env("CARGO_TERM_COLOR", "never");
    let timeout = context
        .remaining()
        .saturating_sub(context.limits.stop_gate.verify_margin());
    let ran = process::run(&mut command, None, timeout)?;
    context.note(format!("verify --fast: {}", ran.describe()));
    if let Finished::TimedOut { .. } = ran.finished {
        return Ok(vec![format!(
            "verify --fast did not finish in {} s",
            timeout.as_secs()
        )]);
    }
    if ran.success() {
        return Ok(Vec::new());
    }
    let evidence: Option<Evidence> = std::fs::read_to_string(&json)
        .ok()
        .and_then(|text| serde_json::from_str(&text).ok());
    Ok(match evidence {
        Some(evidence) => summary_lines(&evidence),
        None => {
            let output = format!("{}{}", ran.stdout(), ran.stderr());
            let tail = context.limits.stop_gate.verify_tail_lines;
            let mut lines: Vec<String> =
                output.lines().rev().take(tail).map(str::to_owned).collect();
            lines.reverse();
            lines.insert(0, format!("verify --fast failed ({})", ran.describe()));
            lines
        }
    })
}

fn mark_draft(context: &Context, identity: &Identity, reason: &str) {
    let (Some(item), Some(agent)) = (identity.item_number(), identity.agent()) else {
        return;
    };
    let model = super::model::current_model(context).ok().flatten();
    context.note(draft_mark_line(handoff::mark_failed(
        &context.repo,
        item,
        agent,
        model.as_deref(),
        reason,
    )));
}

/// The log line for the result of marking the hand-off draft `gate: failed`.
fn draft_mark_line(result: Result<()>) -> String {
    match result {
        Ok(()) => "hand-off draft marked gate: failed".to_owned(),
        Err(error) => format!("could not mark the hand-off draft: {error:#}"),
    }
}

fn regex(pattern: &str) -> Option<Regex> {
    Regex::new(pattern).ok()
}

#[cfg(test)]
mod tests {
    use std::cell::RefCell;

    use super::*;

    fn scratch(name: &str) -> Repo {
        let root =
            std::env::temp_dir().join(format!("xtask-stop-gate-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&root);
        std::fs::create_dir_all(&root).unwrap();
        Repo::at(root)
    }

    #[test]
    fn blocks_count_to_the_limit_then_the_stop_is_allowed() {
        let repo = scratch("counted");
        let given_up = RefCell::new(Vec::new());
        let give_up = |reason: &str| given_up.borrow_mut().push(reason.to_owned());
        for block in 1..=2 {
            let outcome = decide(&repo, "s1", "tree", vec!["red".into()], Some(2), &give_up);
            assert!(
                outcome.text().contains(&format!("block {block} of 2")),
                "{outcome:?}"
            );
        }
        let last = decide(&repo, "s1", "tree", vec!["red".into()], Some(2), &give_up);
        assert_eq!(last, Outcome::Allow);
        assert_eq!(given_up.borrow().as_slice(), ["red"]);
        std::fs::remove_dir_all(repo.root()).unwrap();
    }

    #[test]
    fn a_counter_that_cannot_be_saved_allows_the_stop() {
        let repo = scratch("unsaved");
        std::fs::create_dir_all(repo.path(&StopCounter::path("s1"))).unwrap();
        let given_up = RefCell::new(Vec::new());
        let give_up = |reason: &str| given_up.borrow_mut().push(reason.to_owned());
        let outcome = decide(&repo, "s1", "tree", vec!["red".into()], Some(3), &give_up);
        assert_eq!(outcome, Outcome::Allow);
        let reasons = given_up.borrow();
        assert_eq!(reasons.len(), 1);
        assert!(reasons[0].contains("could not save its round counter"));
        assert!(reasons[0].ends_with("; red"));
        std::fs::remove_dir_all(repo.root()).unwrap();
    }

    #[test]
    fn a_failure_without_limits_allows_the_stop_and_logs_it() {
        let repo = scratch("failure");
        let progress = Mutex::new(Progress::default());
        let outcome = after_failure(&repo, Some("s1"), None, "panicked", None, &progress);
        assert_eq!(outcome, Outcome::Allow);
        let detail = progress.lock().unwrap().detail.clone();
        assert!(
            detail.iter().any(
                |line| line.contains("stop allowed with problems open: the stop gate panicked")
            ),
            "{detail:?}"
        );
        assert!(draft_mark_line(Err(anyhow::anyhow!("disk full"))).contains("could not mark"));
        std::fs::remove_dir_all(repo.root()).unwrap();
    }

    #[test]
    fn claims_need_evidence_and_filed_issues() {
        let repo = Repo::at(std::env::temp_dir().join("xtask-no-such-repo"));
        assert_eq!(claims(&repo, "All tests pass.").len(), 1);
        assert_eq!(
            claims(&repo, "Hand-off drafted; verify is red, see the log.").len(),
            0
        );
        assert_eq!(claims(&repo, "The failure is pre-existing.").len(), 1);
        assert_eq!(
            claims(&repo, "The failure is pre-existing; filed #12.").len(),
            0
        );
        let cited = claims(&repo, "Done: verify green in verify-20261111T100200Z-4.");
        assert_eq!(cited.len(), 1);
        assert!(cited[0].contains("does not hold"));
    }

    #[test]
    fn three_arms() {
        let good = serde_json::json!({"arms": {"fails_before": {"exit": 1}, "passes_after": {"exit": 0}, "fails_on_revert": {"exit": 101}}});
        assert!(arms_hold(&good));
        let bad = serde_json::json!({"three_arm": {"fails_before": 0, "passes_after": 0, "fails_on_revert": 1}});
        assert!(!arms_hold(&bad));
    }
}
