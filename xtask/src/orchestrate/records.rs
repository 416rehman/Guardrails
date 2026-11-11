//! The JSON records that live in issue comments (team/01 section 3, team/02 section 1.4): the
//! readying agent's `ready.v1`, the dispatcher's `lease.v1` and `state.v1`, the worker's
//! `handoff.v1` with its `meta.v1` (harness, model id, attempt; owner instruction 27, also in the
//! pull-request body), and `lane.v1`, which raises an item's review lane (owner instruction 8).
//! Each record sits in a fenced `json` block inside a collapsed section, after one line a person
//! can read. Only comments by the repository's owner, the one identity every agent and the kit
//! post as, count: a record an outsider posts is ignored, and guard-command keeps sessions from
//! posting records by hand.

use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::issue::{Comment, Issue, WorkItem};
use super::risk::Lane;
use crate::config::session::ItemStatus;

pub const READY_SCHEMA: &str = "ready.v1";
pub const LEASE_SCHEMA: &str = "lease.v1";
pub const STATE_SCHEMA: &str = "state.v1";
pub const HANDOFF_SCHEMA: &str = "handoff.v1";
pub const META_SCHEMA: &str = "meta.v1";
pub const LANE_SCHEMA: &str = "lane.v1";
const FENCE_OPEN: &str = "```json";
const FENCE_CLOSE: &str = "```";
/// GitHub's `authorAssociation` for the account that owns the repository.
const OWNER_ASSOCIATION: &str = "OWNER";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ready {
    pub schema: String,
    pub item: u64,
    pub by: String,
    pub acceptance_sha256: String,
    /// [`WorkItem::write_set_sha256`] at readying, so an edit of the write set after it widens
    /// nothing.
    pub write_set_sha256: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Lease {
    pub schema: String,
    pub item: u64,
    pub attempt: u32,
    pub agent: String,
    pub model: String,
    pub acceptance_sha256: String,
    pub branch: String,
    /// The Claude Code session id the dispatcher started the worker with, so a restart resumes it.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session: Option<String>,
}

/// Who wrote a change, as the pull-request body and the worker's hand-off comment state it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Meta {
    pub schema: String,
    pub item: u64,
    pub harness: String,
    pub model: String,
    pub attempt: u32,
}

/// A raised review lane; a lane is never lowered, so the highest one since the item was last
/// readied holds.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LaneRaise {
    pub schema: String,
    pub item: u64,
    pub lane: Lane,
    pub by: String,
    pub reason: String,
}

/// Why the dispatcher moved an item.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Reason {
    PullRequestOpen,
    Stall,
    TurnCap,
    LeaseExpired,
    NoPullRequest,
    WorkerFailed,
    AcceptanceChanged,
    /// The write set no longer matches its `ready.v1` digest.
    WriteSetChanged,
    NoValidReady,
    /// An evaluator failed the change in a review round under the limit.
    EvaluatorFindings,
    /// The review rounds are used up.
    ReviewRoundsUsed,
    /// No verdict arrived within the review deadline.
    NoVerdict,
    /// The merge queue refused the pull request's title or body (owner instruction 27).
    PullRequestInvalid,
    /// A check on the pull request failed.
    ChecksFailed,
    /// The full verify of the tree that would land failed or timed out.
    VerifyFailed,
    /// The pull request does not apply to the current base.
    MergeConflict,
    /// The evaluators the lane needs would all run on one model, and the change needs two.
    EvaluatorsOnOneModel,
    /// An evaluator the lane needs is not in the roster, has no model, or may not run on the
    /// model asked.
    EvaluatorUnavailable,
}

/// A status change the dispatcher made, with the attempt it ends or starts.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Transition {
    pub schema: String,
    pub item: u64,
    pub attempt: u32,
    pub from: ItemStatus,
    pub to: ItemStatus,
    pub reason: Reason,
}

/// One record found in a comment, in comment order.
#[derive(Debug, Clone, PartialEq)]
pub enum Record {
    Ready(Ready),
    Lease(Lease),
    Transition(Transition),
    Handoff(Value),
    Meta(Meta),
    Lane(LaneRaise),
}

impl Reason {
    pub fn describe(self) -> &'static str {
        match self {
            Reason::PullRequestOpen => "the pull request is open",
            Reason::Stall => "the session stalled",
            Reason::TurnCap => "the session reached its turn cap without a pull request",
            Reason::LeaseExpired => "the lease expired",
            Reason::NoPullRequest => "the session ended without a pull request",
            Reason::WorkerFailed => "the session failed",
            Reason::AcceptanceChanged => {
                "the acceptance section no longer matches its ready.v1 digest"
            }
            Reason::WriteSetChanged => "the write set no longer matches its ready.v1 digest",
            Reason::NoValidReady => {
                "it has no ready.v1 from an agent that may ready it and does not implement it"
            }
            Reason::EvaluatorFindings => "an evaluator failed the change; the worker fixes it",
            Reason::ReviewRoundsUsed => "the review rounds are used up",
            Reason::NoVerdict => "no evaluator verdict arrived in time",
            Reason::PullRequestInvalid => {
                "the merge queue refused the pull request's title or body"
            }
            Reason::ChecksFailed => "a check on the pull request failed",
            Reason::VerifyFailed => "the full verify of the tree that would land failed",
            Reason::MergeConflict => "the pull request does not apply to the current base",
            Reason::EvaluatorsOnOneModel => {
                "the evaluators its lane needs run on one model, and this change needs two"
            }
            Reason::EvaluatorUnavailable => {
                "an evaluator its lane needs cannot run: it is not in the roster, has no model, or may not run on the model asked"
            }
        }
    }
}

/// Every record in the issue's comments, oldest first.
pub fn records(issue: &Issue) -> Vec<Record> {
    timed_records(issue)
        .into_iter()
        .map(|(_, record)| record)
        .collect()
}

/// Every record with the time of the comment that carries it, oldest first.
pub fn timed_records(issue: &Issue) -> Vec<(String, Record)> {
    issue
        .comments
        .iter()
        .filter(|comment| trusted(comment))
        .flat_map(|comment| {
            json_blocks(&comment.body)
                .into_iter()
                .filter_map(record)
                .map(|found| (comment.created_at.clone(), found))
        })
        .collect()
}

/// A comment by the repository's owner; one without an author (a fake tracker's) counts.
fn trusted(comment: &Comment) -> bool {
    let unattributed = comment.author.login.is_empty() && comment.author_association.is_empty();
    unattributed || comment.author_association == OWNER_ASSOCIATION
}

/// The highest lane raised for `item` since it was last readied.
pub fn lane_floor(records: &[Record], item: u64) -> Option<Lane> {
    since_ready(records, item)
        .iter()
        .filter_map(|record| match record {
            Record::Lane(raise) if raise.item == item => Some(raise.lane),
            _ => None,
        })
        .max()
}

/// The records from the newest `ready.v1` for `item` on; all of them when there is none.
fn since_ready(records: &[Record], item: u64) -> &[Record] {
    let start = latest_ready(records, item).map_or(0, |(index, _)| index);
    records.get(start..).unwrap_or_default()
}

/// The writer's `meta.v1` in the issue's comments since the current lease.
pub fn latest_meta(records: &[Record], item: u64) -> Option<&Meta> {
    since_lease(records, item)
        .iter()
        .rev()
        .find_map(|record| match record {
            Record::Meta(meta) if meta.item == item => Some(meta),
            _ => None,
        })
}

/// The records from the newest `lease.v1` for `item` on; all of them when there is none.
fn since_lease(records: &[Record], item: u64) -> &[Record] {
    let start = records
        .iter()
        .rposition(|record| matches!(record, Record::Lease(lease) if lease.item == item))
        .unwrap_or(0);
    records.get(start..).unwrap_or_default()
}

/// The first `meta.v1` block in `text`, such as a pull-request body.
pub fn meta_in(text: &str) -> Option<Meta> {
    json_blocks(text)
        .into_iter()
        .find_map(|block| match record(block) {
            Some(Record::Meta(meta)) => Some(meta),
            _ => None,
        })
}

/// The newest `ready.v1` for this issue.
pub fn latest_ready(records: &[Record], item: u64) -> Option<(usize, &Ready)> {
    records
        .iter()
        .enumerate()
        .rev()
        .find_map(|(index, record)| match record {
            Record::Ready(ready) if ready.item == item => Some((index, ready)),
            _ => None,
        })
}

/// Whether `item`'s write set is the one its newest `ready.v1` was readied with.
pub fn write_set_readied(records: &[Record], item: &WorkItem) -> bool {
    latest_ready(records, item.number)
        .is_some_and(|(_, ready)| ready.write_set_sha256 == item.write_set_sha256())
}

/// The newest `lease.v1` posted after the newest `ready.v1`: a fresh readying starts the attempts again.
pub fn current_lease(records: &[Record], item: u64) -> Option<&Lease> {
    since_ready(records, item)
        .iter()
        .rev()
        .find_map(|record| match record {
            Record::Lease(lease) if lease.item == item => Some(lease),
            _ => None,
        })
}

/// The newest hand-off posted after the current lease.
pub fn latest_handoff(records: &[Record], item: u64) -> Option<&Value> {
    since_lease(records, item)
        .iter()
        .rev()
        .find_map(|record| match record {
            Record::Handoff(value) if value.get("item").and_then(Value::as_u64) == Some(item) => {
                Some(value)
            }
            _ => None,
        })
}

/// A comment: one readable line, then the record collapsed under its schema name.
pub fn comment_body(line: &str, schema: &str, json: &str) -> String {
    format!("{line}\n\n{}", collapsed(schema, json))
}

/// The record collapsed under its schema name.
pub fn collapsed(schema: &str, json: &str) -> String {
    format!(
        "<details><summary>{schema}</summary>\n\n{FENCE_OPEN}\n{json}\n{FENCE_CLOSE}\n\n</details>\n"
    )
}

/// The collapsed `meta.v1` block of a pull-request body and a hand-off comment.
pub fn meta_block(meta: &Meta) -> serde_json::Result<String> {
    Ok(collapsed(META_SCHEMA, &serde_json::to_string(meta)?))
}

pub fn lane_comment(raise: &LaneRaise) -> serde_json::Result<String> {
    let line = format!(
        "Review lane raised to {} by {}: {}.",
        raise.lane.name(),
        raise.by,
        raise.reason
    );
    Ok(comment_body(
        &line,
        LANE_SCHEMA,
        &serde_json::to_string(raise)?,
    ))
}

pub fn ready_comment(ready: &Ready) -> serde_json::Result<String> {
    let line = format!(
        "Ready: acceptance criteria sha256 `{}`, readied by {}.",
        ready.acceptance_sha256, ready.by
    );
    Ok(comment_body(
        &line,
        READY_SCHEMA,
        &serde_json::to_string(ready)?,
    ))
}

pub fn lease_comment(lease: &Lease) -> serde_json::Result<String> {
    let line = format!(
        "Leased to {} on {}, attempt {}, branch `{}`.",
        lease.agent, lease.model, lease.attempt, lease.branch
    );
    Ok(comment_body(
        &line,
        LEASE_SCHEMA,
        &serde_json::to_string(lease)?,
    ))
}

pub fn transition_comment(transition: &Transition, line: &str) -> serde_json::Result<String> {
    Ok(comment_body(
        line,
        STATE_SCHEMA,
        &serde_json::to_string(transition)?,
    ))
}

/// The contents of every fenced `json` block in a comment.
pub fn json_blocks(body: &str) -> Vec<String> {
    let body = body.replace("\r\n", "\n");
    let mut blocks = Vec::new();
    let mut current: Option<Vec<&str>> = None;
    for line in body.lines() {
        let trimmed = line.trim();
        current = match current {
            None if trimmed == FENCE_OPEN => Some(Vec::new()),
            None => None,
            Some(lines) if trimmed == FENCE_CLOSE => {
                blocks.push(lines.join("\n"));
                None
            }
            Some(mut lines) => {
                lines.push(line);
                Some(lines)
            }
        };
    }
    blocks
}

fn record(block: String) -> Option<Record> {
    let value: Value = serde_json::from_str(&block).ok()?;
    match value.get("schema").and_then(Value::as_str)? {
        READY_SCHEMA => serde_json::from_value(value).ok().map(Record::Ready),
        LEASE_SCHEMA => serde_json::from_value(value).ok().map(Record::Lease),
        STATE_SCHEMA => serde_json::from_value(value).ok().map(Record::Transition),
        HANDOFF_SCHEMA => Some(Record::Handoff(value)),
        META_SCHEMA => serde_json::from_value(value).ok().map(Record::Meta),
        LANE_SCHEMA => serde_json::from_value(value).ok().map(Record::Lane),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::orchestrate::issue::Comment;

    fn ready(item: u64, by: &str) -> Ready {
        Ready {
            schema: READY_SCHEMA.into(),
            item,
            by: by.into(),
            acceptance_sha256: "ab".repeat(32),
            write_set_sha256: "cd".repeat(32),
        }
    }

    fn lease(item: u64, attempt: u32) -> Lease {
        Lease {
            schema: LEASE_SCHEMA.into(),
            item,
            attempt,
            agent: "impl-rust".into(),
            model: "claude-sonnet-5-5".into(),
            acceptance_sha256: "ab".repeat(32),
            branch: format!("agent/{item}/a{attempt}"),
            session: None,
        }
    }

    fn issue(bodies: Vec<String>) -> Issue {
        Issue {
            number: 9,
            comments: bodies
                .into_iter()
                .map(|body| Comment {
                    body,
                    ..Comment::default()
                })
                .collect(),
            ..Issue::default()
        }
    }

    #[test]
    fn comments_round_trip() {
        let body = ready_comment(&ready(9, "lead-core")).unwrap();
        assert!(body.starts_with("Ready: acceptance criteria sha256 `abab"));
        assert!(body.contains("<details><summary>ready.v1</summary>"));
        let found = records(&issue(vec![body]));
        assert_eq!(found, vec![Record::Ready(ready(9, "lead-core"))]);
    }

    #[test]
    fn a_fresh_ready_restarts_the_attempts() {
        let comments = vec![
            ready_comment(&ready(9, "lead-core")).unwrap(),
            lease_comment(&lease(9, 1)).unwrap(),
            lease_comment(&lease(9, 2)).unwrap(),
        ];
        let found = records(&issue(comments.clone()));
        assert_eq!(current_lease(&found, 9).map(|l| l.attempt), Some(2));
        let mut again = comments;
        again.push(ready_comment(&ready(9, "lead-core")).unwrap());
        let found = records(&issue(again));
        assert_eq!(current_lease(&found, 9), None);
        assert_eq!(current_lease(&found, 10), None);
    }

    #[test]
    fn the_write_set_counts_as_readied_only_with_the_digest_of_the_newest_ready() {
        let item = |globs: &[&str]| WorkItem {
            number: 9,
            write_set: globs.iter().map(|glob| (*glob).to_owned()).collect(),
            ..Issue::default().work_item()
        };
        let readied = item(&["crates/a/**"]);
        let mut first = ready(9, "lead-core");
        first.write_set_sha256 = readied.write_set_sha256();
        let found = records(&issue(vec![ready_comment(&first).unwrap()]));
        assert!(write_set_readied(&found, &readied));
        assert!(!write_set_readied(
            &found,
            &item(&["crates/a/**", ".github/**"])
        ));
        let again = records(&issue(vec![
            ready_comment(&first).unwrap(),
            ready_comment(&ready(9, "lead-core")).unwrap(),
        ]));
        assert!(!write_set_readied(&again, &readied));
        assert!(!write_set_readied(&[], &readied));
    }

    #[test]
    fn handoffs_after_the_lease_and_unknown_blocks() {
        let handoff = "Hand-off.\n\n<details><summary>handoff.v1</summary>\n\n```json\n{\"schema\": \"handoff.v1\", \"item\": 9, \"status\": \"partial\"}\n```\n\n</details>\n";
        let comments = vec![
            lease_comment(&lease(9, 1)).unwrap(),
            handoff.to_owned(),
            "```json\n{\"schema\": \"other\"}\n```\n```json\nnot json\n```".to_owned(),
        ];
        let found = records(&issue(comments));
        assert_eq!(found.len(), 2);
        let latest = latest_handoff(&found, 9).unwrap();
        assert_eq!(latest["status"], "partial");
    }

    #[test]
    fn records_from_anyone_but_the_owner_do_not_count() {
        let mut forged = issue(vec![ready_comment(&ready(9, "lead-core")).unwrap()]);
        forged.comments[0].author.login = "someone-else".into();
        forged.comments[0].author_association = "CONTRIBUTOR".into();
        assert!(records(&forged).is_empty());
        forged.comments[0].author_association = "NONE".into();
        assert!(records(&forged).is_empty());
        forged.comments[0].author.login = "416rehman".into();
        forged.comments[0].author_association = "OWNER".into();
        assert_eq!(records(&forged).len(), 1);
    }

    #[test]
    fn meta_blocks_round_trip_in_bodies_and_comments() {
        let meta = Meta {
            schema: META_SCHEMA.into(),
            item: 9,
            harness: "claude-code".into(),
            model: "claude-opus-5-5".into(),
            attempt: 2,
        };
        let block = meta_block(&meta).unwrap();
        assert!(block.starts_with("<details><summary>meta.v1</summary>"));
        let body = format!("Closes #9\n\n{block}");
        assert_eq!(meta_in(&body), Some(meta.clone()));
        assert_eq!(meta_in("Closes #9"), None);
        let comments = vec![lease_comment(&lease(9, 2)).unwrap(), body];
        let found = records(&issue(comments));
        assert_eq!(latest_meta(&found, 9), Some(&meta));
        assert_eq!(latest_meta(&found, 8), None);
    }

    #[test]
    fn the_highest_lane_since_the_last_ready_holds() {
        let raise = |lane: Lane| LaneRaise {
            schema: LANE_SCHEMA.into(),
            item: 9,
            lane,
            by: "eval-diff".into(),
            reason: "touches the parser".into(),
        };
        let comments = vec![
            lane_comment(&raise(Lane::Full)).unwrap(),
            ready_comment(&ready(9, "lead-core")).unwrap(),
            lane_comment(&raise(Lane::Standard)).unwrap(),
            lane_comment(&raise(Lane::Light)).unwrap(),
        ];
        let body = &comments[2];
        assert!(
            body.starts_with("Review lane raised to standard by eval-diff: touches the parser.")
        );
        let found = records(&issue(comments));
        assert_eq!(lane_floor(&found, 9), Some(Lane::Standard));
        assert_eq!(lane_floor(&found, 10), None);
    }

    #[test]
    fn transitions_serialise_with_kebab_case() {
        let transition = Transition {
            schema: STATE_SCHEMA.into(),
            item: 9,
            attempt: 1,
            from: ItemStatus::Leased,
            to: ItemStatus::InReview,
            reason: Reason::PullRequestOpen,
        };
        let body = transition_comment(&transition, "In review.").unwrap();
        assert!(body.contains("\"to\":\"in-review\""));
        assert!(body.contains("\"reason\":\"pull-request-open\""));
        assert_eq!(
            records(&issue(vec![body])),
            vec![Record::Transition(transition)]
        );
    }
}
