//! The `handoff.v1` draft an agent leaves at `.agent/state/handoff-<n>-<agent>.json` before it stops
//! (team/02 section 1.4); `cargo xtask kit handoff` posts it as the issue comment. The Stop gate
//! validates it and, once it has blocked one diff `[hook.stop_gate] blocks` times, marks it
//! `gate: failed` so the lead re-plans.

use anyhow::Result;
use serde_json::{Map, Value, json};

use super::state::{read_json, write_json};
use crate::config::runtime::Usage;
use crate::repo::Repo;

pub const SCHEMA: &str = "handoff.v1";
const WORKER_STATUSES: &[&str] = &["done", "partial", "blocked", "impossible"];
const EVALUATOR_STATUSES: &[&str] = &["pass", "fail", "cannot-evaluate"];
const ACCEPTANCE_RESULTS: &[&str] = &["pass", "fail", "not-run"];
const SEVERITIES: &[&str] = &["blocker", "major", "minor"];
const REQUIRED: &[&str] = &[
    "schema",
    "item",
    "agent",
    "model",
    "status",
    "round",
    "summary",
    "changed_paths",
    "evidence",
    "decisions",
    "next",
];
const OPTIONAL: &[&str] = &[
    "commit",
    "acceptance",
    "three_arm",
    "findings",
    "protected_change_requests",
    "revert",
    "usage",
    "gate",
];
pub const ARMS: &[&str] = &["fails_before", "passes_after", "fails_on_revert"];

/// What the draft must say for this session.
pub struct Expectation<'a> {
    pub item: u64,
    pub agent: &'a str,
    pub model_ids: &'a [String],
    /// The model id the launcher started the session on (`GRDR_MODEL`), which the draft must
    /// name, since a verdict counts only from the model it was asked on.
    pub launcher_model: Option<&'a str>,
    pub kind: Kind,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Worker,
    /// A worker on a bug item: `three_arm` is required once it is done.
    BugFix,
    Evaluator,
}

#[derive(Clone, Copy)]
enum Shape<'a> {
    Text,
    Integer,
    Bool,
    OneOf(&'a [&'a str]),
    /// An index into an array of this length.
    Index(usize),
}

impl Shape<'_> {
    fn accepts(self, value: &Value) -> bool {
        match self {
            Shape::Text => value.is_string(),
            Shape::Integer => value.is_i64() || value.is_u64(),
            Shape::Bool => value.is_boolean(),
            Shape::OneOf(allowed) => value.as_str().is_some_and(|text| allowed.contains(&text)),
            Shape::Index(length) => value
                .as_u64()
                .and_then(|index| usize::try_from(index).ok())
                .is_some_and(|index| index < length),
        }
    }
}

/// One draft per agent, so the evaluators of one issue never overwrite each other.
pub fn path(item: u64, agent: &str) -> String {
    format!(".agent/state/handoff-{item}-{agent}.json")
}

/// A `round` past `.agents/kit/usage.toml [item] max_review_rounds`, or that bound missing.
pub fn round_problem(value: &Value, max_rounds: Option<u32>) -> Option<String> {
    let Some(max_rounds) = max_rounds else {
        return Some(".agents/kit/usage.toml [item] has no max_review_rounds".to_owned());
    };
    let round = value.get("round").and_then(Value::as_u64)?;
    (round > u64::from(max_rounds))
        .then(|| format!("`round` is past the last review round, {max_rounds}"))
}

/// Problems with the draft, or the one problem that it is missing.
pub fn check(repo: &Repo, expect: &Expectation, max_problems: usize) -> Result<Vec<String>> {
    let location = path(expect.item, expect.agent);
    let value: Option<Value> = match read_json(repo, &location) {
        Ok(value) => value,
        Err(error) => return Ok(vec![format!("{location} is not JSON: {error:#}")]),
    };
    Ok(match value {
        None => vec![format!(
            "no hand-off draft at {location}; write the handoff.v1 JSON there, or pass it to `cargo xtask kit handoff --draft '<json>'`, which writes and posts it (skill grdr-handoff)"
        )],
        Some(value) => validate(&value, expect)
            .into_iter()
            .chain(round_problem(
                &value,
                Usage::load(repo)?.item.max_review_rounds,
            ))
            .take(max_problems)
            .map(|problem| format!("{location}: {problem}"))
            .collect(),
    })
}

pub fn validate(value: &Value, expect: &Expectation) -> Vec<String> {
    let Some(object) = value.as_object() else {
        return vec!["is not a JSON object".to_owned()];
    };
    let mut problems: Vec<String> = REQUIRED
        .iter()
        .filter(|key| !object.contains_key(**key))
        .map(|key| format!("missing `{key}`"))
        .collect();
    problems.extend(
        object
            .keys()
            .filter(|key| !REQUIRED.contains(&key.as_str()) && !OPTIONAL.contains(&key.as_str()))
            .map(|key| format!("unknown key `{key}`")),
    );
    let text = |key: &str| object.get(key).and_then(Value::as_str);
    if object.contains_key("schema") && text("schema") != Some(SCHEMA) {
        problems.push(format!("`schema` is not \"{SCHEMA}\""));
    }
    if object.contains_key("item")
        && object.get("item").and_then(Value::as_u64) != Some(expect.item)
    {
        problems.push(format!("`item` is not {}", expect.item));
    }
    if object.contains_key("agent") && text("agent") != Some(expect.agent) {
        problems.push(format!("`agent` is not \"{}\"", expect.agent));
    }
    if object.contains_key("model")
        && !text("model").is_some_and(|model| expect.model_ids.iter().any(|id| id == model))
    {
        problems.push("`model` is not an exact id from .agents/models.toml".to_owned());
    }
    if let Some(launched) = expect.launcher_model
        && object.contains_key("model")
        && text("model") != Some(launched)
    {
        problems.push(format!(
            "`model` is not {launched}, the model the launcher started this session on"
        ));
    }
    let statuses = if expect.kind == Kind::Evaluator {
        EVALUATOR_STATUSES
    } else {
        WORKER_STATUSES
    };
    let status = text("status");
    if object.contains_key("status") && !status.is_some_and(|status| statuses.contains(&status)) {
        problems.push(format!("`status` is not one of {}", statuses.join(", ")));
    }
    let round = object.get("round").and_then(Value::as_u64);
    if object.contains_key("round") && !round.is_some_and(|round| round >= 1) {
        problems.push("`round` is not a review round from 1".to_owned());
    }
    if object.contains_key("summary")
        && text("summary").is_none_or(|summary| summary.trim().is_empty())
    {
        problems.push("`summary` is empty".to_owned());
    }
    problems.extend(array_of_strings(object, "changed_paths"));
    problems.extend(entries(
        object,
        "evidence",
        &[
            ("cmd", Shape::Text),
            ("exit", Shape::Integer),
            ("log", Shape::Text),
            ("sha256", Shape::Text),
        ],
    ));
    let evidence_count = object
        .get("evidence")
        .and_then(Value::as_array)
        .map_or(0, Vec::len);
    let finished = matches!(status, Some("done" | "pass" | "fail"));
    if finished && evidence_count == 0 {
        problems.push("a finished hand-off names its evidence: `evidence` is empty".to_owned());
    }
    problems.extend(entries(
        object,
        "decisions",
        &[
            ("at", Shape::Text),
            ("choice", Shape::Text),
            ("spec_silent", Shape::Bool),
            ("confidence", Shape::Text),
        ],
    ));
    problems.extend(entries(
        object,
        "protected_change_requests",
        &[("path", Shape::Text), ("why", Shape::Text)],
    ));
    problems.extend(entries(
        object,
        "findings",
        &[
            ("severity", Shape::OneOf(SEVERITIES)),
            ("at", Shape::Text),
            ("claim", Shape::Text),
            ("proof", Shape::Text),
        ],
    ));
    problems.extend(entries(
        object,
        "acceptance",
        &[
            ("id", Shape::Text),
            ("result", Shape::OneOf(ACCEPTANCE_RESULTS)),
            ("evidence", Shape::Index(evidence_count)),
        ],
    ));
    problems.extend(three_arm(
        object,
        expect.kind == Kind::BugFix && status == Some("done"),
        evidence_count,
    ));
    if object.contains_key("next") && text("next").is_none() {
        problems.push("`next` is not a string".to_owned());
    }
    if object.contains_key("gate") && text("gate") != Some("failed") {
        problems.push("`gate` is only ever \"failed\"".to_owned());
    }
    problems
}

/// Once the Stop gate gives up on a diff: the draft says `gate: failed`, written fresh if there
/// was none.
pub fn mark_failed(
    repo: &Repo,
    item: u64,
    agent: &str,
    model: Option<&str>,
    reason: &str,
) -> Result<()> {
    let location = path(item, agent);
    let existing: Option<Value> = read_json(repo, &location).ok().flatten();
    let mut object = match existing {
        Some(Value::Object(object)) => object,
        _ => {
            let mut fresh = Map::new();
            fresh.insert("schema".into(), json!(SCHEMA));
            fresh.insert("item".into(), json!(item));
            fresh.insert("agent".into(), json!(agent));
            fresh.insert("model".into(), json!(model.unwrap_or_default()));
            fresh.insert("status".into(), json!("blocked"));
            fresh.insert("round".into(), json!(1));
            fresh.insert(
                "summary".into(),
                json!(format!(
                    "The Stop gate reached its block limit on one diff: {reason}"
                )),
            );
            fresh.insert("changed_paths".into(), json!([]));
            fresh.insert("evidence".into(), json!([]));
            fresh.insert("decisions".into(), json!([]));
            fresh.insert(
                "next".into(),
                json!("The item's lead re-plans it: the gate failures are in the Stop gate's log."),
            );
            fresh
        }
    };
    object.insert("gate".into(), json!("failed"));
    write_json(repo, &location, &Value::Object(object))
}

fn array_of_strings(object: &Map<String, Value>, key: &str) -> Option<String> {
    let value = object.get(key)?;
    let valid = value
        .as_array()
        .is_some_and(|items| items.iter().all(Value::is_string));
    (!valid).then(|| format!("`{key}` is not an array of strings"))
}

/// Problems with an optional array of objects whose fields have the given shapes.
fn entries(object: &Map<String, Value>, key: &str, fields: &[(&str, Shape)]) -> Vec<String> {
    let Some(value) = object.get(key) else {
        return Vec::new();
    };
    let Some(items) = value.as_array() else {
        return vec![format!("`{key}` is not an array")];
    };
    items
        .iter()
        .enumerate()
        .flat_map(|(index, item)| {
            fields.iter().filter_map(move |(field, shape)| {
                let ok = item.get(*field).is_some_and(|value| shape.accepts(value));
                (!ok).then(|| format!("`{key}[{index}].{field}` is missing or malformed"))
            })
        })
        .collect()
}

fn three_arm(object: &Map<String, Value>, required: bool, evidence: usize) -> Vec<String> {
    let Some(value) = object.get("three_arm") else {
        return if required {
            vec![
                "a done bug fix carries `three_arm` (fails_before, passes_after, fails_on_revert)"
                    .to_owned(),
            ]
        } else {
            Vec::new()
        };
    };
    ARMS.iter()
        .filter(|arm| {
            !value
                .get(**arm)
                .is_some_and(|index| Shape::Index(evidence).accepts(index))
        })
        .map(|arm| format!("`three_arm.{arm}` is not an index into `evidence`"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expectation(ids: &[String]) -> Expectation<'_> {
        Expectation {
            item: 7,
            agent: "impl-rust",
            model_ids: ids,
            launcher_model: None,
            kind: Kind::BugFix,
        }
    }

    fn draft() -> Value {
        json!({
            "schema": "handoff.v1", "item": 7, "agent": "impl-rust", "model": "claude-sonnet-5-5",
            "status": "done", "round": 1, "summary": "Fixed it. Evidence verify-20261111T100200Z-1.",
            "changed_paths": ["src/a.rs"],
            "evidence": [{"cmd": "cargo xtask verify --fast", "exit": 0, "log": ".agent/logs/v.log", "sha256": "ab"},
                         {"cmd": "prove before", "exit": 1, "log": "b", "sha256": "cd"},
                         {"cmd": "prove revert", "exit": 1, "log": "c", "sha256": "ef"}],
            "three_arm": {"fails_before": 1, "passes_after": 0, "fails_on_revert": 2},
            "decisions": [{"at": "src/a.rs:3", "choice": "x", "spec_silent": true, "confidence": "low"}],
            "next": "Evaluators run AC-1."
        })
    }

    #[test]
    fn a_complete_draft_passes() {
        let ids = vec!["claude-sonnet-5-5".to_owned()];
        assert_eq!(validate(&draft(), &expectation(&ids)), Vec::<String>::new());
    }

    #[test]
    fn problems_are_named() {
        let ids = vec!["claude-sonnet-5-5".to_owned()];
        let mut value = draft();
        value["item"] = json!(8);
        value["status"] = json!("finished");
        value["extra"] = json!(1);
        value.as_object_mut().unwrap().remove("three_arm");
        value.as_object_mut().unwrap().remove("decisions");
        let problems = validate(&value, &expectation(&ids));
        assert_eq!(problems.len(), 4, "{problems:#?}");
    }

    #[test]
    fn rounds_stop_at_the_usage_bound() {
        let mut value = draft();
        assert_eq!(round_problem(&value, Some(3)), None);
        value["round"] = json!(4);
        assert!(round_problem(&value, Some(3)).is_some());
        assert!(round_problem(&value, None).is_some());
    }
}
