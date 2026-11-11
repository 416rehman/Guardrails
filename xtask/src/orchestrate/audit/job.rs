//! One audit run end to end: the finder prompt, the find pass and the runner's check, a refuting
//! pass per surviving result, and the `audit-run.v1` record with one ledger record per result.

use std::path::{Path, PathBuf};
use std::time::Duration;

use anyhow::{Result, bail};
use serde_json::{Value, json};

use super::check::{self, Checked, FINDING_SCHEMA, check_finder, prefixed_sha256, verdict};
use super::library::Entry;
use super::runner::Runner;
use super::{AuditArm, OUT_DIR, Request, Scope, write_json, write_text};
use crate::clock::Utc;
use crate::git;
use crate::orchestrate::tiers::RiskPolicy;
use crate::repo::Repo;

const RUN_SCHEMA: &str = "audit-run.v1";
const RUNNER: &str = "cargo xtask audit";

/// One audit run: the prompt, the commit, the scope and where its record goes.
pub(super) struct Job<'a> {
    pub(super) repo: &'a Repo,
    pub(super) runner: &'a Runner,
    pub(super) entry: &'a Entry,
    pub(super) request: &'a Request,
    pub(super) run_id: String,
    pub(super) commit: String,
    pub(super) scope: Scope,
    /// The scope in words, as the finder and verifier prompts name it.
    pub(super) scope_text: String,
    pub(super) run_dir: PathBuf,
}

#[derive(Debug, Clone, Default)]
pub(super) struct Totals {
    pub(super) returned: usize,
    pub(super) after_spans: usize,
    tokens_in: u64,
    tokens_out: u64,
    paused: Duration,
    pub(super) duration: Duration,
    verifier_models: Vec<String>,
}

impl Job<'_> {
    pub(super) fn finder_prompt(&self) -> String {
        let concept = match self.request.arm {
            AuditArm::Power => &self.entry.concept,
            AuditArm::Control => &self.entry.control_concept,
        };
        let preamble = self.entry.fill_preamble(
            &self.scope_text,
            &self.commit,
            &self.run_id,
            &finder_report_path(),
        );
        format!(
            "{}\n{}\n",
            preamble.trim_end(),
            concept.replace("{scope}", &self.scope_text)
        )
    }

    pub(super) fn passes(
        &self,
        worktree: &Path,
        finder_prompt: &str,
    ) -> Result<(Totals, Vec<Value>, Vec<Value>)> {
        let (entry, run_dir, commit) = (self.entry, &self.run_dir, self.commit.as_str());
        write_text(&run_dir.join("finder-prompt.md"), finder_prompt)?;
        let finder_out = finder_report_path();
        let log = run_dir.join("finder.jsonl");
        let finder = self.runner.pass(
            worktree,
            &entry.finder_model,
            entry.finder_turns,
            finder_prompt,
            &finder_out,
            &log,
        )?;
        let mut totals = Totals {
            tokens_in: finder.input_tokens,
            tokens_out: finder.output_tokens,
            paused: finder.paused,
            ..Totals::default()
        };
        let Some(report) = finder.output else {
            bail!(
                "the finder wrote no JSON to {finder_out}; see {}",
                log.display()
            );
        };
        write_json(&run_dir.join("finder.json"), &report)?;
        let file_at = |path: &str| git::show(self.repo, commit, path).ok().flatten();
        let checked = check_finder(&report, entry, commit, &file_at);
        for problem in &checked.problems {
            println!("audit {}: discarded {problem}", entry.id);
        }
        totals.returned = checked.returned;
        totals.after_spans = checked.kept.len();
        let policy = RiskPolicy::load(self.repo)?;
        let mut records = Vec::new();
        for (index, result) in checked.kept.iter().enumerate() {
            let verdicts = self.refute(worktree, index, result, &mut totals)?;
            records.push(ledger_record(
                entry,
                &self.run_id,
                result,
                &verdicts,
                &policy,
            ));
        }
        Ok((totals, records, checked.checked_and_sound))
    }

    /// The refuting passes for one result, each in a new session: the verifier model, and the
    /// second verifier model too at severity 1.
    fn refute(
        &self,
        worktree: &Path,
        index: usize,
        result: &Checked,
        totals: &mut Totals,
    ) -> Result<Vec<(String, Option<check::Verdict>)>> {
        let entry = self.entry;
        let mut models = vec![entry.verifier_model.clone()];
        if result.severity == 1 {
            models.push(entry.second_verifier_model.clone());
        }
        let subject = serde_json::to_string_pretty(
            &json!({"fingerprint": result.fingerprint, "result": result.result}),
        )?;
        let mut verdicts = Vec::new();
        for (verifier_index, model) in models.iter().enumerate() {
            let name = format!("verifier-{}-{}", index + 1, verifier_index + 1);
            let out = format!("{OUT_DIR}/{name}.json");
            let preamble = entry.fill_preamble(&self.scope_text, &self.commit, &self.run_id, &out);
            let verifier = entry
                .verifier
                .replace("{commit}", &self.commit)
                .replace("{out}", &out);
            let prompt = format!(
                "{}\n{}\n{subject}\n",
                preamble.trim_end(),
                verifier.trim_end()
            );
            let log = self.run_dir.join(format!("{name}.jsonl"));
            let pass =
                self.runner
                    .pass(worktree, model, entry.verifier_turns, &prompt, &out, &log)?;
            totals.tokens_in += pass.input_tokens;
            totals.tokens_out += pass.output_tokens;
            totals.paused += pass.paused;
            if !totals.verifier_models.contains(model) {
                totals.verifier_models.push(model.clone());
            }
            let found = pass
                .output
                .as_ref()
                .and_then(|report| verdict(report, &result.fingerprint));
            verdicts.push((model.clone(), found));
        }
        Ok(verdicts)
    }

    pub(super) fn run_record(
        &self,
        totals: &Totals,
        results: Vec<Value>,
        sound: &[Value],
    ) -> Value {
        let (entry, request) = (self.entry, self.request);
        let (id, skill) = match request.arm {
            AuditArm::Power => (
                entry.id.clone(),
                prefixed_sha256(entry.prompt_text.as_bytes()),
            ),
            AuditArm::Control => (
                "control".to_owned(),
                prefixed_sha256(entry.control_concept.as_bytes()),
            ),
        };
        let upheld = results.iter().filter(|r| r["state"] == "upheld").count();
        let preamble = prefixed_sha256(entry.preamble.as_bytes());
        json!({
            "schema": RUN_SCHEMA,
            "run_id": self.run_id,
            "prompt": {"id": id, "version": entry.version, "skill_sha256": skill, "preamble_sha256": preamble},
            "arm": if request.arm == AuditArm::Power { "power" } else { "control" },
            "pair_id": if request.arm == AuditArm::Control { json!(self.run_id) } else { Value::Null },
            "commit": self.commit,
            "scope": self.scope.record(),
            "trigger": request.trigger,
            "harness": {"name": self.runner.harness, "version": self.runner.claude_pin},
            "finder_model": entry.finder_model,
            "verifier_models": totals.verifier_models,
            "tokens_in": totals.tokens_in,
            "tokens_out": totals.tokens_out,
            "usage_window_share": Value::Null,
            "paused_for_limit": totals.paused.as_secs(),
            "duration_s": totals.duration.as_secs(),
            "results_returned": totals.returned,
            "results_after_span_check": totals.after_spans,
            "upheld": upheld,
            "reproduced": 0,
            "checked_and_sound": sound,
            "skipped": [],
            "results": results,
        })
    }
}

/// Where the finder writes its report, relative to the worktree; its prompt names the same path.
fn finder_report_path() -> String {
    format!("{OUT_DIR}/finder.json")
}

/// The ledger record of one result: upheld only if every verifier upheld or downgraded it, at
/// the higher of the severities they gave.
fn ledger_record(
    entry: &Entry,
    run_id: &str,
    checked: &Checked,
    verdicts: &[(String, Option<check::Verdict>)],
    policy: &RiskPolicy,
) -> Value {
    let survived = !verdicts.is_empty()
        && verdicts
            .iter()
            .all(|(_, v)| v.as_ref().is_some_and(|v| v.verdict != "REFUTED"));
    let severity = verdicts
        .iter()
        .filter_map(|(_, v)| v.as_ref().and_then(|v| v.severity))
        .chain(std::iter::once(checked.severity))
        .min()
        .unwrap_or(checked.severity);
    let state = if survived { "upheld" } else { "refuted" };
    let mut record = checked.result.clone();
    let trust_core = record
        .get("evidence")
        .and_then(Value::as_array)
        .is_some_and(|spans| {
            spans
                .iter()
                .filter_map(|s| s.get("path").and_then(Value::as_str))
                .any(|path| policy.is_trust_core(path))
        });
    let verifier: Vec<Value> = verdicts
        .iter()
        .map(|(model, v)| verdict_entry(model, v.as_ref()))
        .collect();
    if survived {
        check::set(&mut record, "severity", json!(severity));
    }
    let fields = [
        ("schema", json!(FINDING_SCHEMA)),
        ("fingerprint", json!(checked.fingerprint)),
        ("run_id", json!(run_id)),
        ("prompt", json!({"id": entry.id, "version": entry.version})),
        ("trust_core", json!(trust_core)),
        (
            "security_candidate",
            json!(entry.is_security_candidate(severity)),
        ),
        ("verifier", json!(verifier)),
        ("proof", json!({"status": "not-attempted"})),
        ("state", json!(state)),
        ("closure", Value::Null),
        (
            "history",
            json!([{"state": state, "run_id": run_id, "at": Utc::now().iso(), "by": RUNNER}]),
        ),
    ];
    for (key, value) in fields {
        check::set(&mut record, key, value);
    }
    record
}

/// A verifier that wrote no valid report counts as REFUTED, the verifier's own default.
fn verdict_entry(model: &str, found: Option<&check::Verdict>) -> Value {
    let Some(found) = found else {
        return json!({"verdict": "REFUTED", "model": model, "reason": "the verifier wrote no valid verifier report; the default is REFUTED"});
    };
    let mut entry = json!({"verdict": found.verdict, "model": model, "reason": found.reason});
    if let (Some(label), Some(severity)) = (&found.label, found.severity) {
        check::set(&mut entry, "label", json!(label));
        check::set(&mut entry, "severity", json!(severity));
    }
    entry
}

pub(super) fn with_skip(mut record: Value, id: &str, reason: &str, detail: &str) -> Value {
    check::set(
        &mut record,
        "skipped",
        json!([{"prompt": id, "reason": reason, "detail": detail}]),
    );
    record
}

/// Prints what may be printed: a security candidate shows only its fingerprint (D-62).
pub(super) fn report(entry: &Entry, records: &[Value]) {
    for record in records.iter().filter(|r| r["state"] == "upheld") {
        let fingerprint = record["fingerprint"].as_str().unwrap_or_default();
        if record["security_candidate"] == true {
            println!(
                "audit {}: {fingerprint} is held for private triage",
                entry.id
            );
        } else {
            println!(
                "audit {}: upheld, severity {}: {} ({fingerprint})",
                entry.id,
                record["severity"],
                record["title"].as_str().unwrap_or_default()
            );
        }
    }
}
