//! The facts a verify run leaves: the full log in `.agent/logs/`, the evidence file in
//! `.agent/evidence/` (command, exit code, duration, tree digest, every gate's outcome), the
//! optional `--json` copy, and the ten-line summary. Gates and hooks read these, never a claim.

use std::fmt::Write as _;

use anyhow::Result;
use serde::{Deserialize, Serialize};

use super::{Form, Outcome};
use crate::config::limits::{EvidenceLimits, Limits};
use crate::repo::{Repo, write_if_changed};

pub const EVIDENCE_SCHEMA: &str = "evidence.v1";
pub const EVIDENCE_DIR: &str = ".agent/evidence";
pub const LOG_DIR: &str = ".agent/logs";
const EXIT_GATE_FAILED: u8 = 2;

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct GateResult {
    pub id: String,
    pub name: String,
    pub duration_ms: u128,
    #[serde(flatten)]
    pub outcome: Outcome,
}

#[derive(Debug, Clone, PartialEq, Deserialize, Serialize)]
pub struct Evidence {
    pub schema: String,
    /// The file stem under `.agent/evidence/`: what a hand-off and the Stop gate cite.
    pub id: String,
    pub command: String,
    pub exit_code: u8,
    pub duration_ms: u128,
    /// [`crate::git::tree_digest`] of the tree the gates ran against.
    pub tree_digest: String,
    pub base: Option<String>,
    pub base_description: String,
    pub form: Form,
    pub started_at: String,
    pub log: String,
    pub gates: Vec<GateResult>,
}

/// A gate's result and the output its command printed, which goes to the log only.
#[derive(Debug, Clone)]
pub struct GateRun {
    pub result: GateResult,
    pub log: String,
}

impl Evidence {
    pub fn path(&self) -> String {
        format!("{EVIDENCE_DIR}/{}.json", self.id)
    }
}

/// 2 when a gate failed, 1 when one could not run, 0 otherwise.
pub fn exit_code(runs: &[GateRun]) -> u8 {
    if runs
        .iter()
        .any(|run| matches!(run.result.outcome, Outcome::Fail { .. }))
    {
        return EXIT_GATE_FAILED;
    }
    u8::from(
        runs.iter()
            .any(|run| matches!(run.result.outcome, Outcome::Error { .. })),
    )
}

pub fn write(
    repo: &Repo,
    evidence: &Evidence,
    runs: &[GateRun],
    json_path: Option<&str>,
) -> Result<()> {
    let limits = &Limits::built_with()?.gates.evidence;
    write_if_changed(
        &repo.path(&evidence.log),
        log_text(evidence, runs).as_bytes(),
    )?;
    let mut recorded = evidence.clone();
    for gate in &mut recorded.gates {
        if let Outcome::Fail { problems } | Outcome::Pass { notes: problems } = &mut gate.outcome {
            problems.truncate(limits.recorded_problems);
        }
    }
    let mut json = serde_json::to_string_pretty(&recorded)?;
    json.push('\n');
    write_if_changed(&repo.path(&evidence.path()), json.as_bytes())?;
    if let Some(path) = json_path {
        write_if_changed(&std::env::current_dir()?.join(path), json.as_bytes())?;
    }
    Ok(())
}

/// One `ERROR <gate-id>` line per failed gate, then the totals, log path and evidence id.
pub fn summary_lines(evidence: &Evidence) -> Vec<String> {
    match Limits::built_with() {
        Ok(limits) => summary(evidence, &limits.gates.evidence),
        Err(error) => vec![format!(
            "verify {}: {error:#}; log {}; evidence {}",
            evidence.form.label(),
            evidence.log,
            evidence.id
        )],
    }
}

fn summary(evidence: &Evidence, limits: &EvidenceLimits) -> Vec<String> {
    let failed: Vec<&GateResult> = evidence
        .gates
        .iter()
        .filter(|gate| gate.outcome.failed())
        .collect();
    let mut lines: Vec<String> = failed
        .iter()
        .take(limits.printed_errors)
        .map(|gate| error_line(gate, limits.line_chars))
        .collect();
    if failed.len() > limits.printed_errors
        && let Some(last) = lines.last_mut()
    {
        let _ = write!(
            last,
            " (and {} more gates failed; see the log)",
            failed.len().saturating_sub(limits.printed_errors)
        );
    }
    let skipped = evidence
        .gates
        .iter()
        .filter(|gate| matches!(gate.outcome, Outcome::Skip { .. }))
        .count();
    let warnings: usize = evidence
        .gates
        .iter()
        .map(|gate| match &gate.outcome {
            Outcome::Pass { notes } => notes.len(),
            _ => 0,
        })
        .sum();
    lines.push(format!(
        "verify {}: {} of {} gates failed, {skipped} skipped, {warnings} warnings, {:.1} s; log {}; evidence {}",
        evidence.form.label(),
        failed.len(),
        evidence.gates.len(),
        evidence.duration_ms as f64 / 1000.0,
        evidence.log,
        evidence.id
    ));
    lines
}

fn log_text(evidence: &Evidence, runs: &[GateRun]) -> String {
    let mut log = format!(
        "{} at {} against {}\ntree {}\n",
        evidence.command, evidence.started_at, evidence.base_description, evidence.tree_digest
    );
    for run in runs {
        let result = &run.result;
        let _ = writeln!(
            log,
            "\n== {} {}: {} ({} ms)",
            result.id,
            result.name,
            status_word(&result.outcome),
            result.duration_ms
        );
        let lines: Vec<&String> = match &result.outcome {
            Outcome::Pass { notes } => notes.iter().collect(),
            Outcome::Fail { problems } => problems.iter().collect(),
            Outcome::Skip { reason } | Outcome::Error { reason } => vec![reason],
        };
        for line in lines {
            let _ = writeln!(log, "{line}");
        }
        log.push_str(&run.log);
    }
    log
}

fn error_line(gate: &GateResult, width: usize) -> String {
    match &gate.outcome {
        Outcome::Fail { problems } => {
            let more = if problems.len() > 1 {
                format!(" (+{} more)", problems.len().saturating_sub(1))
            } else {
                String::new()
            };
            let first = one_line(problems.first().map_or("", String::as_str), width);
            match check_label(&first) {
                Some((check, rest)) => format!("ERROR {} {check}: {rest}{more}", gate.id),
                None => format!("ERROR {}: {}: {first}{more}", gate.id, gate.name),
            }
        }
        Outcome::Error { reason } => format!(
            "ERROR {}: {}: infrastructure error: {}",
            gate.id,
            gate.name,
            one_line(reason, width)
        ),
        Outcome::Pass { .. } | Outcome::Skip { .. } => String::new(),
    }
}

/// A problem that opens with a check label such as `S4` (the structure checks), which team/05
/// section 8 prints after the gate id: `ERROR V20 S4: ...`.
fn check_label(problem: &str) -> Option<(&str, &str)> {
    let (label, rest) = problem.split_once(' ')?;
    let mut chars = label.chars();
    let letter = chars.next().is_some_and(|c| c.is_ascii_uppercase());
    let digits: String = chars.collect();
    (letter && !digits.is_empty() && digits.chars().all(|c| c.is_ascii_digit()))
        .then_some((label, rest))
}

/// A multi-line message (a TOML error with its source excerpt) folded into one bounded line.
fn one_line(text: &str, width: usize) -> String {
    let lines: Vec<&str> = text
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty() && !line.starts_with('|') && !is_excerpt(line))
        .collect();
    let joined = lines.join(" ");
    if joined.chars().count() <= width {
        return joined;
    }
    let mut cut: String = joined.chars().take(width).collect();
    cut.push_str("...");
    cut
}

/// `10 | branch = "..."`: the numbered source line of a parse error.
fn is_excerpt(line: &str) -> bool {
    line.split_once(" |")
        .is_some_and(|(number, _)| !number.is_empty() && number.chars().all(|c| c.is_ascii_digit()))
}

fn status_word(outcome: &Outcome) -> &'static str {
    match outcome {
        Outcome::Pass { .. } => "pass",
        Outcome::Fail { .. } => "fail",
        Outcome::Skip { .. } => "skip",
        Outcome::Error { .. } => "error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(id: &str, outcome: Outcome) -> GateResult {
        GateResult {
            id: id.into(),
            name: id.to_lowercase(),
            duration_ms: 5,
            outcome,
        }
    }

    fn evidence(gates: Vec<GateResult>) -> Evidence {
        Evidence {
            schema: EVIDENCE_SCHEMA.into(),
            id: "verify-x".into(),
            command: "cargo xtask verify --fast".into(),
            exit_code: 2,
            duration_ms: 1500,
            tree_digest: "abc".into(),
            base: None,
            base_description: "no commits yet".into(),
            form: Form::Fast,
            started_at: "2026-11-11T00:00:00Z".into(),
            log: ".agent/logs/verify-x.log".into(),
            gates,
        }
    }

    #[test]
    fn summary_has_one_error_line_per_failed_gate_and_the_log() {
        let lines = summary_lines(&evidence(vec![
            gate(
                "V01",
                Outcome::Pass {
                    notes: vec!["warning S5".into()],
                },
            ),
            gate(
                "V02",
                Outcome::Fail {
                    problems: vec!["error: unused".into(), "error: more".into()],
                },
            ),
            gate("V05", Outcome::skip("no agent")),
            gate(
                "V21",
                Outcome::Error {
                    reason: "missing file".into(),
                },
            ),
        ]));
        assert_eq!(lines.len(), 3);
        assert_eq!(lines[0], "ERROR V02: v02: error: unused (+1 more)");
        assert!(lines[1].starts_with("ERROR V21: v21: infrastructure error"));
        assert!(lines[2].contains("2 of 4 gates failed, 1 skipped, 1 warnings"));
        assert!(lines[2].contains(".agent/logs/verify-x.log"));
    }

    #[test]
    fn summary_never_exceeds_ten_lines() {
        let gates = (0..14)
            .map(|i| {
                gate(
                    &format!("V{i:02}"),
                    Outcome::Fail {
                        problems: vec!["x".into()],
                    },
                )
            })
            .collect();
        let lines = summary_lines(&evidence(gates));
        assert_eq!(lines.len(), 10);
        assert!(lines[8].contains("and 5 more gates failed"));
    }

    #[test]
    fn evidence_round_trips_for_the_stop_gate() {
        let original = evidence(vec![gate(
            "V03",
            Outcome::Fail {
                problems: vec!["test failed".into()],
            },
        )]);
        let json = serde_json::to_string(&original).unwrap();
        assert!(json.contains("\"status\":\"fail\""));
        assert_eq!(serde_json::from_str::<Evidence>(&json).unwrap(), original);
        assert_eq!(original.path(), ".agent/evidence/verify-x.json");
    }

    #[test]
    fn multi_line_errors_fold_into_one_line() {
        let toml_error = "kit sources: parsing roster.toml: TOML parse error at line 10, column 1\n   |\n10 | branch = \"x\"\n   | ^^^^^^\nunknown field `branch`\n";
        let lines = summary_lines(&evidence(vec![gate(
            "V21",
            Outcome::Fail {
                problems: vec![toml_error.into()],
            },
        )]));
        assert_eq!(lines.len(), 2);
        assert_eq!(
            lines[0],
            "ERROR V21: v21: kit sources: parsing roster.toml: TOML parse error at line 10, column 1 unknown field `branch`"
        );
        let width = Limits::built_with().unwrap().gates.evidence.line_chars;
        assert!(one_line(&"x".repeat(width + 1), width).ends_with("..."));
        let structure = summary_lines(&evidence(vec![gate(
            "V20",
            Outcome::Fail {
                problems: vec!["S4 crates/a/src/lib.rs:3: `status` is a string".into()],
            },
        )]));
        assert_eq!(
            structure[0],
            "ERROR V20 S4: crates/a/src/lib.rs:3: `status` is a string"
        );
    }

    #[test]
    fn exit_codes() {
        let run = |outcome| GateRun {
            result: gate("V", outcome),
            log: String::new(),
        };
        assert_eq!(
            exit_code(&[
                run(Outcome::skip("x")),
                run(Outcome::Pass { notes: vec![] })
            ]),
            0
        );
        assert_eq!(exit_code(&[run(Outcome::Error { reason: "x".into() })]), 1);
        assert_eq!(
            exit_code(&[
                run(Outcome::Error { reason: "x".into() }),
                run(Outcome::from_problems(vec!["y".into()]))
            ]),
            2
        );
    }
}
