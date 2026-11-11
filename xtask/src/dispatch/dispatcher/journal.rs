//! The dispatcher's usage log, `.agent/logs/dispatch-usage.jsonl`: one JSON line per lease,
//! session, pause and end of attempt, the record team/01 section 9 asks for.

use serde_json::json;

use crate::clock::Utc;
use crate::orchestrate::claude::Ended;
use crate::orchestrate::records::Lease;
use crate::repo::Repo;

const USAGE_LOG: &str = ".agent/logs/dispatch-usage.jsonl";

pub(super) fn log_session(repo: &Repo, lease: &Lease, ended: &Ended) {
    let report = ended.report();
    let (input, output) = report
        .result
        .as_ref()
        .map_or((0, 0), |r| (r.input_tokens, r.output_tokens));
    let line = json!({
        "at": Utc::now().iso(), "event": "session", "item": lease.item, "attempt": lease.attempt,
        "agent": lease.agent, "model": lease.model, "ended": ended.describe(), "turns": report.turns,
        "input_tokens": input, "output_tokens": output, "duration_s": report.elapsed.as_secs(),
    });
    append(repo, &line.to_string());
}

pub(super) fn note(repo: &Repo, event: &str, lease: Option<&Lease>, detail: &str) {
    let line = json!({
        "at": Utc::now().iso(), "event": event, "item": lease.map(|l| l.item),
        "attempt": lease.map(|l| l.attempt), "detail": detail,
    });
    append(repo, &line.to_string());
}

fn append(repo: &Repo, line: &str) {
    use std::io::Write as _;
    let path = repo.path(USAGE_LOG);
    let opened = path
        .parent()
        .map(std::fs::create_dir_all)
        .transpose()
        .and_then(|_| {
            std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .open(&path)
        });
    if let Ok(mut file) = opened {
        let _ = writeln!(file, "{line}");
    }
}
