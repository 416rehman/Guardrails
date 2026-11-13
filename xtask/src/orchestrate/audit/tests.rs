use std::time::Duration;

use serde_json::json;

use super::*;
use crate::dispatch::worker::Prepare;
use crate::git::Base;
use crate::orchestrate::claude::SessionRules;
use crate::orchestrate::issue::sha256_hex;
use crate::orchestrate::testkit::{FakeProgram, init_git};
use crate::testkit::TempRepo;

const LIBRARY_TOML: &str = "[files]\npreamble = \"preamble.md\"\nverifier = \"verifier.md\"\nprompt = \"prompts/{id}.md\"\nfinding_schema = \"schema/audit-finding.v1.json\"\n\n[defaults]\nmax_findings = 15\nfinder_model = \"sonnet\"\nverifier_model = \"opus\"\nsecond_verifier_model = \"sonnet\"\nfinder_max_turns = 40\nverifier_max_turns = 20\ncontrol_concept = \"Find the bugs in {scope}.\"\n\n[rules]\nallowed_models = [\"opus\", \"sonnet\"]\n\n[embargo]\nseverity = 1\nthemes = [\"security\"]\n\n[[prompt]]\nid = \"A01\"\nname = \"implicit-state-machines\"\nversion = \"1.0.0\"\ntheme = \"state\"\npaths = [\"**/*.rs\"]\nblocking = \"major\"\ncloses-by = [\"type\"]\n";
const FINDING_SCHEMA: &str = include_str!("../../../../audits/schema/audit-finding.v1.json");
const PROMPT: &str = "---\nname: audit-a01-implicit-state-machines\ndescription: Finds implicit state machines.\nlicense: Apache-2.0\nmetadata: { version: 1.0.0, owner: agent-kit, closes-by: [type] }\n---\n# A01 implicit-state-machines (version 1.0.0)\n\nConcept:\nFind every lifecycle in {scope} held in flags.\n\nClass keys: `implicit-state:exclusive-bools`, `implicit-state:no-exit`.\n";
const PREAMBLE: &str = "You are running read-only audit {prompt_id} on {scope} at commit {commit} of the repository.\nWrite JSON to {out}.\n\nConcept:\n";
const VERIFIER: &str = "You are the refuting verifier for one audit result.\nWrite JSON to {out}. Do not edit files.\n\nResult:\n";
const SOURCE: &str = "pub struct InstallRecord {\n    pub probed: bool,\n    pub written: bool,\n    pub canary_passed: bool,\n}\n";
const DONE: &str = "{\"type\":\"result\",\"subtype\":\"success\",\"is_error\":false,\"usage\":{\"input_tokens\":100,\"output_tokens\":10}}\n";
const LIMITED: &str = "{\"type\":\"result\",\"subtype\":\"error_during_execution\",\"is_error\":true,\"result\":\"You've hit your session limit\"}\n";

fn repo() -> (TempRepo, String) {
    let temp = TempRepo::create();
    temp.write(".gitignore", ".agent/\n");
    temp.write(".agents/harness.toml", "[dispatch]\nstall_seconds = 30\nclaude_pin = \"2.1.319\"\n[limits]\nusage_limit_strings = [\"You've hit your session limit\"]\nretry_seconds = 0\n");
    temp.write("audits/library.toml", LIBRARY_TOML);
    temp.write("audits/prompts/A01.md", PROMPT);
    temp.write("audits/preamble.md", PREAMBLE);
    temp.write("audits/verifier.md", VERIFIER);
    temp.write("audits/schema/audit-finding.v1.json", FINDING_SCHEMA);
    temp.write("crates/grdr-agents/src/install.rs", SOURCE);
    init_git(temp.root());
    let commit = git::head(&temp.repo()).unwrap().unwrap();
    (temp, commit)
}

fn runner(fake: &FakeProgram) -> Runner {
    Runner {
        claude: fake.program().to_path_buf(),
        prepare: Prepare::CopyOnly,
        session: SessionRules {
            stall: Duration::from_secs(30),
            retry_after_limit: Duration::ZERO,
            limit_strings: vec!["You've hit your session limit".into()],
            model_limit_strings: Vec::new(),
            poll: Duration::from_millis(50),
            drain_grace: Duration::from_secs(2),
            turn_margin: 2,
        },
        harness: "claude-code".into(),
        claude_pin: "2.1.319".into(),
    }
}

fn request(diff: Option<String>) -> Request {
    Request {
        id: "A01".into(),
        diff,
        commit: None,
        arm: AuditArm::Power,
        trigger: "manual".into(),
    }
}

fn finder_report(commit: &str) -> String {
    json!({
        "schema": "audit-finding.v1", "report": "finder", "prompt": {"id": "A01", "version": "1.0.0"},
        "commit": commit, "applicable": true,
        "results": [
            {"class_key": "implicit-state:exclusive-bools", "locus": {"crate": "grdr-agents", "item": "install::InstallRecord"},
             "title": "InstallRecord holds three booleans", "label": "CONFIRMED", "severity": 2,
             "evidence": [{"path": "crates/grdr-agents/src/install.rs", "line": 2, "quote": "pub probed: bool,\npub written: bool,"}],
             "permits": "eight combinations", "reach": "restart", "smallest_fix": "an enum",
             "closure_proposal": {"kind": "type", "detail": "InstallState"}},
            {"class_key": "implicit-state:exclusive-bools", "locus": {"crate": "grdr-agents", "item": "install::Other"},
             "title": "A span that does not match", "label": "LIKELY", "severity": 3,
             "evidence": [{"path": "crates/grdr-agents/src/install.rs", "line": 9, "quote": "pub ghost: bool,"}]},
            {"class_key": "made-up", "locus": {"crate": "grdr-agents", "item": "x"}, "title": "t", "label": "SMELL", "severity": 4,
             "evidence": [{"path": "crates/grdr-agents/src/install.rs", "line": 1, "quote": "pub struct InstallRecord {"}]}
        ],
        "checked_and_sound": [{"item": "install::Uninstall", "reason": "one enum"}]
    })
    .to_string()
}

fn fingerprint() -> String {
    format!(
        "sha256:{}",
        sha256_hex(b"A01|1|implicit-state:exclusive-bools|grdr-agents|install::InstallRecord")
    )
}

fn run_record(temp: &TempRepo) -> Value {
    let runs = temp.root().join(".agent").join("audits");
    let dir = std::fs::read_dir(&runs)
        .unwrap()
        .next()
        .unwrap()
        .unwrap()
        .path();
    serde_json::from_str(&std::fs::read_to_string(dir.join("run.json")).unwrap()).unwrap()
}

#[test]
fn find_check_refute_and_record() {
    let (temp, commit) = repo();
    let fake = FakeProgram::new("audit-claude");
    let verifier = json!({"schema": "audit-finding.v1", "report": "verifier", "fingerprint": fingerprint(), "verdict": "UPHELD", "reason": "The spans match.", "quotes": []});
    fake.writes(1, ".agent/audit-out/finder.json", &finder_report(&commit))
        .respond(1, DONE, 0)
        .writes(
            2,
            ".agent/audit-out/verifier-1-1.json",
            &verifier.to_string(),
        )
        .respond(2, DONE, 0);
    let code = run(&temp.repo(), &runner(&fake), &request(None), false).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let calls = fake.calls();
    assert_eq!(calls.len(), 2, "{calls:?}");
    assert!(
        calls[0].contains("-p --model claude-sonnet-5-5 --max-turns 40 --permission-mode dontAsk")
    );
    assert!(calls[0].contains("--disallowedTools Bash,NotebookEdit,WebFetch,WebSearch"));
    assert!(calls[1].contains("--model claude-opus-5-5 --max-turns 20"));
    let prompt = fake.stdin(1);
    assert!(prompt.starts_with(&format!(
        "You are running read-only audit A01 on the whole repository at commit {commit}"
    )));
    assert!(prompt.contains("Find every lifecycle in the whole repository held in flags."));
    assert!(fake.stdin(2).contains(&fingerprint()));
    let record = run_record(&temp);
    assert_eq!(record["schema"], "audit-run.v1");
    assert_eq!(record["results_returned"], 3);
    assert_eq!(record["results_after_span_check"], 1);
    assert_eq!(record["upheld"], 1);
    assert_eq!(record["finder_model"], "claude-sonnet-5-5");
    assert_eq!(record["verifier_models"], json!(["claude-opus-5-5"]));
    assert_eq!(record["tokens_in"], 200);
    let result = &record["results"][0];
    assert_eq!(result["fingerprint"], fingerprint());
    assert_eq!(result["state"], "upheld");
    assert_eq!(result["security_candidate"], false);
    assert!(
        result["evidence"][0]["snippet_sha256"]
            .as_str()
            .unwrap()
            .starts_with("sha256:")
    );
    assert!(
        !temp
            .root()
            .join(".agent")
            .join("worktrees")
            .read_dir()
            .map(|mut d| d.next().is_some())
            .unwrap_or(false)
    );
}

#[test]
fn a_usage_limit_resumes_the_same_session_and_refuted_results_do_not_survive() {
    let (temp, commit) = repo();
    let fake = FakeProgram::new("audit-limit");
    let refuted = json!({"schema": "audit-finding.v1", "report": "verifier", "fingerprint": fingerprint(), "verdict": "REFUTED", "reason": "A guard covers it.", "quotes": []});
    fake.respond(1, LIMITED, 1)
        .writes(2, ".agent/audit-out/finder.json", &finder_report(&commit))
        .respond(2, DONE, 0)
        .writes(
            3,
            ".agent/audit-out/verifier-1-1.json",
            &refuted.to_string(),
        )
        .respond(3, DONE, 0);
    let head = git::head(&temp.repo()).unwrap().unwrap();
    temp.write(
        "crates/grdr-agents/src/install.rs",
        &format!("{SOURCE}// changed\n"),
    );
    let code = run(&temp.repo(), &runner(&fake), &request(Some(head)), false).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let calls = fake.calls();
    let session = calls[0]
        .split("--session-id ")
        .nth(1)
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_owned();
    assert!(
        calls[1].contains(&format!("--resume {session}")),
        "{calls:?}"
    );
    let record = run_record(&temp);
    assert_eq!(record["scope"]["kind"], "diff");
    assert_eq!(record["upheld"], 0);
    assert_eq!(record["results"][0]["state"], "refuted");
    assert!(fake.stdin(1).contains("the changes since"));
}

#[test]
fn an_empty_diff_scope_is_skipped_and_dry_runs_start_nothing() {
    let (temp, _) = repo();
    let fake = FakeProgram::new("audit-skip");
    let head = git::head(&temp.repo()).unwrap().unwrap();
    assert_eq!(
        run(&temp.repo(), &runner(&fake), &request(Some(head)), false).unwrap(),
        ExitCode::SUCCESS
    );
    assert_eq!(run_record(&temp)["skipped"][0]["reason"], "scope-absent");
    assert_eq!(
        run(&temp.repo(), &runner(&fake), &request(None), true).unwrap(),
        ExitCode::SUCCESS
    );
    assert!(fake.calls().is_empty());
}

#[test]
fn front_matter_and_models_must_agree_with_the_library() {
    let (temp, _) = repo();
    let models = Models::load(&temp.repo()).unwrap();
    temp.write(
        "audits/prompts/A01.md",
        &PROMPT.replace("closes-by: [type]", "closes-by: [test]"),
    );
    let error = Entry::load(&temp.repo(), &Base::Unborn, &models, "A01").unwrap_err();
    assert!(error.to_string().contains("closes-by"), "{error}");
    temp.write("audits/prompts/A01.md", PROMPT);
    temp.write(
        "audits/library.toml",
        &LIBRARY_TOML.replace("finder_model = \"sonnet\"", "finder_model = \"fable\""),
    );
    let error = Entry::load(&temp.repo(), &Base::Unborn, &models, "A01").unwrap_err();
    assert!(error.to_string().contains("allowed_models"));
    temp.write(
        "audits/library.toml",
        &LIBRARY_TOML.replace("max_findings = 15\n", ""),
    );
    let error = Entry::load(&temp.repo(), &Base::Unborn, &models, "A01").unwrap_err();
    assert!(error.to_string().contains("max_findings"), "{error}");
}

#[test]
fn severities_and_quotes_follow_the_schema() {
    let format = check::FindingFormat::parse(FINDING_SCHEMA).unwrap();
    assert_eq!(format.severities, 1..=4);
    let span = |quote: &str| json!({"path": "crates/grdr-agents/src/install.rs", "line": 1, "quote": quote});
    let file_at = |_: &str| Some(SOURCE.to_owned());
    let three = "pub struct InstallRecord {\n    pub probed: bool,\n    pub written: bool,\n";
    assert!(check::span_matches(&span(three), &format.quote, &file_at));
    let four = format!("{three}    pub canary_passed: bool,");
    assert!(!check::span_matches(&span(&four), &format.quote, &file_at));
}
