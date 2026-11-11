use super::*;
use crate::orchestrate::issue::acceptance;
use crate::orchestrate::records::{Record, records};
use crate::orchestrate::testkit::{MemoryTracker, body, issue};
use crate::testkit::{TempRepo, plain_tiers, risk_tiers};

const LABELS: &str = "[[group]]\nprefix = \"tier:\"\ncount = \"one-when-ready\"\n[[group]]\nprefix = \"agent:\"\ncount = \"one-when-ready\"\n[[transition]]\nfrom = \"proposed\"\nto = \"ready\"\nby = [\"kit\"]\nrun_by = [\"lead-*\", \"product-lead\", \"programme-manager\"]\n";
const NAMES: &[&str] = &[
    "status:proposed",
    "status:ready",
    "tier:low",
    "tier:medium",
    "tier:high",
    "trust-core",
    "kind:feature",
    "squad:core",
    "size:S",
    "agent:impl-rust",
];
const JSON_CRITERIA: &str = "```json\n{\"criteria\": [{\"id\": \"AC-1\", \"check\": \"cargo test -p a\", \"expect\": \"exit 0\", \"oracle\": \"bash under exec tracing\"}]}\n```";

fn repo() -> TempRepo {
    let temp = TempRepo::create();
    let mut labels = LABELS.to_owned();
    for name in NAMES {
        labels.push_str(&format!(
            "[[label]]\nname = \"{name}\"\ncolor = \"ededed\"\ndescription = \"x\"\n"
        ));
    }
    temp.write(".github/labels.toml", &labels);
    let tiers = plain_tiers("[\"proto/**\"]", "[\"crates/**\"]", "[]");
    temp.write(".agents/risk-tiers.toml", &risk_tiers(&tiers, "[]"));
    temp.write("security/trust-core.paths", "crates/grdr-crypto/**\n");
    temp
}

fn tracker(labels: &[&str], write_set: &[&str], criteria: &str) -> MemoryTracker {
    let tracker = MemoryTracker::default();
    tracker.add(issue(21, labels, &body("impl-rust", write_set, criteria)));
    tracker
}

#[test]
fn a_lead_readies_a_proposed_issue_with_labels_and_the_digest() {
    let temp = repo();
    let tracker = tracker(
        &["status:proposed", "tier:low"],
        &["crates/grdr-core/src/**"],
        JSON_CRITERIA,
    );
    let code = ready(&temp.repo(), &tracker, 21, "lead-core", false).unwrap();
    assert_eq!(code, ExitCode::SUCCESS);
    let after = tracker.snapshot(21);
    assert_eq!(after.status(), Some(ItemStatus::Ready));
    for label in [
        "kind:feature",
        "squad:core",
        "size:S",
        "agent:impl-rust",
        "tier:medium",
    ] {
        assert!(after.has_label(label), "{label}: {:?}", after.labels);
    }
    assert!(!after.has_label("tier:low"));
    assert!(!after.has_label("status:proposed"));
    let digest = acceptance(&after.body).unwrap().sha256;
    let write_set = after.work_item().write_set_sha256();
    let found = records(&after);
    assert!(
        matches!(&found[..], [Record::Ready(ready)] if ready.by == "lead-core" && ready.acceptance_sha256 == digest && ready.write_set_sha256 == write_set)
    );
    assert!(after.comments[0].body.starts_with(&format!(
        "Ready: acceptance criteria sha256 `{digest}`, readied by lead-core."
    )));
}

#[test]
fn the_implementer_and_unknown_roles_cannot_ready() {
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let labels = LabelsFile::load(&temp.repo()).unwrap();
    let proposed = issue(
        21,
        &["status:proposed"],
        &body("impl-rust", &["crates/a/**"], JSON_CRITERIA),
    );
    let problems = plan(&kit, &labels, &proposed, "impl-rust", false).unwrap_err();
    assert!(problems.iter().any(|p| p.contains("may not ready")));
    let own = issue(
        21,
        &["status:proposed"],
        &body("lead-core", &["crates/a/**"], JSON_CRITERIA),
    );
    let problems = plan(&kit, &labels, &own, "lead-core", false).unwrap_err();
    assert!(problems.iter().any(|p| p.contains("never implements it")));
    assert!(plan(&kit, &labels, &proposed, "chief-architect", true).is_err());
    temp.write(
        ".agents/kit/seed-scope.toml",
        "agent = \"chief-architect\"
scope = \"seed\"
branch = \"agent/seed\"
paths = []
acts_as = [\"programme-manager\", \"lead-*\"]
",
    );
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    assert!(plan(&kit, &labels, &proposed, "chief-architect", true).is_ok());
    assert!(plan(&kit, &labels, &proposed, "chief-architect", false).is_err());
    assert!(
        labels
            .may_ready("chief-architect", kit.acting_as("chief-architect"))
            .unwrap(),
        "the dispatcher accepts what the seed session readied"
    );
}

#[test]
fn criteria_need_named_oracles_and_protected_write_sets_are_refused() {
    assert!(criteria_problems(JSON_CRITERIA).is_empty());
    assert!(criteria_problems("AC-1 | cargo test | exit 0 | oracle: bash").is_empty());
    assert_eq!(criteria_problems("AC-1 | cargo test | exit 0").len(), 1);
    let missing = criteria_problems(
        "```json\n{\"criteria\": [{\"id\": \"AC-1\", \"check\": \"x\", \"expect\": \"y\"}]}\n```",
    );
    assert_eq!(missing, vec!["acceptance criterion 1 has no `oracle`"]);
    let temp = repo();
    let kit = LaunchKit::load(&temp.repo()).unwrap();
    let labels = LabelsFile::load(&temp.repo()).unwrap();
    let protected = issue(
        21,
        &["status:proposed"],
        &body("impl-rust", &["Cargo.toml"], JSON_CRITERIA),
    );
    let problems = plan(&kit, &labels, &protected, "lead-core", false).unwrap_err();
    assert!(
        problems.iter().any(|p| p.contains("protected path")),
        "{problems:?}"
    );
    let trust = issue(
        21,
        &["status:proposed"],
        &body("impl-rust", &["crates/grdr-crypto/src/**"], JSON_CRITERIA),
    );
    let readying = plan(&kit, &labels, &trust, "lead-core", false).unwrap();
    assert!(readying.edit.add.contains(&"trust-core".to_owned()));
    let ready_already = issue(
        21,
        &["status:ready"],
        &body("impl-rust", &["crates/a/**"], JSON_CRITERIA),
    );
    assert!(plan(&kit, &labels, &ready_already, "lead-core", false).is_err());
}
