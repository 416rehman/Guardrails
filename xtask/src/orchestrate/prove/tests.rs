use super::*;
use crate::orchestrate::testkit::{FakeProgram, init_git};
use crate::testkit::TempRepo;

/// The test-count pattern of `.agents/harness.toml [prove]`.
const CARGO_COUNT: &str = r"running (\d+) tests?";

fn config(fake: &FakeProgram) -> ProveConfig {
    ProveConfig {
        command: vec![
            fake.program().to_string_lossy().into_owned(),
            "{test}".into(),
        ],
        count_regex: r"ran (\d+) tests".into(),
        test_paths: vec!["**/tests/**".into(), "**/tests.rs".into()],
    }
}

#[test]
fn the_repository_harness_names_the_proof() {
    let text = std::fs::read_to_string(
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../.agents/harness.toml"),
    )
    .unwrap();
    let file: ProveFile = crate::config::parse_toml(&text, HARNESS_FILE).unwrap();
    assert!(
        file.prove
            .command
            .iter()
            .any(|word| word == TEST_PLACEHOLDER)
    );
    assert!(file.prove.test_paths.contains(&"**/tests.rs".to_owned()));
    let temp = TempRepo::create();
    temp.write(HARNESS_FILE, "[github]\nrepository = \"o/n\"\n");
    assert!(ProveConfig::load(&temp.repo()).is_err());
}

#[test]
fn three_arms_land_in_one_proof_the_stop_gate_reads() {
    let temp = TempRepo::create();
    temp.write(".gitignore", ".agent/\n");
    temp.write("crates/a/src/lib.rs", "pub fn a() -> u8 { 1 }\n");
    init_git(temp.root());
    temp.write(
        "crates/a/tests/a.rs",
        "#[test]\nfn two() { assert_eq!(a::a(), 2); }\n",
    );
    let fake = FakeProgram::new("prove-test");
    fake.respond(1, "ran 1 tests\nFAILED\n", 101)
        .respond(2, "ran 1 tests\nok\n", 0)
        .respond(3, "ran 1 tests\nFAILED\n", 101);
    let repo = temp.repo();
    let base = git::resolve_base(&repo).unwrap();
    let config = config(&fake);
    let before = prove(&repo, &config, Arm::Before, Some("two"), &base, Some(7)).unwrap();
    assert!(before.arms.fails_before.as_ref().unwrap().holds);
    assert!(!before.holds);
    temp.write("crates/a/src/lib.rs", "pub fn a() -> u8 { 2 }\n");
    let after = prove(&repo, &config, Arm::After, None, &base, Some(7)).unwrap();
    assert!(after.arms.passes_after.as_ref().unwrap().holds);
    let revert = prove(&repo, &config, Arm::Revert, None, &base, Some(7)).unwrap();
    assert!(revert.holds, "{revert:#?}");
    assert_eq!(revert.tree_digest, git::tree_digest(&repo).unwrap());
    assert!(fake.calls().iter().all(|call| call.trim() == "two"));
    let text = std::fs::read_to_string(repo.path(EVIDENCE)).unwrap();
    let value: serde_json::Value = serde_json::from_str(&text).unwrap();
    assert_eq!(value["arms"]["fails_before"]["exit"], 101);
    assert_eq!(value["arms"]["passes_after"]["exit"], 0);
    assert_eq!(value["arms"]["fails_on_revert"]["exit"], 101);
    assert!(
        repo.path(&format!(".agent/evidence/{}.json", revert.id))
            .is_file()
    );
    assert!(
        !std::env::temp_dir()
            .join(format!("xtask-prove-{}", std::process::id()))
            .exists()
    );
}

#[test]
fn an_arm_that_runs_no_test_does_not_hold_and_edits_drop_stale_arms() {
    assert!(!Arm::After.holds(0, Some(0)));
    assert!(Arm::After.holds(0, None));
    assert!(!Arm::Before.holds(0, Some(3)));
    assert!(!Arm::Revert.holds(1, Some(0)));
    assert_eq!(
        count_tests(
            CARGO_COUNT,
            "running 2 tests\nrunning 0 tests\nrunning 1 test\n"
        ),
        Some(3)
    );
    assert_eq!(count_tests(CARGO_COUNT, "error: could not compile"), None);
    let result = |digest: &str| ArmResult {
        cmd: "t".into(),
        exit: 0,
        tests: Some(1),
        holds: true,
        tree_digest: digest.into(),
        log: "l".into(),
        sha256: "s".into(),
        at: "a".into(),
    };
    let mut arms = Arms::default();
    arms.set(Arm::Before, result("one"));
    arms.set(Arm::After, result("two"));
    arms.set(Arm::Revert, result("three"));
    assert!(arms.passes_after.is_none());
    assert!(arms.fails_before.is_some());
}

#[test]
fn the_revert_arm_needs_a_base_commit() {
    let temp = TempRepo::create();
    let fake = FakeProgram::new("prove-unborn");
    let error = prove(
        &temp.repo(),
        &config(&fake),
        Arm::Revert,
        Some("t"),
        &Base::Unborn,
        None,
    )
    .unwrap_err();
    assert!(error.to_string().contains("needs a base commit"));
}
