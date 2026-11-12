use super::*;
use crate::orchestrate::testkit::{git, init_git};
use crate::testkit::{TempRepo, risk_tiers, tier};

/// The tiers of the classifier tests, with the light lane naming eval-diff.
fn tiers() -> String {
    let high = tier(
        "high",
        "[\"proto/**\", \"Cargo.lock\"]",
        "[\"new_dependency\", \"major_bump\", \"unsafe_added\", \"wire_or_pack_format_change\"]",
        "[\"eval-security\", \"cross-model review\"]",
    );
    let medium = tier("medium", "[\"crates/**\"]", "[]", "[\"eval-diff\"]");
    let low = tier(
        "low",
        "[\"docs/**\", \"**/*.md\"]",
        "[\"tests_only_addition\"]",
        "[]",
    );
    risk_tiers(&format!("{high}{medium}{low}"), "[\"eval-diff\"]")
}

fn policy() -> (TempRepo, RiskPolicy, GlobList) {
    let temp = TempRepo::create();
    temp.write(".agents/risk-tiers.toml", &tiers());
    temp.write("security/trust-core.paths", "crates/grdr-crypto/**\n");
    let policy = RiskPolicy::load_at(&temp.repo(), &Base::Unborn).unwrap();
    let protected = GlobList::new(&["**/AGENTS.md", "Cargo.toml"], Case::Insensitive).unwrap();
    (temp, policy, protected)
}

fn change(path: &str, before: Option<&str>, after: Option<&str>) -> FileChange {
    let lines = |text: Option<&str>| {
        text.map(|t| t.lines().map(str::to_owned).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let (old, new) = (lines(before), lines(after));
    FileChange {
        path: path.into(),
        added: new
            .iter()
            .filter(|line| !old.contains(line))
            .cloned()
            .collect(),
        removed: old
            .iter()
            .filter(|line| !new.contains(line))
            .cloned()
            .collect(),
        before: before.map(str::to_owned),
        after: after.map(str::to_owned),
    }
}

fn run(changes: &[FileChange], floor: Option<RiskTier>) -> Assessment {
    let (_temp, policy, protected) = policy();
    let floor = Floor {
        tier: floor,
        lane: None,
    };
    assess(
        &policy,
        &protected,
        changes,
        floor,
        Vec::new(),
        &Base::Unborn,
    )
}

#[test]
fn prose_and_comment_only_changes_take_the_static_lane() {
    let docs = run(
        &[change("docs/guide.md", Some("Old.\n"), Some("New.\n"))],
        None,
    );
    assert_eq!((docs.tier, docs.lane), ("low", Lane::Static));
    let code = "fn a() -> u8 {\n    1\n}\n";
    let commented = "/// Returns one.\nfn a() -> u8 {\n    // the answer\n    1\n}\n";
    let comment = run(
        &[change(
            "crates/grdr-crypto/src/lib.rs",
            Some(code),
            Some(commented),
        )],
        None,
    );
    assert_eq!(
        comment.lane,
        Lane::Full,
        "a trust-core path always takes the full lane"
    );
    assert!(comment.trust_core);
    let ordinary = run(
        &[change("crates/a/src/lib.rs", Some(code), Some(commented))],
        None,
    );
    assert_eq!(ordinary.lane, Lane::Static);
    let protected = run(
        &[change("crates/a/AGENTS.md", Some("x\n"), Some("y\n"))],
        None,
    );
    assert_ne!(protected.lane, Lane::Static);
}

#[test]
fn small_changes_away_from_sensitive_surfaces_are_light() {
    let small = run(
        &[change(
            "crates/a/src/lib.rs",
            Some("fn a() -> u8 { 1 }\n"),
            Some("fn a() -> u8 { 2 }\n"),
        )],
        None,
    );
    assert_eq!((small.tier, small.lane), ("medium", Lane::Light));
    let public = run(
        &[change(
            "crates/a/src/lib.rs",
            Some("fn a() {}\n"),
            Some("pub fn a() {}\n"),
        )],
        None,
    );
    assert_eq!(public.lane, Lane::Standard);
    let big: String = (0..60)
        .map(|i| format!("const C{i}: u8 = {i};\n"))
        .collect();
    let large = run(&[change("crates/a/src/lib.rs", Some(""), Some(&big))], None);
    assert_eq!(large.lane, Lane::Standard);
    let tests = run(
        &[change(
            "crates/a/tests/parse.rs",
            None,
            Some("#[test]\nfn t() {}\n"),
        )],
        None,
    );
    assert_eq!((tests.tier, tests.lane), ("low", Lane::Light));
}

#[test]
fn triggers_and_floors_raise_the_tier_to_full() {
    let unsafe_code = run(
        &[change(
            "crates/a/src/lib.rs",
            Some("fn a() {}\n"),
            Some("fn a() { unsafe { b() } }\n"),
        )],
        None,
    );
    assert_eq!((unsafe_code.tier, unsafe_code.lane), ("high", Lane::Full));
    assert!(
        unsafe_code
            .reasons
            .iter()
            .any(|r| r.starts_with("unsafe_added"))
    );
    let dependency = run(
        &[change(
            "crates/a/Cargo.toml",
            Some("[dependencies]\n"),
            Some("[dependencies]\nregex = \"1\"\n"),
        )],
        None,
    );
    assert_eq!(dependency.tier, "high");
    assert!(
        dependency
            .reasons
            .iter()
            .any(|r| r == "new_dependency: dependencies.regex in crates/a/Cargo.toml")
    );
    let floored = run(
        &[change("docs/guide.md", Some("a\n"), Some("b\n"))],
        Some(RiskTier::High),
    );
    assert_eq!(floored.tier, "high");
    assert_eq!(floored.lane, Lane::Static);
    let floored_code = run(
        &[change(
            "crates/a/src/lib.rs",
            Some("fn a() -> u8 { 1 }\n"),
            Some("fn a() -> u8 { 2 }\n"),
        )],
        Some(RiskTier::High),
    );
    assert_eq!(floored_code.lane, Lane::Full);
    assert!(
        floored_code
            .evidence_required
            .contains(&"cross-model review".to_owned())
    );
}

#[test]
fn changes_come_from_git_against_the_base() {
    let temp = TempRepo::create();
    temp.write("crates/a/src/lib.rs", "fn a() -> u8 {\n    1\n}\n");
    init_git(temp.root());
    temp.write("crates/a/src/lib.rs", "fn a() -> u8 {\n    2\n}\n");
    temp.write("docs/new.md", "# New\n");
    let base = git::resolve_base(&temp.repo()).unwrap();
    let found = changes(&temp.repo(), &base).unwrap();
    let lib = found
        .iter()
        .find(|c| c.path == "crates/a/src/lib.rs")
        .unwrap();
    assert_eq!(lib.added, vec!["    2"]);
    assert_eq!(lib.removed, vec!["    1"]);
    assert!(lib.before.as_deref().unwrap().contains("    1"));
    let new = found.iter().find(|c| c.path == "docs/new.md").unwrap();
    assert_eq!(new.added, vec!["# New"]);
    assert!(new.before.is_none());
    let _ = git(temp.root(), &["status", "--short"]);
}

#[test]
fn removed_lines_that_look_like_headers_stay_content() {
    let diff = "diff --git a/q.sql b/q.sql\n--- a/q.sql\n+++ b/q.sql\n@@ -1 +1 @@\n--- old comment\n+-- new comment\n";
    let parsed = parse_diff(diff);
    assert_eq!(
        parsed["q.sql"],
        (
            vec!["-- new comment".to_owned()],
            vec!["-- old comment".to_owned()]
        )
    );
}

#[test]
fn a_trust_core_lockfile_within_its_majors_is_the_only_static_trust_core_change() {
    let temp = TempRepo::create();
    temp.write(".agents/risk-tiers.toml", &tiers());
    temp.write(
        "security/trust-core.paths",
        "Cargo.lock\ncrates/grdr-crypto/**\n",
    );
    let policy = RiskPolicy::load_at(&temp.repo(), &Base::Unborn).unwrap();
    let protected = GlobList::new(&["Cargo.toml"], Case::Insensitive).unwrap();
    let lock = |version: &str| format!("[[package]]\nname = \"serde\"\nversion = \"{version}\"\n");
    let classify = |changes: &[FileChange]| {
        let floor = Floor {
            tier: None,
            lane: None,
        };
        assess(
            &policy,
            &protected,
            changes,
            floor,
            Vec::new(),
            &Base::Unborn,
        )
    };
    let patch = change("Cargo.lock", Some(&lock("1.0.1")), Some(&lock("1.0.2")));
    let within = classify(std::slice::from_ref(&patch));
    assert!(within.trust_core);
    assert_eq!(within.lane, Lane::Static);
    let major = change("Cargo.lock", Some(&lock("1.0.1")), Some(&lock("2.0.0")));
    assert_eq!(classify(&[major]).lane, Lane::Full);
    let docs = change("crates/grdr-crypto/README.md", Some("a\n"), Some("b\n"));
    assert_eq!(classify(&[patch, docs]).lane, Lane::Full);
}

#[test]
fn lockfiles_within_their_majors_are_static_and_lanes_only_rise() {
    let temp = TempRepo::create();
    temp.write(".agents/risk-tiers.toml", &tiers());
    let policy = RiskPolicy::load_at(&temp.repo(), &Base::Unborn).unwrap();
    let protected = GlobList::new(&["Cargo.toml"], Case::Insensitive).unwrap();
    let lock = |version: &str| format!("[[package]]\nname = \"serde\"\nversion = \"{version}\"\n");
    let classify = |changes: &[FileChange], lane: Option<Lane>| {
        let floor = Floor { tier: None, lane };
        assess(
            &policy,
            &protected,
            changes,
            floor,
            Vec::new(),
            &Base::Unborn,
        )
    };
    let patch = change("Cargo.lock", Some(&lock("1.0.1")), Some(&lock("1.0.2")));
    assert_eq!(
        classify(std::slice::from_ref(&patch), None).lane,
        Lane::Static
    );
    let major = change("Cargo.lock", Some(&lock("1.0.1")), Some(&lock("2.0.0")));
    assert_eq!(classify(&[major], None).lane, Lane::Full);
    let generated = change("gen/out.rs", Some("a\n"), Some("b\n"));
    assert_eq!(classify(&[generated], None).lane, Lane::Static);
    let raised = classify(std::slice::from_ref(&patch), Some(Lane::Standard));
    assert_eq!(raised.lane, Lane::Standard);
    assert!(
        raised
            .reasons
            .iter()
            .any(|r| r == "lane raised from static to standard")
    );
    let full = change("proto/a.proto", Some("a\n"), Some("b\n"));
    assert_eq!(classify(&[full], Some(Lane::Light)).lane, Lane::Full);
    assert_eq!(Lane::parse("light"), Some(Lane::Light));
    assert_eq!(Lane::parse("fast"), None);
}

#[test]
fn a_runtime_trust_core_path_adds_its_trigger_evaluators_and_a_kit_path_does_not() {
    let temp = TempRepo::create();
    let tiers = tiers()
        .replace(
            "distinct_models = 2
[high]",
            "distinct_models = 2
runtime_paths = [\"crates/**\"]
[high]",
        )
        .replace(
            "[trigger_evaluators]
",
            "[trigger_evaluators]
runtime_trust_core = [\"eval-platform\"]
",
        );
    temp.write(".agents/risk-tiers.toml", &tiers);
    temp.write(
        "security/trust-core.paths",
        "crates/grdr-crypto/**
xtask/**
",
    );
    let policy = RiskPolicy::load_at(&temp.repo(), &Base::Unborn).unwrap();
    let protected = GlobList::new(&["Cargo.toml"], Case::Insensitive).unwrap();
    let judged = |path: &str| {
        let changes = [change(
            path,
            Some(
                "a
",
            ),
            Some(
                "b
",
            ),
        )];
        assess(
            &policy,
            &protected,
            &changes,
            Floor::default(),
            Vec::new(),
            &Base::Unborn,
        )
    };
    let runtime = judged("crates/grdr-crypto/src/lib.rs");
    assert!(
        runtime.triggers.contains(&"runtime_trust_core".to_owned()),
        "{runtime:?}"
    );
    assert!(
        runtime
            .evidence_required
            .contains(&"eval-platform".to_owned()),
        "{runtime:?}"
    );
    let kit = judged("xtask/src/main.rs");
    assert!(kit.trust_core && kit.lane == Lane::Full, "{kit:?}");
    assert!(
        !kit.evidence_required.contains(&"eval-platform".to_owned()),
        "{kit:?}"
    );
}
