use std::fs;
use std::path::{Path, PathBuf};

use super::rules::{RemovedGate, RequiredFile, Rules};
use super::*;
use crate::testkit::TempRepo;

const FIXTURES: &str = "fixtures/governance";
/// A fixture case's list of repository files to delete, one path per line.
const ABSENT: &str = "absent.txt";

fn checkout() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// A temporary tree holding the repository's own governance files, rules and brand manifest,
/// with fixture `case` laid over it: its files replace the copies and `absent.txt` deletes some.
fn tree(case: Option<&str>) -> TempRepo {
    let temp = TempRepo::create();
    let source = checkout();
    let copy = |path: &str| temp.write(path, &fs::read_to_string(source.join(path)).unwrap());
    copy(RULES_PATH);
    copy(BRAND_PATH);
    let rules = Rules::at(&temp.repo(), &Base::Unborn).unwrap();
    rules.files.iter().for_each(|file| copy(&file.path));
    let Some(case) = case else {
        return temp;
    };
    let overlay = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join(FIXTURES)
        .join(case);
    for entry in fs::read_dir(&overlay).unwrap() {
        let path = entry.unwrap().path();
        let name = path.file_name().unwrap().to_str().unwrap().to_owned();
        let text = fs::read_to_string(&path).unwrap();
        if name == ABSENT {
            text.lines()
                .for_each(|absent| fs::remove_file(temp.repo().path(absent)).unwrap());
        } else {
            temp.write(&name, &text);
        }
    }
    temp
}

fn found(case: Option<&str>) -> Vec<String> {
    let temp = tree(case);
    problems(&temp.repo(), &Base::Unborn).unwrap()
}

#[test]
fn the_repository_governance_files_pass() {
    assert_eq!(found(None), Vec::<String>::new());
}

#[test]
fn a_tree_without_the_covenant_fails() {
    assert_eq!(
        found(Some("missing-covenant")),
        vec!["COVENANT.md: missing; design/30 sections 13 to 16 give its content"]
    );
}

#[test]
fn a_governance_file_without_its_succession_section_fails() {
    assert_eq!(
        found(Some("no-succession")),
        vec!["GOVERNANCE.md: no `## Succession` section"]
    );
}

#[test]
fn a_bot_in_maintainers_fails() {
    assert_eq!(
        found(Some("bot-maintainer")),
        vec![
            "MAINTAINERS.md: `dependabot[bot]` is a bot or agent handle; only people hold an entry (D-61)"
        ]
    );
}

#[test]
fn a_roster_agent_in_maintainers_fails() {
    assert_eq!(
        found(Some("agent-maintainer")),
        vec![
            "MAINTAINERS.md: `Chief-Architect` is a bot or agent handle; only people hold an entry (D-61)"
        ]
    );
}

#[test]
fn a_removed_human_gate_or_a_missing_product_name_fails() {
    let file = RequiredFile {
        path: "AI_POLICY.md".into(),
        sections: vec!["The rules".into()],
    };
    let gates = vec![RemovedGate {
        phrase: "owner approval".into(),
        removed: "the owner approves nothing that lands".into(),
    }];
    let text = "# AI policy\n\nGuardrails ADR\n\n## The rules\n\nHigh-tier changes wait for Owner Approval.\n";
    assert_eq!(
        file_problems(&file, text, "Guardrails ADR", &gates),
        vec![
            "AI_POLICY.md:7: names the removed human gate `owner approval`; the owner approves nothing that lands"
        ]
    );
    assert_eq!(
        file_problems(&file, text, "Other Product", &[]),
        vec!["AI_POLICY.md: never names the product `Other Product` that brand/brand.toml gives"]
    );
}

#[test]
fn maintainers_without_a_block_or_with_an_unnamed_entry_fail() {
    let rules = Rules::at(&tree(None).repo(), &Base::Unborn)
        .unwrap()
        .maintainers;
    let agents = BTreeSet::new();
    assert_eq!(
        maintainer_problems("# Maintainers\n", &rules, &agents),
        vec!["MAINTAINERS.md: no ```toml block with the [[maintainer]] entries"]
    );
    let unnamed =
        "```toml\n[[maintainer]]\nname = \"\"\nhandle = \"someone\"\naffiliation = \"\"\n```\n";
    assert_eq!(
        maintainer_problems(unnamed, &rules, &agents),
        vec!["MAINTAINERS.md: `someone` needs a name and a declared affiliation"]
    );
    let empty = "```toml\n```\n";
    assert_eq!(
        maintainer_problems(empty, &rules, &agents),
        vec!["MAINTAINERS.md: lists no maintainer"]
    );
}
