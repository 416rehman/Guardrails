//! S6, S7 and the interface checks over the kit's own source as a corpus: every file lexes and
//! is judged without a panic, the checks' own modules are clean under the repository's real brand
//! and vendor names, and S7 in Rust reports only the kinds Rust can hold.

use std::path::Path;

use super::{Check, Names, Policy, analyse};
use crate::git::{AddedLines, Base};
use crate::paths::RepoPath;
use crate::repo::{Repo, walk_files};

const OWN_MODULES: &[&str] = &["xtask/src/gates/structure/", "xtask/src/gates/interface/"];
const RUST_KINDS: &[&str] = &[
    "holds the bound",
    "is a bound written",
    "literal `",
    "brand name",
    "vendor name",
];

fn corpus() -> (Repo, Vec<RepoPath>) {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf();
    let repo = Repo::at(&root);
    let mut paths = Vec::new();
    for dir in ["xtask/src", ".agents/kit/workflows"] {
        for file in walk_files(&root.join(dir)).unwrap() {
            paths.extend(repo.relative(&file).filter(super::applies_to));
        }
    }
    (repo, paths)
}

#[test]
fn the_kit_source_is_judged_and_its_checks_are_clean() {
    let (repo, paths) = corpus();
    assert!(
        paths.len() > 50,
        "the corpus is the kit source, {} files",
        paths.len()
    );
    let mut policy = Policy::for_tests();
    policy.names = Names::load(&repo, &Base::Unborn).unwrap();
    let mut own = Vec::new();
    for path in &paths {
        let text = std::fs::read_to_string(repo.path(path.as_str())).unwrap();
        let findings = analyse(path, &text, &AddedLines::All, &policy);
        for finding in &findings {
            let panic_or_value = matches!(finding.check, Check::S6 | Check::S7);
            if panic_or_value && OWN_MODULES.iter().any(|dir| path.as_str().starts_with(dir)) {
                own.push(finding.to_string());
            }
            if finding.check == Check::S7 && path.extension() == Some("rs") {
                assert!(
                    RUST_KINDS.iter().any(|kind| finding.message.contains(kind)),
                    "{finding}"
                );
            }
        }
    }
    assert!(own.is_empty(), "{own:#?}");
}
