//! `cargo xtask hooks-selftest` (team/03 section 4.2, V18): fires every handler against fixtures in
//! `xtask/fixtures/hooks/` inside a throwaway git repository, from a working directory outside it,
//! and fails if a blocking handler does not block or an allowed case is blocked. The fixtures cover
//! the Windows backslash path, the working directory outside the repository, the large payload, the
//! forced timeout, the missing item snapshot, a fable session for a non-architect, a chief-architect
//! resume that must carry the ownership sentence, the oversized and ill-ordered source files, the
//! three-bool struct, and each command the deny list of team/03 section 4.1 names, plus the
//! owner's kit rules in `rule_cases.rs`.

pub(super) mod cases;
mod harness;
mod rule_cases;

use std::process::ExitCode;

use crate::cli::{self, Spec};

/// Gate V18: the self-test's failures, for `verify`.
pub fn problems() -> anyhow::Result<Vec<String>> {
    Ok(harness::run(None, false)?.failures().to_vec())
}

pub fn run(args: &[&str]) -> ExitCode {
    let owned: Vec<String> = args.iter().map(|arg| (*arg).to_string()).collect();
    let parsed = match cli::parse(
        &owned,
        &Spec {
            flags: &["--verbose", "-v"],
            options: &["--only"],
        },
    ) {
        Ok(parsed) => parsed,
        Err(error) => {
            eprintln!("hooks-selftest: {error:#}");
            return ExitCode::from(1);
        }
    };
    let verbose = parsed.has("--verbose") || parsed.has("-v");
    let only = parsed.value("--only");
    match harness::run(only, verbose) {
        Ok(report) => {
            print!("{}", report.summary());
            if report.failed() {
                ExitCode::from(2)
            } else {
                ExitCode::SUCCESS
            }
        }
        Err(error) => {
            eprintln!("hooks-selftest could not run: {error:#}");
            ExitCode::from(1)
        }
    }
}
