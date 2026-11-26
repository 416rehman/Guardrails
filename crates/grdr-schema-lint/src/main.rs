// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! CLI entrypoint supporting `check`, `regenerate`, `capture --check`, `registry --check`, `compare`, and `manifests`.
#![deny(clippy::arithmetic_side_effects)]

use std::collections::BTreeSet;
use std::env;
use std::path::PathBuf;
use std::process::ExitCode;

use grdr_schema_lint::{
    LintReport, check_capture_only, check_manifests, check_registry_only, compare_roots,
    lint_repo_root, regenerate_schema_artifacts,
};

fn main() -> ExitCode {
    let args: Vec<String> = env::args().skip(1).collect();
    let Ok(root) = env::current_dir() else {
        eprintln!("GRDR-LINT-0001: unable to resolve current working directory");
        return ExitCode::from(2);
    };
    let Some((cmd, tail)) = args.split_first() else {
        return handle_report("check", lint_repo_root(&root));
    };
    match cmd.as_str() {
        "check" if tail.is_empty() => handle_report("check", lint_repo_root(&root)),
        "regenerate" if tail.is_empty() => match regenerate_schema_artifacts(&root) {
            Ok(ctx) => {
                println!(
                    "regenerated fields.json, registry.rs, capture.rs ({} fields)",
                    ctx.fields.len()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("{err}");
                ExitCode::from(2)
            }
        },
        "capture" if matches!(tail, [f] if f == "--check") => {
            handle_report("capture", check_capture_only(&root))
        }
        "registry" if matches!(tail, [f] if f == "--check") => {
            handle_report("registry", check_registry_only(&root))
        }
        "manifests" if tail.is_empty() => match check_manifests(&root) {
            Ok(pins) => {
                println!(
                    "grdr-schema-lint: manifests clean ({} foreign pins)",
                    pins.len()
                );
                ExitCode::SUCCESS
            }
            Err(err) => {
                eprintln!("{err}");
                ExitCode::from(2)
            }
        },
        "compare" => run_compare(tail),
        _ => {
            eprintln!(
                "usage: grdr-schema-lint <check|regenerate|capture --check|registry --check|compare --base DIR --head DIR [--accepted-rfcs CSV]|manifests>"
            );
            ExitCode::from(2)
        }
    }
}

fn handle_report(label: &str, res: Result<LintReport, grdr_schema_lint::LintError>) -> ExitCode {
    match res {
        Ok(report) if report.is_clean() => {
            println!(
                "grdr-schema-lint ({label}): clean ({} proto, {} cedar, {} vocab)",
                report.proto_files_checked, report.cedar_files_checked, report.vocab_terms_checked
            );
            ExitCode::SUCCESS
        }
        Ok(report) => {
            for f in &report.findings {
                eprintln!("{} {}: {}", f.code, f.target, f.message);
            }
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}

fn run_compare(args: &[String]) -> ExitCode {
    let mut base: Option<PathBuf> = None;
    let mut head: Option<PathBuf> = None;
    let mut seen_rfcs = false;
    let mut rfcs = BTreeSet::new();
    let mut idx = 0usize;
    while let Some(flag) = args.get(idx) {
        let Some(val) = args.get(idx.saturating_add(1)) else {
            eprintln!("missing value for `{flag}`");
            return ExitCode::from(2);
        };
        match flag.as_str() {
            "--base" => {
                if base.is_some() {
                    eprintln!("duplicate `--base` flag");
                    return ExitCode::from(2);
                }
                base = Some(PathBuf::from(val));
            }
            "--head" => {
                if head.is_some() {
                    eprintln!("duplicate `--head` flag");
                    return ExitCode::from(2);
                }
                head = Some(PathBuf::from(val));
            }
            "--accepted-rfcs" => {
                if seen_rfcs {
                    eprintln!("duplicate `--accepted-rfcs` flag");
                    return ExitCode::from(2);
                }
                seen_rfcs = true;
                for r in val.split(',').map(str::trim).filter(|s| !s.is_empty()) {
                    rfcs.insert(r.to_owned());
                }
            }
            other => {
                eprintln!("unknown compare flag `{other}`");
                return ExitCode::from(2);
            }
        }
        idx = idx.saturating_add(2);
    }
    let (Some(b), Some(h)) = (base, head) else {
        eprintln!("compare requires --base <dir> --head <dir>");
        return ExitCode::from(2);
    };
    match compare_roots(&b, &h, &rfcs) {
        Ok(report) if report.findings.is_empty() => {
            println!("grdr-schema-lint (compare): compatible");
            ExitCode::SUCCESS
        }
        Ok(report) => {
            for f in &report.findings {
                eprintln!("{} {}: {}", f.code, f.target, f.message);
            }
            ExitCode::from(1)
        }
        Err(err) => {
            eprintln!("{err}");
            ExitCode::from(2)
        }
    }
}
