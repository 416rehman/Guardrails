//! The package-manager gate (owner instruction 24): pnpm is the only JavaScript package manager.
//! It fails on another manager's lockfile anywhere in the tree, on a `package.json` whose
//! `packageManager` or `devEngines.packageManager` names anything but pnpm, and on an npm or npx
//! call in a `package.json` script or a `run` step under `.github/workflows/`. The tree is every
//! tracked file and every untracked one git does not ignore.

use anyhow::Result;
use serde_json::Value;

use super::{Context, Outcome};
use crate::git;
use crate::repo::Repo;

const FOREIGN_LOCKFILES: &[&str] = &[
    "package-lock.json",
    "npm-shrinkwrap.json",
    "yarn.lock",
    "bun.lockb",
    "bun.lock",
];
const MANIFEST: &str = "package.json";
const MANAGER: &str = "pnpm";
const FOREIGN_PROGRAMS: &[&str] = &["npm", "npx"];
const SHELL_WORD_BREAKS: &str = ";&|()`$\"'{}";
const WORKFLOWS: &str = ".github/workflows/";
const WORKFLOW_EXTENSIONS: &[&str] = &[".yml", ".yaml"];
const RUN_KEY: &str = "run:";
const BLOCK_SCALARS: &[char] = &['|', '>'];

pub fn gate(context: &Context) -> Result<Outcome> {
    let files = tree_files(&context.repo)?;
    let mut problems = Vec::new();
    let mut scanned = 0_usize;
    for path in &files {
        let name = path.rsplit('/').next().unwrap_or(path);
        if FOREIGN_LOCKFILES.contains(&name) {
            problems.push(format!(
                "{path} is another package manager's lockfile; delete it and run pnpm install, which writes pnpm-lock.yaml"
            ));
        }
        let is_workflow = path.starts_with(WORKFLOWS)
            && WORKFLOW_EXTENSIONS.iter().any(|ext| path.ends_with(ext));
        if name != MANIFEST && !is_workflow {
            continue;
        }
        let Some(text) = context.repo.read_optional(path)? else {
            continue;
        };
        scanned += 1;
        if is_workflow {
            problems.extend(workflow_problems(path, &text));
        } else {
            problems.extend(manifest_problems(path, &text));
        }
    }
    if problems.is_empty() && scanned == 0 {
        return Ok(Outcome::skip("no package.json and no workflow"));
    }
    Ok(Outcome::from_problems(problems))
}

fn tree_files(repo: &Repo) -> Result<Vec<String>> {
    let listed = git::output(
        repo,
        &[
            "ls-files",
            "--cached",
            "--others",
            "--exclude-standard",
            "-z",
        ],
    )?;
    Ok(listed
        .split('\0')
        .filter(|path| !path.is_empty())
        .map(str::to_owned)
        .collect())
}

/// A manifest that names another manager, or a script that runs npm or npx.
fn manifest_problems(path: &str, text: &str) -> Vec<String> {
    let value: Value = match serde_json::from_str(text) {
        Ok(value) => value,
        Err(error) => return vec![format!("{path} is not JSON: {error}")],
    };
    let mut problems = Vec::new();
    let declared = [
        ("packageManager", value.get("packageManager")),
        (
            "devEngines.packageManager",
            value.pointer("/devEngines/packageManager/name"),
        ),
    ];
    for (key, found) in declared {
        let Some(found) = found else { continue };
        if !names_pnpm(found.as_str().unwrap_or_default()) {
            problems.push(format!(
                "{path}: `{key}` is {found}; it names {MANAGER}, as `{MANAGER}@<version>`"
            ));
        }
    }
    let scripts = value
        .get("scripts")
        .and_then(Value::as_object)
        .into_iter()
        .flatten();
    for (name, script) in scripts {
        if let Some(program) = script.as_str().and_then(foreign_program) {
            problems.push(format!(
                "{path}: script `{name}` runs {program}; use {MANAGER} (pnpm run, pnpm exec, pnpm dlx)"
            ));
        }
    }
    problems
}

/// Every `run` step of a workflow, one line or a block, that calls npm or npx.
fn workflow_problems(path: &str, text: &str) -> Vec<String> {
    let mut problems = Vec::new();
    let mut block: Option<usize> = None;
    for (index, line) in text.lines().enumerate() {
        let indent = line.len() - line.trim_start().len();
        let trimmed = line.trim_start().trim_start_matches("- ");
        let command = match block {
            Some(run_indent) if line.trim().is_empty() || indent > run_indent => line,
            _ => {
                block = None;
                let Some(value) = trimmed.strip_prefix(RUN_KEY).map(str::trim) else {
                    continue;
                };
                if value.starts_with(BLOCK_SCALARS) {
                    block = Some(indent);
                    continue;
                }
                value
            }
        };
        if let Some(program) = foreign_program(command) {
            problems.push(format!(
                "{path}:{}: a run step calls {program}; install with pnpm install --frozen-lockfile and run with pnpm",
                index + 1
            ));
        }
    }
    problems
}

/// `pnpm` or `pnpm@<version>`.
fn names_pnpm(value: &str) -> bool {
    value == MANAGER
        || value
            .strip_prefix(MANAGER)
            .is_some_and(|rest| rest.starts_with('@'))
}

/// The first word of `command` that runs npm or npx, as a program or through a path.
fn foreign_program(command: &str) -> Option<&'static str> {
    command
        .split(|c: char| c.is_whitespace() || SHELL_WORD_BREAKS.contains(c))
        .filter(|word| !word.is_empty())
        .find_map(|word| {
            let program = word.rsplit(['/', '\\']).next().unwrap_or(word);
            let program = program.strip_suffix(".cmd").unwrap_or(program);
            FOREIGN_PROGRAMS
                .iter()
                .find(|foreign| **foreign == program)
                .copied()
        })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn manifests_name_pnpm_and_scripts_never_call_npm() {
        let good = r#"{"packageManager": "pnpm@10.20.0", "devEngines": {"packageManager": {"name": "pnpm", "onFail": "error"}}, "scripts": {"build": "pnpm -r build", "lint": "oxlint && pnpm exec tsc"}}"#;
        assert!(manifest_problems("package.json", good).is_empty());
        let bad = r#"{"packageManager": "yarn@4.0.0", "scripts": {"setup": "npm ci", "gen": "cd x && npx tsc", "ok": "npm-run-all"}}"#;
        assert_eq!(manifest_problems("web/package.json", bad).len(), 3);
        assert_eq!(manifest_problems("p.json", "{").len(), 1);
    }

    #[test]
    fn workflow_run_steps_are_scanned() {
        let workflow = "name: npm audit\njobs:\n  web:\n    steps:\n      - run: pnpm install --frozen-lockfile\n      - name: build\n        run: |\n          pnpm -r build\n          ./node_modules/.bin/npx vite\n        env:\n          NPM: npm\n      - run: npm test\n";
        let problems = workflow_problems(".github/workflows/web.yml", workflow);
        assert_eq!(problems.len(), 2, "{problems:#?}");
        assert!(problems[0].contains(":9:"));
        assert!(problems[1].contains(":12:"));
    }

    #[test]
    fn programs_are_whole_words() {
        assert_eq!(foreign_program("npm install"), Some("npm"));
        assert_eq!(foreign_program("FOO=1 npx tsc"), Some("npx"));
        assert_eq!(foreign_program("C:\\node\\npm.cmd ci"), Some("npm"));
        assert_eq!(foreign_program("pnpm install && pnpm-lock check"), None);
        assert!(names_pnpm("pnpm@10.20.0"));
        assert!(!names_pnpm("pnpmx@1"));
    }
}
