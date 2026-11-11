//! Shell commands as `guard-command` judges them: every simple command reduced to the program it
//! runs, its arguments, its environment assignments and its redirections. Wrappers (`env`, `sudo`,
//! `timeout`, `xargs`, `npx`) are unwrapped and nested shells (`bash -c`, `pwsh -Command`, `cmd /c`,
//! `eval`) and command substitutions are scanned as commands of their own.

mod dialect;
mod lexer;
mod nested;
mod scan;

pub use lexer::{Dialect, Redirect, RedirectKind, Resolve, Word};
use nested::nested_source;

const SKIPPED_KEYWORDS: &[&str] = &[
    "!", "{", "}", "then", "do", "else", "elif", "if", "while", "until", "time",
];
const NON_COMMANDS: &[&str] = &[
    "for", "select", "case", "function", "done", "fi", "esac", "in", "[[", "]]",
];
const EXPORTERS: &[&str] = &["export", "declare", "typeset", "local", "readonly"];
const SUFFIXES: &[&str] = &[".exe", ".cmd", ".bat", ".com"];

/// The variables the scanner may substitute and how deep it reads: nested shells and nested
/// command substitutions, each beyond its bound an opaque command.
#[derive(Clone, Copy)]
pub struct Reading<'a> {
    pub resolve: Resolve<'a>,
    pub nested_shells: usize,
    pub substitutions: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Program {
    /// The lowercase base name, without a Windows executable suffix.
    Named(String),
    /// The program word depends on an expansion, or a nested command cannot be read.
    Opaque(String),
    /// Assignments or redirections only.
    Nothing,
}

#[derive(Debug, Clone)]
pub struct Invocation {
    pub program: Program,
    pub args: Vec<Word>,
    /// `NAME=value` prefixes, `export` arguments and PowerShell `$env:NAME = value`.
    pub assignments: Vec<(String, Word)>,
    pub redirects: Vec<Redirect>,
    pub after_pipe: bool,
    /// `xargs` appends arguments read from stdin, which the scanner cannot see.
    pub hidden_args: bool,
    /// The wrappers in front of the program, such as `npx` or `npm exec`.
    pub wrappers: Vec<String>,
    pub dialect: Dialect,
}

impl Invocation {
    pub fn name(&self) -> Option<&str> {
        match &self.program {
            Program::Named(name) => Some(name),
            _ => None,
        }
    }

    pub fn values(&self) -> impl Iterator<Item = &str> {
        self.args.iter().map(|word| word.value.as_str())
    }

    /// Arguments that do not start with `-`.
    pub fn positionals(&self) -> impl Iterator<Item = &Word> {
        self.args.iter().filter(|word| !word.value.starts_with('-'))
    }

    /// The first `count` non-option arguments, when they are all literal.
    pub fn leading(&self, count: usize) -> Option<Vec<&str>> {
        let words: Vec<&Word> = self.positionals().take(count).collect();
        (words.len() == count && words.iter().all(|word| !word.opaque))
            .then(|| words.iter().map(|word| word.value.as_str()).collect())
    }

    fn opaque(reason: &str, dialect: Dialect) -> Invocation {
        Invocation {
            program: Program::Opaque(reason.to_owned()),
            args: Vec::new(),
            assignments: Vec::new(),
            redirects: Vec::new(),
            after_pipe: false,
            hidden_args: false,
            wrappers: Vec::new(),
            dialect,
        }
    }
}

/// Every invocation in `source`, nested ones included.
pub fn parse(source: &str, dialect: Dialect, reading: Reading) -> Vec<Invocation> {
    let mut out = Vec::new();
    collect(source, dialect, reading, 0, &mut out);
    out
}

/// `git.exe`, `/usr/bin/git` and `C:\Git\cmd\GIT.EXE` are all `git`.
pub fn program_name(value: &str) -> String {
    let base = value
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(value)
        .to_ascii_lowercase();
    SUFFIXES
        .iter()
        .find_map(|suffix| base.strip_suffix(suffix).map(str::to_owned))
        .unwrap_or(base)
}

fn collect(
    source: &str,
    dialect: Dialect,
    reading: Reading,
    depth: usize,
    out: &mut Vec<Invocation>,
) {
    let scanned = lexer::scan(source, dialect, reading.resolve, 0, reading.substitutions);
    for simple in scanned.commands {
        normalise(simple, dialect, reading, depth, out);
    }
    for (inner, inner_dialect) in scanned.substitutions {
        nested(&inner, inner_dialect, reading, depth, out);
    }
}

fn nested(
    source: &str,
    dialect: Dialect,
    reading: Reading,
    depth: usize,
    out: &mut Vec<Invocation>,
) {
    if depth >= reading.nested_shells {
        out.push(Invocation::opaque(
            "commands nested too deeply to read",
            dialect,
        ));
        return;
    }
    collect(source, dialect, reading, depth + 1, out);
}

fn normalise(
    simple: lexer::Simple,
    dialect: Dialect,
    reading: Reading,
    depth: usize,
    out: &mut Vec<Invocation>,
) {
    let words = simple.words;
    let mut index = 0;
    while words
        .get(index)
        .is_some_and(|word| !word.opaque && SKIPPED_KEYWORDS.contains(&word.value.as_str()))
    {
        index += 1;
    }
    if words
        .get(index)
        .is_some_and(|word| !word.opaque && NON_COMMANDS.contains(&word.value.as_str()))
    {
        return;
    }
    let mut assignments = Vec::new();
    if dialect == Dialect::PowerShell
        && let Some((assignment, next)) = powershell_assignment(&words, index)
    {
        assignments.push(assignment);
        index = next;
    }
    while let Some(assignment) = words.get(index).and_then(split_assignment) {
        assignments.push(assignment);
        index += 1;
    }
    let mut wrappers = Vec::new();
    let (index, hidden_args) = skip_wrappers(&words, index, &mut assignments, &mut wrappers);
    let mut invocation = Invocation {
        program: Program::Nothing,
        args: Vec::new(),
        assignments,
        redirects: simple.redirects,
        after_pipe: simple.after_pipe,
        hidden_args,
        wrappers,
        dialect,
    };
    let Some(word) = words.get(index) else {
        if !invocation.assignments.is_empty() || !invocation.redirects.is_empty() {
            out.push(invocation);
        }
        return;
    };
    invocation.args = words.get(index + 1..).unwrap_or_default().to_vec();
    if word.opaque {
        invocation.program = Program::Opaque(word.raw.clone());
        out.push(invocation);
        return;
    }
    let name = program_name(&word.value);
    if EXPORTERS.contains(&name.as_str()) {
        let exported: Vec<(String, Word)> = invocation
            .args
            .iter()
            .filter_map(split_assignment)
            .collect();
        invocation.assignments.extend(exported);
    }
    invocation.program = Program::Named(name);
    if let Some(inner) = nested_source(&invocation) {
        match inner {
            Ok((source, inner_dialect)) => nested(&source, inner_dialect, reading, depth, out),
            Err(reason) => out.push(Invocation::opaque(&reason, dialect)),
        }
    }
    out.push(invocation);
}

/// Skips wrappers that run the command after them; returns the program's index and whether
/// arguments are added from stdin.
fn skip_wrappers(
    words: &[Word],
    mut index: usize,
    assignments: &mut Vec<(String, Word)>,
    wrappers: &mut Vec<String>,
) -> (usize, bool) {
    let mut hidden_args = false;
    while let Some(word) = words.get(index).filter(|word| !word.opaque) {
        let next = words.get(index + 1).map(|word| word.value.as_str());
        let wrapper = program_name(&word.value);
        index = match wrapper.as_str() {
            "env" => {
                let after =
                    skip_options(words, index + 1, &["-u", "--unset", "-C", "--chdir", "-S"]);
                let mut at = after;
                while let Some(assignment) = words.get(at).and_then(split_assignment) {
                    assignments.push(assignment);
                    at += 1;
                }
                at
            }
            "sudo" | "doas" => skip_options(
                words,
                index + 1,
                &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"],
            ),
            "nice" => skip_options(words, index + 1, &["-n", "--adjustment"]),
            "nohup" | "builtin" | "time" => skip_options(words, index + 1, &[]),
            "exec" => skip_options(words, index + 1, &["-a"]),
            "stdbuf" => skip_options(words, index + 1, &["-i", "-o", "-e"]),
            "command" if matches!(next, Some("-v" | "-V")) => return (words.len(), false),
            "command" => skip_options(words, index + 1, &[]),
            "timeout" => {
                skip_options(words, index + 1, &["-s", "-k", "--signal", "--kill-after"]) + 1
            }
            "xargs" => {
                hidden_args = true;
                skip_options(
                    words,
                    index + 1,
                    &[
                        "-I",
                        "-L",
                        "-n",
                        "-P",
                        "-d",
                        "-E",
                        "-s",
                        "-a",
                        "--max-args",
                        "--max-procs",
                        "--delimiter",
                        "--arg-file",
                        "--replace",
                    ],
                )
            }
            "npx" | "bunx" | "pnpx" => skip_options(words, index + 1, &["-p", "--package"]),
            "npm" | "pnpm" | "yarn" if matches!(next, Some("exec" | "dlx" | "x")) => {
                skip_options(words, index + 2, &[])
            }
            _ => break,
        };
        wrappers.push(match (wrapper.as_str(), next) {
            ("npm" | "pnpm" | "yarn", Some(sub)) => format!("{wrapper} {sub}"),
            _ => wrapper,
        });
    }
    (index, hidden_args)
}

/// The index of the first argument from `from` on that is not an option; `valued` options take
/// the next word.
fn skip_options(words: &[Word], from: usize, valued: &[&str]) -> usize {
    let mut index = from;
    while let Some(word) = words.get(index) {
        if word.value == "--" {
            return index + 1;
        }
        if !word.value.starts_with('-') || word.value == "-" {
            break;
        }
        index += if valued.contains(&word.value.as_str()) {
            2
        } else {
            1
        };
    }
    index
}

/// `NAME=value` with a literal name.
fn split_assignment(word: &Word) -> Option<(String, Word)> {
    let (name, _) = word.raw.split_once('=')?;
    let valid = name.starts_with(|c: char| c.is_ascii_alphabetic() || c == '_')
        && name.chars().all(|c| c.is_ascii_alphanumeric() || c == '_');
    if !valid {
        return None;
    }
    let value = word.value.split_once('=').map_or("", |(_, value)| value);
    Some((name.to_owned(), word.with_value(value)))
}

/// `$env:NAME = value`, `$env:NAME="value"` and `$x = <command>`; returns the assignment and the
/// index where a command may start (the value of `$x = git status` is a command).
fn powershell_assignment(words: &[Word], index: usize) -> Option<((String, Word), usize)> {
    let word = words.get(index)?;
    let raw = word.raw.strip_prefix('$')?;
    let (name, value, next) = match raw.split_once('=') {
        Some((name, value)) => {
            let unquoted = value.trim_matches(['"', '\'']).to_owned();
            (
                name.to_owned(),
                Word {
                    value: unquoted,
                    raw: word.raw.clone(),
                    opaque: value.contains('$'),
                },
                index + 1,
            )
        }
        None if words.get(index + 1).is_some_and(|next| next.raw == "=") => {
            let value = words.get(index + 2).cloned().unwrap_or_default();
            (raw.to_owned(), value, index + 2)
        }
        None => return None,
    };
    let name = match name.get(..4) {
        Some(prefix) if prefix.eq_ignore_ascii_case("env:") => {
            name.get(prefix.len()..).unwrap_or_default().to_owned()
        }
        _ => name,
    };
    Some(((name, value), next))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn none(_: &str) -> Option<String> {
        None
    }

    fn reading(resolve: Resolve<'_>) -> Reading<'_> {
        Reading {
            resolve,
            nested_shells: 6,
            substitutions: 8,
        }
    }

    fn programs(source: &str, dialect: Dialect) -> Vec<Program> {
        parse(source, dialect, reading(&none))
            .into_iter()
            .map(|i| i.program)
            .collect()
    }

    fn named(name: &str) -> Program {
        Program::Named(name.to_owned())
    }

    #[test]
    fn wrappers_and_assignments_unwrap() {
        let parsed = parse(
            "INSTA_UPDATE=always env A=1 sudo -u me timeout 5 git.exe push",
            Dialect::Bash,
            reading(&none),
        );
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].program, named("git"));
        assert_eq!(parsed[0].values().collect::<Vec<_>>(), vec!["push"]);
        let names: Vec<&str> = parsed[0]
            .assignments
            .iter()
            .map(|(n, _)| n.as_str())
            .collect();
        assert_eq!(names, vec!["INSTA_UPDATE", "A"]);
        let exported = parse("export INSTA_UPDATE=always", Dialect::Bash, reading(&none));
        assert_eq!(exported[0].assignments[0].0, "INSTA_UPDATE");
    }

    #[test]
    fn nested_shells_and_substitutions_are_scanned() {
        let found = programs(
            "bash -lc 'git push --force' && echo $(cargo publish)",
            Dialect::Bash,
        );
        assert!(found.contains(&named("git")));
        assert!(found.contains(&named("cargo")));
        let ps = programs("pwsh -NoProfile -Command \"git push -f\"", Dialect::Bash);
        assert!(ps.contains(&named("git")));
        let cmd = programs("cmd /c git push --force", Dialect::PowerShell);
        assert!(cmd.contains(&named("git")));
        assert!(programs("if git push; then echo; fi", Dialect::Bash).contains(&named("git")));
    }

    #[test]
    fn opaque_programs_and_nested_commands() {
        assert!(matches!(
            programs("$GIT push", Dialect::Bash)[0],
            Program::Opaque(_)
        ));
        assert!(
            programs("eval \"$X\"", Dialect::Bash)
                .iter()
                .any(|p| matches!(p, Program::Opaque(_)))
        );
        assert!(
            programs("sh -c \"$CMD\"", Dialect::Bash)
                .iter()
                .any(|p| matches!(p, Program::Opaque(_)))
        );
        assert!(
            programs("pwsh -enc AAAA", Dialect::Bash)
                .iter()
                .any(|p| matches!(p, Program::Opaque(_)))
        );
    }

    #[test]
    fn powershell_environment_assignment() {
        let parsed = parse(
            "$env:INSTA_UPDATE = 'always'; cargo test",
            Dialect::PowerShell,
            reading(&none),
        );
        let assignment = parsed.iter().find_map(|i| i.assignments.first()).unwrap();
        assert_eq!(assignment.0, "INSTA_UPDATE");
        assert_eq!(assignment.1.value, "always");
        let inline = parse(
            "$env:INSTA_UPDATE=\"always\"",
            Dialect::PowerShell,
            reading(&none),
        );
        assert_eq!(inline[0].assignments[0].0, "INSTA_UPDATE");
    }

    #[test]
    fn program_names_drop_paths_and_suffixes() {
        assert_eq!(program_name(r"C:\Program Files\Git\cmd\GIT.EXE"), "git");
        assert_eq!(program_name("/usr/bin/pnpm.cmd"), "pnpm");
        assert_eq!(program_name("./.agent/kit/bin/xtask"), "xtask");
    }
}
