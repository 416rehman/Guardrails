//! The command string a nested shell runs, which `guard-command` scans as a command of its own:
//! `bash -c`; PowerShell's `-Command` in every form `powershell` and `pwsh` accept (a `-`, `--` or
//! `/` prefix, an abbreviation, or no switch at all, where Windows PowerShell runs its first
//! argument); `cmd /c`, `/k` and `/r`, alone, after other switches or joined to the command;
//! `eval` and `Invoke-Expression`. Git Bash passes a `//c` argument to Windows programs as `/c`.
//! `cmd` reads `\` as a path separator, where the Bash reading of its command would drop it, and
//! expands `%NAME%` and drops `^` before it runs a word, so its command is read with `/` for `\`
//! and refused when it holds `%` or `^`. A command the scanner cannot read is an error, never a
//! pass.

use super::{Dialect, Invocation, Word};

const SHELLS: &[&str] = &["sh", "bash", "zsh", "dash", "ksh", "fish"];
const POWERSHELLS: &[&str] = &["pwsh", "powershell"];
/// The dashes PowerShell takes as a switch's `-`: hyphen-minus, en dash, em dash, horizontal bar.
const DASHES: &[char] = &['-', '\u{2013}', '\u{2014}', '\u{2015}'];
/// The `cmd` switches whose rest of the line is the command it runs.
const CMD_COMMAND_SWITCHES: &[char] = &['c', 'k', 'r'];
/// `cmd`'s expansion and escape characters, which change a word before it runs.
const CMD_REWRITES: &[char] = &['%', '^'];
/// An argument that makes the shell read its command from stdin.
const STDIN: &str = "-";
/// The switches of `powershell` and `pwsh`, each with the shortest prefix of it they accept.
const POWERSHELL_SWITCHES: &[(&str, &str, Switch)] = &[
    ("command", "c", Switch::Command),
    ("commandwithargs", "commandwithargs", Switch::Command),
    ("cwa", "cwa", Switch::Command),
    ("encodedcommand", "e", Switch::Encoded),
    ("ec", "ec", Switch::Encoded),
    ("file", "f", Switch::File),
    ("configurationfile", "configurationfile", Switch::Valued),
    ("configurationname", "config", Switch::Valued),
    ("custompipename", "custompipename", Switch::Valued),
    ("encodedarguments", "encodeda", Switch::Valued),
    ("ea", "ea", Switch::Valued),
    ("executionpolicy", "ex", Switch::Valued),
    ("ep", "ep", Switch::Valued),
    ("inputformat", "inp", Switch::Valued),
    ("if", "if", Switch::Valued),
    ("outputformat", "o", Switch::Valued),
    ("of", "of", Switch::Valued),
    ("psconsolefile", "psc", Switch::Valued),
    ("settingsfile", "settings", Switch::Valued),
    ("version", "v", Switch::Valued),
    ("windowstyle", "w", Switch::Valued),
    ("workingdirectory", "wo", Switch::Valued),
    ("wd", "wd", Switch::Valued),
    ("help", "h", Switch::Flag),
    ("?", "?", Switch::Flag),
    ("interactive", "i", Switch::Flag),
    ("login", "l", Switch::Flag),
    ("mta", "mta", Switch::Flag),
    ("noexit", "noe", Switch::Flag),
    ("nologo", "nol", Switch::Flag),
    ("noninteractive", "noni", Switch::Flag),
    ("noprofile", "nop", Switch::Flag),
    ("noprofileloadtime", "noprofileloadtime", Switch::Flag),
    ("sta", "sta", Switch::Flag),
];

/// What a PowerShell command-line switch does.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Switch {
    /// The arguments after it are the command.
    Command,
    /// A command nobody can read.
    Encoded,
    /// A script file, which the guard does not read.
    File,
    /// Takes the next argument as its value.
    Valued,
    /// Takes no value.
    Flag,
}

/// What a PowerShell command line runs.
#[derive(Debug, PartialEq, Eq)]
enum Runs {
    /// An interactive shell or a script file.
    NoCommand,
    /// The command made of the arguments from this index on.
    From(usize),
    /// A command the guard cannot read, and why.
    Unreadable(String),
}

/// The command string a shell, `cmd`, `eval` or `Invoke-Expression` runs; an error when it
/// cannot be read.
pub(super) fn nested_source(invocation: &Invocation) -> Option<Result<(String, Dialect), String>> {
    let name = invocation.name()?;
    let args = &invocation.args;
    if SHELLS.contains(&name) {
        let flag = args.iter().position(|word| {
            let value = &word.value;
            value.starts_with('-') && !value.starts_with("--") && value.contains('c')
        })?;
        let source = args
            .get(flag + 1..)
            .unwrap_or_default()
            .iter()
            .find(|word| !word.value.starts_with('-'))?;
        return Some(literal(std::slice::from_ref(source), Dialect::Bash, name));
    }
    if POWERSHELLS.contains(&name) {
        return match powershell_runs(args) {
            Runs::NoCommand => None,
            Runs::Unreadable(reason) => Some(Err(format!("{name} {reason}"))),
            Runs::From(start) => {
                let command = args.get(start..).unwrap_or_default();
                Some(literal(command, Dialect::PowerShell, name))
            }
        };
    }
    match name {
        "cmd" => cmd_command(args).map(|command| cmd_source(&command, name)),
        "eval" => Some(literal(args, Dialect::Bash, name)),
        "invoke-expression" | "iex" if !args.is_empty() => {
            Some(literal(args, Dialect::PowerShell, name))
        }
        _ => None,
    }
}

/// Walks the switches the way PowerShell does: the first argument that is no switch starts the
/// command, which Windows PowerShell runs and `pwsh` takes as a script; a switch the table does not
/// know could be one a newer PowerShell reads, so it is refused.
fn powershell_runs(args: &[Word]) -> Runs {
    let mut index = 0;
    while let Some(word) = args.get(index) {
        if word.value == STDIN {
            return Runs::Unreadable("reads its command from stdin".to_owned());
        }
        let Some(name) = powershell_switch_name(&word.value) else {
            return Runs::From(index);
        };
        let reads_stdin = args.get(index + 1).is_some_and(|next| next.value == STDIN);
        match powershell_switch(&name) {
            Some(Switch::Command | Switch::File) if reads_stdin => {
                return Runs::Unreadable(format!("-{name} - reads its command from stdin"));
            }
            Some(Switch::Command) => return Runs::From(index + 1),
            Some(Switch::Encoded) => {
                return Runs::Unreadable("-EncodedCommand hides the command".to_owned());
            }
            Some(Switch::File) => return Runs::NoCommand,
            Some(Switch::Valued) => index += 2,
            Some(Switch::Flag) => index += 1,
            None => {
                return Runs::Unreadable(format!(
                    "{} is a switch the guard does not know; name the command with -Command",
                    word.value
                ));
            }
        }
    }
    Runs::NoCommand
}

/// A switch's name in lower case without its prefix: `/` or one of [`DASHES`], then at most one
/// more of [`DASHES`].
fn powershell_switch_name(value: &str) -> Option<String> {
    let value = as_passed(value);
    let rest = value
        .strip_prefix('/')
        .or_else(|| value.strip_prefix(DASHES))?;
    let rest = rest.strip_prefix(DASHES).unwrap_or(rest);
    Some(rest.to_lowercase())
}

/// `value` as Git Bash passes it to a Windows program, which turns a leading `//` into `/`.
fn as_passed(value: &str) -> &str {
    value
        .strip_prefix('/')
        .filter(|rest| rest.starts_with('/'))
        .unwrap_or(value)
}

/// The switch `name` abbreviates, when it is at least as long as that switch's shortest prefix.
fn powershell_switch(name: &str) -> Option<Switch> {
    POWERSHELL_SWITCHES
        .iter()
        .find(|(switch, shortest, _)| switch.starts_with(name) && name.len() >= shortest.len())
        .map(|(_, _, kind)| *kind)
}

/// The words of the command `cmd` runs: everything after the first `/c`, `/k` or `/r`, which may
/// follow other switches in the same argument (`/q/c`) or have the command joined to it (`/cgit`).
fn cmd_command(args: &[Word]) -> Option<Vec<Word>> {
    let (index, joined) = args.iter().enumerate().find_map(|(index, word)| {
        cmd_switch_rest(as_passed(&word.value)).map(|rest| (index, word.with_value(rest)))
    })?;
    let mut command: Vec<Word> = Vec::new();
    if !joined.value.is_empty() {
        command.push(joined);
    }
    command.extend(args.get(index + 1..).unwrap_or_default().iter().cloned());
    Some(command)
}

/// What follows the first command switch in one `cmd` argument that starts with `/`.
fn cmd_switch_rest(value: &str) -> Option<&str> {
    if !value.starts_with('/') {
        return None;
    }
    value.match_indices('/').find_map(|(at, _)| {
        let mut rest = value.get(at + 1..)?.chars();
        let switch = rest.next()?.to_ascii_lowercase();
        CMD_COMMAND_SWITCHES
            .contains(&switch)
            .then_some(rest.as_str())
    })
}

/// `cmd`'s command, read in the Bash dialect with `/` for each `\`.
fn cmd_source(words: &[Word], name: &str) -> Result<(String, Dialect), String> {
    let (source, dialect) = literal(words, Dialect::Bash, name)?;
    if source.contains(CMD_REWRITES) {
        return Err(format!(
            "{name} expands `%` and drops `^` before it runs a command, which the guard cannot follow; run the command in Bash or PowerShell"
        ));
    }
    Ok((source.replace('\\', "/"), dialect))
}

fn literal(words: &[Word], dialect: Dialect, name: &str) -> Result<(String, Dialect), String> {
    if words.iter().any(|word| word.opaque) {
        return Err(format!("{name} runs a command built from an expansion"));
    }
    let source: Vec<&str> = words.iter().map(|word| word.value.as_str()).collect();
    Ok((source.join(" "), dialect))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn words(args: &[&str]) -> Vec<Word> {
        args.iter()
            .map(|arg| Word {
                value: (*arg).to_owned(),
                raw: (*arg).to_owned(),
                opaque: false,
            })
            .collect()
    }

    #[test]
    fn every_powershell_spelling_of_command_starts_the_command() {
        for switch in [
            "-c",
            "-Command",
            "/c",
            "/Command",
            "//c",
            "--command",
            "-com",
            "\u{2013}c",
        ] {
            let args = words(&["-NoProfile", switch, "git", "push"]);
            assert_eq!(powershell_runs(&args), Runs::From(2), "{switch}");
        }
        let args = words(&["-cwa", "git push $args", "--force"]);
        assert_eq!(powershell_runs(&args), Runs::From(1));
    }

    #[test]
    fn windows_powershell_runs_its_first_argument_after_the_switches() {
        let args = words(&[
            "-NoLogo",
            "-ep",
            "Bypass",
            "-WindowStyle",
            "Hidden",
            "git push",
        ]);
        assert_eq!(powershell_runs(&args), Runs::From(5));
        assert_eq!(powershell_runs(&words(&["git push"])), Runs::From(0));
        assert_eq!(powershell_runs(&words(&["-NoProfile"])), Runs::NoCommand);
        assert_eq!(
            powershell_runs(&words(&["-File", "x.ps1", "git"])),
            Runs::NoCommand
        );
    }

    #[test]
    fn hidden_and_unknown_powershell_commands_are_unreadable() {
        for args in [
            &["/enc", "AAAA"][..],
            &["-e", "AAAA"],
            &["/EncodedCommand", "AAAA"],
            &["-Command", "-"],
            &["-File", "-"],
            &["-"],
            &["-NoSuchSwitch", "git push"],
        ] {
            assert!(
                matches!(powershell_runs(&words(args)), Runs::Unreadable(_)),
                "{args:?}"
            );
        }
        assert_eq!(
            powershell_runs(&words(&["-ea", "AAAA", "-c", "x"])),
            Runs::From(3)
        );
    }

    #[test]
    fn cmd_runs_what_follows_its_command_switch_in_any_spelling() {
        let source = |args: &[&str]| {
            cmd_command(&words(args)).map(|command| {
                command
                    .iter()
                    .map(|word| word.value.clone())
                    .collect::<Vec<_>>()
                    .join(" ")
            })
        };
        assert_eq!(source(&["/c", "git", "push"]).as_deref(), Some("git push"));
        assert_eq!(source(&["//c", "git", "push"]).as_deref(), Some("git push"));
        assert_eq!(
            source(&["/d", "/S", "/C", "git push"]).as_deref(),
            Some("git push")
        );
        assert_eq!(
            source(&["/q/k", "git", "push"]).as_deref(),
            Some("git push")
        );
        assert_eq!(source(&["/e:on/r", "git"]).as_deref(), Some("git"));
        assert_eq!(source(&["/Cgit", "push"]).as_deref(), Some("git push"));
        assert_eq!(source(&["/d", "/q"]), None);
        assert_eq!(source(&["echo", "a/c"]), None);
    }

    #[test]
    fn cmd_keeps_its_backslashes_and_refuses_what_it_rewrites() {
        let copy = words(&["copy", "evil", r"C:\Users\dev\.claude\settings.json"]);
        assert_eq!(
            cmd_source(&copy, "cmd"),
            Ok((
                "copy evil C:/Users/dev/.claude/settings.json".to_owned(),
                Dialect::Bash
            ))
        );
        for rewritten in [
            &["copy", "x", r"%USERPROFILE%\.claude"][..],
            &["g^it", "push"],
        ] {
            assert!(
                cmd_source(&words(rewritten), "cmd").is_err(),
                "{rewritten:?}"
            );
        }
    }
}
