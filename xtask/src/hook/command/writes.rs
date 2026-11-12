//! The write class of team/03 section 4.1: a shell command that writes into a protected path,
//! the kit's state, a git directory, the main checkout or, for an agent, a file outside the
//! repository that configures later sessions, by redirection, by a command that writes the files
//! it names, by an xtask, cargo vet or cargo mutants output option, by `kit place`, or by deleting
//! a directory that holds one; and the writes the scanner cannot see (`xargs` into a write
//! command, `find -delete`, .NET file calls), which are denied outright. A target is judged where
//! it lands once the links on its way are followed, and the target of a link a command makes is
//! judged as a write, since later writes through the link land there; an agent links only to
//! paths inside the repository. PowerShell's `$null` discards what is redirected to it, as `NUL`
//! and `/dev/null` do.

use std::path::Path;

use super::Rules;
use super::rules::{lowercase, runs_xtask};
use crate::hook::guard_path::{KIT_STATE, outside_refusal};
use crate::hook::path_skills::fixed_prefix;
use crate::hook::shell::{Dialect, Invocation, RedirectKind, Word};
use crate::paths::Located;

/// xtask options whose value is a file the command writes.
const XTASK_OUTPUTS: &[&str] = &["--json", "--out", "--output"];
/// `kit place --stage` copies files into the staging directory instead of placing them.
const PLACE_STAGE_FLAG: &str = "--stage";
/// cargo vet and cargo mutants options whose value is a file or directory they write, by the cargo
/// subcommand they belong to. The allow rules narrow these tools to their read-only forms, and
/// these targets are judged against the protected paths and the repository edge like any write.
const CARGO_OUTPUTS: &[(&str, &[&str])] = &[
    ("vet", &["--output-file", "--log-file", "--store-path"]),
    ("mutants", &["--output", "-o"]),
];

const DELETE_COMMANDS: &[&str] = &[
    "rm",
    "rmdir",
    "unlink",
    "shred",
    "del",
    "erase",
    "rd",
    "ri",
    "remove-item",
];

const FIND_RUNNERS: &[&str] = &["-exec", "-execdir", "-ok", "-okdir"];

/// .NET file and directory classes a PowerShell command can write through.
const DOTNET_FILE_CLASSES: &[&str] = &[
    "[io.file]::",
    "[system.io.file]::",
    "[io.directory]::",
    "[system.io.directory]::",
];

const DOTNET_READS: &[&str] = &["read", "exists", "get", "open"];

const GLOB_CHARACTERS: &[char] = &['*', '?', '['];

const QUOTES: &[char] = &['\'', '"'];

const DESTINATION_COMMANDS: &[&str] = &[
    "cp",
    "mv",
    "install",
    "ln",
    "copy",
    "move",
    "copy-item",
    "move-item",
    "cpi",
    "mi",
];

const OPERAND_COMMANDS: &[&str] = &[
    "tee",
    "rm",
    "rmdir",
    "unlink",
    "truncate",
    "touch",
    "shred",
    "del",
    "erase",
    "ri",
    "remove-item",
    "set-content",
    "add-content",
    "out-file",
    "new-item",
    "ni",
    "clear-content",
    "sc",
    "ac",
    "tee-object",
    "rename-item",
    "rni",
];

const MODE_COMMANDS: &[&str] = &["chmod", "chown", "chgrp"];

/// `ln`'s options that take the next word as their value.
const LN_VALUED: &[&str] = &["-t", "--target-directory", "-S", "--suffix"];
const LN_TARGET_DIRECTORY: &[&str] = &["-t", "--target-directory"];
/// `New-Item` makes a link when its item type, under either name, is one of these.
const LINK_ITEM_TYPE_PARAMETERS: &[&str] = &["-itemtype", "-type"];
const LINK_ITEM_TYPES: &[&str] = &["symboliclink", "junction", "hardlink"];
/// `New-Item`'s link target, under either name.
const LINK_TARGET_PARAMETERS: &[&str] = &["-target", "-value"];
/// PowerShell's automatic variable that discards what is written to it.
const POWERSHELL_NULL: &str = "$null";

/// Options of the Unix write commands that take the next word as their value.
const BASH_VALUED: &[&str] = &[
    "-t",
    "--target-directory",
    "-e",
    "-f",
    "--expression",
    "--file",
    "-m",
    "--mode",
    "-o",
    "--owner",
    "-g",
    "--group",
    "-s",
    "--size",
    "-r",
    "--reference",
];

const POWERSHELL_PATH_PARAMETERS: &[&str] = &[
    "-path",
    "-literalpath",
    "-filepath",
    "-destination",
    "-lp",
    "-pspath",
];

const POWERSHELL_VALUE_PARAMETERS: &[&str] = &[
    "-value",
    "-encoding",
    "-itemtype",
    "-name",
    "-newname",
    "-inputobject",
];

/// Writes into protected paths, the kit's state, a git directory, the main checkout or session
/// configuration, by redirection, by a command that writes the files it names, or through a link
/// the command makes.
pub fn writes(rules: &Rules, invocation: &Invocation, cwd: Option<&Path>) -> Vec<String> {
    let name = invocation
        .name()
        .unwrap_or("this command")
        .to_ascii_lowercase();
    if let Some(reason) = unreadable_write(invocation, &name) {
        return vec![reason];
    }
    let mut targets: Vec<Word> = invocation
        .redirects
        .iter()
        .filter(|redirect| redirect.kind == RedirectKind::Write)
        .map(|redirect| redirect.target.clone())
        .collect();
    targets.extend(written_operands(invocation).into_iter().cloned());
    targets.extend(xtask_outputs(invocation));
    let outputs = cargo_outputs(invocation);
    let discards = |target: &Word| {
        invocation.dialect == Dialect::PowerShell
            && target.raw.eq_ignore_ascii_case(POWERSHELL_NULL)
    };
    targets.retain(|target| !discards(target));
    let deletes = DELETE_COMMANDS.contains(&name.as_str());
    let mut reasons: Vec<String> = Vec::new();
    let found = targets
        .iter()
        .map(|target| {
            write_problem(rules, target, cwd)
                .or_else(|| deletes.then(|| deleted_tree(rules, target, cwd)).flatten())
        })
        .chain(outputs.iter().map(|target| {
            // An output option names a file or the directory a tool fills, so a directory that
            // holds a protected path is refused as a write into it, not only when it matches.
            write_problem(rules, target, cwd)
                .or_else(|| tree_problem(rules, target, cwd, "writing into"))
        }))
        .chain(
            link_targets(invocation)
                .into_iter()
                .map(|target| link_problem(rules, target, cwd)),
        );
    for reason in found.flatten() {
        if !reasons.contains(&reason) {
            reasons.push(reason);
        }
    }
    reasons
}

/// A write whose targets the scanner cannot see: `xargs` feeding a write command, `find -delete`
/// or `find -exec <write command>`, and a .NET file call in PowerShell.
fn unreadable_write(invocation: &Invocation, name: &str) -> Option<String> {
    if invocation.hidden_args && is_write_command(name) {
        return Some(format!(
            "{name} gets the files it writes from stdin; name them literally"
        ));
    }
    if name == "find" {
        let values = lowercase(invocation);
        let runs_writer = values.windows(2).any(|pair| match pair {
            [runner, program] => {
                FIND_RUNNERS.contains(&runner.as_str())
                    && is_write_command(&crate::hook::shell::program_name(program))
            }
            _ => false,
        });
        if values.iter().any(|value| value == "-delete") || runs_writer {
            return Some(
                "find -delete and find -exec <write command> write files nobody named; name each file literally"
                    .to_owned(),
            );
        }
    }
    let class = DOTNET_FILE_CLASSES.iter().find(|class| {
        name.strip_prefix(**class)
            .is_some_and(|method| !DOTNET_READS.iter().any(|read| method.starts_with(read)))
    })?;
    Some(format!(
        "`{}` writes through .NET, which the guard cannot read; use Set-Content or Remove-Item with a literal -Path",
        class.trim_end_matches("::")
    ))
}

fn is_write_command(name: &str) -> bool {
    DESTINATION_COMMANDS.contains(&name)
        || OPERAND_COMMANDS.contains(&name)
        || MODE_COMMANDS.contains(&name)
        || DELETE_COMMANDS.contains(&name)
        || matches!(name, "sed" | "perl" | "dd")
}

fn runs_kit(invocation: &Invocation) -> bool {
    match invocation.name() {
        Some("xtask") => true,
        Some("cargo") => {
            let words = lowercase(invocation);
            let words: Vec<&str> = words.iter().map(String::as_str).collect();
            words.contains(&"xtask") || runs_xtask(&words)
        }
        _ => false,
    }
}

/// The files an xtask command writes through `--json`, `--out` or `--output`, and the paths
/// `kit place` puts in place.
fn xtask_outputs(invocation: &Invocation) -> Vec<Word> {
    if !runs_kit(invocation) {
        return Vec::new();
    }
    let args = &invocation.args;
    let mut found = Vec::new();
    for (index, word) in args.iter().enumerate() {
        let value = word.value.as_str();
        if XTASK_OUTPUTS.contains(&value) {
            found.extend(args.get(index + 1).cloned());
        } else if let Some((flag, path)) = value.split_once('=')
            && XTASK_OUTPUTS.contains(&flag)
        {
            found.push(word.with_value(path));
        }
    }
    let staging = args.iter().any(|word| word.value == PLACE_STAGE_FLAG);
    let after_place = args.windows(2).position(
        |pair| matches!(pair, [kit, place] if kit.value == "kit" && place.value == "place"),
    );
    if let Some(start) = after_place.filter(|_| !staging) {
        found.extend(
            args.iter()
                .skip(start + 2)
                .filter(|word| !word.value.starts_with('-'))
                .cloned(),
        );
    }
    found
}

/// The files cargo vet or cargo mutants writes through an output option (`--output-file`,
/// `--log-file`, `--store-path`, `--output`, `-o`).
fn cargo_outputs(invocation: &Invocation) -> Vec<Word> {
    if invocation.name() != Some("cargo") {
        return Vec::new();
    }
    let Some((_, flags)) = cargo_subcommand(invocation)
        .and_then(|sub| CARGO_OUTPUTS.iter().find(|(name, _)| *name == sub.as_str()))
    else {
        return Vec::new();
    };
    let args = &invocation.args;
    let mut found = Vec::new();
    for (index, word) in args.iter().enumerate() {
        let value = word.value.as_str();
        if flags.contains(&value) {
            found.extend(args.get(index + 1).cloned());
        } else if let Some((flag, path)) = value.split_once('=')
            && flags.contains(&flag)
        {
            found.push(word.with_value(path));
        }
    }
    found
}

/// The cargo subcommand: the first operand that is not a `+toolchain` or a global option.
fn cargo_subcommand(invocation: &Invocation) -> Option<String> {
    let mut words = invocation
        .values()
        .filter(|word| !word.starts_with('+') && !word.starts_with('-'));
    words.next().map(str::to_ascii_lowercase)
}

/// Deleting a directory that holds a protected path or the kit's state, or the repository itself.
fn deleted_tree(rules: &Rules, target: &Word, cwd: Option<&Path>) -> Option<String> {
    tree_problem(rules, target, cwd, "deleting")
}

/// `verb` applied to a directory (or the repository root) that holds a protected path or the
/// kit's state: the operation reaches a protected file through the directory it names.
fn tree_problem(rules: &Rules, target: &Word, cwd: Option<&Path>, verb: &str) -> Option<String> {
    let Located::Inside(path) = rules.context.repo.locate(&target.value, cwd) else {
        return None;
    };
    if path.is_root() {
        return Some(format!(
            "{verb} `{}` reaches the whole repository, protected paths included",
            target.raw
        ));
    }
    let dir = format!("{}/", path.as_str().to_ascii_lowercase());
    let held = rules
        .protected_paths
        .iter()
        .map(String::as_str)
        .chain(KIT_STATE.iter().copied())
        .map(|glob| fixed_prefix(glob).to_ascii_lowercase())
        .find(|prefix| !prefix.is_empty() && format!("{prefix}/").starts_with(&dir))?;
    Some(format!(
        "{verb} {path} reaches {held}, which is protected or the kit's own state"
    ))
}

/// The paths a command links to: every `ln` operand but the link it makes, `mklink`'s target, and
/// the target of a `New-Item` link.
fn link_targets(invocation: &Invocation) -> Vec<&Word> {
    let Some(name) = invocation.name() else {
        return Vec::new();
    };
    let args = &invocation.args;
    match name.to_ascii_lowercase().as_str() {
        "ln" => {
            let operands = operands(args, LN_VALUED);
            let into_directory = flag_value(args, LN_TARGET_DIRECTORY).is_some();
            match operands.split_last() {
                Some((_, sources)) if !into_directory && !sources.is_empty() => sources.to_vec(),
                _ => operands,
            }
        }
        "mklink" => args
            .iter()
            .filter(|word| !word.value.starts_with('/'))
            .skip(1)
            .collect(),
        "new-item" | "ni" => {
            let links = flag_value(args, LINK_ITEM_TYPE_PARAMETERS).is_some_and(|kind| {
                LINK_ITEM_TYPES.contains(&kind.value.to_ascii_lowercase().as_str())
            });
            if !links {
                return Vec::new();
            }
            flag_value(args, LINK_TARGET_PARAMETERS)
                .into_iter()
                .collect()
        }
        _ => Vec::new(),
    }
}

/// Why a link to `target` may not be made: a write there would be refused, or, for an agent, it
/// leads out of the repository, where every write through it would escape the repository's rules.
fn link_problem(rules: &Rules, target: &Word, cwd: Option<&Path>) -> Option<String> {
    if let Some(reason) = write_problem(rules, target, cwd) {
        return Some(reason);
    }
    let outside = matches!(
        rules.context.repo.locate(&target.value, cwd),
        Located::Outside(_)
    );
    (outside && rules.identity.is_agent()).then(|| {
        format!(
            "a link to `{}` leads out of the repository, so writes through it would leave the guard's view; an agent links only to paths inside the repository",
            target.raw
        )
    })
}

fn written_operands(invocation: &Invocation) -> Vec<&Word> {
    let Some(name) = invocation.name() else {
        return Vec::new();
    };
    let name = name.to_ascii_lowercase();
    let cmdlet = invocation.dialect == Dialect::PowerShell || name.contains('-');
    let args = &invocation.args;
    if DESTINATION_COMMANDS.contains(&name.as_str()) {
        if cmdlet {
            let positional = powershell_positionals(args);
            return flag_value(args, &["-destination"])
                .or_else(|| positional.get(1).copied())
                .into_iter()
                .collect();
        }
        let operands = operands(args, BASH_VALUED);
        return flag_value(args, &["-t", "--target-directory"])
            .or_else(|| operands.last().copied())
            .into_iter()
            .collect();
    }
    if OPERAND_COMMANDS.contains(&name.as_str()) {
        if cmdlet {
            let mut targets: Vec<&Word> = POWERSHELL_PATH_PARAMETERS
                .iter()
                .filter_map(|flag| flag_value(args, &[flag]))
                .collect();
            targets.extend(powershell_positionals(args));
            return targets;
        }
        return operands(args, BASH_VALUED);
    }
    match name.as_str() {
        _ if MODE_COMMANDS.contains(&name.as_str()) => {
            operands(args, BASH_VALUED).into_iter().skip(1).collect()
        }
        "sed" | "perl"
            if invocation.values().any(|arg| {
                arg.starts_with("-i") || arg.starts_with("-pi") || arg == "--in-place"
            }) =>
        {
            let scripted = invocation
                .values()
                .any(|arg| matches!(arg, "-e" | "-f" | "--expression" | "--file"));
            operands(args, BASH_VALUED)
                .into_iter()
                .skip(usize::from(!scripted))
                .collect()
        }
        "dd" => args
            .iter()
            .filter(|word| word.value.starts_with("of="))
            .collect(),
        _ => Vec::new(),
    }
}

/// Arguments of a cmdlet that are not parameters or parameter values.
fn powershell_positionals(args: &[Word]) -> Vec<&Word> {
    let mut found = Vec::new();
    let mut index = 0;
    while let Some(word) = args.get(index) {
        let lower = word.value.to_ascii_lowercase();
        let valued = POWERSHELL_PATH_PARAMETERS.contains(&lower.as_str())
            || POWERSHELL_VALUE_PARAMETERS.contains(&lower.as_str());
        index += if valued { 2 } else { 1 };
        if !lower.starts_with('-') {
            found.push(word);
        }
    }
    found
}

/// Arguments that are neither options nor the values of `valued` options.
fn operands<'w>(args: &'w [Word], valued: &[&str]) -> Vec<&'w Word> {
    let mut found = Vec::new();
    let mut index = 0;
    let mut options_done = false;
    while let Some(word) = args.get(index) {
        index += 1;
        if options_done || !word.value.starts_with('-') || word.value == "-" {
            found.push(word);
        } else if word.value == "--" {
            options_done = true;
        } else if valued.contains(&word.value.as_str()) {
            index += 1;
        }
    }
    found
}

fn flag_value<'w>(args: &'w [Word], flags: &[&str]) -> Option<&'w Word> {
    let index = args
        .iter()
        .position(|word| flags.contains(&word.value.to_ascii_lowercase().as_str()))?;
    args.get(index + 1)
}

fn write_problem(rules: &Rules, target: &Word, cwd: Option<&Path>) -> Option<String> {
    let value = target.value.strip_prefix("of=").unwrap_or(&target.value);
    if !target.opaque && value.is_empty() {
        return None;
    }
    let relative =
        !(value.starts_with('/') || value.starts_with('\\') || value.get(1..2) == Some(":"));
    let globbed = value.contains(GLOB_CHARACTERS) && !target.raw.starts_with(QUOTES);
    if target.opaque || globbed || (relative && cwd.is_none()) {
        return Some(format!(
            "the write target `{}` depends on an expansion or an unknown directory; name the file literally",
            target.raw
        ));
    }
    let located = match rules.context.repo.locate_through_links(value, cwd) {
        Ok(located) => located,
        Err(error) => {
            return Some(format!(
                "the write target `{}` goes through a link the guard cannot follow ({error:#}); write the path it leads to",
                target.raw
            ));
        }
    };
    let path = match located {
        Located::Inside(path) => path,
        Located::Outside(absolute) => {
            return outside_refusal(rules.context, rules.identity, &absolute);
        }
    };
    let text = path.as_str();
    if rules.kit_state.is_kit_written(text) {
        return Some(format!(
            "{path} is the kit's own state, written by xtask and the hooks only"
        ));
    }
    let widened = rules
        .widened
        .as_ref()
        .is_some_and(|globs| globs.is_match(text));
    if rules.protected.is_match(text) && !widened {
        return Some(format!(
            "{path} is a protected path; a shell write to it is denied like an edit (ask in the hand-off's protected_change_requests)"
        ));
    }
    None
}
