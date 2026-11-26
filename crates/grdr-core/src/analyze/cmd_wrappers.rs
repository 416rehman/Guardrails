// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Shell wrapper unwrapping (`sudo`, `env`, `stdbuf`, `chroot`) and dialect selection.

use crate::analyze::cmd_wrappers_cmd::{has_cmd_caret_outside_quotes, has_win_backslash_path};
use crate::analyze::cmd_wrappers_extract::{
    extract_attached_cmd_c, extract_cmd_c_script, extract_env_split_string, extract_head_cmd,
    extract_posix_c_script, extract_ps_c_script, has_cmd_c_invocation, is_assign_token,
    join_quoted_tokens, skip_options,
};
use crate::analyze::types::{LimitKind, ShellDialect, Span, UnresolvedKind, UnresolvedReason};

/// Auto-detects likely primary shell dialect from command text when caller does not specify one.
#[must_use]
pub fn detect_shell_dialect(raw: &str) -> ShellDialect {
    let first_word = extract_head_cmd(raw);

    if matches!(
        first_word.as_str(),
        "powershell"
            | "powershell.exe"
            | "pwsh"
            | "pwsh.exe"
            | "iex"
            | "invoke-expression"
            | "invoke-webrequest"
            | "invoke-restmethod"
            | "remove-item"
            | "start-process"
    ) {
        return ShellDialect::PowerShell;
    }
    if first_word == "cmd" || first_word == "cmd.exe" {
        return ShellDialect::Cmd;
    }

    let lower = raw.to_ascii_lowercase();
    if lower.contains("-encodedcommand")
        || lower.contains("invoke-expression")
        || lower.contains("invoke-webrequest")
        || lower.contains("invoke-restmethod")
        || lower.contains("frombase64string")
        || lower.contains("[scriptblock]::create")
        || lower.contains("iex(")
    {
        ShellDialect::PowerShell
    } else if has_cmd_c_invocation(&lower)
        || lower.contains("cmd.exe")
        || has_cmd_caret_outside_quotes(raw)
    {
        ShellDialect::Cmd
    } else {
        ShellDialect::Posix
    }
}

/// Returns every plausible shell dialect that should evaluate `raw` without fail-open blind spots.
#[must_use]
pub fn plausible_dialects(raw: &str) -> Vec<ShellDialect> {
    let primary = detect_shell_dialect(raw);
    let lower = raw.to_ascii_lowercase();
    let first_word = extract_head_cmd(raw);

    let explicit_ps = matches!(
        first_word.as_str(),
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe"
    );
    let explicit_cmd = first_word == "cmd" || first_word == "cmd.exe";

    let mut dialects = Vec::new();
    if !explicit_ps && !explicit_cmd {
        dialects.push(ShellDialect::Posix);
    } else if lower.contains(';')
        || lower.contains("&&")
        || lower.contains("||")
        || lower.contains('|')
        || lower.contains('\n')
    {
        // Multi-clause command starting with a shell might still contain POSIX clauses.
        dialects.push(ShellDialect::Posix);
    }

    let maybe_ps = explicit_ps
        || primary == ShellDialect::PowerShell
        || lower.contains("powershell")
        || lower.contains("pwsh")
        || lower.contains("iex(")
        || lower.contains("iex ")
        || lower.contains("icm ")
        || lower.contains("irm ")
        || lower.contains("iwr ")
        || lower.contains("invoke-")
        || lower.contains("remove-item")
        || lower.contains("frombase64string")
        || lower.contains("[scriptblock]")
        || lower.contains(".invoke(")
        || lower.contains("$env:")
        || lower.contains("<#")
        || lower.contains("`u{");
    if maybe_ps && !dialects.contains(&ShellDialect::PowerShell) {
        dialects.push(ShellDialect::PowerShell);
    }

    let maybe_cmd = explicit_cmd
        || primary == ShellDialect::Cmd
        || matches!(first_word.as_str(), "call" | "@call")
        || has_cmd_c_invocation(&lower)
        || lower.contains("cmd.exe")
        || has_cmd_caret_outside_quotes(raw)
        || has_cmd_percent_var(raw)
        || has_win_backslash_path(raw);
    if maybe_cmd && !dialects.contains(&ShellDialect::Cmd) {
        dialects.push(ShellDialect::Cmd);
    }

    if !dialects.contains(&primary) {
        dialects.push(primary);
    }
    dialects
}

/// Strips prefix wrappers (`sudo -u root`, `env -u X VAR=1`, `nohup`, `timeout`, `command`, `exec`)
/// to expose the effective command slice for classification.
#[must_use]
pub fn unwrap_prefix_command(argv: &[String]) -> &[String] {
    unwrap_prefix_inner(argv, 8, false).unwrap_or(argv)
}

pub(crate) fn unwrap_prefix_command_checked(
    argv: &[String],
    max_depth: usize,
) -> Result<&[String], UnresolvedReason> {
    unwrap_prefix_inner(argv, max_depth, true)
}

/// Extracts all nested shell invocations (`bash -ec`, `pwsh -co`, `cmd /c`, `find -exec`, `xargs`, etc.).
pub(crate) fn extract_wrapper_invocations(argv: &[String]) -> Vec<(ShellDialect, String)> {
    let unwrapped = unwrap_prefix_command(argv);
    let Some(first) = unwrapped.first() else {
        return Vec::new();
    };
    let bin = extract_head_cmd(first);

    match bin.as_str() {
        "env" => extract_env_split_string(unwrapped).into_iter().collect(),
        "bash" | "sh" | "dash" | "zsh" | "ash" | "ksh" | "mksh" => {
            extract_posix_c_script(unwrapped).into_iter().collect()
        }
        "powershell" | "powershell.exe" | "pwsh" | "pwsh.exe" => {
            extract_ps_c_script(unwrapped).into_iter().collect()
        }
        "cmd" | "cmd.exe" => {
            if let Some(attached) = extract_attached_cmd_c(first, unwrapped.get(1..).unwrap_or(&[]))
            {
                vec![attached]
            } else {
                extract_cmd_c_script(unwrapped).into_iter().collect()
            }
        }
        "xargs" => {
            let Some(pos) = skip_options(
                unwrapped,
                1,
                &[
                    "-I",
                    "-J",
                    "-L",
                    "-n",
                    "-P",
                    "-R",
                    "-S",
                    "-s",
                    "-d",
                    "-E",
                    "-a",
                    "--max-args",
                    "--max-procs",
                    "--max-chars",
                    "--delimiter",
                    "--arg-file",
                    "--process-slot-var",
                ],
                false,
            ) else {
                return Vec::new();
            };
            let rest = unwrapped.get(pos..).unwrap_or(&[]);
            if rest.is_empty() {
                Vec::new()
            } else {
                vec![join_quoted_tokens(rest)]
            }
        }
        "find" => extract_find_exec_invocations(unwrapped),
        _ => Vec::new(),
    }
}

fn extract_find_exec_invocations(unwrapped: &[String]) -> Vec<(ShellDialect, String)> {
    let mut out = Vec::new();
    let mut idx = 1usize;
    while let Some(tok) = unwrapped.get(idx) {
        if matches!(tok.as_str(), "-exec" | "-execdir" | "-ok" | "-okdir") {
            let Some(rest) = unwrapped.get(idx.saturating_add(1)..) else {
                break;
            };
            let is_plus_end = matches!(tok.as_str(), "-exec" | "-execdir");
            let end = rest
                .iter()
                .enumerate()
                .position(|(i, a)| {
                    a == ";"
                        || (is_plus_end
                            && a == "+"
                            && i > 0
                            && rest.get(i.saturating_sub(1)).map(String::as_str) == Some("{}"))
                })
                .unwrap_or(rest.len());
            if let Some(inner) = rest.get(..end)
                && !inner.is_empty()
            {
                out.push(join_quoted_tokens(inner));
            }
            idx = idx.saturating_add(1).saturating_add(end).saturating_add(1);
            continue;
        }
        if tok == "-fprintf" {
            idx = idx.saturating_add(3);
            continue;
        }
        if is_find_one_arg_predicate(tok) {
            idx = idx.saturating_add(2);
            continue;
        }
        idx = idx.saturating_add(1);
    }
    out
}

fn is_find_one_arg_predicate(tok: &str) -> bool {
    matches!(
        tok,
        "-D" | "-f"
            | "-maxdepth"
            | "-mindepth"
            | "-name"
            | "-iname"
            | "-lname"
            | "-ilname"
            | "-path"
            | "-ipath"
            | "-wholename"
            | "-iwholename"
            | "-regex"
            | "-iregex"
            | "-regextype"
            | "-type"
            | "-xtype"
            | "-perm"
            | "-user"
            | "-group"
            | "-uid"
            | "-gid"
            | "-size"
            | "-links"
            | "-inum"
            | "-samefile"
            | "-fstype"
            | "-atime"
            | "-amin"
            | "-anewer"
            | "-ctime"
            | "-cmin"
            | "-cnewer"
            | "-mtime"
            | "-mmin"
            | "-Btime"
            | "-Bmin"
            | "-Bnewer"
            | "-used"
            | "-context"
            | "-flags"
            | "-printf"
            | "-fprint"
            | "-fprint0"
            | "-fls"
            | "-files0-from"
    ) || tok.starts_with("-newer")
}

fn unwrap_prefix_inner(
    argv: &[String],
    max_depth: usize,
    fail_on_limit: bool,
) -> Result<&[String], UnresolvedReason> {
    let mut cur = argv;
    let mut depth = 0usize;
    while let Some(first) = cur.first() {
        let bin = first
            .rsplit(['/', '\\'])
            .next()
            .unwrap_or(first)
            .to_ascii_lowercase();
        let next_pos = match bin.as_str() {
            "sudo" => skip_options(
                cur,
                1,
                &[
                    "-u",
                    "-g",
                    "-C",
                    "-D",
                    "-R",
                    "-T",
                    "-h",
                    "-p",
                    "-r",
                    "-t",
                    "-U",
                    "--user",
                    "--group",
                    "--chdir",
                    "--host",
                    "--close-from",
                    "--chroot",
                    "--command-timeout",
                    "--prompt",
                    "--role",
                    "--type",
                    "--other-user",
                ],
                true,
            ),
            "doas" => skip_options(cur, 1, &["-u", "-C"], false),
            "env" => {
                if env_has_split_string(cur) {
                    break;
                }
                crate::analyze::cmd_wrappers_extract::skip_env_options(
                    cur,
                    1,
                    &["-u", "-C", "-a", "--unset", "--chdir", "--argv0"],
                )
            }
            "nohup" | "time" | "setsid" => skip_options(cur, 1, &[], false),
            "stdbuf" => skip_options(
                cur,
                1,
                &["-i", "-o", "-e", "--input", "--output", "--error"],
                false,
            ),
            "ionice" => skip_options(
                cur,
                1,
                &[
                    "-c",
                    "-n",
                    "-p",
                    "-P",
                    "-u",
                    "--class",
                    "--classdata",
                    "--pid",
                    "--pgid",
                    "--uid",
                ],
                false,
            ),
            "chrt" => skip_options(cur, 1, &[], false).map(|p| {
                if cur
                    .get(p)
                    .is_some_and(|s| !s.is_empty() && s.bytes().all(|b| b.is_ascii_digit()))
                {
                    p.saturating_add(1)
                } else {
                    p
                }
            }),
            "taskset" => skip_options(cur, 1, &["-c", "--cpu-list"], false).map(|p| {
                let had_list_or_pid = cur.get(1..p).unwrap_or(&[]).iter().any(|a| {
                    a == "--cpu-list"
                        || a.starts_with("--cpu-list=")
                        || a == "--pid"
                        || a.starts_with("--pid=")
                        || (a.starts_with('-')
                            && !a.starts_with("--")
                            && a.chars().skip(1).any(|ch| ch == 'c' || ch == 'p'))
                });
                if had_list_or_pid {
                    p
                } else {
                    p.saturating_add(1)
                }
            }),
            "chroot" => skip_options(cur, 1, &["--userspec", "--groups"], false)
                .map(|p| p.saturating_add(1)),
            "command" => skip_options(cur, 1, &[], false),
            "exec" => skip_options(cur, 1, &["-a"], false),
            "nice" => skip_options(cur, 1, &["-n", "--adjustment"], false),
            "timeout" => skip_options(cur, 1, &["-k", "-s", "--kill-after", "--signal"], false)
                .map(|p| p.saturating_add(1)),
            "busybox" => skip_options(cur, 1, &[], false),
            _ => break,
        };
        depth = depth.saturating_add(1);
        if depth > max_depth {
            if fail_on_limit {
                return Err(UnresolvedReason {
                    kind: UnresolvedKind::LimitExceeded(LimitKind::NestingDepth),
                    span: Span::from_usize(0, first.len()),
                    detail: "prefix wrapper unwrap nesting depth exceeded".into(),
                });
            }
            break;
        }
        let Some(pos) = next_pos else {
            break;
        };
        if let Some(rest) = cur.get(pos..)
            && !rest.is_empty()
        {
            cur = rest;
        } else {
            break;
        }
    }
    Ok(cur)
}

fn env_has_split_string(argv: &[String]) -> bool {
    let mut i = 1usize;
    while let Some(arg) = argv.get(i) {
        if arg == "--" {
            return false;
        }
        if is_assign_token(arg) {
            i = i.saturating_add(1);
            continue;
        }
        if arg == "--split-string" || arg.starts_with("--split-string=") {
            return true;
        }
        if matches!(
            arg.as_str(),
            "-u" | "-C" | "-a" | "--unset" | "--chdir" | "--argv0"
        ) {
            i = i.saturating_add(2);
            continue;
        }
        if arg.starts_with('-') && !arg.starts_with("--") && arg.len() > 1 {
            let body = arg.get(1..).unwrap_or("");
            let mut step = 1usize;
            for (idx, ch) in body.char_indices() {
                if ch == 'S' {
                    return true;
                }
                if matches!(ch, 'u' | 'C' | 'a') {
                    if idx.saturating_add(1) == body.len() {
                        step = 2;
                    }
                    break;
                }
            }
            i = i.saturating_add(step);
            continue;
        }
        if !arg.starts_with('-') {
            return false;
        }
        i = i.saturating_add(1);
    }
    false
}

fn has_cmd_percent_var(raw: &str) -> bool {
    let bytes = raw.as_bytes();
    let mut i = 0usize;
    while i < bytes.len() {
        if bytes.get(i) == Some(&b'%')
            && let Some(rel) = bytes
                .get(i.saturating_add(1)..)
                .and_then(|s| s.iter().position(|&b| b == b'%'))
        {
            if rel > 0 {
                let inner = bytes
                    .get(i.saturating_add(1)..i.saturating_add(1).saturating_add(rel))
                    .unwrap_or(&[]);
                if inner
                    .first()
                    .is_some_and(|b| b.is_ascii_alphabetic() || *b == b'_')
                {
                    return true;
                }
            }
            i = i.saturating_add(rel).saturating_add(2);
            continue;
        }
        i = i.saturating_add(1);
    }
    false
}
