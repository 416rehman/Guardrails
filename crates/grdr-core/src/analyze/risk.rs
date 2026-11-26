// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Structural risk-tagging and clause evaluation helpers for `crates::analyze` (`D-10`, `D-28`).

use std::collections::BTreeMap;

use grdr_model::{ActionClass, CommandParseStatus};

use crate::analyze::cmd::{CommandTree, canonicalise_shell_plausible};
use crate::analyze::cmd_wrappers::unwrap_prefix_command;
use crate::analyze::net::{
    HostClass, HostClassifierConfig, HostSyntax, IpExposureClass, NormalizedHostUrl,
    UserinfoPresence, classify_url_or_host,
};
use crate::analyze::path::{
    ProtectedPathClass, canonicalize_path_lex, canonicalize_windows_path_lex,
    classify_protected_path, split_ntfs_ads,
};
use crate::analyze::types::{Resolution, ShellLimits};

pub(crate) fn evaluate_exec_target(
    target: &str,
    legacy_cmd_status: CommandParseStatus,
    legacy_canonical_text: String,
) -> (String, CommandParseStatus, Option<CommandTree>) {
    let limits = ShellLimits::from_schema();
    let shell_res = canonicalise_shell_plausible(target.as_bytes(), &BTreeMap::new(), &limits);
    let (shell_status, tree_opt) = match shell_res {
        Resolution::Resolved(tree) => (CommandParseStatus::Resolved, Some(tree)),
        Resolution::Unresolved(_) => (CommandParseStatus::Unresolved, None),
        Resolution::Malformed(_) => (CommandParseStatus::Malformed, None),
    };
    let status = worse_parse_status(legacy_cmd_status, shell_status);
    let canonical = match &tree_opt {
        Some(tree) if !tree.canonical_lines.is_empty() => {
            tree.canonical_lines.join(" ; ").to_ascii_lowercase()
        }
        _ => legacy_canonical_text,
    };
    (canonical, status, tree_opt)
}

pub(crate) fn apply_tree_risk(
    tree: &CommandTree,
    corpus: &mut String,
    case_corpus: &mut String,
    risk_tags: &mut Vec<String>,
    risk_score: &mut u32,
) {
    if tree.decoded_layers > 0 {
        add_risk(risk_tags, risk_score, "exec.decoded", 30);
    }
    for line in &tree.canonical_lines {
        corpus.push('\n');
        corpus.push_str(&line.to_ascii_lowercase());
        case_corpus.push('\n');
        case_corpus.push_str(line);
    }
    for child in &tree.decoded_children {
        corpus.push('\n');
        corpus.push_str(&child.to_ascii_lowercase());
        case_corpus.push('\n');
        case_corpus.push_str(child);
    }
    for fact in &tree.facts {
        push_unique_tag(risk_tags, &fact.key);
    }
    for clause in &tree.clauses {
        for tok in &clause.argv {
            let tok_bin = tok
                .rsplit(['/', '\\'])
                .next()
                .unwrap_or(tok)
                .to_ascii_lowercase();
            if matches!(
                tok_bin.as_str(),
                "sudo" | "doas" | "runas" | "pkexec" | "su"
            ) {
                add_risk(risk_tags, risk_score, "privilege-escalation", 50);
            }
        }
        let effective = unwrap_prefix_command(&clause.argv);
        let Some(cmd0) = effective.first().or_else(|| clause.argv.first()) else {
            continue;
        };
        let (bin, inline_switches) = if let Some((head, sw)) = split_unrooted_cmd_switches(cmd0) {
            (head.to_ascii_lowercase(), Some(sw))
        } else {
            (
                cmd0.rsplit(['/', '\\'])
                    .next()
                    .unwrap_or(cmd0)
                    .to_ascii_lowercase(),
                None,
            )
        };
        if matches!(bin.as_str(), "sudo" | "doas" | "runas" | "pkexec" | "su") {
            add_risk(risk_tags, risk_score, "privilege-escalation", 50);
        }
        if is_network_bin(&bin) {
            add_risk(risk_tags, risk_score, "external-network", 30);
        }
        if is_destructive_clause(&bin, effective, inline_switches) {
            add_risk(risk_tags, risk_score, "destructive-action", 45);
        }
        for arg in &clause.argv {
            if let Some(url_cand) = extract_exec_url_candidate(arg, &bin)
                && let Resolution::Resolved(url_norm) =
                    classify_url_or_host(url_cand, &HostClassifierConfig::default())
            {
                apply_net_risk(&url_norm, risk_tags, risk_score);
            }
            let canon = canonicalize_path_lex(arg);
            let clean_path = strip_exec_path_ads_and_win_dots(arg, &canon);
            apply_path_class_risk(&clean_path, risk_tags, risk_score);
        }
    }
}

pub(crate) fn is_posix_only_path(raw: &str, canon: &str) -> bool {
    let trimmed = raw.trim();
    !trimmed.contains('\\')
        && !is_win_drive_prefix(trimmed)
        && !is_win_drive_prefix(canon)
        && !canon.starts_with("//")
        && (canon.starts_with('/') || canon.starts_with("~/"))
}

pub(crate) fn strip_exec_path_ads_and_win_dots(raw: &str, canon: &str) -> String {
    if is_posix_only_path(raw, canon) {
        return canon.to_owned();
    }
    let (base, _ads) = split_ntfs_ads(canon);
    canonicalize_windows_path_lex(base)
}

fn is_win_drive_prefix(s: &str) -> bool {
    let mut chars = s.chars();
    matches!(
        (chars.next(), chars.next()),
        (Some(d), Some(':')) if d.is_ascii_alphabetic()
    )
}

fn is_network_bin(bin: &str) -> bool {
    matches!(
        bin,
        "curl"
            | "wget"
            | "nc"
            | "ncat"
            | "socat"
            | "scp"
            | "rsync"
            | "invoke-webrequest"
            | "iwr"
            | "invoke-restmethod"
            | "irm"
    )
}

fn extract_exec_url_candidate<'a>(arg: &'a str, bin: &str) -> Option<&'a str> {
    let trimmed = arg.trim();
    if trimmed.is_empty() {
        return None;
    }
    if trimmed.contains("://") {
        let cand = if trimmed.starts_with('-') {
            trimmed.split_once('=').map(|(_, rhs)| rhs)?
        } else {
            trimmed
        };
        let low = cand.to_ascii_lowercase();
        if cand.contains("://") && !low.starts_with("file://") {
            return Some(cand);
        }
        return None;
    }
    if is_network_bin(bin)
        && !trimmed.starts_with('-')
        && !trimmed.starts_with('/')
        && !trimmed.starts_with('.')
        && !trimmed.contains('=')
        && !trimmed.contains('\\')
        && (trimmed.contains('.') || trimmed.contains(':'))
    {
        return Some(trimmed);
    }
    None
}

pub(crate) fn apply_path_class_risk(path: &str, risk_tags: &mut Vec<String>, risk_score: &mut u32) {
    for cls in classify_protected_path(path) {
        match cls {
            ProtectedPathClass::AgentControl
            | ProtectedPathClass::GrdrControl
            | ProtectedPathClass::MonitoringConfig => {
                add_risk(risk_tags, risk_score, "agent-control-file", 70);
            }
            ProtectedPathClass::CredStore
            | ProtectedPathClass::PrivateKey
            | ProtectedPathClass::AgentStore
            | ProtectedPathClass::BrowserStore
            | ProtectedPathClass::Autorun => {
                add_risk(risk_tags, risk_score, "sensitive-credential", 65);
            }
            ProtectedPathClass::SessionTmp => {}
        }
    }
}

pub(crate) fn apply_net_risk(
    url_norm: &NormalizedHostUrl,
    risk_tags: &mut Vec<String>,
    risk_score: &mut u32,
) {
    if url_norm.host_syntax == HostSyntax::RawIpLiteral {
        add_risk(risk_tags, risk_score, "host.raw-ip", 35);
    }
    if url_norm.userinfo == UserinfoPresence::Present {
        add_risk(risk_tags, risk_score, "url.userinfo", 45);
    }
    match url_norm.ip_exposure {
        Some(IpExposureClass::Loopback) => add_risk(risk_tags, risk_score, "ip.loopback", 30),
        Some(IpExposureClass::CloudMetadataLinkLocal) => {
            add_risk(risk_tags, risk_score, "ip.cloud-metadata", 65);
        }
        Some(IpExposureClass::PrivateRfc1918) => {
            add_risk(risk_tags, risk_score, "ip.private-rfc1918", 40);
        }
        Some(IpExposureClass::PublicRoutable) => {
            add_risk(risk_tags, risk_score, "ip.public-routable", 10);
        }
        None => {}
    }
    for cls in &url_norm.classes {
        match cls {
            HostClass::CloudMetadata => {
                add_risk(risk_tags, risk_score, "host.cloud-metadata", 65);
            }
            HostClass::PasteCapture => add_risk(risk_tags, risk_score, "host.paste-capture", 50),
            HostClass::TunnelService => {
                add_risk(risk_tags, risk_score, "host.tunnel-service", 50);
            }
            HostClass::Signup => add_risk(risk_tags, risk_score, "host.signup", 35),
            HostClass::OrgInternal => add_risk(risk_tags, risk_score, "host.org-internal", 25),
            HostClass::ModelProvider | HostClass::MultiTenantApi | HostClass::PackageRegistry => {}
        }
    }
    for fact in &url_norm.facts {
        push_unique_tag(risk_tags, &fact.key);
    }
}

pub(crate) fn apply_pattern_risk(
    raw_lower: &str,
    corpus: &str,
    action_class: ActionClass,
    risk_tags: &mut Vec<String>,
    risk_score: &mut u32,
) {
    if matches_either(
        raw_lower,
        corpus,
        &[
            ".claude/",
            ".claude.json",
            ".cursor/",
            ".codex/",
            ".gemini/",
            "grdr-data/",
            "security/",
        ],
    ) {
        add_risk(risk_tags, risk_score, "agent-control-file", 70);
    }
    if matches_either(
        raw_lower,
        corpus,
        &[
            ".ssh/",
            ".aws/",
            ".gnupg/",
            ".config/gh/",
            "id_rsa",
            "id_ed25519",
            ".env.production",
        ],
    ) {
        add_risk(risk_tags, risk_score, "sensitive-credential", 65);
    }
    if matches_either(
        raw_lower,
        corpus,
        &[
            "--dangerously-skip-permissions",
            "--no-verify",
            "--disable-hooks",
            "grdr_disable",
        ],
    ) {
        add_risk(risk_tags, risk_score, "hook-bypass", 75);
    }
    if matches_either(
        raw_lower,
        corpus,
        &[
            "rm -rf",
            "rm -fr",
            "remove-item -recurse -force",
            "git reset --hard",
            "mkfs.",
        ],
    ) || action_class == ActionClass::FileDelete
    {
        add_risk(risk_tags, risk_score, "destructive-action", 45);
    }
    if matches_either(
        raw_lower,
        corpus,
        &["sudo ", "doas ", "runas ", "verb runas"],
    ) || action_class == ActionClass::Elevate
    {
        add_risk(risk_tags, risk_score, "privilege-escalation", 50);
    }
    if matches_either(
        raw_lower,
        corpus,
        &[
            "curl ",
            "invoke-webrequest",
            "pastebin",
            "webhook.site",
            "transfer.sh",
        ],
    ) || matches!(
        action_class,
        ActionClass::NetRequest | ActionClass::NetConnect | ActionClass::DataFlow
    ) {
        add_risk(risk_tags, risk_score, "external-network", 30);
    }
    if matches!(action_class, ActionClass::McpCall | ActionClass::McpConnect)
        && matches_either(
            raw_lower,
            corpus,
            &["write", "delete", "push", "create", "execute"],
        )
    {
        add_risk(risk_tags, risk_score, "mcp-write", 35);
    }
}

pub(crate) fn add_risk(risk_tags: &mut Vec<String>, risk_score: &mut u32, tag: &str, pts: u32) {
    if push_unique_tag(risk_tags, tag) {
        *risk_score = risk_score.saturating_add(pts);
    }
}

fn push_unique_tag(risk_tags: &mut Vec<String>, tag: &str) -> bool {
    if risk_tags.iter().any(|t| t == tag) {
        false
    } else {
        risk_tags.push(tag.to_owned());
        true
    }
}

pub(crate) fn worse_parse_status(
    a: CommandParseStatus,
    b: CommandParseStatus,
) -> CommandParseStatus {
    match (a, b) {
        (CommandParseStatus::Malformed, _) | (_, CommandParseStatus::Malformed) => {
            CommandParseStatus::Malformed
        }
        (CommandParseStatus::Unresolved, _) | (_, CommandParseStatus::Unresolved) => {
            CommandParseStatus::Unresolved
        }
        _ => CommandParseStatus::Resolved,
    }
}

fn split_unrooted_cmd_switches(cmd0: &str) -> Option<(&str, &str)> {
    if cmd0.starts_with('/') {
        return None;
    }
    let tail = cmd0.rsplit('\\').next().unwrap_or(cmd0);
    let slash_idx = tail.find('/')?;
    let head = tail.get(..slash_idx)?;
    let sw = tail.get(slash_idx..)?;
    if head.eq_ignore_ascii_case("del")
        || head.eq_ignore_ascii_case("erase")
        || head.eq_ignore_ascii_case("rd")
        || head.eq_ignore_ascii_case("rmdir")
    {
        Some((head, sw))
    } else {
        None
    }
}

fn is_destructive_clause(bin: &str, argv: &[String], inline_switches: Option<&str>) -> bool {
    let mut lower_args: Vec<String> = argv.iter().map(|a| a.to_ascii_lowercase()).collect();
    if let Some(sw) = inline_switches {
        lower_args.push(sw.to_ascii_lowercase());
    }
    if bin == "rm" {
        let has_r = lower_args.iter().any(|a| {
            a == "--recursive" || (a.starts_with('-') && !a.starts_with("--") && a.contains('r'))
        });
        let has_f = lower_args.iter().any(|a| {
            a == "--force" || (a.starts_with('-') && !a.starts_with("--") && a.contains('f'))
        });
        return has_r && has_f;
    }
    if matches!(bin, "remove-item" | "ri" | "del" | "erase" | "rd" | "rmdir") {
        let has_ps_r = lower_args
            .iter()
            .any(|a| a.starts_with("-r") && "-recurse".starts_with(a.as_str()));
        let has_ps_fo = lower_args
            .iter()
            .any(|a| a.starts_with("-f") && "-force".starts_with(a.as_str()));
        if has_ps_r && has_ps_fo {
            return true;
        }
        if matches!(bin, "del" | "erase" | "rd" | "rmdir") {
            let has_switch = |sw: &str| {
                lower_args.iter().any(|a| {
                    a.starts_with('/')
                        && a.split('/').skip(1).all(|seg| {
                            !seg.is_empty()
                                && (seg.len() <= 2
                                    || (seg.starts_with('a')
                                        && seg.bytes().skip(1).all(|b| {
                                            matches!(
                                                b,
                                                b':' | b'-'
                                                    | b'r'
                                                    | b'h'
                                                    | b's'
                                                    | b'a'
                                                    | b'i'
                                                    | b'l'
                                                    | b'o'
                                            )
                                        })))
                        })
                        && a.split('/').skip(1).any(|seg| seg == sw)
                })
            };
            if has_switch("s") && has_switch("q") {
                return true;
            }
        }
        return false;
    }
    if bin == "git" {
        return is_destructive_git(&lower_args);
    }
    bin.starts_with("mkfs.")
        || (bin == "dd" && lower_args.iter().any(|a| a.starts_with("of=/dev/")))
}

fn is_destructive_git(lower_args: &[String]) -> bool {
    let mut i = 1usize;
    while let Some(arg) = lower_args.get(i) {
        if matches!(
            arg.as_str(),
            "-c" | "--git-dir" | "--work-tree" | "--namespace" | "--super-prefix"
        ) {
            i = i.saturating_add(2);
            continue;
        }
        if arg.starts_with('-') {
            i = i.saturating_add(1);
            continue;
        }
        let rest = lower_args.get(i.saturating_add(1)..).unwrap_or(&[]);
        return match arg.as_str() {
            "reset" => rest.iter().any(|a| a == "--hard"),
            "push" => rest.iter().any(|a| {
                a == "--force" || (a.starts_with('-') && !a.starts_with("--") && a.contains('f'))
            }),
            _ => false,
        };
    }
    false
}

fn matches_either(raw: &str, normalized: &str, needles: &[&str]) -> bool {
    needles
        .iter()
        .any(|needle| raw.contains(needle) || normalized.contains(needle))
}
