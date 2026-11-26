// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Shared shell canonicalisation budget, status merging, and literal argv fact collection.

use std::collections::HashSet;

use crate::analyze::cmd::{CanonicalClause, CommandTree};
use crate::analyze::cmd_dialects::ParsedClause;
use crate::analyze::cmd_wrappers::unwrap_prefix_command;
use crate::analyze::decode::DecodeBudget;
use crate::analyze::types::{
    AnalyzeFact, AnalyzeLimits, FactOriginTag, LimitKind, Resolution, ShellLimits, Span,
    UnresolvedKind, UnresolvedReason,
};

pub(super) struct CanonicaliseBudget {
    pub(super) decode: DecodeBudget,
    remaining_output_bytes: usize,
    remaining_clauses: usize,
}

impl CanonicaliseBudget {
    pub(super) fn from_limits(limits: &ShellLimits) -> Self {
        let a_limits = AnalyzeLimits::from_schema();
        Self {
            decode: DecodeBudget::new(
                a_limits.decode_max_bytes,
                a_limits.decode_max_layers,
                a_limits.decode_max_nodes,
            ),
            remaining_output_bytes: usize::try_from(limits.expanded_max)
                .unwrap_or(usize::MAX)
                .max(a_limits.decode_max_bytes),
            remaining_clauses: usize::try_from(limits.words_max).unwrap_or(4096),
        }
    }

    pub(super) fn take_output_bytes(&mut self, bytes: usize) -> bool {
        if bytes > self.remaining_output_bytes {
            return false;
        }
        self.remaining_output_bytes = self.remaining_output_bytes.saturating_sub(bytes);
        true
    }

    pub(super) fn take_clause(&mut self) -> bool {
        if self.remaining_clauses == 0 {
            return false;
        }
        self.remaining_clauses = self.remaining_clauses.saturating_sub(1);
        true
    }
}

pub(super) fn merge_sub_tree(
    parent: &mut CommandTree,
    sub: CommandTree,
    budget: &mut CanonicaliseBudget,
    span_end: usize,
) -> Result<(), Resolution<CommandTree>> {
    for c in sub.clauses {
        if !budget.take_clause() {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::Words),
                span: Span::from_usize(0, span_end),
                detail: "merged clauses exceed budget".into(),
            }]));
        }
        let clause_bytes: usize = c
            .argv
            .iter()
            .map(String::len)
            .sum::<usize>()
            .saturating_add(
                c.assignments
                    .iter()
                    .map(|(k, v)| k.len().saturating_add(v.len()))
                    .sum::<usize>(),
            );
        if !budget.take_output_bytes(clause_bytes) {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::ExpandedBytes),
                span: Span::from_usize(0, span_end),
                detail: "merged clause bytes exceed budget".into(),
            }]));
        }
        parent.clauses.push(c);
    }
    for line in sub.canonical_lines {
        if !budget.take_output_bytes(line.len()) {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::ExpandedBytes),
                span: Span::from_usize(0, span_end),
                detail: "merged canonical lines exceed budget".into(),
            }]));
        }
        parent.canonical_lines.push(line);
    }
    for child in sub.decoded_children {
        if !budget.take_output_bytes(child.len()) {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::ExpandedBytes),
                span: Span::from_usize(0, span_end),
                detail: "merged decoded children exceed budget".into(),
            }]));
        }
        parent.decoded_children.push(child);
    }
    parent.decoded_layers = parent.decoded_layers.max(sub.decoded_layers);
    parent.facts.extend(sub.facts);
    Ok(())
}

pub(super) fn merge_opt_err(
    cur: Option<Resolution<CommandTree>>,
    next: Resolution<CommandTree>,
) -> Resolution<CommandTree> {
    match cur {
        None => next,
        Some(prev) => pick_worse_resolution(prev, next),
    }
}

pub(super) fn pick_worse_resolution(
    a: Resolution<CommandTree>,
    b: Resolution<CommandTree>,
) -> Resolution<CommandTree> {
    match (a, b) {
        (m @ Resolution::Malformed(_), _) => m,
        (_, m @ Resolution::Malformed(_)) => m,
        (Resolution::Unresolved(mut u1), Resolution::Unresolved(u2)) => {
            u1.extend(u2);
            Resolution::Unresolved(u1)
        }
        (u @ Resolution::Unresolved(_), _) => u,
        (_, u @ Resolution::Unresolved(_)) => u,
        (r, _) => r,
    }
}

pub(super) fn merge_resolved_trees(mut acc: CommandTree, tree: CommandTree) -> CommandTree {
    let mut seen_lines: HashSet<String> = acc.canonical_lines.iter().cloned().collect();
    for line in tree.canonical_lines {
        if seen_lines.insert(line.clone()) {
            acc.canonical_lines.push(line);
        }
    }
    let mut seen_children: HashSet<String> = acc.decoded_children.iter().cloned().collect();
    for child in tree.decoded_children {
        if seen_children.insert(child.clone()) {
            acc.decoded_children.push(child);
        }
    }
    acc.decoded_layers = acc.decoded_layers.max(tree.decoded_layers);
    acc.facts.extend(tree.facts);
    let mut seen_clauses: HashSet<CanonicalClause> = acc.clauses.iter().cloned().collect();
    for c in tree.clauses {
        if seen_clauses.insert(c.clone()) {
            acc.clauses.push(c);
        }
    }
    acc
}

pub(super) fn collect_literal_argv_facts(clause: &ParsedClause, facts: &mut Vec<AnalyzeFact>) {
    for (k, _) in &clause.assignments {
        if k.eq_ignore_ascii_case("PGPASSWORD") || k.eq_ignore_ascii_case("MYSQL_PWD") {
            facts.push(AnalyzeFact {
                key: "exec.inline_password".into(),
                value: k.to_owned(),
                origin: FactOriginTag::Deterministic,
                span: None,
            });
        }
    }
    let unwrapped = unwrap_prefix_command(&clause.argv);
    if let Some(bin) = unwrapped.first() {
        let base = bin.rsplit(['/', '\\']).next().unwrap_or(bin);
        if (base.eq_ignore_ascii_case("sshpass")
            && unwrapped.iter().any(|a| a == "-p" || a.starts_with("-p")))
            || (base.eq_ignore_ascii_case("mysql")
                && unwrapped.iter().any(|a| a.starts_with("-p") && a.len() > 2))
            || (base.eq_ignore_ascii_case("curl")
                && unwrapped.iter().any(|a| a == "-u" || a == "--user"))
        {
            facts.push(AnalyzeFact {
                key: "exec.inline_password".into(),
                value: "cli_flag".into(),
                origin: FactOriginTag::Deterministic,
                span: None,
            });
        }
    }
    for flag in [
        "--dangerously-skip-permissions",
        "--no-verify",
        "--disable-hooks",
    ] {
        if clause.argv.iter().any(|a| a.eq_ignore_ascii_case(flag)) {
            facts.push(AnalyzeFact {
                key: "flag.bypass-permissions".into(),
                value: flag.to_owned(),
                origin: FactOriginTag::Deterministic,
                span: None,
            });
        }
    }
}

pub(super) fn push_clause_record(
    clause: &ParsedClause,
    sep_name: &str,
    tree: &mut CommandTree,
    budget: &mut CanonicaliseBudget,
    span_end: usize,
) -> Result<(), Resolution<CommandTree>> {
    let joined = clause.argv.join(" ");
    if !joined.is_empty() {
        if !budget.take_output_bytes(joined.len()) {
            return Err(Resolution::Unresolved(vec![UnresolvedReason {
                kind: UnresolvedKind::LimitExceeded(LimitKind::ExpandedBytes),
                span: Span::from_usize(0, span_end),
                detail: "canonical line byte budget exceeded".into(),
            }]));
        }
        tree.canonical_lines.push(joined);
    }
    tree.clauses.push(CanonicalClause {
        argv: clause.argv.clone(),
        assignments: clause.assignments.clone(),
        separator: sep_name.to_owned(),
    });
    Ok(())
}
