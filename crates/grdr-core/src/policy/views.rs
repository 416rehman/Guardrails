// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! 3-tier Simple / Advanced / Cedar views, round-trip canonicalizer, and Cedar source lints.

use std::collections::BTreeSet;

use cedar_policy::{Effect, Policy};
use grdr_model::{ActionClass, ApprovalGrade, LossBehaviour, Mode, RemedyCapability};

use super::PolicyError;
use super::lint::MAX_CEDAR_NESTING_DEPTH;
pub use super::lint::{compute_cedar_reads, lint_cedar_source_extended};
use super::lint_scan::{cedar_body_slice, check_cedar_nesting_depth, strip_comments_and_strings};
use super::render::{
    escape_cedar_string, parse_optional_final, parse_optional_grade, parse_optional_loss,
    parse_optional_mode, parse_optional_obligation, parse_optional_remedy,
};

const ALL_ACTION_CLASSES: [ActionClass; 15] = [
    ActionClass::Exec,
    ActionClass::FileRead,
    ActionClass::FileWrite,
    ActionClass::FileDelete,
    ActionClass::NetConnect,
    ActionClass::NetRequest,
    ActionClass::LlmRequest,
    ActionClass::McpConnect,
    ActionClass::McpCall,
    ActionClass::CredUse,
    ActionClass::AgentSpawn,
    ActionClass::ConfigChange,
    ActionClass::Elevate,
    ActionClass::UiAct,
    ActionClass::DataFlow,
];

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PrincipalFilter {
    SessionOnly,
    AnyPrincipal,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum WorkspaceScope {
    AnyPath,
    OutsideWorkspaceOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecursionFilter {
    AnyOp,
    RecursiveOnly,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SnapshotObligation {
    NotRequired,
    Required,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RuleAnnotations {
    pub id: String,
    pub class: String,
    pub mode: Mode,
    pub max_mode: Mode,
    pub min_grade: ApprovalGrade,
    pub on_loss: LossBehaviour,
    pub remedy: RemedyCapability,
    pub final_rule: bool,
    pub snapshot: SnapshotObligation,
    pub message: String,
    pub steer: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SimpleRuleView {
    pub rule_id: String,
    pub title: String,
    pub mode: Mode,
    pub action_classes: Vec<ActionClass>,
    pub protect_list: BTreeSet<String>,
    pub allow_list: BTreeSet<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AdvancedRuleAst {
    pub annotations: RuleAnnotations,
    pub principal_filter: PrincipalFilter,
    pub workspace_scope: WorkspaceScope,
    pub recursion_filter: RecursionFilter,
    pub action_classes: Vec<ActionClass>,
    pub resource_classes: BTreeSet<String>,
    pub command_classes: BTreeSet<String>,
    pub facts: BTreeSet<String>,
    pub unless_classes: BTreeSet<String>,
}

pub fn simple_to_advanced(view: &SimpleRuleView) -> AdvancedRuleAst {
    let mut resource_classes = BTreeSet::new();
    if !view.protect_list.is_empty() {
        resource_classes.insert(format!("match:{}", view.rule_id));
    }
    let mut unless_classes = BTreeSet::new();
    for allowed in &view.allow_list {
        unless_classes.insert(format!("allow:{allowed}"));
    }
    AdvancedRuleAst {
        annotations: RuleAnnotations {
            id: view.rule_id.clone(),
            class: "custom".into(),
            mode: view.mode,
            max_mode: Mode::Block,
            min_grade: ApprovalGrade::G1,
            on_loss: LossBehaviour::FailClosed,
            remedy: RemedyCapability::Plain,
            final_rule: view.mode == Mode::Block,
            snapshot: SnapshotObligation::NotRequired,
            message: view.title.clone(),
            steer: "Follow workspace policy or request an exception.".into(),
        },
        principal_filter: PrincipalFilter::SessionOnly,
        workspace_scope: WorkspaceScope::AnyPath,
        recursion_filter: RecursionFilter::AnyOp,
        action_classes: view.action_classes.clone(),
        resource_classes,
        command_classes: BTreeSet::new(),
        facts: BTreeSet::new(),
        unless_classes,
    }
}

pub fn advanced_to_cedar(ast: &AdvancedRuleAst) -> String {
    let ann = &ast.annotations;
    let principal = match ast.principal_filter {
        PrincipalFilter::SessionOnly => "principal is Grdr::Session",
        PrincipalFilter::AnyPrincipal => "principal",
    };
    let action_clause = render_action_clause(&ast.action_classes);
    let mut when_clauses = Vec::new();
    if ast.recursion_filter == RecursionFilter::RecursiveOnly {
        when_clauses.push("context.recursive".into());
    }
    if ast.workspace_scope == WorkspaceScope::OutsideWorkspaceOnly {
        when_clauses.push("!resource.in_workspace".into());
    }
    if !ast.resource_classes.is_empty() {
        when_clauses.push(format!(
            "resource.classes.containsAny([{}])",
            render_string_list(&ast.resource_classes)
        ));
    }
    if !ast.command_classes.is_empty() {
        when_clauses.push(format!(
            "context.command.classes.containsAny([{}])",
            render_string_list(&ast.command_classes)
        ));
    }
    if !ast.facts.is_empty() {
        when_clauses.push(format!(
            "context.facts.containsAny([{}])",
            render_string_list(&ast.facts)
        ));
    }

    let when_block = if when_clauses.is_empty() {
        String::new()
    } else {
        format!("\nwhen {{ {} }}", when_clauses.join(" && "))
    };
    let unless_block = if ast.unless_classes.is_empty() {
        String::new()
    } else {
        format!(
            "\nunless {{ resource.classes.containsAny([{}]) }}",
            render_string_list(&ast.unless_classes)
        )
    };

    let on_loss_label = match ann.on_loss {
        LossBehaviour::AllowOnLoss => "allow",
        LossBehaviour::FailClosed => "step-up",
        LossBehaviour::Block => "block",
    };
    let final_line = if ann.final_rule {
        "\n@final(\"true\")"
    } else {
        ""
    };
    let remedy_line = if ann.remedy == RemedyCapability::ModifyTransform {
        "\n@remedy(\"modify\")"
    } else {
        ""
    };
    let obligation_line = if ann.snapshot == SnapshotObligation::Required {
        "\n@obligation(\"snapshot\")"
    } else {
        ""
    };

    format!(
        "@id(\"{id}\")\n@class(\"{class}\")\n@mode(\"{mode}\")\n@max_mode(\"{max_mode}\")\n@min_grade(\"{min_grade:?}\")\n@on_loss(\"{on_loss_label}\"){final_line}{remedy_line}{obligation_line}\n@message(\"{msg}\")\n@steer(\"{steer}\")\nforbid (\n  {principal},\n  {action_clause},\n  resource\n){when_block}{unless_block};",
        id = escape_str(&ann.id),
        class = escape_str(&ann.class),
        mode = ann.mode.label(),
        max_mode = ann.max_mode.label(),
        min_grade = ann.min_grade,
        msg = escape_str(&ann.message),
        steer = escape_str(&ann.steer),
    )
}

pub fn parse_cedar_to_advanced(source: &str) -> Result<AdvancedRuleAst, PolicyError> {
    check_cedar_nesting_depth("view-parse", source)?;
    let policy =
        Policy::parse_with_depth_limit(None, source, MAX_CEDAR_NESTING_DEPTH).map_err(|e| {
            PolicyError::CompileFailed {
                rule_id: "view-parse".into(),
                detail: e.to_string(),
            }
        })?;
    if policy.effect() != Effect::Forbid {
        return Err(PolicyError::PermitNotAllowed {
            rule_id: policy.id().to_string(),
        });
    }
    let rule_id = policy.annotation("id").unwrap_or("view-parse");
    let canonical = policy.to_string();
    let body = cedar_body_slice(&canonical);
    let body_sanitized = strip_comments_and_strings(body, false);
    let unsupported = [
        "||",
        "containsAll",
        "!=",
        " like ",
        "resource.port",
        "context.session.labels",
        "context.source_labels",
        "context.cloud",
        "context.tenant",
        "context.http",
        "context.args",
        "context.child",
        "context.change_classes",
        "context.attribution",
        "context.assurance",
        "principal is Grdr::Process",
        "principal in",
    ];
    let body_no_allowed_not = body_sanitized.replace("!resource.in_workspace", "");
    let has_unsupported_not = body_no_allowed_not.contains('!');
    let eq_outside_action = body_sanitized.match_indices("==").any(|(idx, _)| {
        let before = body_sanitized.get(..idx).unwrap_or("").trim_end();
        !before.strip_suffix("action").is_some_and(|head| {
            head.chars()
                .next_back()
                .is_none_or(|c| !c.is_ascii_alphanumeric() && c != '_')
        })
    });
    if unsupported.iter().any(|tok| body_sanitized.contains(tok))
        || has_unsupported_not
        || eq_outside_action
    {
        return Err(PolicyError::ValidationFailed {
            rule_id: rule_id.into(),
            detail: "rule contains predicates outside the Advanced builder subset".into(),
        });
    }
    let mode = parse_optional_mode(rule_id, policy.annotation("mode"), Mode::Ask)?;
    let max_mode = parse_optional_mode(rule_id, policy.annotation("max_mode"), Mode::Block)?;
    let min_grade =
        parse_optional_grade(rule_id, policy.annotation("min_grade"))?.unwrap_or(ApprovalGrade::G1);
    let on_loss = parse_optional_loss(rule_id, policy.annotation("on_loss"), None)?;
    let final_rule = parse_optional_final(rule_id, policy.annotation("final"))?;
    let remedy = if parse_optional_remedy(rule_id, policy.annotation("remedy"))?.is_some() {
        RemedyCapability::ModifyTransform
    } else {
        RemedyCapability::Plain
    };
    let snapshot = if parse_optional_obligation(rule_id, policy.annotation("obligation"))?
        .as_deref()
        == Some("snapshot")
    {
        SnapshotObligation::Required
    } else {
        SnapshotObligation::NotRequired
    };
    let annotations = RuleAnnotations {
        id: policy.annotation("id").unwrap_or("custom.rule").to_owned(),
        class: policy.annotation("class").unwrap_or("custom").to_owned(),
        mode,
        max_mode,
        min_grade,
        on_loss,
        remedy,
        final_rule,
        snapshot,
        message: policy
            .annotation("message")
            .unwrap_or("Blocked by rule.")
            .to_owned(),
        steer: policy
            .annotation("steer")
            .unwrap_or("Follow policy guidance.")
            .to_owned(),
    };

    let mut action_classes = Vec::new();
    for ac in ALL_ACTION_CLASSES {
        let marker = format!("Grdr::Action::\"{}\"", ac.as_str());
        if body.contains(&marker) {
            action_classes.push(ac);
        }
    }

    let (when_part, unless_part) = body.split_once("unless").unwrap_or((body, ""));
    let mut resource_classes = BTreeSet::new();
    if let Some(after_res) = when_part.split("resource.classes").nth(1) {
        let clause = after_res.split("&&").next().unwrap_or(after_res);
        extract_quoted_literals(clause, &mut resource_classes);
    }
    let mut facts = BTreeSet::new();
    if let Some(after_facts) = when_part.split("context.facts").nth(1) {
        let clause = after_facts.split("&&").next().unwrap_or(after_facts);
        extract_quoted_literals(clause, &mut facts);
    }
    let mut command_classes = BTreeSet::new();
    if let Some(after_cmd) = when_part.split("context.command.classes").nth(1) {
        let clause = after_cmd.split("&&").next().unwrap_or(after_cmd);
        extract_quoted_literals(clause, &mut command_classes);
    }
    let mut unless_classes = BTreeSet::new();
    if !unless_part.is_empty() {
        let unless_sanitized = strip_comments_and_strings(unless_part, false);
        if !unless_sanitized.contains("resource.classes") || unless_sanitized.contains("&&") {
            return Err(PolicyError::ValidationFailed {
                rule_id: rule_id.into(),
                detail: "unless clause is outside the Advanced builder subset".into(),
            });
        }
        extract_quoted_literals(unless_part, &mut unless_classes);
    }

    Ok(AdvancedRuleAst {
        annotations,
        principal_filter: if body.contains("principal is Grdr::Session") {
            PrincipalFilter::SessionOnly
        } else {
            PrincipalFilter::AnyPrincipal
        },
        workspace_scope: if body.contains("!resource.in_workspace") {
            WorkspaceScope::OutsideWorkspaceOnly
        } else {
            WorkspaceScope::AnyPath
        },
        recursion_filter: if body.contains("context.recursive") {
            RecursionFilter::RecursiveOnly
        } else {
            RecursionFilter::AnyOp
        },
        action_classes,
        resource_classes,
        command_classes,
        facts,
        unless_classes,
    })
}

pub fn canonicalize_cedar_via_roundtrip(source: &str) -> Result<String, PolicyError> {
    let ast = parse_cedar_to_advanced(source)?;
    let printed = advanced_to_cedar(&ast);
    let reparsed = parse_cedar_to_advanced(&printed)?;
    Ok(advanced_to_cedar(&reparsed))
}

fn render_action_clause(actions: &[ActionClass]) -> String {
    if actions.is_empty() {
        "action in Grdr::Action::\"any\"".into()
    } else if actions.len() == 1 {
        let act = actions.first().map(|a| a.as_str()).unwrap_or("exec");
        format!("action == Grdr::Action::\"{act}\"")
    } else {
        let items: Vec<String> = actions
            .iter()
            .map(|a| format!("Grdr::Action::\"{}\"", a.as_str()))
            .collect();
        format!("action in [{}]", items.join(", "))
    }
}

fn render_string_list(values: &BTreeSet<String>) -> String {
    values
        .iter()
        .map(|s| format!("\"{}\"", escape_str(s)))
        .collect::<Vec<_>>()
        .join(", ")
}

fn extract_quoted_literals(segment: &str, out: &mut BTreeSet<String>) {
    let mut in_string = false;
    let mut escaped = false;
    let mut current = String::new();
    for ch in segment.chars() {
        if !in_string {
            if ch == '"' {
                in_string = true;
                current.clear();
            }
            continue;
        }
        if escaped {
            let unesc = match ch {
                'n' => '\n',
                'r' => '\r',
                't' => '\t',
                other => other,
            };
            current.push(unesc);
            escaped = false;
        } else if ch == '\\' {
            escaped = true;
        } else if ch == '"' {
            in_string = false;
            if !current.is_empty() {
                out.insert(current.clone());
            }
        } else {
            current.push(ch);
        }
    }
}

pub(crate) fn parse_mode_attr(raw: Option<&str>) -> Option<Mode> {
    match raw? {
        "Off" => Some(Mode::Off),
        "Watch" => Some(Mode::Watch),
        "Ask" => Some(Mode::Ask),
        "Block" => Some(Mode::Block),
        _ => None,
    }
}

pub(crate) fn parse_grade_attr(raw: Option<&str>) -> Option<ApprovalGrade> {
    match raw? {
        "G0" => Some(ApprovalGrade::G0),
        "G1" => Some(ApprovalGrade::G1),
        "G2" => Some(ApprovalGrade::G2),
        "G3" => Some(ApprovalGrade::G3),
        _ => None,
    }
}

pub(crate) fn parse_loss_attr(raw: Option<&str>) -> Option<LossBehaviour> {
    match raw? {
        "allow" => Some(LossBehaviour::AllowOnLoss),
        "step-up" => Some(LossBehaviour::FailClosed),
        "block" => Some(LossBehaviour::Block),
        _ => None,
    }
}

fn escape_str(raw: &str) -> String {
    escape_cedar_string(raw)
}
