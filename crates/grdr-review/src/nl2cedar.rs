// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors

//! Watch-only `nl2cedar` pack-driven AST draft builder, ambiguity clarifications,
//! Unicode/word-boundary matching, and inert assistant re-exports (`docs/design/19`, `P2`, `P14`).

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};

use grdr_model::{ActionClass, ApprovalGrade, CodedError, Mode};
use grdr_schema::cedar::{CedarPlane, resource_entity_type_for_action, validate_policy_source};

use crate::ReviewRequirement;
pub use crate::inert::{
    AssistantContentOrigin, ExplainFindingDraft, ExplainFindingOutput, InertExplanation,
    MAX_INERT_EXPLANATION_CHARS, SummariseSessionDraft, SummariseSessionOutput,
    build_explain_finding_output, build_summarise_session_output, render_inert_explanation,
};
use crate::nl2cedar_probe::{
    InvarianceProbe, contains_normalized_term, normalize_for_matching, verify_no_new_allows,
};

pub const CODE_REV_NL2CEDAR_FORBIDDEN: &str = "GRDR-REV-0007";
const MAX_NL2CEDAR_PROMPT_BYTES: usize = 4_096;
const MAX_RULE_ID_LEN: usize = 64;
const DEFAULT_CATALOG_JSON: &str = include_str!("../data/nl2cedar-catalog.json");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nl2CedarTargetRule {
    #[serde(default)]
    pub rule_id_hint: String,
    pub keywords: Vec<String>,
    pub action_class: ActionClass,
    pub target_prefix: String,
    pub resource_class: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Nl2CedarTargetCatalog {
    #[serde(default)]
    pub version: String,
    pub rules: Vec<Nl2CedarTargetRule>,
    pub fallback_action: ActionClass,
    pub fallback_prefix: String,
    pub fallback_class: String,
    #[serde(default)]
    pub permissive_tokens: Vec<String>,
    #[serde(default)]
    pub clarification_terms: Vec<String>,
    #[serde(default)]
    pub ambiguous_principal_terms: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DraftMode {
    WatchOnly,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CedarDraftRule {
    pub rule_id: String,
    pub mode: DraftMode,
    pub mapped_mode: Mode,
    pub effect: String,
    pub action_class: ActionClass,
    pub target_prefix: String,
    pub cedar_source: String,
    pub requires_human_review: ReviewRequirement,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "scope", rename_all = "snake_case")]
pub enum BuilderPrincipalScope {
    AllSessions,
    SessionLabel { label: String },
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CedarForbidBuilderAst {
    pub rule_id: String,
    pub principal_scope: BuilderPrincipalScope,
    pub action_class: ActionClass,
    pub target_prefix: String,
    pub resource_class: String,
    #[serde(default)]
    pub unless_label: Option<String>,
    #[serde(default)]
    pub require_recursive_context: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Nl2CedarAuthoringRequest {
    pub rule_id: String,
    pub prompt: String,
    pub org_classes: BTreeSet<String>,
    pub org_lists: BTreeSet<String>,
    pub org_labels: BTreeSet<String>,
    pub baseline_cedar_source: Option<String>,
    pub approved_clarifications: BTreeSet<String>,
    pub builder_override: Option<CedarForbidBuilderAst>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "status", rename_all = "snake_case")]
pub enum Nl2CedarOutcome {
    Draft(CedarDraftRule),
    NeedsClarification {
        ambiguous_terms: Vec<String>,
        questions: Vec<String>,
    },
}

impl Default for Nl2CedarTargetCatalog {
    fn default() -> Self {
        Self::embedded().unwrap_or_else(|_| Self {
            version: "fallback".into(),
            rules: Vec::new(),
            fallback_action: ActionClass::Exec,
            fallback_prefix: "custom.watch".into(),
            fallback_class: "custom-watch".into(),
            permissive_tokens: vec!["permit".into(), "allow".into(), "grant".into()],
            clarification_terms: Vec::new(),
            ambiguous_principal_terms: Vec::new(),
        })
    }
}

impl Nl2CedarTargetCatalog {
    pub fn embedded() -> Result<Self, CodedError> {
        Self::from_json_str(DEFAULT_CATALOG_JSON)
    }

    pub fn from_json_str(raw: &str) -> Result<Self, CodedError> {
        serde_json::from_str::<Self>(raw).map_err(|e| {
            nl_err(
                format!("invalid nl2cedar catalog JSON: {e}"),
                "Fix nl2cedar catalog pack syntax.",
            )
        })
    }
}

/// Generates a Watch-only `forbid` Cedar draft from the embedded data-driven catalog.
pub fn draft_watch_only_nl2cedar(
    prompt: &str,
    rule_id: &str,
) -> Result<CedarDraftRule, CodedError> {
    let catalog = Nl2CedarTargetCatalog::embedded()?;
    draft_watch_only_nl2cedar_with_catalog(prompt, rule_id, &catalog)
}

/// Generates a Watch-only `forbid` Cedar draft using an explicit data-driven target catalog.
pub fn draft_watch_only_nl2cedar_with_catalog(
    prompt: &str,
    rule_id: &str,
    catalog: &Nl2CedarTargetCatalog,
) -> Result<CedarDraftRule, CodedError> {
    let norm = validate_prompt_and_rule_id(prompt, rule_id, catalog)?;
    let (action_class, target_prefix, resource_class) = infer_target_from_catalog(&norm, catalog);
    let safe_prefix = sanitize_cedar_string_literal(&target_prefix)?;
    let safe_class = sanitize_cedar_string_literal(&resource_class)?;
    let ast = CedarForbidBuilderAst {
        rule_id: rule_id.to_owned(),
        principal_scope: BuilderPrincipalScope::AllSessions,
        action_class,
        target_prefix: safe_prefix,
        resource_class: safe_class,
        unless_label: None,
        require_recursive_context: false,
    };
    let cedar_source = render_and_validate_ast(&ast, None)?;
    Ok(build_draft_rule(ast, cedar_source))
}

/// Evaluates a full NL2Cedar authoring request with clarification detection,
/// typed builder AST generation, strict Cedar schema check, and baseline `ALLOW` invariance (`AI-13`).
pub fn author_watch_only_nl2cedar(
    req: &Nl2CedarAuthoringRequest,
    catalog: &Nl2CedarTargetCatalog,
) -> Result<Nl2CedarOutcome, CodedError> {
    let norm = validate_prompt_and_rule_id(&req.prompt, &req.rule_id, catalog)?;
    if let Some((ambiguous_terms, questions)) = detect_clarifications_needed(&norm, req, catalog) {
        return Ok(Nl2CedarOutcome::NeedsClarification {
            ambiguous_terms,
            questions,
        });
    }

    let ast = if let Some(override_ast) = &req.builder_override {
        if override_ast.rule_id != req.rule_id {
            return Err(nl_err(
                "builder AST rule_id mismatch",
                "Align rule_id across request and AST.",
            ));
        }
        sanitize_builder_ast(override_ast, &req.org_labels)?
    } else {
        let (action_class, target_prefix, resource_class) =
            infer_target_from_catalog(&norm, catalog);
        CedarForbidBuilderAst {
            rule_id: req.rule_id.clone(),
            principal_scope: BuilderPrincipalScope::AllSessions,
            action_class,
            target_prefix: sanitize_cedar_string_literal(&target_prefix)?,
            resource_class: sanitize_cedar_string_literal(&resource_class)?,
            unless_label: None,
            require_recursive_context: contains_normalized_term(&norm, "recursive"),
        }
    };

    let cedar_source = render_and_validate_ast(&ast, req.baseline_cedar_source.as_deref())?;
    Ok(Nl2CedarOutcome::Draft(build_draft_rule(ast, cedar_source)))
}

fn validate_prompt_and_rule_id(
    prompt: &str,
    rule_id: &str,
    catalog: &Nl2CedarTargetCatalog,
) -> Result<String, CodedError> {
    validate_cedar_rule_id(rule_id)?;
    if prompt.len() > MAX_NL2CEDAR_PROMPT_BYTES {
        return Err(nl_err(
            "nl2cedar prompt exceeds max byte bound",
            "Shorten prompt and retry.",
        ));
    }
    let norm = normalize_for_matching(prompt);
    if norm.is_empty() {
        return Err(nl_err(
            "nl2cedar prompt cannot be empty",
            "Provide a restrictive description.",
        ));
    }
    for bad in &catalog.permissive_tokens {
        if contains_normalized_term(&norm, bad) {
            return Err(nl_err(
                format!("nl2cedar refused permissive request token `{bad}` under P2"),
                "nl2cedar generates Watch-only forbid drafts and cannot emit permits.",
            ));
        }
    }
    Ok(norm)
}

fn detect_clarifications_needed(
    norm: &str,
    req: &Nl2CedarAuthoringRequest,
    catalog: &Nl2CedarTargetCatalog,
) -> Option<(Vec<String>, Vec<String>)> {
    let mut terms = Vec::new();
    let mut questions = Vec::new();
    for term in &catalog.clarification_terms {
        let mapped = req.org_classes.contains(term)
            || req.org_lists.contains(term)
            || req.org_labels.contains(term)
            || req.approved_clarifications.contains(term);
        if !mapped && contains_normalized_term(norm, term) {
            terms.push(term.clone());
            questions.push(format!(
                "Clarify `{term}` using an explicit org class, list, or label."
            ));
        }
    }
    for principal_term in &catalog.ambiguous_principal_terms {
        let has_resolved = req.builder_override.as_ref().is_some_and(|b| {
            matches!(
                b.principal_scope,
                BuilderPrincipalScope::SessionLabel { .. }
            )
        }) || req.approved_clarifications.contains(principal_term);
        if !has_resolved && contains_normalized_term(norm, principal_term) {
            terms.push(principal_term.clone());
            questions.push(format!(
                "Specify exact principal role instead of `{principal_term}`."
            ));
        }
    }
    if contains_normalized_term(norm, "and")
        && contains_normalized_term(norm, "or")
        && !norm.contains('(')
        && !req.approved_clarifications.contains("boolean_precedence")
    {
        terms.push("boolean_precedence".into());
        questions.push("Group combined `and` / `or` clauses with parentheses.".into());
    }
    (!terms.is_empty()).then_some((terms, questions))
}

fn nl_err(msg: impl Into<String>, hint: &str) -> CodedError {
    CodedError::new(CODE_REV_NL2CEDAR_FORBIDDEN, msg, hint)
}

fn sanitize_builder_ast(
    ast: &CedarForbidBuilderAst,
    org_labels: &BTreeSet<String>,
) -> Result<CedarForbidBuilderAst, CodedError> {
    let safe_prefix = sanitize_cedar_string_literal(&ast.target_prefix)?;
    let safe_class = sanitize_cedar_string_literal(&ast.resource_class)?;
    let principal_scope = match &ast.principal_scope {
        BuilderPrincipalScope::AllSessions => BuilderPrincipalScope::AllSessions,
        BuilderPrincipalScope::SessionLabel { label } => {
            let safe_label = sanitize_cedar_string_literal(label)?;
            if !org_labels.contains(&safe_label) {
                return Err(nl_err(
                    format!(
                        "session scope label `{safe_label}` missing from registered org labels"
                    ),
                    "Use a declared organisation label for principal scoping.",
                ));
            }
            BuilderPrincipalScope::SessionLabel { label: safe_label }
        }
    };
    let unless_label = match &ast.unless_label {
        Some(lbl) => {
            let safe_lbl = sanitize_cedar_string_literal(lbl)?;
            if !org_labels.contains(&safe_lbl) {
                return Err(nl_err(
                    format!("unless label `{safe_lbl}` missing from org label registry"),
                    "Register label before referencing it in a Watch-only draft.",
                ));
            }
            Some(safe_lbl)
        }
        None => None,
    };
    Ok(CedarForbidBuilderAst {
        rule_id: ast.rule_id.clone(),
        principal_scope,
        action_class: ast.action_class,
        target_prefix: safe_prefix,
        resource_class: safe_class,
        unless_label,
        require_recursive_context: ast.require_recursive_context,
    })
}

fn render_and_validate_ast(
    ast: &CedarForbidBuilderAst,
    baseline_cedar_source: Option<&str>,
) -> Result<String, CodedError> {
    let resource_type = resource_entity_type_for_action(ast.action_class.as_str());
    let mut when_clauses = vec![format!(
        "resource.classes.contains(\"{}\")",
        ast.resource_class
    )];
    if ast.require_recursive_context
        && matches!(
            ast.action_class,
            ActionClass::FileRead | ActionClass::FileWrite | ActionClass::FileDelete
        )
    {
        when_clauses.push("context.recursive".into());
    }
    if let BuilderPrincipalScope::SessionLabel { ref label } = ast.principal_scope {
        when_clauses.push(format!("context.session.labels.contains(\"{label}\")"));
    }
    let unless_block = ast
        .unless_label
        .as_ref()
        .map(|lbl| format!("\nunless {{ context.session.labels.contains(\"{lbl}\") }}"))
        .unwrap_or_default();

    let source = format!(
        "@id(\"{}\")\n@mode(\"watch\")\nforbid (\n  principal is Grdr::Session,\n  action == Grdr::Action::\"{}\",\n  resource is {resource_type}\n)\nwhen {{ {} }}{unless_block};",
        ast.rule_id,
        ast.action_class.as_str(),
        when_clauses.join(" && "),
    );
    let draft_set = validate_policy_source(CedarPlane::Runtime, &source).map_err(|e| {
        nl_err(
            format!("generated Cedar draft failed schema check: {e}"),
            "Review parameters.",
        )
    })?;
    let all_watch_forbid_non_final = draft_set.policies().all(|p| {
        p.effect() == cedar_policy::Effect::Forbid
            && p.annotation("mode") == Some("watch")
            && p.annotation("final").is_none()
    });
    if draft_set.policies().count() != 1 || !all_watch_forbid_non_final {
        return Err(nl_err(
            "nl2cedar AST validation rejected non-watch, final, permit, or multi-statement draft",
            "Only a single Watch-only non-final forbid statement is permitted.",
        ));
    }
    if let Some(baseline_src) = baseline_cedar_source {
        let mut probe_labels = Vec::new();
        if let BuilderPrincipalScope::SessionLabel { ref label } = ast.principal_scope {
            probe_labels.push(label.clone());
        }
        if let Some(ref lbl) = ast.unless_label {
            probe_labels.push(lbl.clone());
        }
        verify_no_new_allows(&InvarianceProbe {
            baseline_src,
            draft_src: &source,
            action_name: ast.action_class.as_str(),
            resource_type,
            resource_class: &ast.resource_class,
            probe_labels: &probe_labels,
        })?;
    }
    Ok(source)
}

fn build_draft_rule(ast: CedarForbidBuilderAst, cedar_source: String) -> CedarDraftRule {
    CedarDraftRule {
        rule_id: ast.rule_id,
        mode: DraftMode::WatchOnly,
        mapped_mode: Mode::Watch,
        effect: "forbid".into(),
        action_class: ast.action_class,
        target_prefix: ast.target_prefix,
        cedar_source,
        requires_human_review: ReviewRequirement::StepUpApproval {
            min_grade: ApprovalGrade::G2,
        },
    }
}

fn validate_cedar_rule_id(rule_id: &str) -> Result<(), CodedError> {
    if rule_id.is_empty()
        || rule_id.len() > MAX_RULE_ID_LEN
        || !rule_id
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
    {
        return Err(nl_err(
            "invalid rule_id: must match ^[A-Za-z0-9._-]{1,64}$",
            "Use an alphanumeric identifier with `.`, `_`, or `-` only.",
        ));
    }
    Ok(())
}

fn sanitize_cedar_string_literal(raw: &str) -> Result<String, CodedError> {
    if raw.is_empty()
        || raw.len() > 128
        || raw.contains('"')
        || raw.contains('\\')
        || raw.chars().any(char::is_control)
    {
        return Err(nl_err(
            "invalid target string literal in nl2cedar catalog",
            "Use bounded ASCII string literals without quotes or control bytes.",
        ));
    }
    Ok(raw.to_owned())
}

fn infer_target_from_catalog(
    norm: &str,
    catalog: &Nl2CedarTargetCatalog,
) -> (ActionClass, String, String) {
    let mut best: Option<(usize, &Nl2CedarTargetRule)> = None;
    for entry in &catalog.rules {
        let hits = entry
            .keywords
            .iter()
            .filter(|kw| contains_normalized_term(norm, kw))
            .count();
        if hits > 0 && best.is_none_or(|(best_hits, _)| hits > best_hits) {
            best = Some((hits, entry));
        }
    }
    if let Some((_, entry)) = best {
        return (
            entry.action_class,
            entry.target_prefix.clone(),
            entry.resource_class.clone(),
        );
    }
    (
        catalog.fallback_action,
        catalog.fallback_prefix.clone(),
        catalog.fallback_class.clone(),
    )
}
