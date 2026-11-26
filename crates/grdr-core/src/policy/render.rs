// SPDX-License-Identifier: Apache-2.0
// SPDX-FileCopyrightText: The Guardrails ADR Authors
//! Renders PolicyRules to Cedar 4.x text and performs strict single-policy validation.

use std::str::FromStr;

use cedar_policy::{Effect, Policy, PolicyId, PolicySet, Schema, ValidationMode, Validator, pst};
use grdr_model::{ApprovalGrade, LossBehaviour, Mode, PolicyRule};

use super::PolicyError;
use super::compiler::runtime_schema;
use super::views::{parse_grade_attr, parse_loss_attr, parse_mode_attr};

pub(crate) const PARSER_DEPTH_LIMIT: usize = 64;
pub(crate) const BASE_PERMIT_ID: &str = "grdr.base.permit";
const BASE_PERMIT_CEDAR: &str = r#"@id("grdr.base.permit")
permit (principal, action, resource);"#;

pub(crate) struct ParsedRuleAnns {
    pub(crate) min_grade: Option<ApprovalGrade>,
    pub(crate) on_loss: LossBehaviour,
    pub(crate) approver: String,
    pub(crate) remedy_transform: Option<String>,
    pub(crate) requires_snapshot: bool,
    pub(crate) is_final: bool,
}

pub fn validate_cedar_rule(source: &str) -> Result<Policy, PolicyError> {
    let schema = runtime_schema()?;
    let policy = Policy::parse_with_depth_limit(None, source, PARSER_DEPTH_LIMIT).map_err(|e| {
        PolicyError::CompileFailed {
            rule_id: "custom".into(),
            detail: e.to_string(),
        }
    })?;
    if policy.effect() != Effect::Forbid {
        return Err(PolicyError::PermitNotAllowed {
            rule_id: policy.id().to_string(),
        });
    }
    let mut set = PolicySet::new();
    let pid = policy.id().to_string();
    add_policy_to_set(&mut set, policy.clone(), &pid)?;
    validate_policy_set(schema, &set, &pid)?;
    Ok(policy)
}

pub fn render_rule_cedar(rule: &PolicyRule) -> String {
    let id_esc = escape_cedar_string(&rule.id);
    let reason_esc = escape_cedar_string(&rule.reason_template);
    let mode_label = rule.mode.label();
    let min_grade = format!("{:?}", rule.min_grade);
    let final_attr = if rule.locked && rule.mode == grdr_model::Mode::Block {
        " @final(\"true\")"
    } else {
        ""
    };

    let action_clause = if rule.matcher.action_classes.is_empty() {
        "action in Grdr::Action::\"any\"".to_string()
    } else if rule.matcher.action_classes.len() == 1 {
        let act = rule
            .matcher
            .action_classes
            .first()
            .map(|a| a.as_str())
            .unwrap_or("exec");
        format!("action == Grdr::Action::\"{act}\"")
    } else {
        let items: Vec<String> = rule
            .matcher
            .action_classes
            .iter()
            .map(|a| format!("Grdr::Action::\"{}\"", a.as_str()))
            .collect();
        format!("action in [{}]", items.join(", "))
    };

    let mut conditions = Vec::new();
    if !rule.matcher.agents.is_empty() {
        let checks: Vec<String> = rule
            .matcher
            .agents
            .iter()
            .map(|agent| {
                let norm = escape_cedar_string(&agent.trim().to_ascii_lowercase());
                format!("principal in Grdr::Agent::\"{norm}\"")
            })
            .collect();
        if checks.len() == 1 {
            if let Some(single) = checks.into_iter().next() {
                conditions.push(single);
            }
        } else {
            conditions.push(format!("({})", checks.join(" || ")));
        }
    }
    if !rule.matcher.target_prefixes.is_empty() || !rule.matcher.target_contains.is_empty() {
        conditions.push(format!("resource.classes.contains(\"match:{id_esc}\")"));
    }

    let when_block = if conditions.is_empty() {
        String::new()
    } else {
        format!("\nwhen {{ {} }}", conditions.join(" && "))
    };

    format!(
        "@id(\"{id_esc}\")\n@class(\"out-of-boundary\")\n@mode(\"{mode_label}\")\n@min_grade(\"{min_grade}\"){final_attr}\n@message(\"{reason_esc}\")\nforbid (\n  principal is Grdr::Session,\n  {action_clause},\n  resource\n){when_block};"
    )
}

pub(crate) fn validate_policy_set(
    schema: &Schema,
    set: &PolicySet,
    label: &str,
) -> Result<(), PolicyError> {
    let validator = Validator::new(schema.clone());
    let result = validator.validate(set, ValidationMode::Strict);
    if !result.validation_passed() {
        let errs: Vec<String> = result
            .validation_errors()
            .map(ToString::to_string)
            .collect();
        return Err(PolicyError::ValidationFailed {
            rule_id: label.into(),
            detail: errs.join("; "),
        });
    }
    Ok(())
}

pub(crate) fn add_policy_to_set(
    set: &mut PolicySet,
    policy: Policy,
    rule_id: &str,
) -> Result<(), PolicyError> {
    set.add(policy).map_err(|e| PolicyError::CompileFailed {
        rule_id: rule_id.into(),
        detail: e.to_string(),
    })
}

pub(crate) fn parse_policy_id(raw: &str) -> Result<PolicyId, PolicyError> {
    PolicyId::from_str(raw).map_err(|e| PolicyError::CompileFailed {
        rule_id: raw.into(),
        detail: e.to_string(),
    })
}

pub(crate) fn build_grant_unless_clause(rule_id: &str) -> Result<pst::Clause, PolicyError> {
    let escaped = escape_cedar_string(rule_id);
    let helper_src = format!(
        "forbid (principal, action, resource) unless {{ context.grants.contains(\"{escaped}\") }};"
    );
    let helper =
        Policy::parse_with_depth_limit(None, &helper_src, PARSER_DEPTH_LIMIT).map_err(|e| {
            PolicyError::CompileFailed {
                rule_id: rule_id.into(),
                detail: e.to_string(),
            }
        })?;
    let pst_helper = helper
        .try_into_pst()
        .map_err(|e| PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: e.to_string(),
        })?;
    let pst::Policy::Static(sp) = pst_helper else {
        return Err(PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: "unexpected linked policy while building grant clause".into(),
        });
    };
    sp.body()
        .clauses()
        .first()
        .cloned()
        .ok_or_else(|| PolicyError::CompileFailed {
            rule_id: rule_id.into(),
            detail: "missing unless clause in grant helper".into(),
        })
}

pub(crate) fn add_base_permit(set: &mut PolicySet) -> Result<(), PolicyError> {
    let base_policy = Policy::parse_with_depth_limit(
        Some(parse_policy_id(BASE_PERMIT_ID)?),
        BASE_PERMIT_CEDAR,
        PARSER_DEPTH_LIMIT,
    )
    .map_err(|e| PolicyError::CompileFailed {
        rule_id: BASE_PERMIT_ID.into(),
        detail: e.to_string(),
    })?;
    add_policy_to_set(set, base_policy, BASE_PERMIT_ID)
}

pub(crate) fn escape_cedar_string(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    for ch in raw.chars() {
        match ch {
            '\\' => out.push_str("\\\\"),
            '"' => out.push_str("\\\""),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            other => out.push(other),
        }
    }
    out
}

pub(crate) fn parse_optional_mode(
    rule_id: &str,
    raw: Option<&str>,
    default: Mode,
) -> Result<Mode, PolicyError> {
    match raw {
        Some(val) => parse_mode_attr(Some(val)).ok_or_else(|| PolicyError::ValidationFailed {
            rule_id: rule_id.into(),
            detail: format!("invalid mode attribute `{val}`"),
        }),
        None => Ok(default),
    }
}

pub(crate) fn parse_optional_grade(
    rule_id: &str,
    raw: Option<&str>,
) -> Result<Option<ApprovalGrade>, PolicyError> {
    match raw {
        Some(val) => {
            parse_grade_attr(Some(val))
                .map(Some)
                .ok_or_else(|| PolicyError::ValidationFailed {
                    rule_id: rule_id.into(),
                    detail: format!("invalid @min_grade attribute `{val}`"),
                })
        }
        None => Ok(None),
    }
}

pub(crate) fn parse_optional_loss(
    rule_id: &str,
    raw: Option<&str>,
    class_default: Option<LossBehaviour>,
) -> Result<LossBehaviour, PolicyError> {
    match raw {
        Some(val) => parse_loss_attr(Some(val)).ok_or_else(|| PolicyError::ValidationFailed {
            rule_id: rule_id.into(),
            detail: format!("invalid @on_loss attribute `{val}`"),
        }),
        None => Ok(class_default.unwrap_or(LossBehaviour::FailClosed)),
    }
}

pub(crate) fn parse_optional_class(
    rule_id: &str,
    raw: Option<&str>,
) -> Result<(Option<ApprovalGrade>, Option<LossBehaviour>), PolicyError> {
    match raw {
        None => Ok((None, None)),
        Some(val) => match val.trim().to_ascii_lowercase().as_str() {
            "routine" | "baseline" => {
                Ok((Some(ApprovalGrade::G0), Some(LossBehaviour::AllowOnLoss)))
            }
            "out-of-boundary" | "containment" | "cloud" | "dataflow" | "egress" | "mcp"
            | "supply-chain" | "elevate" | "irreversible" | "secret" => {
                Ok((Some(ApprovalGrade::G1), None))
            }
            "config-tamper" => Ok((Some(ApprovalGrade::G2), Some(LossBehaviour::Block))),
            _ => Err(PolicyError::ValidationFailed {
                rule_id: rule_id.into(),
                detail: format!("invalid @class attribute `{val}`"),
            }),
        },
    }
}

pub(crate) fn parse_optional_approver(
    rule_id: &str,
    raw: Option<&str>,
) -> Result<String, PolicyError> {
    match raw {
        None => Ok("self".into()),
        Some(val) => {
            let norm = val.trim().to_ascii_lowercase();
            match norm.as_str() {
                "self" | "sponsor" | "admin" | "quorum" => Ok(norm),
                _ => Err(PolicyError::ValidationFailed {
                    rule_id: rule_id.into(),
                    detail: format!("invalid @approver attribute `{val}`"),
                }),
            }
        }
    }
}

pub(crate) fn parse_optional_remedy(
    rule_id: &str,
    raw: Option<&str>,
) -> Result<Option<String>, PolicyError> {
    match raw {
        None => Ok(None),
        Some(val) => {
            let norm = val.trim().to_ascii_lowercase();
            match norm.as_str() {
                "none" | "plain" => Ok(None),
                "modify" | "modify:auto" => Ok(Some("modify:auto".into())),
                "modify:redact-secrets" | "modify:swap-credential" | "modify:wrap-launcher" => {
                    Ok(Some(norm))
                }
                _ => Err(PolicyError::ValidationFailed {
                    rule_id: rule_id.into(),
                    detail: format!("invalid @remedy attribute `{val}`"),
                }),
            }
        }
    }
}

pub(crate) fn parse_optional_obligation(
    rule_id: &str,
    raw: Option<&str>,
) -> Result<Option<String>, PolicyError> {
    match raw {
        None => Ok(None),
        Some(val) => {
            let norm = val.trim().to_ascii_lowercase();
            match norm.as_str() {
                "receipt" | "expect" | "snapshot" | "pin-recorder" | "notify-user"
                | "notify-sponsor" => Ok(Some(norm)),
                _ => Err(PolicyError::ValidationFailed {
                    rule_id: rule_id.into(),
                    detail: format!("invalid @obligation attribute `{val}`"),
                }),
            }
        }
    }
}

pub(crate) fn parse_rule_annotations(
    effective_id: &str,
    policy: &Policy,
) -> Result<ParsedRuleAnns, PolicyError> {
    let (class_grade, class_loss) = parse_optional_class(effective_id, policy.annotation("class"))?;
    let explicit_grade = parse_optional_grade(effective_id, policy.annotation("min_grade"))?;
    let min_grade = explicit_grade.or(class_grade);
    let on_loss = parse_optional_loss(effective_id, policy.annotation("on_loss"), class_loss)?;
    let approver = parse_optional_approver(effective_id, policy.annotation("approver"))?;
    let remedy_transform = parse_optional_remedy(effective_id, policy.annotation("remedy"))?;
    let requires_snapshot =
        parse_optional_obligation(effective_id, policy.annotation("obligation"))?.as_deref()
            == Some("snapshot");
    let is_final = parse_optional_final(effective_id, policy.annotation("final"))?;
    Ok(ParsedRuleAnns {
        min_grade,
        on_loss,
        approver,
        remedy_transform,
        requires_snapshot,
        is_final,
    })
}

pub(crate) fn parse_optional_final(rule_id: &str, raw: Option<&str>) -> Result<bool, PolicyError> {
    match raw {
        Some("true") => Ok(true),
        Some("false") | None => Ok(false),
        Some(other) => Err(PolicyError::ValidationFailed {
            rule_id: rule_id.into(),
            detail: format!("invalid @final attribute `{other}`"),
        }),
    }
}

pub(crate) fn check_reserved_rule_prefix(
    pack_id: &str,
    effective_id: &str,
    is_base_pack: bool,
    is_essentials_pack: bool,
) -> Result<(), PolicyError> {
    let reserved_base = effective_id.starts_with("base.") || effective_id.starts_with("grdr.base.");
    let reserved_ess = effective_id.starts_with("essentials.");
    let reserved_grdr = effective_id.starts_with("grdr.") && !pack_id.starts_with("grdr.");
    if effective_id.starts_with("system.")
        || effective_id.starts_with("policy.")
        || (reserved_base && !is_base_pack)
        || (reserved_ess && !is_essentials_pack)
        || reserved_grdr
    {
        return Err(PolicyError::ValidationFailed {
            rule_id: effective_id.into(),
            detail: "reserved rule id prefix is forbidden in untrusted pack".into(),
        });
    }
    Ok(())
}

pub(crate) fn compile_parsed_policy(
    rule: &PolicyRule,
    raw_policy: Policy,
    policy_id: &str,
    mode: Mode,
    is_final: bool,
    attach_grant_unless: bool,
    allow_permit: bool,
) -> Result<Policy, PolicyError> {
    let parsed_id = parse_policy_id(policy_id)?;
    let policy = raw_policy.new_id(parsed_id);
    let effect = policy.effect();
    if effect == Effect::Permit && !allow_permit {
        return Err(PolicyError::PermitNotAllowed {
            rule_id: rule.id.clone(),
        });
    }

    let is_final = is_final || policy.annotation("final").is_some_and(|val| val == "true");
    let pst_policy = policy
        .try_into_pst()
        .map_err(|e| PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: e.to_string(),
        })?;
    let pst::Policy::Static(static_policy) = pst_policy else {
        return Err(PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: "linked template policies are not permitted in rule definitions".into(),
        });
    };

    let mut template = static_policy.body().clone();
    template
        .annotations
        .insert("mode".into(), mode.label().into());
    if is_final {
        template.annotations.insert("final".into(), "true".into());
    }

    let needs_grant_clause = attach_grant_unless
        && effect == Effect::Forbid
        && !is_final
        && matches!(mode, Mode::Ask | Mode::Block);
    if needs_grant_clause {
        let grant_clause = build_grant_unless_clause(&rule.id)?;
        template
            .try_add_clause(grant_clause)
            .map_err(|e| PolicyError::CompileFailed {
                rule_id: rule.id.clone(),
                detail: e.to_string(),
            })?;
    }

    let updated =
        pst::StaticPolicy::try_from(template).map_err(|e| PolicyError::CompileFailed {
            rule_id: rule.id.clone(),
            detail: e.to_string(),
        })?;
    Policy::from_pst(pst::Policy::Static(updated)).map_err(|e| PolicyError::CompileFailed {
        rule_id: rule.id.clone(),
        detail: e.to_string(),
    })
}
